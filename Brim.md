---
Learn and practice log investigation, pcap analysis and threat hunting with Brim.
---

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/a8cac632c5b0becd8b206d09d408e30e.png)

### Introduction 

BRIM is an open-source desktop application that processes pcap files and logs files. Its primary focus is providing search and analytics. In this room, you will learn how to use Brim, process pcap files and investigate log files to find the needle in the haystack! This room expects you to be familiar with basic security concepts and processing Zeek log files. We suggest completing the "Network Fundamentals" path and the "Zeek room" before starting working in this room. 

https://www.brimdata.io/

A VM is attached to this room. You don't need SSH or RDP; the room provides a "Split View" feature. Exercise files are located in the folder on the desktop. 
NOTE: DO NOT directly interact with any domains and IP addresses in this room. 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/a5a19cd102e7e30a0ffa65bf6389d919.png)

### What is Brim? 

What is Brim?

Brim is an open-source desktop application that processes pcap files and logs files, with a primary focus on providing search and analytics. It uses the Zeek log processing format. It also supports Zeek signatures and Suricata Rules for detection.

It can handle two types of data as an input;

    Packet Capture Files: Pcap files created with tcpdump, tshark and Wireshark like applications.
    Log Files: Structured log files like Zeek logs.

Brim is built on open-source platforms:

    Zeek: Log generating engine.
    Zed Language: Log querying language that allows performing keywoırd searches with filters and pipelines.
    ZNG Data Format: Data storage format that supports saving data streams.
    Electron and React: Cross-platform UI.

Why Brim?

Ever had to investigate a big pcap file? Pcap files bigger than one gigabyte are cumbersome for Wireshark. Processing big pcaps with tcpdump and Zeek is efficient but requires time and effort. Brim reduces the time and effort spent processing pcap files and investigating the log files by providing a simple and powerful GUI application.

Brim vs Wireshark vs Zeek

While each of them is powerful and useful, it is good to know the strengths and weaknesses of each tool and which one to use for the best outcome. As a traffic capture analyser, some overlapping functionalities exist, but each one has a unique value for different situations.

The common best practice is handling medium-sized pcaps with Wireshark, creating logs and correlating events with Zeek, and processing multiple logs in Brim.

	Brim	Wireshark	Zeek
Purpose	Pcap processing; event/stream and log investigation.	Traffic sniffing. Pcap processing; packet and stream investigation.	Pcap processing; event/stream and log investigation.
GUI	✔
	✔
	✖
Sniffing	✖
	✔
	✔
Pcap processing	✔
	✔
	✔
Log processing	✔
	✖
	✔
Packet decoding	✖
	✔
	✔
Filtering	✔
	✔
	✔
Scripting
	✖
	✖
	✔
Signature Support	✔
	✖
	✔
Statistics	✔
	✔
	✔
File Extraction	✖
	✔
	✔
Handling  pcaps over 1GB	Medium performance
	Low performance
	Good performance
Ease of Management	4/5	4/5	3/5

### The Basics 

Landing Page

Once you open the application, the landing page loads up. The landing page has three sections and a file importing window. It also provides quick info on supported file formats.

    Pools: Data resources, investigated pcap and log files.
    Queries: List of available queries.
    History: List of launched queries.

Pools and Log Details

Pools represent the imported files. Once you load a pcap, Brim processes the file and creates Zeek logs, correlates them, and displays all available findings in a timeline, as shown in the image below. 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/e429e9a957eef2c68ed6f7a84d004fd6.png)

The timeline provides information about capture start and end dates. Brim also provides information fields. You can hover over fields to have more details on the field. The above image shows a user hovering over the Zeek's conn.log file and uid value. This information will help you in creating custom queries. The rest of the log details are shown in the right pane and provides details of the log file fields. Note that you can always export the results by using the export function located near the timeline.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/b190e9dc7fd7ff3b32d5cdfa2838f64d.png)

You can correlate each log entry by reviewing the correlation section at the log details pane (shown on the left image). This section provides information on the source and destination addresses, duration and associated log files. This quick information helps you answer the "Where to look next?" question and find the event of interest and linked evidence.

You can also right-click on each field to filter and accomplish a list of tasks.

    Filtering values
    Counting fields
    Sorting (A-Z and Z-A)
    Viewing details 
    Performing whois lookup on IP address
    Viewing the associated packets in Wireshark

The image below demonstrates how to perform whois lookup and Wireshark packet inspection.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/0e9b4478872cb03531abccd80bdf32f8.png)

Queries and History

Queries help us to correlate finding and find the event of the interest. History stores executed queries.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/28cc8ffb12a9b997833779fb228a379e.png)

The image on the left demonstrates how to browse the queries and load a specific query from the library.

Queries can have names, tags and descriptions. Query library lists the query names, and once you double-click, it passes the actual query to the search bar.

You can double-click on the query and execute it with ease. Once you double-click on the query, the actual query appears on the search bar and is listed under the history tab.

The results are shown under the search bar. In this case, we listed all available log sources created by Brim. In this example, we only insert a pcap file, and it automatically creates nine types of Zeek log files. 

Brim has 12 premade queries listed under the "Brim" folder. These queries help us discover the Brim query structure and accomplish quick searches from templates.  You can add new queries by clicking on the "+" button near the "Queries" menu.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/05866c647f05235deaad8a9b32dbb454.png)


Process the "sample.pcap" file and look at the details of the first DNS log that appear on the dashboard. What is the "qclass_name"?
You can review the details of the log files by "right-click --> "Open details".

![[Pasted image 20221211104118.png]]

*C_INTERNET*


Look at the details of the first NTP log that appear on the dashboard. What is the "duration" value?
The correlation section provides the duration value.
![[Pasted image 20221211104332.png]]

*0.005*


Look at the details of the STATS packet log that is visible on the dashboard. What is the "reassem_tcp_size"?

![[Pasted image 20221211104457.png]]

*540*

### Default Queries 

Default Queries

We mentioned that Brim had 12 premade queries in the previous task. Let's see them in action! Now, open Brim, import the sample pcap and go through the walkthrough.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/700e9a56564f3bb4ca7fdad421dc0cab.png)

Reviewing Overall Activity

This query provides general information on the pcap file. The provided information is valuable for accomplishing further investigation and creating custom queries. It is impossible to create advanced or case-specific queries without knowing the available log files.

The image on the left shows that there are 20 logs generated for the provided pcap file. 

Windows Specific Networking Activity

This query focuses on Windows networking activity and details the source and destination addresses and named pipe, endpoint and operation detection. The provided information helps investigate and understand specific Windows events like SMB enumeration, logins and service exploiting.
Brim - windows networking activity

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/8146a1b9eb1481fd8b4a03f3f8af0f63.png)

Unique Network Connections and Transferred Data

These two queries provide information on unique connections and connection-data correlation. The provided info helps analysts detect weird and malicious connections and suspicious and beaconing activities. The uniq list provides a clear list of unique connections that help identify anomalies. The data list summarises the data transfer rate that supports the anomaly investigation hypothesis.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/b94be33d13d9c597c070f151b3521bb4.png)

DNS and HTTP Methods

These queries provide the list of the DNS queries and HTTP methods. The provided information helps analysts to detect anomalous DNS and HTTP traffic. You can also narrow the search by viewing the "HTTP POST" requests with the available query and modifying it to view the "HTTP GET" methods.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/3c9173d3c3c36f3f9972bba86e54f174.png)

File Activity

This query provides the list of the available files. It helps analysts to detect possible data leakage attempts and suspicious file activity. The query provides info on the detected file MIME and file name and hash values (MD5, SHA1).

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/138f5f08d57d005d47c168c42db7887d.png)

IP Subnet Statistics

This query provides the list of the available IP subnets. It helps analysts detect possible communications outside the scope and identify out of ordinary IP addresses. 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/16d18107e659e30667e63f2b7175cfad.png)

Suricata Alerts

These queries provide information based on Suricata rule results. Three different queries are available to view the available logs in different formats (category-based, source and destination-based, and subnet based). 

Note: Suricata is an open-source threat detection engine that can act as a rule-based Intrusion Detection and Prevention System. It is developed by the Open Information Security Foundation (OISF). Suricata works and detects anomalies in a similar way to Snort and can use the same signatures. 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/1fa588a68ed5d635ba8842ff3ecec6ad.png)


Investigate the files. What is the name of the detected GIF file?
Use task4 pcap file.

![[Pasted image 20221211111745.png]]

![[Pasted image 20221211112014.png]]

*cat01_with_hidden_text.gif*

Investigate the conn logfile. What is the number of the identified city names?
	
	You can filter the conn logfile and then view the available sections by scrolling the horizontal bar. _path=="conn" | cut geo.resp.country_code, geo.resp.region, geo.resp.city

	_path=="conn" | cut geo.resp.country_code, geo.resp.region, geo.resp.city | sort geo.resp.city

![[Pasted image 20221211112359.png]]


*2*


Investigate the Suricata alerts. What is the Signature id of the alert category "Potential Corporate Privacy Violation"?

![[Pasted image 20221211112807.png]]

![[Pasted image 20221211112712.png]]

*2,012,887*

### Use Cases 

Custom Queries and Use Cases

There are a variety of use case examples in traffic analysis. For a security analyst, it is vital to know the common patterns and indicators of anomaly or malicious traffic. In this task, we will cover some of them. Let's review the basics of the Brim queries before focusing on the custom and advanced ones.

Brim Query Reference

```
Purpose	Syntax	Example Query
Basic search 	You can search any string and numeric value. 	

Find logs containing an IP address or any value.
10.0.0.1

Logical operators 	Or, And, Not. 	

Find logs contain three digits of an IP AND NTP keyword.
192 and NTP

Filter values	"field name" == "value"	

Filter source IP.
id.orig_h==192.168.121.40

List specific log file contents
	_path=="log name"
	

List the contents of the conn log file.
_path=="conn"

Count field values 	count () by "field"	

Count the number of the available log files.
count () by _path

Sort findings	sort	

Count the number of the available log files and sort recursively.
count () by _path | sort -r

Cut specific field from a log file	_path=="conn" | cut "field name"	

Cut the source IP, destination port and destination IP addresses from the conn log file.
_path=="conn" | cut id.orig_h, id.resp_p, id.resp_h

List unique values	uniq	

Show the unique network connections. 

_path=="conn" | cut id.orig_h, id.resp_p, id.resp_h | sort | uniq

Note: It is highly suggested to use field names and filtering options and not rely on the blind/irregular search function. Brim provides great indexing of log sources, but it is not performing well in irregular search queries. The best practice is always to use the field filters to search for the event of interest.
Communicated Hosts
	

Identifying the list of communicated hosts is the first step of the investigation. Security analysts need to know which hosts are actively communicating on the network to detect any suspicious and abnormal activity in the first place. This approach will help analysts to detect possible access violations, exploitation attempts and malware infections.

Query: _path=="conn" | cut id.orig_h, id.resp_h | sort | uniq
Frequently Communicated Hosts
	

After having the list of communicated hosts, it is important to identify which hosts communicate with each other most frequently. This will help security analysts to detect possible data exfiltration, exploitation and backdooring activities.

Query: _path=="conn" | cut id.orig_h, id.resp_h | sort | uniq -c | sort -r
Most Active Ports
	

Suspicious activities are not always detectable in the first place. Attackers use multiple ways of hiding and bypassing methods to avoid detection. However, since the data is evidence, it is impossible to hide the packet traces. Investigating the most active ports will help analysts to detect silent and well-hidden anomalies by focusing on the data bus and used services. 

Query: _path=="conn" | cut id.resp_p, service | sort | uniq -c | sort -r count

Query:  _path=="conn" | cut id.orig_h, id.resp_h, id.resp_p, service | sort id.resp_p | uniq -c | sort -r 
Long Connections
	

For security analysts, the long connections could be the first anomaly indicator. If the client is not designed to serve a continuous service, investigating the connection duration between two IP addresses can reveal possible anomalies like backdoors.

Query: _path=="conn" | cut id.orig_h, id.resp_p, id.resp_h, duration | sort -r duration
Transferred Data 
	

Another essential point is calculating the transferred data size. If the client is not designed to serve and receive files and act as a file server, it is important to investigate the total bytes for each connection. Thus, analysts can distinguish possible data exfiltration or suspicious file actions like malware downloading and spreading.

Query: _path=="conn" | put total_bytes := orig_bytes + resp_bytes | sort -r total_bytes | cut uid, id, orig_bytes, resp_bytes, total_bytes
DNS and HTTP Queries
	

Identifying suspicious and out of ordinary domain connections and requests is another significant point for a security analyst. Abnormal connections can help detect C2 communications and possible compromised/infected hosts. Identifying the suspicious DNS queries and HTTP requests help security analysts to detect malware C2 channels and support the investigation hypothesis.

Query: _path=="dns" | count () by query | sort -r

Query: _path=="http" | count () by uri | sort -r
Suspicious Hostnames
	

Identifying suspicious and out of ordinary hostnames helps analysts to detect rogue hosts. Investigating the DHCP logs provides the hostname and domain information.

Query: _path=="dhcp" | cut host_name, domain
Suspicious IP Addresses
	

For security analysts, identifying suspicious and out of ordinary IP addresses is essential as identifying weird domain addresses. Since the connection logs are stored in one single log file (conn), filtering IP addresses is more manageable and provides more reliable results.

Query: _path=="conn" | put classnet := network_of(id.resp_h) | cut classnet | count() by classnet | sort -r
Detect Files
	

Investigating transferred files is another important point of traffic investigation. Performing this hunt will help security analysts to detect the transfer of malware or infected files by correlating the hash values. This act is also valuable for detecting transferring of sensitive files.

Query: filename!=null
SMB Activity
	

Another significant point is investigating the SMB activity. This will help analysts to detect possible malicious activities like exploitation, lateral movement and malicious file sharing. When running an investigation, it is suggested to ask, "What is going on in SMB?".

Query: _path=="dce_rpc" OR _path=="smb_mapping" OR _path=="smb_files"
Known Patterns
	

Known patterns represent alerts generated by security solutions. These alerts are generated against the common attack/threat/malware patterns and known by endpoint security products, firewalls and IDS/IPS solutions. This data source highly relies on available signatures, attacks and anomaly patterns. Investigating available log sources containing alerts is vital for a security analyst.

Brim supports the Zeek and Suricata logs, so any anomaly detected by these products will create a log file. Investigating these log files can provide a clue where the analyst should focus.

Query: event_type=="alert" or _path=="notice" or _path=="signatures"
```

###  Exercise: Threat Hunting with Brim | Malware C2 Detection 

Threat Hunting with Brim | Malware C2 Detection

It is just another malware campaign spread with CobaltStrike. We know an employee clicks on a link, downloads a file, and then network speed issues and anomalous traffic activity arises. Now, open Brim, import the sample pcap and go through the walkthrough.

 Let's investigate the traffic sample to detect malicious C2 activities!

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/fcae25712f15175255e7d725ff18cccd.png)

Let's look at the available logfiles first to see what kind of data artefact we could have. The image on the left shows that we have many alternative log files we could rely on. Let's review the frequently communicated hosts before starting to investigate individual logs.

Query:  cut id.orig_h, id.resp_p, id.resp_h | sort  | uniq -c | sort -r count

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/b56c196610b0a270aaab8102ef3e15ae.png)

This query provides sufficient data that helped us decide where to focus. The IP addresses "10.22.xx" and "104.168.xx" draw attention in the first place. Let's look at the port numbers and available services before focusing on the suspicious IP address and narrowing our search.

	Query: _path=="conn" | cut id.resp_p, service | sort | uniq -c | sort -r count

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/c166d49a6f0226462941ea3d7fa483b7.png)

Nothing extremely odd in port numbers, but there is a massive DNS record available. Let's have a closer look.

	Query:  _path=="dns" | count() by query | sort -r

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/e8e99b9574ae2bb9b9bcd00bc3a2f4d6.png)

There are out of ordinary DNS queries. Let's enrich our findings by using VirusTotal to identify possible malicious domains.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/aa38d28211b3017f4b0f6c158ffa9ae3.png)

We have detected two additional malicious IP addresses (we have the IP 45.147.xx from the log files and gathered the 68.138.xx and 185.70.xx from VirusTotal) linked with suspicious DNS queries with the help of external research. Let's look at the HTTP requests before narrowing down our investigation with the found malicious IP addresses.

	Query:  _path=="http" | cut id.orig_h, id.resp_h, id.resp_p, method, host, uri | uniq -c | sort value.uri

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/cdc582d20a3c62c89cdfba7af569c5ea.png)

We detect a file download request from the IP address we assumed as malicious. Let's validate this idea with VirusTotal and validate our hypothesis. 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/a040972d62794ecb27d03ca973251961.png)

VirusTotal results show that the IP address "104.xx" is linked with a file. Once we investigate that file, we discover that these two findings are associated with CobaltStrike. Up to here, we've followed the abnormal activity and found the malicious IP addresses. Our findings represent the C2 communication. Now let's conclude our hunt by gathering the low hanging fruits with Suricata logs.

	Query:  event_type=="alert" | count() by alert.severity,alert.category | sort count

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/bf13990b1e9cb18531f0a3c0e574fbc2.png)

Now we can see the overall malicious activities detected by Suricata. Note that you can investigate the rest of the IP addresses to identify the secondary C2 traffic anomaly without using the Suricata logs. This task demonstrates two different approaches to detecting anomalies. 

Investigating each alarm category and signature to enhance the threat hunting activities and post-hunting system hardening operations is suggested. Please note, Adversaries using CobaltStrike are usually skilled threats and don't rely on a single C2 channel. Common experience and use cases recommend digging and keeping the investigation by looking at additional C2 channels.

This concludes our hunt for the given case. Now, repeat this exercise in the attached VM and ask the questions below.


What is the name of the file downloaded from the CobaltStrike C2 connection?

```
ips: 10.22.5.47 , 104.168.44.45

dns count 184 , let's investigate

hashingold.top -- lasticjugs.top (virustotal)

https://www.virustotal.com/gui/domain/hashingold.top/relations


IP

44.227.65.245

44.227.76.166

157.245.198.147

137.184.221.191

68.183.206.22


45.147.228.138 

https://www.virustotal.com/gui/domain/lasticjugs.top/relations

IP

44.227.76.166

44.227.65.245

157.245.198.147

185.70.186.133 

possible ips

_path=="http" | cut id.orig_h, id.resp_h, id.resp_p, method, host, uri | uniq -c | sort value.uri

found the file download from the host: 104.168.44.45 /download/4564.exe

---

_path=="conn" | id.resp_h==104.168.44.45 | count() by id.resp_p

id.resp_h 443 ---> 328

```

![[Pasted image 20221211115832.png]]



![[Pasted image 20221211120109.png]]

![[Pasted image 20221211120403.png]]

![[Pasted image 20221211121249.png]]

*4564.exe*


What is the number of CobaltStrike connections using port 443?
The IP starting with "104" is CobaltStrike.

![[Pasted image 20221211122641.png]]

**


There is an additional C2 channel in used the given case. What is the name of the secondary C2 channel?
	 
	 event_type=="alert" | cut alert.signature | sort -r | uniq -c | sort -r count

Command and Control (C2) Infrastructure are a set of programs used to communicate with a victim machine. This is comparable to a reverse shell, but is generally more advanced and often communicate via common network protocols, like HTTP, HTTPS and DNS. 
![[Pasted image 20221211123213.png]]

*IcedID*

### Exercise: Threat Hunting with Brim | Crypto Mining 

Threat Hunting with Brim | Crypto Mining

Cryptocurrencies are frequently on the agenda with their constantly rising value and legal aspect. The ability to obtain cryptocurrencies by mining other than purchasing is becoming one of the biggest problems in today's corporate environments. Attackers not only compromise the systems and ask for a ransom, but sometimes they also install mining tools (cryptojacking). Other than the attackers and threat actors, sometimes internal threats and misuse of trust and privileges end up installing coin miners in the corporate environment.

Usually, mining cases are slightly different from traditional compromising activities. Internal attacks don't typically contain major malware samples. However, this doesn't mean they aren't malicious as they are exploiting essential corporate resources like computing power, internet, and electricity. Also, crypto mining activities require third party applications and tool installations which could be vulnerable or create backdoors. Lastly, mining activities are causing network performance and stability problems. Due to these known facts, coin mining is becoming one of the common use cases of threat hunters.

Now, open Brim, import the sample pcap and go through the walkthrough.

Let's investigate a traffic sample to detect a coin mining activity!

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/6bf48a81a4904ac4c0896ba38cb058b0.png)

Let's look at the available logfiles first to see what kind of data artefact we could have. The image on the left shows that we don't have many alternative log files we could rely on. Let's review the frequently communicated hosts to see if there is an anomaly indicator. 

Query:  cut id.orig_h, id.resp_p, id.resp_h | sort  | uniq -c | sort -r

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/d6fbc67b061e4c38522ba5df364b8dc8.png)

This query provided sufficient data that helped us decide where to focus. The IP address "192.168.xx" draws attention in the first place. Let's look at the port numbers and available services before focusing on the suspicious IP address and narrowing our search.

	Query: _path=="conn" | cut id.resp_p, service | sort | uniq -c | sort -r count

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/2b36a8f09b094b06da9ea95a354ff9e6.png)

There is multiple weird port usage, and this is not usual. Now, we are one step closer to the identification of the anomaly. Let's look at the transferred data bytes to support our findings and find more indicators.

	Query: _path=="conn" | put total_bytes := orig_bytes + resp_bytes | sort -r total_bytes | cut uid, id, orig_bytes, resp_bytes, total_bytes

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/8d30202d4ab8b8b61b9c3c8f435761a5.png)

The query result proves massive traffic originating from the suspicious IP address. The detected IP address is suspicious. However, we don't have many supportive log files to correlate our findings and detect accompanying activities. At this point, we will hunt the low hanging fruits with the help of Suricata rules. Let's investigate the Suricata logs.
	
	Query: event_type=="alert" | count() by alert.severity,alert.category | sort count

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/f1aa85bc7dfc14478afd0ffbbf832d20.png)

Suricata rules have helped us conclude our hunt quickly, as the alerts tell us we are investigating a "Crypto Currency Mining" activity. Let's dig deeper and discover which data pool is used for the mining activity. First, we will list the associated connection logs with the suspicious IP, and then we will run a VirusTotal search against the destination IP.

	Query: _path=="conn" | 192.168.1.100

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/79438eae146833967d3e6a3af7835a33.png)

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/0103bf02af6332ba8d60e02a5107b926.png)

We investigated the first destination IP address and successfully identified the mining server. In real-life cases, you may need to investigate multiple IP addresses to find the event of interest.

Lastly, let's use Suricata logs to discover mapped out MITRE ATT&CK techniques.

	Query: event_type=="alert" | cut alert.category, alert.metadata.mitre_technique_name, alert.metadata.mitre_technique_id, alert.metadata.mitre_tactic_name | sort | uniq -c

![999](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/cd0190902c6c195fc8e984d745998819.png)

Now we can identify the mapped out MITRE ATT&CK details as shown in the table below.
Suricata Category
	MITRE Technique Name
	MITRE Technique Id
	MITRE Tactic Name
Crypto Currency Mining
	Resource_Hijacking
	T1496
	Impact

This concludes our hunt for the given case. Now, repeat this exercise in the attached VM and ask the questions below.



How many connections used port 19999?

![[Pasted image 20221211130241.png]]

```
id.resp_p==19999 | count() by id.resp_p 
```

*22*


What is the name of the service used by port 6666?

![[Pasted image 20221211130652.png]]
```
id.resp_p==6666 | cut id.resp_p, service | sort | uniq -c
```

*irc*


What is the amount of transferred total bytes to "101.201.172.235:8888"?

![[Pasted image 20221211130859.png]]

```
_path=="conn" id.resp_p==8888 id.resp_h==101.201.172.235 | put total_bytes := orig_bytes + resp_bytes | sort -r total_bytes | cut uid, id, orig_bytes, resp_bytes, total_bytes
```

*3,729*



What is the detected MITRE tactic id?
Investigate the alert logs without filter and find the tactic id field.
MITRE Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK) 

![[Pasted image 20221211131636.png]]


```
event_type=="alert" | alert.metadata.mitre_tactic_id
```

*TA0040*


### Conclusion 



Congratulations! You just finished the Brim room.

In this room, we covered Brim, what it is, how it operates, and how to use it to investigate threats. 

Now, we invite you to complete the Brim challenge room: Masterminds
https://tryhackme.com/room/mastermindsxlq (I'll do it soon)



[[Zeek Exercises]]