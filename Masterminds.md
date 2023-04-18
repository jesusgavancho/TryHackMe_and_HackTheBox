----
Practice analyzing malicious traffic using Brim.
----
![](https://tryhackme-images.s3.amazonaws.com/room-icons/03fe1b480ba9d32b7065f2dda0bf4fba.png)

###  Detect the compromise using Brim.

 Start Machine

![](https://i.ibb.co/T1tPZdn/Depositphotos-174220344-s-2019.jpg)  

Three machines in the Finance department at Pfeffer PLC were compromised. We suspect the initial source of the compromise happened through a phishing attempt and by an infected USB drive. The Incident Response team managed to pull the network traffic logs from the endpoints. Use Brim to investigate the network traffic for any indicators of an attack and determine who stands behind the attacks. 

**NOTE: DO NOT** directly interact with any domains and IP addresses in this challenge. 

---

Deploy the machine attached to this task; it will be visible in the **split-screen** view once it is ready.

If you don't see a virtual machine load then click the **Show Split View** button.

![](https://assets.tryhackme.com/additional/brimchallenge/brim-split-view.png)

Answer the questions below

Read the above.

 Completed

###  [Infection 1]

![111](https://i.ibb.co/SrZtgk8/Depositphotos-29702781-s-2019.jpg)

  

Start by loading the Infection1 packet capture in Brim to investigate the compromise event for the first machine. All the PCAPs can be found here: `/home/ubuntu/Desktop/PCAPs`  

**Note**: For questions that require multiple answers, please separate the answers with a comma.

Answer the questions below

```
using brim

suricata alert "Trojan was detected"
filter: 192.168.75.249 status_code==404

host: cambiasuhistoria.growlab.es, www.letscompareonline.com

filter: 192.168.75.249 response_body_len==1309

host: ww25.gocphongthe.com && id.resp_h: 199.59.242.153

filter: dns query=="CAB.MYKFN.COM" 
6 + 1 = 7

filter: bhaktivrind.com
uri: /cgi-bin/JBbb8/

filter: _path=="http" host=="hdmilg.xyz" 
id.resp_h: 185.239.243.112 && host: hdmilg.xyz && uri: /catzx.exe

https://malware.me/report/15424
md5: 5b86fcaf5ab130c47731cc168a2ca852
https://www.virustotal.com/gui/file/0aae44ceb97790a03f1093278faeb08fbdfbef70ba53d6516428c10644d64132

I was wrong, I thought from the filename catzx.exe NanoCore (second question)

https://www.virustotal.com/gui/domain/cambiasuhistoria.growlab.es/community
Emotet

#emotet  
This IOC was found in a paste: https://pastebin.com/aZPxxwcr with the title "Weekend Emotet IoCs and Notes for 2021/01/22-24" by jroosen

https://news.sophos.com/en-us/2019/03/05/emotet-101-stage-3-the-emotet-executable/

```

Provide the victim's IP address.

![[Pasted image 20230418124746.png]]

*192.168.75.249*

The victim attempted to make HTTP connections to two suspicious domains with the status '404 Not Found'. Provide the hosts/domains requested. 

	*cambiasuhistoria.growlab.es, www.letscompareonline.com*

The victim made a successful HTTP connection to one of the domains and received the response_body_len of 1,309 (uncompressed content size of the data transferred from the server). Provide the domain and the destination IP address.

*ww25.gocphongthe.com,199.59.242.153*

	How many unique DNS requests were made to cab[.]myfkn[.]com domain (including the capitalized domain)? 

![[Pasted image 20230418130106.png]]

*7*

	Provide the URI of the domain bhaktivrind[.]com that the victim reached out over HTTP. 

*/cgi-bin/JBbb8/*

Provide the IP address of the malicious server and the executable that the victim downloaded from the server. 

![[Pasted image 20230418130848.png]]

*185.239.243.112, catzx.exe*

Based on the information gathered from the second question, provide the name of the malware using [VirusTotal](https://www.virustotal.com/gui/home/upload).

Check what the Community has to say.

*Emotet*

### [Infection 2]

![111](https://i.ibb.co/6v1mjDq/Blue-file-folder-isolated-on-white-background.jpg)  

Please, navigate to the Infection2 packet capture in Brim to investigate the compromise event for the second machine.

Note: For questions that require multiple answers, please separate the answers with a comma.  

Answer the questions below

```
using brim

filter: event_type=="alert" | alerts := union(alert.category) by src_ip, dest_ip

src_ip: 192.168.75.146

filter: 192.168.75.146 method=="POST"

3 connections via POST

id.resp_h: 5.181.156.252

filter: _path=="dns" | count() by query | sort -r

filter: hypercustom.top

id.resp_h: 45.95.203.28 && method: GET && host: hypercustom.top && uri: /jollion/apines.exe

https://urlhaus.abuse.ch/browse.php?search=hypercustom.top

https://infosecwriteups.com/redline-stealer-malware-static-analysis-69367b37a146

```

Provide the IP address of the victim machine. 

*192.168.75.146*

Provide the IP address the victim made the POST connections to. 

*5.181.156.252*

How many POST connections were made to the IP address in the previous question?

*3*

Provide the domain where the binary was downloaded from. 

*hypercustom.top*

Provide the name of the binary including the full URI.

*/jollion/apines.exe*

Provide the IP address of the domain that hosts the binary.

*45.95.203.28*

There were 2 Suricata "A Network Trojan was detected" alerts. What were the source and destination IP addresses? 

![[Pasted image 20230418134548.png]]

*192.168.75.146,45.95.203.28*

Taking a look at .top domain in HTTP requests, provide the name of the stealer (Trojan that gathers information from a system) involved in this packet capture using [URLhaus Database](https://urlhaus.abuse.ch/). 

![[Pasted image 20230418134719.png]]

*RedLine Stealer*

###  [Infection 3]

![111](https://i.ibb.co/bP1frZQ/Depositphotos-5808322-s-2019.jpg)  

Please, load the Infection3 packet capture in Brim to investigate the compromise event for the third machine.  

Note: For questions that require multiple answers, please separate the answers with a comma.  

Answer the questions below

```
using brim

filter: event_type=="alert" | alerts := union(alert.category) by src_ip, dest_ip

	src_ip: 192.168.75.232

filter: _path=="http" | cut id.orig_h, id.resp_h, id.resp_p, method,host, uri | uniq -c

xfhoahegue.ru, afhoahegue.ru, efhoahegue.ru
id.resp_h: 63.251.106.25, 199.21.76.77, 162.217.98.146

filter: dns 63.251.106.25

2 queries

filter: 63.251.106.25 method=="GET" uri!="/s/VNEW=1"

5 executables 

user_agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:25.0) Gecko/20100101 Firefox/25.0

filter: _path=="dns" | count() 

986

https://www.virustotal.com/gui/domain/xfhoahegue.ru/details

[Phorphiex/Trik Botnet Campaign Leads to Multiple Infections]

https://appriver.com/blog/phorphiextrik-botnet-campaign-leads-to-multiple-infections-ransomware-banking-trojan-cryptojacking
```

Provide the IP address of the victim machine.

![[Pasted image 20230418135132.png]]

*192.168.75.232*

Provide three C2 domains from which the binaries were downloaded (starting from the earliest to the latest in the timestamp)

Start from the bottom of the output and work your way up or use '| sort ts'.

![[Pasted image 20230418140047.png]]

*xfhoahegue.ru, afhoahegue.ru, efhoahegue.ru*

Provide the IP addresses for all three domains in the previous question.

*63.251.106.25, 199.21.76.77, 162.217.98.146*

How many unique DNS queries were made to the domain associated from the first IP address from the previous answer? 

*2*

How many binaries were downloaded from the above domain in total? 

*5*

Provided the user-agent listed to download the binaries. 

Try to type "user_agent" in the search bar.

*Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:25.0) Gecko/20100101 Firefox/25.0*

Provide the amount of DNS connections made in total for this packet capture.

*986*

With some OSINT skills, provide the name of the worm using the first domain you have managed to collect from Question 2. (Please use quotation marks for Google searches, don't use .ru in your search, and DO NOT interact with the domain directly).

*phorphiex*

[[Lunizz CTF]]