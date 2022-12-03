---
Learn what is the Pyramid of Pain and how to utilize this model to determine the level of difficulty it will cause for an adversary to change the indicators associated with them, and their campaign. 
---

![](https://tryhackme-images.s3.amazonaws.com/room-icons/8936117864e5ca45181c1de6d6e83e5c.png)
###  Introduction 

![](https://i.ibb.co/QYWXRSh/pop2.png)

This well-renowned concept is being applied to cybersecurity solutions like [Cisco Security](https://gblogs.cisco.com/ca/2020/08/26/the-canadian-bacon-cisco-security-and-the-pyramid-of-pain/), [SentinelOne](https://www.sentinelone.com/blog/revisiting-the-pyramid-of-pain-leveraging-edr-data-to-improve-cyber-threat-intelligence/), and [SOCRadar](https://socradar.io/re-examining-the-pyramid-of-pain-to-use-cyber-threat-intelligence-more-effectively/) to improve the effectiveness of CTI (Cyber Threat Intelligence), threat hunting, and incident response exercises.

Understanding the Pyramid of Pain concept as a Threat Hunter, Incident Responder, or SOC Analyst is important.

Are you ready to explore what hides inside the Pyramid of Pain? 

###  Hash Values (Trivial) 

As per Microsoft, the hash value is a numeric value of a fixed length that uniquely identifies data. A hash value is the result of a hashing algorithm. The following are some of the most common hashing algorithms: 

    MD5 (Message Digest, defined by RFC 1321) - was designed by Ron Rivest in 1992 and is a widely used cryptographic hash function with a 128-bit hash value. MD5 hashes are NOT considered cryptographically secure. In 2011, the IETF published RFC 6151, "Updated Security Considerations for the MD5 Message-Digest and the HMAC-MD5 Algorithms," which mentioned a number of attacks against MD5 hashes, including the hash collision.
    https://datatracker.ietf.org/doc/html/rfc6151

    SHA-1 (Secure Hash Algorithm 1, defined by RFC 3174) - was invented by United States National Security Agency in 1995. When data is fed to SHA-1 Hashing Algorithm, SHA-1 takes an input and produces a 160-bit hash value string as a 40 digit hexadecimal number. NIST deprecated the use of SHA-1 in 2011 and banned its use for digital signatures at the end of 2013 based on it being susceptible to brute-force attacks. Instead, NIST recommends migrating from SHA-1 to stronger hash algorithms in the SHA-2 and SHA-3 families.
    https://csrc.nist.gov/news/2017/research-results-on-sha-1-collisions
    https://iacr.org/archive/crypto2005/36210017/36210017.pdf


    The SHA-2 (Secure Hash Algorithm 2) - SHA-2 Hashing Algorithm was designed by The National Institute of Standards and Technology (NIST) and the National Security Agency (NSA) in 2001 to replace SHA-1. SHA-2 has many variants, and arguably the most common is SHA-256. The SHA-256 algorithm returns a hash value of 256-bits as a 64 digit hexadecimal number.

A hash is not considered to be cryptographically secure if two files have the same hash value or digest.

Security professionals usually use the hash values to gain insight into a specific malware sample, a malicious or a suspicious file, and as a way to uniquely identify and reference the malicious artifact.

You probably read the ransomware reports in the past, where security researchers would provide the hashes related to the malicious or suspicious files used at the end of the report. You can check out The DFIR Report and FireEye Threat Research Blogs if you’re interested in seeing an example.

https://thedfirreport.com/
some stories
https://www.trellix.com/en-us/about/newsroom/stories/research/yanluowang-ransomware-leaks-analysis.html

Various online tools can be used to do hash lookups like VirusTotal and [Metadefender Cloud - OPSWAT](https://metadefender.opswat.com/?lang=enhttps://metadefender.opswat.com/?lang=en).

VirusTotal:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/60c7fac321aca20049602d2b/room-content/b217b6aa2148826ef0e88ec28c2aa79e.png)

MetaDefender Cloud - OPSWAT:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/60c7fac321aca20049602d2b/room-content/8e9ad0b23f711036a023a9311dfa0b1d.png)

```
curl 'https://api.metadefender.com/v4/ip/192.0.0.1' \
    -H 'apikey: 8ce7c57cabfa165d9db646e5cb2d4f49'

{"address":"192.0.0.1","lookup_results":{"start_time":"2022-12-01T04:03:04.101Z","detected_by":0,"sources":[{"provider":"webroot.com","assessment":"trustworthy","detect_time":"","update_time":"2022-12-01T04:03:04.169Z","status":0},{"provider":"avira.com","assessment":"","detect_time":"","update_time":"2022-12-01T04:03:04.115Z","status":5},{"provider":"reputation.alienvault.com","assessment":"","detect_time":"","update_time":"2022-12-01T04:03:04.139Z","status":5},{"provider":"danger.rulez.sk","assessment":"","detect_time":"","update_time":"2022-12-01T04:03:04.139Z","status":5},{"provider":"feodotracker.abuse.ch","assessment":"","detect_time":"","update_time":"2022-12-01T04:03:04.139Z","status":5},{"provider":"spamhaus.org","assessment":"","detect_time":"","update_time":"2022-12-01T04:03:04.139Z","status":5},{"provider":"isc.sans.edu","assessment":"","detect_time":"","update_time":"2022-12-01T04:03:04.139Z","status":5}]},"geo_info":{}}   
```

As you might have noticed, it is really easy to spot a malicious file if we have the hash in our arsenal.  However, as an attacker, it’s trivial to modify a file by even a single bit, which would produce a different hash value. With so many variations and instances of known malware or ransomware, threat hunting using file hashes as the IOC (Indicators of Compromise) can become a difficult task.

Let’s take a look at an example of how you can change the hash value of a file by simply appending a string to the end of a file using echo: File Hash (Before Modification)

```
  
PS C:\Users\THM\Downloads> Get-FileHash .\OpenVPN_2.5.1_I601_amd64.msi -Algorithm MD5
Algorithm Hash                             Path                                                 
_________ ____                             ____                                                 
MD5       D1A008E3A606F24590A02B853E955CF7 C:\Users\THM\Downloads\OpenVPN_2.5.1_I601_amd64.msi

File Hash (After Modification)

PS C:\Users\THM\Downloads> echo "AppendTheHash" >> .\OpenVPN_2.5.1_I601_amd64.msi
PS C:\Users\THM\Downloads> Get-FileHash .\OpenVPN_2.5.1_I601_amd64.msi -Algorithm MD5
Algorithm Hash                             Path                                                 
_________ ____                             ____                                                 
MD5       9D52B46F5DE41B73418F8E0DACEC5E9F C:\Users\THM\Downloads\OpenVPN_2.5.1_I601_amd64.msi


PS C:\Users\User\Desktop> Get-FileHash .\ospf.txt -Algorithm MD5

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
MD5             D548D2DFA50EE4E2A9F58FDFD1A75AC6                                       C:\Users\User\Desktop\ospf.txt


┌──(root㉿kali)-[/home/kali/Desktop]
└─# pwsh
PowerShell 7.3.0
PS /home/kali/Desktop> ls
comandos_mininet  learning_mininet.py  test.txt
PS /home/kali/Desktop> cat ./test.txt
testing:)
PS /home/kali/Desktop> Get-FileHash ./test.txt -Algorithm MD5

Algorithm       Hash
---------       ----                                                    
MD5             876B8CF2D198AC32C70E6E091762AB63 

PS /home/kali/Desktop> echo "AppendTheHash" >> ./test.txt
PS /home/kali/Desktop> Get-FileHash ./test.txt -Algorithm MD5

Algorithm       Hash
---------       ----                                                    
MD5             8D9DAF6250BBB0B9C11634C7A7CEBD80 

```


Provide the ransomware name for the hash '63625702e63e333f235b5025078cea1545f29b1ad42b1e46031911321779b6be' using open-source lookup tools

```
┌──(kali㉿kali)-[~]
└─$ curl 'https://api.metadefender.com/v4/hash/63625702e63e333f235b5025078cea1545f29b1ad42b1e46031911321779b6be' \
    -H 'apikey: 8ce7c57cabfa165d9db646e5cb2d4f49'
{"scan_result_history_length":8,"malware_family":"cryptor","malware_type":["trojan","ransom","backdoor"],"threat_name":"Trojan/Cryptor!UKA5wFNU","votes":{"up":0,"down":2},"sandbox":false,"file_id":"bzIyMDExMWUxSi1KYXA2Qw","data_id":"bzIyMDExMWUxSi1KYXA2Q3h2WXdtdWdSQjA","sanitized":{"result":"Error","reason":"File is not sanitizable","progress_percentage":100},"process_info":{"post_processing":{"actions_failed":"","actions_ran":"","converted_destination":"","converted_to":"","copy_move_destination":""},"blocked_reason":"Infected","file_type_skipped_scan":false,"profile":"multiscan_sanitize","progress_percentage":100,"result":"Blocked"},"scan_results":{"scan_details":{"AhnLab":{"def_time":"2022-01-12T00:00:00.000Z","scan_result_i":1,"scan_time":320,"threat_found":"Malware/Win32.Generic"},"Antiy":{"def_time":"2021-12-31T02:15:00.000Z","scan_result_i":0,"scan_time":319,"threat_found":""},"Comodo":{"def_time":"2022-01-11T03:48:14.000Z","scan_result_i":1,"scan_time":515,"threat_found":"Malware"},"CrowdStrike Falcon ML":{"def_time":"2022-01-11T00:00:00.000Z","scan_result_i":1,"scan_time":259,"threat_found":"win/malicious_confidence_100"},"Emsisoft":{"def_time":"2022-01-11T11:36:00.000Z","scan_result_i":1,"scan_time":406,"threat_found":"Trojan.GenericKD.36235215 (B)"},"HAURI":{"def_time":"2022-01-11T00:00:00.000Z","scan_result_i":0,"scan_time":315,"threat_found":""},"IKARUS":{"def_time":"2022-01-11T13:18:25.000Z","scan_result_i":1,"scan_time":194,"threat_found":"Trojan.SuspectCRC"},"K7":{"def_time":"2022-01-11T13:20:00.000Z","scan_result_i":1,"scan_time":368,"threat_found":"Riskware ( 0040eff71 )"},"Kaspersky":{"def_time":"2022-01-11T10:58:00.000Z","scan_result_i":1,"scan_time":675,"threat_found":"Trojan-Ransom.Win32.Cryptor.eay"},"Quick Heal":{"def_time":"2022-01-10T22:23:00.000Z","scan_result_i":0,"scan_time":401,"threat_found":""},"Webroot SMD":{"def_time":"2022-01-04T21:00:10.000Z","scan_result_i":1,"scan_time":704,"threat_found":"Malware"},"Microsoft Defender":{"def_time":"2022-01-11T06:35:31.000Z","scan_result_i":0,"scan_time":307,"threat_found":""},"Zillya!":{"def_time":"2022-01-09T19:10:00.000Z","scan_result_i":1,"scan_time":241,"threat_found":"Backdoor.Androm.Win32.76038"},"Avira":{"def_time":"2022-01-11T13:22:00.000Z","scan_result_i":1,"scan_time":872,"threat_found":"HEUR/AGEN.1141670"},"ClamAV":{"def_time":"2022-01-11T09:24:18.000Z","scan_result_i":0,"scan_time":1115,"threat_found":""},"Filseclab":{"def_time":"2022-01-10T23:07:10.000Z","scan_result_i":0,"scan_time":826,"threat_found":""},"Huorong":{"def_time":"2022-01-11T09:31:47.000Z","scan_result_i":1,"scan_time":957,"threat_found":"Backdoor/Agent.ld"},"SUPERAntiSpyware":{"def_time":"2022-01-08T17:46:38.151Z","scan_result_i":0,"scan_time":1348,"threat_found":""},"AegisLab":{"def_time":"2022-01-11T07:36:38.000Z","scan_result_i":0,"scan_time":2288,"threat_found":""},"Bitdefender":{"def_time":"2022-01-11T10:20:39.000Z","scan_result_i":1,"scan_time":2356,"threat_found":"Trojan.GenericKD.36235215"},"Cyren":{"def_time":"2022-01-11T13:37:00.000Z","scan_result_i":1,"scan_time":2286,"threat_found":"W32/Trojan.HANI-2747"},"McAfee":{"def_time":"2022-01-10T00:00:00.000Z","scan_result_i":1,"scan_time":2169,"threat_found":"Trojan-FTSE!6349D5381BEA"},"NANOAV":{"def_time":"2022-01-11T12:28:00.000Z","scan_result_i":1,"scan_time":1970,"threat_found":"Trojan.Win32.Cryptor.iiqmuo"},"RocketCyber":{"def_time":"2022-01-11T00:00:00.000Z","scan_result_i":2,"scan_time":2298,"threat_found":""},"Sophos":{"def_time":"2022-01-11T04:21:13.000Z","scan_result_i":1,"scan_time":2281,"threat_found":"Troj/Ransom-GEM"},"TACHYON":{"def_time":"2022-01-11T00:00:00.000Z","scan_result_i":0,"scan_time":2278,"threat_found":""},"Trend Micro":{"def_time":"2022-01-10T20:22:49.000Z","scan_result_i":1,"scan_time":2505,"threat_found":"Ransom.593AC082"},"Trend Micro HouseCall":{"def_time":"2022-01-10T20:38:35.000Z","scan_result_i":1,"scan_time":2513,"threat_found":"Ransom.593AC082"},"VirusBlokAda":{"def_time":"2022-01-10T07:53:42.000Z","scan_result_i":0,"scan_time":2275,"threat_found":""},"Jiangmin":{"def_time":"2022-01-11T04:37:05.000Z","scan_result_i":1,"scan_time":3282,"threat_found":"Trojan.Cryptor.vo"},"Xvirus Anti-Malware":{"def_time":"2022-01-10T20:58:25.000Z","scan_result_i":0,"scan_time":3166,"threat_found":""},"ESET":{"def_time":"2022-01-11T11:38:42.000Z","scan_result_i":1,"scan_time":5804,"threat_found":"a variant of Win32/Kryptik.HJAO trojan"},"Vir.IT ML":{"def_time":"2022-01-11T12:30:00.000Z","scan_result_i":0,"scan_time":848,"threat_found":""},"Vir.IT eXplorer":{"def_time":"2022-01-11T12:30:00.000Z","scan_result_i":0,"scan_time":2363,"threat_found":""}},"scan_all_result_i":1,"start_time":"2022-01-11T15:06:50.120Z","total_time":5910,"total_avs":34,"total_detected_avs":21,"progress_percentage":100,"scan_all_result_a":"Infected"},"file_info":{"file_size":822784,"upload_timestamp":"2022-01-11T15:06:47.400Z","md5":"6349D5381BEAE42063EDE8CB76143267","sha1":"B82BB1E2778A0C9FF7683435C21FBB92C8F87D10","sha256":"63625702E63E333F235B5025078CEA1545F29B1AD42B1E46031911321779B6BE","file_type_category":"E","file_type_description":"Executable File","file_type_extension":"exe","display_name":"Conti_1.exe"},"share_file":1,"private_processing":0,"rest_version":"4","additional_info":["appinfo","peinfo"],"stored":true}  
```

![[Pasted image 20221130232311.png]]

*Conti*

### IP Address (Easy) 

You may have learned the importance of an IP Address from the "What is Networking?" Room. the importance of the IP Address. An IP address is used to identify any device connected to a network. These devices range from desktops, to servers and even CCTV cameras!. We rely on IP addresses to send and receive the information over the network. But we are not going to get into the structure and functionality of the IP address. As a part of the Pyramid of Pain, we’ll evaluate how IP addresses are used as an indicator.

In the Pyramid of Pain, IP addresses are indicated with the color green. You might be asking why and what you can associate the green colour with?

From a defense standpoint, knowledge of the IP addresses an adversary uses can be valuable. A common defense tactic is to block, drop, or deny inbound requests from IP addresses on your parameter or external firewall. This tactic is often not bulletproof as it’s trivial for an experienced adversary to recover simply by using a new public IP address.

Malicious IP connections ([app.any.run](https://app.any.run/tasks/a66178de-7596-4a05-945d-704dbf6b3b90)):

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/60c7fac321aca20049602d2b/room-content/86baaabb1df7d710dfc219762c4713e6.png)

NOTE! Do not attempt to interact with the IP addresses shown above.

One of the ways an adversary can make it challenging to successfully carry out IP blocking is by using Fast Flux.

According to [Akamai](https://blogs.akamai.com/2017/10/digging-deeper-an-in-depth-analysis-of-a-fast-flux-network-part-one.html), Fast Flux is a DNS technique used by botnets to hide phishing, web proxying, malware delivery, and malware communication activities behind compromised hosts acting as proxies. The purpose of using the Fast Flux network is to make the communication between malware and its command and control server (C&C) challenging to be discovered by security professionals. 

So, the primary concept of a Fast Flux network is having multiple IP addresses associated with a domain name, which is constantly changing. Palo Alto created a great fictional scenario to explain Fast Flux: "Fast Flux 101: How Cybercriminals Improve the Resilience of Their Infrastructure to Evade Detection and Law Enforcement Takedowns"
https://unit42.paloaltonetworks.com/fast-flux-101/

Use the following [any.run](https://app.any.run/tasks/a66178de-7596-4a05-945d-704dbf6b3b90/) URL to answer the questions below:


What is the ASN for the third IP address observed?
Check the Connections tab
![[Pasted image 20221130235145.png]]
*Host Europe GmbH*


What is the domain name associated with the first IP address observed?
Check the DNS Requests tab
*craftingalegacy.com*

### Domain Names (Simple) 

Let's step up the Pyramid of Pain and move on to Domain Names. You can see the transition of colors - from green to teal.

Domain Names can be thought as simply mapping an IP address to a string of text. A domain name can contain a domain and a top-level domain (evilcorp.com) or a sub-domain followed by a domain and top-level domain (tryhackme.evilcorp.com). But we will not go into the details of how the Domain Name System (DNS) works. You can learn more about DNS in this "DNS in Detail" Room. 

Domain Names can be a little more of a pain for the attacker to change as they would most likely need to purchase the domain, register it and modify DNS records. Unfortunately for defenders, many DNS providers have loose standards and provide APIs to make it even easier for the attacker to change the domain.

Malicious Sodinokibi C2 (Command and Control Infrastructure) domains:

![1040](https://tryhackme-images.s3.amazonaws.com/user-uploads/60c7fac321aca20049602d2b/room-content/efcc44de8368a8cc7d99148f560ae2fd.png)


![](https://tryhackme-images.s3.amazonaws.com/user-uploads/60c7fac321aca20049602d2b/room-content/03ad636820590525bdd91e28a04bbec1.png)

Can you spot anything malicious in the above screenshot? Now, compare it to the legitimate website view below:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/60c7fac321aca20049602d2b/room-content/7c4329f6d1d09a739097f818dc42e733.png)

This is one of the examples of a Punycode attack used by the attackers to redirect users to a malicious domain that seems legitimate at first glance.

What is Punycode? As per [Wandera](https://www.wandera.com/punycode-attacks/), "Punycode is a way of converting words that cannot be written in ASCII, into a Unicode ASCII encoding."

What you saw in the URL above is adıdas.de which has the Punycode of http://xn--addas-o4a.de/
Internet Explorer, Google Chrome, Microsoft Edge, and Apple Safari are now pretty good at translating the obfuscated characters into the full Punycode domain name.

To detect the malicious domains, proxy logs or web server logs can be used.

Attackers usually hide the malicious domains under URL Shorteners. A URL Shortener is a tool that creates a short and unique URL that will redirect to the specific website specified during the initial step of setting up the URL Shortener link. According to [Cofense](https://cofense.com/url-shorteners-fraudsters-friend/), attackers use the following URL Shortening services to generate malicious links: 


![[Pasted image 20221201225158.png]]

![[Pasted image 20221201225224.png]]
![[Pasted image 20221201225238.png]]

    bit.ly
    goo.gl
    ow.ly
    s.id
    smarturl.it
    tiny.pl
    tinyurl.com
    x.co

You can see the actual website the shortened link is redirecting you to by appending "+" to it (see the examples below). Type the shortened URL in the address bar of the web browser and add the above characters to see the redirect URL. 

NOTE: The examples of the shortened links below are non-existent. 


![](https://i.ibb.co/rFhwNsw/terminal.png)


![[Pasted image 20221202104323.png]]


https://en.wikipedia.org/wiki/List_of_URI_schemes (to make XSS)

Go to this report on [app.any.run](https://app.any.run/tasks/a66178de-7596-4a05-945d-704dbf6b3b90) and provide the first malicious URL request you are seeing, you will be using this report to answer the remaining questions of this task.
*craftingalegacy.com*

![[Pasted image 20221202104911.png]]


What term refers to an address used to access websites?
*Domain Name*



What type of attack uses Unicode characters in the domain name to imitate the a known domain?
*Punnycode Attack*

Provide the redirected website for the shortened URL using a preview: https://tinyurl.com/bw7t8p4u
![[Pasted image 20221202104558.png]]

	*https://tryhackme.com/*

### Host Artifacts (Annoying) 

Let's take another step up to the yellow zone.

On this level, the attacker will feel a little more annoyed and frustrated if you can detect the attack. The attacker would need to circle back at this detection level and change his attack tools and methodologies. This is very time-consuming for the attacker, and probably, he will need to spend more resources on his adversary tools.

Host artifacts are the traces or observables that attackers leave on the system, such as registry values, suspicious process execution, attack patterns or IOCs (Indicators of Compromise), files dropped by malicious applications, or anything exclusive to the current threat.

Suspicious process execution from Word: 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/60c7fac321aca20049602d2b/room-content/6b91c7de5654b7f285991787cb3bb4fe.png)

Suspicious events followed by opening a malicious application: 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/60c7fac321aca20049602d2b/room-content/6d742c9c22f99f30e3c8356ef7c36800.png)

The files modified/dropped by the malicious actor:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/60c7fac321aca20049602d2b/room-content/200da81eca90f66535ccfbc7d09699de.png)


What is the suspicious IP the victim machine tried to connect to in the screenshot above?
*35.214.215.33*

![[Pasted image 20221202110626.png]]

Use the tools introduced in task 2 and provide the name of the malware associated with the IP address
*emotet*

	 https://pastebin.com/SgcKe9LK (EMotet IOC)

Using your OSINT skills, what is the name of the malicious document associated with the dropped binary?
*G_jugk.exe*

Use your OSINT skills and provide the name of the malicious document associated with the dropped binary 
Try Google ;)
https://www.joesandbox.com/analysis/302663/1/html

![[Pasted image 20221202120426.png]]
![[Pasted image 20221202120732.png]]

was really tricky to found it, google it like G_jugk.exe any.run
then found https://any.run/report/e2d2ebafc33d7c7819f414031215c3669bccdfb255af3cbe0177b2c601b0e0cd/90b76d7b-8df6-43c5-90ec-d4bbcfb4fa19

![[Pasted image 20221202121627.png]]

*CMO-100120 CDW-102220.doc*

### Network Artifacts (Annoying) 

Network Artifacts also belong to the yellow zone in the Pyramid of Pain. This means if you can detect and respond to the threat, the attacker would need more time to go back and change his tactics or modify the tools, which gives you more time to respond and detect the upcoming threats or remediate the existing ones.

A network artifact can be a user-agent string, C2 information, or URI patterns followed by the HTTP POST requests.An attacker might use a User-Agent string that hasn’t been observed in your environment before or seems out of the ordinary. The User-Agent is defined by [RFC2616](https://datatracker.ietf.org/doc/html/rfc2616#page-145) as the request-header field that contains the information about the user agent originating the request.

Network artifacts can be detected in Wireshark PCAPs (file that contains the packet data of a network) by using a network protocol analyzer such as [TShark](https://www.wireshark.org/docs/wsug_html_chunked/AppToolstshark.html) or exploring IDS (Intrusion Detection System) logging from a source such as [Snort](https://www.snort.org/).

HTTP POST requests containing suspicious strings:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/60c7fac321aca20049602d2b/room-content/a6e36c7601f7b4ec07ce2a102ffb33ab.png)

Let's use TShark to filter out the User-Agent strings by using the following command:

	tshark -Y http.request -T fields -e http.host -e http.user_agent -r analysis_file.pcap 

![999](https://tryhackme-images.s3.amazonaws.com/user-uploads/60c7fac321aca20049602d2b/room-content/642cac93b8c5b7bf8c82d448cb48c1d1.png)

These are the most common User-Agent strings found for the [Emotet Downloader Trojan](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/emotet-downloader-trojan-returns-in-force/)

If you can detect the custom User-Agent strings that the attacker is using, you might be able to block them, creating more obstacles and making their attempt to compromise the network more annoying.


What browser uses the User-Agent string shown in the screenshot above?
Try to search for the User-Agent string "Mozilla/4.0(compatible;MSIE7.0;WindowsNT6.1;Trident/4.0;SLCC2;.NETCLR2.0.50727; .NETCLR3.5.30729;.NETCLR3.0.30729;MediaCenterPC6.0;.NET4.0C;.NET4.0E)" on Google 

Tested with IE8, there is an error message in the lower left corner of the page. Detailed error information User Agent: Mozilla/4.0(compatible;MSIE7.0;WindowsNT6.1;Trident/4.0;SLCC2;.NETCLR2.0.50727;.NETCLR3.5.30729;.NETCLR3.0.30729; MediaCenterPC6.0;.NET4.0C;.NET4.0E) Timestamp: Thu,21Jun2012 11:48:14UTC Message: Missing Object Line: 79 Characters: 13 Code: 0 The line where the error is reported is vara=document.getElementById("limits ").innerHTML;
https://www.iamivan.net/a/b3VQX0z.html
*Internet Explorer*



How many POST requests are in the screenshot from the pcap file?
*6*

### Tools (Challenging) 

Congratulations! We have made it to the challenging part for the adversaries!

At this stage, we have levelled﻿ up our detection capabilities against the artifacts. The attacker would most likely give up trying to break into your network or go back and try to create a new tool that serves the same purpose. It will be a game over for the attackers as they would need to invest some money into building a new tool (if they are capable of doing so), find the tool that has the same potential, or even gets some training to learn how to be proficient in a certain tool. 

Attackers would use the utilities to create malicious macro documents (maldocs) for spearphishing attempts, a backdoor that can be used to establish C2 (Command and Control Infrastructure), any custom .EXE, and .DLL files, payloads, or password crackers. https://www.varonis.com/blog/what-is-c2/

A Trojan dropped the suspicious "Stealer.exe" in the Temp folder:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/60c7fac321aca20049602d2b/room-content/20624b49722fd8d0ba062d6206c1d021.png)

The execution of the suspicious binary:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/60c7fac321aca20049602d2b/room-content/8638b80dc730bfc88e37633f648b15e2.png)

Antivirus signatures, detection rules, and YARA rules can be great weapons for you to use against attackers at this stage.

[MalwareBazaar](https://bazaar.abuse.ch/) and [Malshare](https://malshare.com/) are good resources to provide you with access to the samples, malicious feeds, and YARA results - these all can be very helpful when it comes to threat hunting and incident response. 

For detection rules, [SOC Prime Threat Detection Marketplace](https://tdm.socprime.com/) is a great platform, where security professionals share their detection rules for different kinds of threats including the latest CVE's that are being exploited in the wild by adversaries. 

![[Pasted image 20221202193810.png]]

Fuzzy hashing is also a strong weapon against the attacker's tools. Fuzzy hashing helps you to perform similarity analysis - match two files with minor differences based on the fuzzy hash values. One of the examples of fuzzy hashing is the usage of SSDeep; on the [SSDeep](https://ssdeep-project.github.io/ssdeep/index.html) official website, you can also find the complete explanation for fuzzy hashing. 

Example of SSDeep from VirusTotal:

![](https://i.ibb.co/qnyYHtR/ssdeep.png)


Provide the method used to determine similarity between the files 
*Fuzzy hashing*



Provide the alternative name for fuzzy hashes without the abbreviation 
Check the SSDeep official webpage
*context triggered piecewise hashes*

###  TTPs (Tough) 



It is not over yet. But good news, we made it to the final stage or the apex of the Pyramid of Pain! 

TTPs stands for Tactics, Techniques & Procedures. This includes the whole MITRE [ATT&CK Matrix](https://attack.mitre.org/), which means all the steps taken by an adversary to achieve his goal, starting from phishing attempts to persistence and data exfiltration. 

If you can detect and respond to the TTPs quickly, you leave the adversaries almost no chance to fight back. For, example if you could detect a [Pass-the-Hash attack](https://www.beyondtrust.com/resources/glossary/pass-the-hash-pth-attack) using Windows Event Log Monitoring and remediate it, you would be able to find the compromised host very quickly and stop the lateral movement inside your network. At this point, the attacker would have two options:

    Go back, do more research and training, reconfigure their custom tools
    Give up and find another target

Option 2 definitely sounds less time and resource-consuming.


Navigate to ATT&CK Matrix webpage. How many techniques fall under the Exfiltration category?
![[Pasted image 20221202201223.png]]

*9*


Chimera is a China-based hacking group that has been active since 2018. What is the name of the commercial, remote access tool they use for C2 beacons and data exfiltration?
Check MITRE ATT&CK Matrix
https://attack.mitre.org/groups/G0114/

![[Pasted image 20221202201357.png]]

*Cobalt Strike*

### Practical: The Pyramid of Pain 

Deploy the static site attached to this task and place the prompts into the correct tiers in the pyramid of pain!

Once you are sure, submit your answer on the static site to retrieve a flag!

![[Pasted image 20221202201505.png]]

![[Pasted image 20221202203339.png]]

hmm some problems (broken question)

### Conclusion 

Now you have learned the concept of the Pyramid of Pain. Maybe it is time to apply this in practice. Please, navigate to the Static Site to perform the exercise. 

You can pick any APT (Advanced Persistent Threat Groups) as another exercise. A good place to look at would be FireEye Advanced Persistent Threat Groups. When you have determined the APT Group you want to research - find their indicators and ask yourself: " What can I do or what detection rules and approach can I create to detect the adversary's activity?", and "Where does this activity or detection fall on the Pyramid of Pain?”

As David Blanco states, "the amount of pain you cause an adversary depends on the types of indicators you are able to make use of". 

https://www.fireeye.com/current-threats/apt-groups.html

[[Junior Security Analyst Intro]]