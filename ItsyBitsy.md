---
Put your ELK knowledge together and investigate an incident.
---

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/684f1b236b4c7ff0a1f9e246491ba63e.png)


![](https://tryhackme-images.s3.amazonaws.com/room-icons/be84f26c22e5a051fc003dba5ed3dcd4.png)

### troduction

In this challenge room, we will take a simple challenge to investigate an alert by IDS regarding a potential C2 communication.

Room Machine

Before moving forward, deploy the machine. When you deploy the machine, it will be assigned an IP **Machine IP**: `MACHINE_IP`. The machine will take up to 3-5 minutes to start. Use the following credentials to log in and access the logs in the Discover tab.

**Username:** `Admin`

**Password:** `elastic123`

### Scenario - Investigate a potential C2 communication alert

Scenario

During normal SOC monitoring, Analyst John observed an alert on an IDS solution indicating a potential C2 communication from a user Browne from the HR department. A suspicious file was accessed containing a malicious pattern THM:{ ________ }. A week-long HTTP connection logs have been pulled to investigate. Due to limited resources, only the connection logs could be pulled out and are ingested into the `connection_logs` index in Kibana.  

Our task in this room will be to examine the network connection logs of this user, find the link and the content of the file, and answer the questions.

Answer the questions below

How many events were returned for the month of March 2022?

![[Pasted image 20221214120148.png]]

*1482*

What is the IP associated with the suspected user in the logs?

![[Pasted image 20221214124026.png]]

![[Pasted image 20221214124037.png]]

*192.166.65.54*

The user’s machine used a legit windows binary to download a file from the C2 server. What is the name of the binary?

```
Actions
	
Field
	
Value
_id
	
VIHyBIEBK8vxbSsZQilf
_index
	
connection_logs
_score
	
 - 
_type
	
_doc
@timestamp
	
Mar 10, 2022 @ 06:23:11.924911000
destination_ip
	
104.23.99.190
destination_port
	
80
host
	
pastebin.com
index
	
http_traffic
method
	
HEAD
request_body_len
	
10
response_body_len
	
5
source_ip
	
192.166.65.54
source_port
	
53,249
status_code
	
200
status_msg
	
OK
timestamp
	
Mar 10, 2022 @ 06:23:11.924911000
uid
	
C8D20I2ggQSCXNNZn7
uri
	
/yTg0Ah6a
user_agent
	
bitsadmin
version
	
3.2
```

*bitsadmin*

The infected machine connected with a famous filesharing site in this period, which also acts as a C2 server used by the malware authors to communicate. What is the name of the filesharing site?

*pastebin.com*

What is the full URL of the C2 to which the infected host is connected?

*pastebin.com/yTg0Ah6a*

A file was accessed on the filesharing site. What is the name of the file accessed?

![[Pasted image 20221214124333.png]]

*secret.txt*

The file contains a secret code with the format THM{_____}.

*THM{SECRET__CODE}*



[[Investigating with ELK 101]]