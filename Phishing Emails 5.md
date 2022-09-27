---
Use the knowledge attained to analyze a malicious email. 
---

![](https://assets.tryhackme.com/additional/phishing1/phish-room-banner-final.png)

### Just another day as a SOC Analyst.. 

![](https://assets.tryhackme.com/additional/phishing5/main.png)

A Sales Executive at Greenholt PLC received an email that he didn't expect to receive from a customer. He claims that the customer never uses generic greetings such as "Good day" and didn't expect any amount of money to be transferred to his account. The email also contains an attachment that he never requested. He forwarded the email to the SOC (Security Operations Center) department for further investigation. 

Investigate the email sample to determine if it is legitimate. 

Tip: Open the EML file with Thunderbird. 

Deploy the machine attached to this task; it will be visible in the split-screen view once it is ready.

If you don't see a virtual machine load then click the Show Split View button.


```
go to show split view / open challenge.eml with Thunderbird email
```

![[Pasted image 20220926205543.png]]

![](https://www.cyb3rm3.com/web/image/832-e6b981a8/2022-01-01%2016_48_39-TryHackMe%20_%20Phishing%20Emails%205.png)

What is the email's timestamp? (answer format: mm/dd/yyyy hh:mm
*06/10/2020 05:58*

Who is the email from?
*Mr. James Jackson*

What is his email address?
*info@mutawamarine.com*
What email address will receive a reply to this email? 
*info.mutawamarine@mail.com*

```
with thunderbird more view source

X-Originating-IP: [x.x.x.x]
Received: from 10.197.41.148  (EHLO sub.redacted.com) (x.x.x.x)
  by mta4212.mail.bf1.yahoo.com with SMTP; Wed, 10 Jun 2020 05:58:54 +0000
Received: from hwsrv-737338.hostwindsdns.com ([192.119.71.157]:51810 helo=mutawamarine.com)
	by sub.redacted.com with esmtp (Exim 4.80)
	(envelope-from <info@mutawamarine.com>)


```
What is the Originating IP?
The answer is NOT in X-Originating-Ip
*192.119.71.157*

```
use https://db-ip.com/
and search 192.119.71.157

Address type	IPv4  
Hostname	client-192-119-71-157.hostwindsdns.com
ASN	54290 - HOSTWINDS
ISP	Hostwinds LLC.
Connection	Hosting


```
![[Pasted image 20220926210746.png]]

Who is the owner of the Originating IP? (Do not include the "." in your answer.)
 Perform a WHOIS lookup for the name of the organization
*Hostwinds LLC*

```
with https://dmarcian.com/spf-survey/

enter domain
mutawamarine.com
survey domain


```
![[Pasted image 20220926211224.png]]

What is the SPF record for the Return-Path domain?
*v=spf1 include:spf.protection.outlook.com -all*

```
https://dmarcian.com/dmarc-inspector/
enter domain
mutawamarine.com
survey domain
v=DMARC1; p=quarantine; fo=1
```


What is the DMARC record for the Return-Path domain?
*v=DMARC1; p=quarantine; fo=1*

What is the name of the attachment?
*SWT_#09674321____PDF__.cab*

![](https://www.cyb3rm3.com/web/image/838-287e9c2c/2022-01-01%2017_28_13-TryHackMe%20_%20Phishing%20Emails%205.png)

What is the SHA256 hash of the file attachment?
*2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f*

![[Pasted image 20220926213222.png]]

What is the attachments file size? (Don't forget to add "KB" to your answer, NUM KB)
Don't go by the Linux file properties. Obtain the file hash and use an Open Source resource to help you with this.



What is the actual file extension of the attachment?
*rar*




[[NIS - Linux Part I]]