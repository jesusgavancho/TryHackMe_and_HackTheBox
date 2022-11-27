```
┌──(kali㉿kali)-[~/Downloads/PHishing]
└─$ wget http://0.0.0.0:8000/Email1.eml
--2022-08-02 17:10:23--  http://0.0.0.0:8000/Email1.eml
Connecting to 0.0.0.0:8000... failed: Connection refused.
                                                                                     
┌──(kali㉿kali)-[~/Downloads/PHishing]
└─$ wget http://10.10.121.122:8000/Email1.eml
--2022-08-02 17:10:51--  http://10.10.121.122:8000/Email1.eml
Connecting to 10.10.121.122:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 34459 (34K) [message/rfc822]
Saving to: ‘Email1.eml’

Email1.eml            100%[======================>]  33.65K   175KB/s    in 0.2s    

2022-08-02 17:10:52 (175 KB/s) - ‘Email1.eml’ saved [34459/34459]

                                                                                     
┌──(kali㉿kali)-[~/Downloads/PHishing]
└─$ ls
Email1.eml
                                                                                     
┌──(kali㉿kali)-[~/Downloads/PHishing]
└─$ wget http://10.10.121.122:8000/Email2.eml
--2022-08-02 17:11:03--  http://10.10.121.122:8000/Email2.eml
Connecting to 10.10.121.122:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 316446 (309K) [message/rfc822]
Saving to: ‘Email2.eml’

Email2.eml            100%[======================>] 309.03K   392KB/s    in 0.8s    

2022-08-02 17:11:04 (392 KB/s) - ‘Email2.eml’ saved [316446/316446]

                                                                                     
┌──(kali㉿kali)-[~/Downloads/PHishing]
└─$ wget http://10.10.121.122:8000/Email3.eml
--2022-08-02 17:11:08--  http://10.10.121.122:8000/Email3.eml
Connecting to 10.10.121.122:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 117299 (115K) [message/rfc822]
Saving to: ‘Email3.eml’

Email3.eml            100%[======================>] 114.55K  95.7KB/s    in 1.2s    

2022-08-02 17:11:10 (95.7 KB/s) - ‘Email3.eml’ saved [117299/117299]

analyse with https://app.phishtool.com/submit
Scenario:
You are a SOC Analyst and have been tasked to analyse a suspicious email Email1.eml. Use the tool and skills learnt on this task to answer the questions.
Answer the questions below

What organisation is the attacker trying to pose as in the email? LinkedIn


What is the senders email address? darkabutla@sc500.whpservers.com


What is the recipient's email address? cabbagecare@hotsmail.com

What is the Originating IP address? Defang the IP address. 204[.]93[.]183[.]11 (not harmless)

How many hops did the email go through to get to the recipient? 4

https://talosintelligence.com/reputation_center/lookup?search=204.93.183.11

What is the listed domain of the IP address from the previous task? scnet.net

What is the customer name of the IP address? (whois) Complete Web Reviews

According to Email2.eml, what is the recipient's email address? chris.lyons@supercarcenterdetroit.com

https://talosintelligence.com/sha_searches (searching for sha256)
From Talos Intelligence, the attached file can also be identified by the Detection Alias that starts with an H...
HIDDENEXT/Worm.Gen

What is the name of the attachment on Email3.eml? Sales_Receipt 5606.xls

What malware family is associated with the attachment on Email3.eml? dridex


What port is classified as Secure Transport for SMTP? 465

What port is classified as Secure Transport for IMAP? 993

What port is classified as Secure Transport for POP3? 995

What email header is the same as "Reply-to"? Return-Path

Once you find the email sender's IP address, where can you retrieve more information about the IP?  http://www.arin.net

In the above screenshots, what is the URI of the blocked image? https://i.imgur.com/LSWOtDI.png  
In the above screenshots, what is the name of the PDF attachment?  Payment-updateid.pdf   

In the attached virtual machine, view the information in email2.txt and reconstruct the PDF using the base64 data. What is the text within the PDF? THM{BENIGN_PDF_ATTACHMENT} (decode the base64 y save en 1.pdf)

Different types of malicious emails can be classified as one of the following:

    Spam - unsolicited junk emails sent out in bulk to a large number of recipients. The more malicious variant of Spam is known as MalSpam.
    Phishing -  emails sent to a target(s) purporting to be from a trusted entity to lure individuals into providing sensitive information. 
    Spear phishing - takes phishing a step further by targeting a specific individual(s) or organization seeking sensitive information.  
    Whaling - is similar to spear phishing, but it's targeted specifically to C-Level high-position individuals (CEO, CFO, etc.), and the objective is the same. 
    Smishing - takes phishing to mobile devices by targeting mobile users with specially crafted text messages. 
    Vishing - is similar to smishing, but instead of using text messages for the social engineering attack, the attacks are based on voice calls. 

When it comes to phishing, the modus operandi is usually the same depending on the objective of the email.

For example, the objective can be to harvest credentials, and another is to gain access to the computer. 

Below are typical characteristics phishing emails have in common:

    The sender email name/address will masquerade as a trusted entity (email spoofing)
    The email subject line and/or body (text) is written with a sense of urgency or uses certain keywords such as Invoice, Suspended, etc. 
    The email body (HTML) is designed to match a trusting entity (such as Amazon)
    The email body (HTML) is poorly formatted or written (contrary from the previous point)
    The email body uses generic content, such as Dear Sir/Madam. 
    Hyperlinks (oftentimes uses URL shortening services to hide its true origin)
    A malicious attachment posing as a legitimate document

We'll look at each of these techniques (characteristics) in greater detail in the next room within the Phishing module.

Reminder: When dealing with hyperlinks and attachments, you need to be careful not to accidentally click on the hyperlink or the attachment. 

Hyperlinks and IP addresses should be 'defanged'. You can read more about this technique here. 

What trusted entity is this email masquerading as? VGhhbmsgeW91ISBIb21lIERlcG90 (base64) 
From: =?UTF-8?B?VGhhbmsgeW91ISBIb21lIERlcG90?= <support@teckbe.com>
Thank you! Home Depot

What is the subject line? Subject: =?UTF-8?B?T3JkZXIgUGxhY2VkIDogWW91ciBPcmRlciBJRCBPRDIzMjE2NTcwODkyOTEgUGxhY2VkIFN1Y2Nlc3NmdWxseQ==?=

T3JkZXIgUGxhY2VkIDogWW91ciBPcmRlciBJRCBPRDIzMjE2NTcwODkyOTEgUGxhY2VkIFN1Y2Nlc3NmdWxseQ== -> Order Placed : Your Order ID OD2321657089291 Placed Successfully

What is the URL link for - CLICK HERE? (Enter the defanged URL) hxxp[://]t[.]teckbe[.]com/p/?j3=3DEOowFcEwFHl6EOAyFcoUFV= TVEchwFHlUFOo6lVTTDcATE7oUE7AUET=3D=3D

What is BEC? you should know what BEC (Business Email Compromise) means.

A BEC is when an adversary gains control of an internal employee's account and then uses the compromised email account to convince other internal employees to perform unauthorized or fraudulent actions. 

https://anonymiz.com/shorten-url (shorten url anonimously) example -> https://anonymiz.com/ltkl

https://anon.to/ -> example (tryhackme/phishing2) -> https://anon.to/ExGbFK

***unshort urls***
http://www.checkshorturl.com/expand.php
https://unshorten.me/

What phrase does the gibberish sender email start with? noreply

What is the root domain for each URL? Defang the URL. devret[.]xyz

 https://app.any.run/tasks/12dcbc54-be0f-4250-b6c1-94d548816e5c/#
 
This email sample used the names of a few major companies, their products, and logos such as OneDrive and Adobe. What other company name was used in this phishing email?  citrix

What should users do if they receive a suspicious email or text message claiming to be from Netflix?
https://www.consumeraffairs.com/news/police-warn-of-new-netflix-email-phishing-scam-121718.html
forward the message to phishing@netflix.com
Benefits of Using BCC

Using the BCC field to send an email message to a large group of people has a number of benefits, including:

    The privacy of email addresses is protected in the original message. Recipients will receive the message, but won't be able to see the addresses listed in the BCC field.
    
 what is a .dot file?
Word document template files are developed by Microsoft to serve as page layout template files of certain Microsoft Windows word processing applications. 

What does BCC mean? Blind Carbon Copy
What technique was used to persuade the victim to not ignore the email and act swiftly? urgency

What is the name of the executable that the Excel attachment attempts to run? regasms.exe

https://phishingquiz.withgoogle.com/




```

[[Overpass3]]