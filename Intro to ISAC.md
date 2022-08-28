---
Learn how to utilize Information Sharing and Analysis Centers to gather threat intelligence and collect IOCs.
---

![](https://tryhackme-images.s3.amazonaws.com/room-icons/aff8179e0339b875e4cb93befb8cb455.png)

###  Introduction 

Information Sharing and Analysis Centers (ISACs), are used to share and exchange various Indicators of Compromise (IOCs) to obtain threat intelligence. IOCs can include MD5s, IPs, YARA rules, and more. There are many ISACs that can be used to gather threat intelligence including AlienVault OTX, Threat Connect, and MISP.

![](https://camo.githubusercontent.com/884ef5b297f0c7e7c5c9453087ee550a12cdfb13/68747470733a2f2f692e696d6775722e636f6d2f493055536d716a2e706e67)

Malware and IOCs used in this room have been sourced from The Zoo Malware Repository. All credit goes to the respective owners.

Warning: This room uses neutered malware in a virtual environment, exercise caution when interacting with samples.


Read the above and move on to 'What are ISACs'.
*No answer needed*

### Basic Terminology 

Before diving in, let's briefly discuss a few terms that you will often hear when dealing with the framework, threat intelligence, etc.

APT is an acronym for Advanced Persistent Threat. This can be considered a team/group (threat group), or even country (nation-state group), that engages in long-term attacks against organizations and/or countries. The term 'advanced' can be misleading as it will tend to cause us to believe that each APT group all have some super-weapon, e.i. a zero-day exploit, that they use. That is not the case. As we will see a bit later, the techniques these APT groups use are quite common and can be detected with the right implementations in place. You can view FireEye's current list of APT groups [here](https://www.mandiant.com/resources/insights/apt-groups).

TTP is an acronym for Tactics, Techniques, and Procedures, but what does each of these terms mean?

    The Tactic is the adversary's goal or objective.
    The Technique is how the adversary achieves the goal or objective.
    The Procedure is how the technique is executed.

TI is an acronym for Threat Intelligence. Threat Intelligence is an overarching term for all collected information on adversaries and TTPs. You will also commonly hear CTI or Cyber Threat Intelligence which is just another way of saying Threat Intelligence.

IOCs is an acronym for Indicators of Compromise, the indicators for malware and adversary groups. Indicators can include file hashes, IPs, names, etc.


Read the above and familiarize yourself with the various terminology.
*No answer needed*

###  What is Threat Intelligence 

Threat Intelligence, also known as TI and Cyber Threat Intelligence also known as, CTI, is used to provide information about the threat landscape specifically adversaries and their TTPs. Typically CTI revolves around APT groups and/or other threats, these can be well-known groups or up and coming new threats.

Data must be analyzed to be considered threat intelligence. Once analyzed and actionable, then it becomes threat intelligence. The data needs context around to become intel.

CTI is a precautionary measure that companies use or contribute to so that other corporations do not get hit with the same attacks. Of course, adversaries change their TTPs all the time so the TI landscape is constantly changing.

Vendors and corporations will sometimes share their collected CTI in what are called ISACs or Information Sharing and Analysis Centers. ISACs collect various indicators of an adversary that other corporations can use as a precaution against adversaries.

If you are not familiar with adversaries and their TTPs I would suggest checking out the following resources.

APT Groups and Operations (https://docs.google.com/spreadsheets/u/1/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/pubhtml)
    Tryhackme Mitre Room
    FireEye APT Report https://www.mandiant.com/resources/insights/apt-groups

Threat Intelligence is also broken up into three different types.

    Strategic

	Assist senior management make informed decisions specifically about the security budget and strategies.

    Tactical

	Interacts with the TTPs and attack models to identify adversary attack patterns.

    Operational

	Interact with IOCs and how the adversaries operationalize.

In this room, we will mainly be focusing on Operational CTI but all forms of threat intelligence have their place and I encourage you to research each thoroughly.


Read the above and move on to, What are ISACs *No answer needed*

###  What are ISACs 



According to the National Council of ISACs, "Information Sharing and Analysis Centers (ISACs) are member-driven organizations, delivering all-hazards threat and mitigation information to asset owners and operators". ISACs can be community-centered or vendor-specific. ISACs include CTI from threat actors as well as mitigation information in the form of IOCs, YARA rules, etc. ISACs maintain situational awareness by sharing and collaborating to maintain CTI, through a National Council of ISACs.

You can view a list of member ISACs here: https://www.nationalisacs.org/member-isacs.

We will be focusing on ISACs as they pertain to cybersecurity and cyber threat intelligence; however, ISACs can be utilized for more than just cybersecurity.

Below is a list of ISACs that can help a blue team we will only be showcasing a few in this room.

    US-CERT   https://www.cisa.gov/uscert/
    AlienVault OTX https://otx.alienvault.com/
    ThreatConnect https://threatconnect.com/
    MISP https://www.misp-project.org/

This room will specifically focus on AlienVault OTX and ThreatConnect; however, there are many more ISACs that can be used to gather threat intelligence. I encourage you to go out and research others on your own to get a good feeling for what you like and what various ISACs can offer.

### Using Threat Connect to create a Threat Intel dashboard 

Threat Connect Overview

Threat Connect focuses more on the information and new developments within cybersecurity and the threat landscape and connecting the landscape with indicators. This intelligence can help your team make better-informed decisions on what to prioritize. Threat Connect would fall under the tactical type of threat intelligence. 

There is a free and open-source version of Threat Connect available but if you were actually using this on a security team you would want to pay for access to the full platform. Threat Connect is a very large platform with many capabilities but we will only be using it to create our threat intel dashboard and gather indicators from other ISACs like AlienVault OTX. It is important to have multiple sources for the information or intelligence that you collect.

Sign up for a free ThreatConnect account here.

Note: Currently ThreatConnect has gone through a new re-branding and seems to no longer offer a free account. I am looking into options for the future.

Creating a Threat Intel Dashboard

Straight out of the box Threat Connect comes with a pre-configured dashboard you can use, as well as 4 other more specific dashboards: Operations Dashboard, Source Analysis, OSINT Overview, and Covid-19 Related Activity.

We will only be covering the default dashboard in-depth but feel free to play with other dashboards as much as you want to get familiar with them as well as the other features ThreatConnect has.

![](https://i.imgur.com/QCWkkcc.png)

Breaking Down the Dashboard

We can break up the various sections of the dashboard to make it more digestible and see what each section has to offer.

    Top Sources by Observations

	This section sorts observations or indicators by the owner or source of the observation. This is helpful to find reliable sources for intelligence as a majority of threat intel is community-driven.

![](https://i.imgur.com/eqXIepC.png)

    Latest Intelligence

	Gives the latest intelligence that has been reported to the platform. This can be helpful if you want to stay on top of the newest rising threats.

![](https://i.imgur.com/Sq1jWm5.png)

    Top Sources by False Positives

	Similar to the Top Sources by Observations this will sort the owners by who has the most false positives. This can be useful to stay away from indicator owners who generate a lot of false positives and their intel may not be as high quality.

![](https://i.imgur.com/GaaUBXN.png)

    Top Tags

	This is a collection of the top tags used to categorize indicators. This can be useful to quickly find a topic or to identify trends within the threat landscape.


![](https://i.imgur.com/0llIW3Q.png)

    Indicator Breakdown

	A breakdown of all of their intelligence combined and what indicators make up the platform. This is not super helpful for most applications as it only gives a brief overview of the platform as a whole.


![](https://i.imgur.com/P1VVRwk.png)

For the most part, the other sections of the dashboard could be ignored as they are just overviews of what is on the platform rather than specific threat intelligence.


Custom Dashboards

You can use all of these various parts of the default dashboard to create your own personalized dashboard that fits your liking.

For example, this is part of the Operations Dashboard I like to use.

![](https://i.imgur.com/9yAt0IV.png)

Note: Threat Connect can go far beyond your normal ISAC including Incident Response Playbooks, Graphs, etc. However, these features are only available in the paid version. Let's move on to using Alienvault to gather a collection of IOCs.

### Introduction to AlienVault OTX 

AlienVault OTX from AT&T Cybersecurity is one of the main ISACs that is used as an exchange for community maintained threat intelligence.

You will need to create an AlienVault account before you can fully use the application. Go to https://otx.alienvault.com/ and create an account before continuing.

Alienvault uses 'Pulses' to create trackers for various categories. Pulses can be categorized by Malware type, APT or group, and targeted industry. All pulses are community-created excluding official pulses from AlienVault. 

Pulses can include a wide variety of IOCs such as File Hashes (MD5, SHA1), IPv4, IPv6, Domain, URL, YARA, CVE, and more. 

![](https://i.imgur.com/SEddt8E.png)

The main page of OTX you will use is the Dashboard. The default dashboard includes a visualization of the most common active malware broken down by category as well as a list of Subscribed Pulses. By default, only AlienVault's Subscribed Pulses will be listed. This can be expanded upon later.

There are also six different tabs that you can navigate to on the navigation bar, they are outlined below.

    Dashboard - This is shown above in the screenshot above. It's the main page of OTX and will provide a brief overview of important intel.
    Browse - This will allow you to see all new pulses and sort by various categories to find the newest intel.
    Scan Endpoints - This is an automated service called OTX Endpoint Security that will scan endpoints for indicators.
    Create Pulse - This will allow you to create your own pulses and contribute to the threat exchange.
    Submit Sample - This allows you to submit a malware sample or URL sample which OTX will analyze and generate a report based on the provided sample.
    API Integration - Allows synchronization of the threat exchange with other tools for monitoring your environment.

### Using OTX to gather Threat Intelligence 

Pulse Overview

Pulses can consist of a description, tags, indicator types (file hash, Yara, IP, domain, etc.), and threat infrastructure (country of origin). OTX uses pulses as their indicators. A majority of pulses are community-created and maintained. You need to keep this in mind when using pulses for threat intelligence as not all pulses are legit or may contain inaccurate information. Always verify and analyze the indicators used before using them for CTI.


Breaking Down a Pulse

First, we need to understand how to analyze and gather information from a pulse in order to understand how to use OTX's many categories, ways of obtaining threat intelligence, and indicators.

As an example, we will be looking at the Xanthe - Docker aware miner pulse released from the official AlienVault account. You can find it [here](https://otx.alienvault.com/pulse/5fc6767d4cca089129062db9).

Pulses consist of three main sections: Pulse Description, Indicator Overview, Indicators. We will break down these sections further and identify each component of them.

Pulse Description

The Pulse Description consists of the description itself, references, tags, malware families, and ATT&CK IDs. The three most important parts are the reference section, the description itself, and the ATT&CK IDs. The references can be used to verify the pulse and get further background information on the pulse/indicators. The description can give you a brief overview of what the pulse is for and how it was gathered which can be useful when quickly looking for pulses to use. The ATT&CK IDs can be used to quickly identify what TTPs are being used by the pulse and familiarize yourself with them. For more information about ATT&CK check out Heavenraiza's MITRE room.

![](https://i.imgur.com/8xAOHxf.png)


Indicator Overview

The Indicator Overview will give you a very brief statistical representation of the indicators within the pulse as well as threat infrastructure. The indicator overview can be useful when looking for a very specific IOC like a file hash or YARA rule, etc.

![](https://i.imgur.com/J4zKnQB.png)

From here we can see that the pulse has six different types of indicators as well as four different countries that the pulse is originating from.

Note: A majority of pulses do not have threat infrastructure however it can be useful when analyzing a pulse for CTI.

Indicators 

Indicators are probably the most important section of the entire pulse. It contains all of the indicators and information about them.

![](https://i.imgur.com/LWW3fT7.png)

There is a lot of information to break down for each pulse. Look below for more information about each column of the indicators.

    Type - The type of indicator (URL, File Hash, IP, Domain, etc.)
    Indicator - The indicator itself
    Added - Date added, pulses can be updated this can be useful to track the pulses history
    Active - Shows, whether the indicator is still seen in the wild and active, can be useful when selecting pulses to use.
    Related Pulses - Shows pulses that share the same indicator, can be useful to cross-check indicators.
    Extra Information (Advanced) - These are the advanced options including Dynamic Analysis, Network Activity, and YARA rules. 

The Advanced section of indicators can contain the most information and allow you to get a better understanding of what you are dealing with. Not all pulses or indicators will contain any advanced information but it can be very useful when available. Below is an example of a YARA detection and dynamic analysis of a binary from a file hash.

![](https://i.imgur.com/rlGXrWn.png)

Finding Pulses based on Malware

If you want to find pulses only for a specific malware strain you can look for pulses based on malware. This allows you to very quickly find IOCs and rules for a specific strain of malware.

Note: Malware authors are constantly working to change and mitigate indicators and signatures, be aware that indicators change when looking for specific malware indicators.

![](https://i.imgur.com/LVvBTDG.png)

The menu for malware is by far the most detailed including features of the malware, related pulses, process visualization, and file samples if available.

![](https://i.imgur.com/ZgWoLk0.png)

OTX will also visualize the processes the malware is running. Overall the malware categories will allow you to quickly identify multiple aspects of malware including processes, features and pulses.


Finding Pulses based on Adversaries

To get started with identifying pulses by adversaries you need to have a foundational knowledge of adversaries and their operations. To get an introduction to adversarial operations check out the APT Groups and Operations spreadsheet. You can identify pulses based on the adversary group.

Note: Each vendor has its own naming scheme for APTs take note of this when looking for pulses by adversary.

![](https://i.imgur.com/LlsFZ7B.png)

The adversary menu will give you a short description of the group as well as pulses related to that group.


Finding Pulses based on Industry

A common vector for adversaries to focus on is the industry of their target, for example, finance, education, aerospace, etc. Adversaries will sometimes target corporations in one specific industry. An example of this is the Ryuk malware being distributed by "one" group targeting financial corporations

![](https://i.imgur.com/0ig9d7p.png)

When opening the industry menu you will see a general description as well as any pulses tag / related to the industry.

### Creating IOCs 


Warning: These are live malware samples that can be destructive if taken out of this sandbox, exercise caution when analyzing.

Creating IOCs Manually

A large portion of ISACs are community contributions where contributors take the latest malware samples and create IOCs for them. There are a few tools that can help with the creation of IOCs including strings, winmd5free, and Mandiant IOC Editor. There are also tools that can be used to automate this process like Mandiant Redline however that is out of scope for this room.

![](https://i.imgur.com/qmK1Hpc.png)

To begin, deploy the provided machine and RDP using these credentials: 

User: Jon

Pass: alqfna22

Please allow the machine at least five minutes to fully boot. 

If you open the Tools folder on the Desktop you will see all of the tools necessary to create IOCs for both the practice binaries and the scenarios.


![](https://i.imgur.com/wexyGaQ.png)

To begin collecting indicators from a sample you can gather the MD5 file hash using WinMD5. Simply run WinMD5 and select the file you want to gather from.

![](https://i.imgur.com/INqhxa7.png)

Practice with the Cerber sample in `C:\Users\Jon\Documents\Practice\Practice 1\`

To get another baseline of information we can look at the properties of the file to find other indicators including size, name, date created, etc.

![](https://i.imgur.com/rK9xFEs.png)

To get our final indicator and probably the most unique we need to run strings on the sample to identify if there are any unusual or unique strings that we can use in the IOC. I would advise taking the output into a file to view later.

Syntax: `./strings.exe <path to file> -accepteula > output.txt`

![](https://i.imgur.com/Pt2X2QP.png)

You're looking for strings that are human-readable and unique this can include IPs, BTC Addresses, unique function names, etc. You may not always find unique strings right away with some samples. This is where the use of an automated tool like Redline could come in handy as well as for identifying other indicators.

The string below is unique enough that it could be used as an indicator.

![](https://i.imgur.com/NO1f3xI.png)

Continue looking through the strings output of the Cerber ransomware to find unique strings.

Once you have all of your indicators prepared you can begin creating an IOC with Mandiant IOCe.

1. Create a new IOC by navigating to File > New Indicator.

![](https://i.imgur.com/hzV3oxh.png)

2. Add in your indicators to the IOC from the Item tab, for more in-depth information on creating IOCs check out the IOCe user guide.     

![](https://i.imgur.com/gTjm71U.png)

This is an example of an IOC for the Cerber sample. If this was a real investigation you could then upload it to AlienVault OTX or another ISAC.


Creating Pulses from IOCs

Note: Please do not take malware outside of the sandbox or create a pulse on OTX without an actual investigation.

You can navigate to the Create Pulse tab of AlienVault OTX to begin creating a pulse.

![](https://i.imgur.com/oP9GWZH.png)

AlienVault OTX can automatically extract indicators including MD5, SHA265 hashes, etc. Even though OTX automatically extracts indicators it is still suggested to create your own IOCs.

![](https://i.imgur.com/pUlBLGN.png)

AlienVault OTX also has built-in functionality to take a malware sample under the submit a sample tab and analyze it. This will give back many indicators including MD5 hashes, SHA256 hashes, and PE anomalies as well as related pulses.

![](https://i.imgur.com/m7Jadd5.png)

Connecting IOCs with Pulses

Now that we have all of our information on the unknown sample we can look for other pulses on OTX similar to our sample. This is important to gather CTI because adversaries can change their TTPs and in turn change CTI, this is why ISACs are so important to keep up with the ever-changing threat scene.

Let's look at the pulse in the next task for the Cryxos.B Trojan and Cerber Ransomware and see if you can connect the unknown practice sample with the pulses. This specific pulse is part of another malware known as Cryxos.B that is used as a trojan to get the Cerber ransomware onto devices.

![[Pasted image 20220828003702.png]]

Read the above and practice using the Cerber ransomware sample.  *No answer needed*

###  Investigation Scenarios 



Scenario 1

Your incident response team has quarantined a suspicious bin file. The team thinks it is a ransomware variation. Investigate and create indicators for the file.

You can find the shellcode under `C:\Users\Jon\Documents\Scenarios\Scenario 1`


Scenario 2

You have been assigned to analyze this week's quarantined files. The file is thought to be an unknown trojan or a new strain of the emotet malware. Investigate and create indicators for the file.

You can find the shellcode under `C:\Users\Jon\Documents\Scenarios\Scenario 2`

Read the above and complete the investigations  *No answer needed*

What is the name of the file from Scenario 1?
*29D6161522C7F7F21B35401907C702BDDB05ED47.bin*

What is the size of the file from Scenario 1 in bytes?
*96,535*

What is the size on disk of the file from Scenario 1 in bytes?
*98,304*

What is the MD5 hash of the file from Scenario 1?
*8baa9b809b591a11af423824f4d9726a*

What is the name of the file from Scenario 2?
*cryptowall.bin*
What is the size of the file from Scenario 2 in bytes?
*246,272*
What is the size on disk of the file from Scenario 2 in bytes?
*249,856*
What is the MD5 hash of the file from Scenario 2?
*47363b94cee907e2b8926c1be61150c7*
Create IOCs for both files using IOCe. *No answer needed*

[[Wireshark 101]]






