---
Learn how to use TheHive, a Security Incident Response Platform, to report investigation findings
---

![](https://assets.tryhackme.com/room-banners/hive.png)

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/f21a147d2f821f48f2a53c5e2ecf21c4.png)

### Room Outline

Welcome to TheHive Project Outline!

This room will cover the foundations of using the TheHive Project, a Security Incident Response Platform.

Specifically, we will be looking at:

-   What TheHive is?
-   An overview of the platform's functionalities and integrations.
-   Installing TheHive for yourself.
-   Navigating the UI.
-   Creation of a case assessment.

Before we begin, ensure you download the attached file, as it will be needed for Task 5.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/8b77d97cbbcf1649bab545addd0f2bad.png)

### Introduction

TheHive Project is a scalable, open-source and freely available Security Incident Response Platform, designed to assist security analysts and practitioners working in SOCs, CSIRTs and CERTs to track, investigate and act upon identified security incidents in a swift and collaborative manner.

Security Analysts can collaborate on investigations simultaneously, ensuring real-time information pertaining to new or existing cases, tasks, observables and IOCs are available to all team members.

More information about the project can be found on [https://thehive-project.org/](https://thehive-project.org/)[](https://thehive-project.org/) & their [GitHub Repo](https://github.com/TheHive-Project/TheHive).[](https://thehive-project.org/)

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/b249487ffe52d672accdfceb365462fa.png)

Image: Cases dashboard on TheHive by order of reported severity

  

TheHive Project operates under the guide of three core functions:

-   **Collaborate:** Multiple analysts from one organisation can work together on the same case simultaneously. Through its live stream capabilities, everyone can keep an eye on the cases in real time.
-   **Elaborate:** Investigations correspond to cases. The details of each case can be broken down into associated tasks, which can be created from scratch or through a template engine. Additionally, analysts can record their progress, attach artifacts of evidence and assign tasks effortlessly.
-   **Act:** A quick triaging process can be supported by allowing analysts to add observables to their cases, leveraging tags, flagging IOCs and identifying previously seen observables to feed their threat intelligence.

### TheHive Features & Integrations

TheHive allows analysts from one organisation to work together on the same case simultaneously. This is due to the platform's rich feature set and integrations that support analyst workflows. The features include:

-   **Case/Task Management:** Every investigation is meant to correspond to a case that has been created. Each case can be broken down into one or more tasks for added granularity and even be turned into templates for easier management. Additionally, analysts can record their progress, attach pieces of evidence or noteworthy files, add tags and other archives to cases.
    
-   **Alert Triage:** Cases can be imported from SIEM alerts, email reports and other security event sources. This feature allows an analyst to go through the imported alerts and decide whether or not they are to be escalated into investigations or incident response.
    
-   **Observable Enrichment with Cortex:** One of the main feature integrations TheHive supports is Cortex, an observable analysis and active response engine. Cortex allows analysts to collect more information from threat indicators by performing correlation analysis and developing patterns from the cases. More information on [Cortex](https://github.com/TheHive-Project/Cortex/).
    
-   **Active Response:** TheHive allows analysts to use Responders and run active actions to communicate, share information about incidents and prevent or contain a threat.
    
-   **Custom Dashboards:** Statistics on cases, tasks, observables, metrics and more can be compiled and distributed on dashboards that can be used to generate useful KPIs within an organisation.
    
-   **Built-in MISP Integration:** Another useful integration is with [MISP](https://www.misp-project.org/index.html), a threat intelligence platform for sharing, storing and correlating Indicators of Compromise of targeted attacks and other threats. This integration allows analysts to create cases from MISP events, import IOCs or export their own identified indicators to their MISP communities.

Malware Information Sharing Platform is is an open-source threat information platform used to facilitate the collection and sharing of threat information.

Other notable integrations that TheHive supports are [DigitalShadows2TH](https://github.com/TheHive-Project/DigitalShadows2TH) & [ZeroFox2TH](https://github.com/TheHive-Project/Zerofox2TH), free and open-source extensions of alert feeders from [DigitalShadows](https://www.digitalshadows.com/) and [ZeroFox](https://www.zerofox.com/) respectively. These integrations ensure that alerts can be added into TheHive and transformed into new cases using pre-defined incident response templates or by adding to existing cases.

Answer the questions below

Which open-source platform supports the analysis of observables within TheHive?

*Cortex*

### User Profiles & Permissions

TheHive offers an administrator the ability to create an organisation group to identify the analysts and assign different roles based on a list of pre-configured user profiles.  

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/853ee5298bfa5e60bf2fcf8d832268ff.png)

Admin Console -  Create Organisation

  

The pre-configured user profiles are:

-   **admin:** full administrative permissions on the platform; can't manage any Cases or other data related to investigations;
-   **org-admin:** manage users and all organisation-level configuration, can create and edit Cases, Tasks, Observables and run Analysers and Responders;
-   **analyst:** can create and edit Cases, Tasks, Observables and run Analysers & Responders;
-   **read-only:** Can only read, Cases, Tasks and Observables details;

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/b38aa62d7e9b6ddb08a200987a2bb3df.png)  

Admin Console -  Add User

  

Each user profile has a pre-defined list of permissions that would allow the user to perform different tasks based on their role. When a profile has been selected, its permissions will be listed.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/a0413ab7ab43bdb220919d7a48e4ddfe.png)  

  

The full list of permissions includes:

Permission  

Functions  

**manageOrganisation (1)  
**

Create & Update an organisation  

**manageConfig (1)  
**

Update Configuration  

**manageProfile (1)  
**

Create, update & delete Profiles  

**manageTag (1)  
**

Create, update & Delete Tags  

**manageCustomField (1)  
**

Create, update & delete Custom Fields  

**manageCase  
**

Create, update & delete Cases  

**manageObservable  
**

Create, update & delete Observables  

**manageALert  
**

Create, update & import Alerts  

**manageUser  
**

Create, update & delete Users  

**manageCaseTemplate  
**

Create, update & delete Case templates  

**manageTask  
**

Create, update & delete Tasks  

**manageShare**  

Share case, task & observable with other organisations  

**manageAnalyse (2)  
**

Execute Analyse  

**manageAction (2)  
**

Execute Actions  

**manageAnalyserTemplate (2)  
**

Create, update & delete Analyser Templates  

_Note that (1) Organisations, configuration, profiles and tags are global objects. The related permissions are effective only on the “admin” organisation. (2) Actions, analysis and template are available only if the Cortex connector is enabled._

In addition to adding new user profiles, the admin can also perform other operations such as creating case custom fields, custom observable types, custom analyser templates and importing TTPs from the MITRE ATT&CK framework, as displayed in the image below.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/23c56b240bbeabf412e2bb69651e9a52.png)  

Imported list of ATT&CK Patterns

  

Deploy the machine attached to follow along on the next task. Please give it a minimum of 5 minutes to boot up. It would be best if you connected to the portal via [http://MACHINE_IP/index.html](http://machine_ip/index.html)[](http://machine_ip/index.html) on the AttackBox or using your VPN connection.

Log on to the _analyst_ profile using the credentials: 

_Username: analyst@tryhackme.me Password: analyst1234_

Answer the questions below

Which pre-configured account cannot manage any cases?

*admin*

Which permission allows a user to create, update or delete observables?

*manageObservable*

Which permission allows a user to execute actions?

*manageAction*

### Analyst Interface Navigation

**SCENARIO**

You have captured network traffic on your network after suspicion of data exfiltration being done on the network. This traffic corresponds to FTP connections that were established. Your task is to analyse the traffic and create a case on TheHive to facilitate the progress of an investigation. If you are unfamiliar with using Wireshark, please check out [this room](https://tryhackme.com/room/wireshark) first and come back to complete this task. 

  

_Source of PCAP file: IntroSecCon CTF 2020_

  

Once an analyst has logged in to the dashboard, they will be greeted with the screen below. At the top, various menu options are listed that allow the user to create new cases and see their tasks and alerts. A list of active cases will be populated on the centre console when analysts create them.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/9b044f28a831732ff79c94109e84baf0.png)

Image: TheHive Main Landing Page

  

On clicking the`New Case` tab, a pop-up window opens, providing the analyst with fields to input their case details and tasks. The following options must be indicated on the case to set different categories and filter options:

-   **_Severity_:** This showcases the level of impact the incident being investigated has on the environment from low to critical levels.
-   **_TLP_:** The Traffic Light Protocol is a set of designations to ensure that sensitive information is shared with the appropriate audience. The range of colours represents a scale between full disclosure of information (_White_) and No disclosure/ Restricted (_Red_). You can find more information about the definitions on the [CISA](https://www.cisa.gov/tlp) website.
-   **_PAP_:**  The Permissible Actions Protocol is used to indicate what an analyst can do with the information, whether an attacker can detect the current analysis state or defensive actions in place. It uses a colour scheme similar to TLP and is part of the [MISP taxonomies](https://www.misp-project.org/taxonomies.html#_pap).

With this in mind, we open a new case and fill in the details of our investigation, as seen below. Additionally, we add a few tasks to the case that would guide the investigation of the event. 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/15ff110d1a816ca7ff517ee63288783b.gif)  

New Case Window  

  

In the visual below, we add the corresponding tactic and technique associated with the case. This provides additional information that can be helpful to map out the threat. As this is an exfiltration investigation, that is the specific tactic chosen and followed by the specific T1048.003 technique for Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/f390eb83345ba7e4d5582ae8038ef2c1.gif)  

TTPs Selection Window

Case observables will be added from the Observables tab and you would have to indicate the following details:

**Field**

**Description**

**Examples**

_Type *:_  

The observable dataType  

IP address, Hash, Domain

_Value *:_  

Your observable value  

8.8.8.8, 127.0.0.1

_One observable per line:_  

Create one observable per line inserted in the value field.  

  

_One single multiline observable:_  

Create one observable, no matter the number of lines  

Long URLs

_TLP *:_  

Define here the way the information should be shared.  

  

_Is IOC:_  

Check if this observable is considered an Indicator of Compromise  

Emotet IP

_Has been sighted:_  

Has this observable been sighted on your information system?  

  

_Ignore for similarity:_  

Do not correlate this observable with other similar observables.  

  

_Tags **:_  

Insightful information Tags.  

Malware IP; MITRE Tactics

_Description **:_   

Description of the observable  

  

In our scenario, we are adding the IP address 192... as our observable as this IP is the source of the FTP requests. Depending on the situation of your analysis, this observable can be marked as an IOC or if it has been sighted before in a different investigation.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/d3e3e6f85aa9169aa78104beebc79b8e.gif)  

New Observables Window  

Answer the questions below

Where are the TTPs imported from?

A globally-accessible knowledge base of adversary tactics and techniques based on real-world observations.

*MITRE ATT&CK Framework*

According to the Framework, what type of Detection "Data source" would our investigation be classified under?  

Research on the TTP assigned

![[Pasted image 20221217130013.png]]

*Network Traffic*

Upload the pcap file as an observable. What is the flag obtained from [](https://10-10-82-47.p.thmlabs.com/files/flag.html)[https://10.10.82.47//files/flag.html](https://10.10.82.47//files/flag.html)

![[Pasted image 20221217130033.png]]

![[Pasted image 20221217130537.png]]

http://10.10.82.47/files/flag.html

![[Pasted image 20221217130957.png]]

*THM{FILES_ARE_OBSERVABLERS}*

### Room Conclusion 



We have now reached the end of TheHive Project room.

This room has hopefully given you a good grasp of how incident response and management is performed using TheHive and give you a working knowledge of the tool.

You are advised to experiment with these foundations until you are completely comfortable with them and to open up to more experiments with the mentioned integrations and others.


[[Velociraptor]]