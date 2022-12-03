---
Learn about the four core features of the Diamond Model of Intrusion Analysis: adversary, infrastructure, capability, and victim.
---

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/6d6ef602b1284ab0505fae8b413413e0.png)

![](https://assets.tryhackme.com/additional/banners/Cyber%20Defence%20Frameworks%20icon%20and%20banner-02.svg)


### Introduction 

What is The Diamond Model?

The Diamond Model of Intrusion Analysis was developed by cybersecurity professionals - Sergio Caltagirone, Andrew Pendergast, and Christopher Betz in 2013.

[As described by its creators](https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf), the Diamond Model is composed of four core features: adversary, infrastructure, capability, and victim, and establishes the fundamental atomic element of any intrusion activity. You might have also noticed two additional components or axes of the Diamond Model - Social, Political and Technology; we will go into a little bit more detail about them later in this room. Why is it called a "Diamond Model"? The four core features are edge-connected, representing their underlying relationships and arranged in the shape of a diamond. 

The Diamond Model carries the essential concepts of intrusion analysis and adversary operations while allowing the flexibility to expand and encompass new ideas and concepts. The model provides various opportunities to integrate intelligence in real-time for network defence, automating correlation across events, classifying events with confidence into adversary campaigns, and forecasting adversary operations while planning and gaming mitigation strategies.

Why should you learn about The Diamond Model?

The Diamond Model can help you identify the elements of an intrusion. At the end of this room, you will create a Diamond Model for events such as a breach, intrusion, attack, or incident. You will also be able to analyze an Advanced Persistent Threat (APT). 

The Diamond Model can also help explain to other people who are non-technical about what happened during an event or any valuable information on the malicious threat actor.

### Adversary 

Who is an Adversary?

An adversary is also known as an attacker, enemy, cyber threat actor, or hacker. The adversary is the person who stands behind the cyberattack. Cyberattacks can be an instruction or a breach.

According to the creators of the Diamond Model,  an adversary is an actor or organization responsible for utilizing a capability against the victim to achieve their intent. Adversary knowledge can generally be mysterious, and this core feature is likely to be empty for most events – at least at the time of discovery. 

It is essential to know the distinction between adversary operator and adversary customer because it will help you understand intent, attribution, adaptability, and persistence by helping to frame the relationship between an adversary and victim pair.  

It is difficult to identify an adversary during the first stages of a cyberattack. Utilizing data collected from an incident or breach, signatures, and other relevant information can help you determine who the adversary might be.

Adversary Operator is the “hacker” or person(s) conducting the intrusion activity.

Adversary Customer is the entity that stands to benefit from the activity conducted in the intrusion. It may be the same person who stands behind the adversary operator, or it may be a separate person or group.

As an example, an adversary customer could control different operators simultaneously. Each operator might have its capabilities and infrastructure.


What is the term for a person/group that has the intention to perform malicious actions against cyber resources?
*Adversary Operator*



What is the term of the person or a group that will receive the benefits from the cyberattacks?
*Adversary Customer*

### Victim 



Victim – is a target of the adversary. A victim can be an organization, person, target email address, IP address, domain, etc. It's essential to understand the difference between the victim persona and the victim assets because they serve different analytic functions. 

A victim can be an opportunity for the attackers to get a foothold on the organization they are trying to attack. There is always a victim in every cyberattack. For example, the spear-phishing email (a well-crafted email targeting a specific person of interest) was sent to the company, and someone (victim) clicked on the link. In this case, the victim is the selected target of interest for an adversary. 

Victim Personae are the people and organizations being targeted and whose assets are being attacked and exploited. These can be organization names, people’s names, industries, job roles, interests, etc.

Victim Assets are the attack surface and include the set of systems, networks, email addresses, hosts, IP addresses, social networking accounts, etc., to which the adversary will direct their capabilities.


What is the term that applies to the Diamond Model for organizations or people that are being targeted?

*Victim Personae*

### Capability 


Capability – is also known as the skill, tools, and techniques used by the adversary in the event. The capability highlights the adversary’s tactics, techniques, and procedures (TTPs). 

The capability can include all techniques used to attack the victims, from the less sophisticated methods, such as manual password guessing, to the most sophisticated techniques, like developing malware or a malicious tool. 

Capability Capacity is all of the vulnerabilities and exposures that the individual capability can use. 

An Adversary Arsenal is a set of capabilities that belong to an adversary. The combined capacities of an adversary's capabilities make it the adversary's arsenal.

An adversary must have the required capabilities. The capabilities can be malware and phishing email development skills or, at least, access to capabilities, such as acquiring malware or ransomware as a service.

*Adversary Arsenal*

### Infrastructure 


Infrastructure – is also known as software or hardware. Infrastructure is the physical or logical interconnections that the adversary uses to deliver a capability or maintain control of capabilities. For example, a command and control centre (C2) and the results from the victim (data exfiltration). 

The infrastructure can also be IP addresses, domain names, email addresses, or even a malicious USB device found in the street that is being plugged into a workstation. 

Type 1 Infrastructure is the infrastructure controlled or owned by the adversary. 

Type 2 Infrastructure is the infrastructure controlled by an intermediary. Sometimes the intermediary might or might not be aware of it. This is the infrastructure that a victim will see as the adversary. Type 2 Infrastructure has the purpose of obfuscating the source and attribution of the activity. Type 2 Infrastructure includes malware staging servers, malicious domain names, compromised email accounts, etc.

Service Providers are organizations that provide services considered critical for the adversary availability of Type 1 and Type 2 Infrastructures, for example, Internet Service Providers, domain registrars, and webmail providers.



To which type of infrastructure do malicious domains and compromised email accounts belong?
*Type 2 Infrastructure*



What type of infrastructure is most likely owned by an adversary? 
*Type 1 Infrastructure*

### Event Meta Features 

![222](https://i.ibb.co/g7s4P6b/Advertising-Content-Feature-Native-Premium-Blue-Dotted-Line-Line-Icon.jpg)

Six possible meta-features can be added to the Diamond Model. Meta-features are not required, but they can add some valuable information or intelligence to the Diamond Model.

    Timestamp - is the date and time of the event. Each event can be recorded with a date and time that it occurred, such as 2021-09-12 02:10:12.136. The timestamp can include when the event started and stopped. Timestamps are essential to help determine the patterns and group the malicious activity. For example, if the intrusion or breach happened at 3 am in the United States, it might be possible that the attack was carried out from a specific country with a different time zone and standard business hours. 
    Phase - these are the phases of an intrusion, attack, or breach. According to the Diamond Model creators and the Axiom 4, "Every malicious activity contains two or more phases which must be successfully executed in succession to achieve the desired result." Malicious activities don't occur in two or more events rather than just one. A great example can be the Cyber Kill Chain developed by Lockheed Martin. You can find out more about the Cyber Kill Chain by visiting the Cyber Kill Chain room on TryHackMe 
    The phases can be: 
    1. Reconnaissance
    2. Weaponization
    3. Delivery
    4. Exploitation
    5. Installation
    6. Command & Control
    7. Actions on Objective
    For example, an attacker needs to do some research to discover the target or a victim. Then they would try to exploit the target, establish a command-and-control centre and, lastly, exfiltrate the sensitive information. 
    Result - While the results and post-conditions of an adversary’s operations will not always be known or have a high confidence value when they are known, they are helpful to capture. It is crucial to capture the results and post-conditions of an adversary's operations, but sometimes they might not always be known. The event results can be labelled as "success," "failure," or "unknown." The event results can also be related to the CIA (confidentiality, integrity, and availability) triad, such as Confidentiality Compromised, Integrity Compromised, and Availability Compromised. Another approach can also be documenting all of the post-conditions resulting from the event, for example, information gathered in the reconnaissance stage or successful passwords/sensitive data exfiltration.
    Direction - This meta-feature helps describe host-based and network-based events and represents the direction of the intrusion attack. The Diamond Model of Intrusion Analysis defines seven potential values for this meta-feature: Victim-to-Infrastructure, Infrastructure-to-Victim, Infrastructure-to-Infrastructure, Adversary-to-Infrastructure, Infrastructure-to-Adversary, Bidirectional or Unknown.
    Methodology - This meta-feature will allow an analyst to describe the general classification of intrusion, for example, phishing, DDoS, breach, port scan, etc. 
    Resources - According to the Diamond Model, every intrusion event needs one or more external resources to be satisfied to succeed. Examples of the resources can include the following: software (e.g., operating systems, virtualization software, or Metasploit framework), knowledge (e.g., how to use Metasploit to execute the attack and run the exploit), information (e.g., a username/password to masquerade), hardware (e.g., servers, workstations, routers), funds (e.g., money to purchase domains), facilities (e.g., electricity or shelter), access (e.g., a network path from the source host to the victim and vice versa, network access from an Internet Service Provider (ISP)).


What meta-feature does the axiom "Every malicious activity contains two or more phases which must be successfully executed in succession to achieve the desired result" belong to? 
*phase*

You can label the event results as "success", "failure", and "unknown". What meta-feature is this related to? 
*result*

To what meta-feature is this phrase applicable "Every intrusion event requires one or more external resources to be satisfied prior to success"? 
*resource*

### Social-Political Component 


The social-political component describes the needs and intent of the adversary, for example, financial gain, gaining acceptance in the hacker community, hacktivism, or espionage. 

The scenario can be that the victim provides a “product”, for example, computing resources & bandwidth as a zombie in a botnet for crypto mining (producing new cryptocurrencies by solving cryptographic equations through the use of computers) purposes, while the adversary consumes their product or gets financial gain. 


###  Technology Component 

Technology – the technology meta-feature or component highlights the relationship between the core features: capability and infrastructure. The capability and infrastructure describe how the adversary operates and communicates. A scenario can be a watering-hole attack which is a methodology where the adversary compromises legitimate websites that they believe their targeted victims will visit.

### Practice Analysis 

Are you ready to construct the Diamond Model? Please, deploy the static site attached to this task and dive into the case study and extract the information needed to populate our Diamond Model. 

https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2016/05/20081514/E-ISAC_SANS_Ukraine_DUC_5.pdf

(Please note: The case study for this room occurred in 2015, and is not in light of recent developments in Ukraine). 

Answer the questions below

Ensure you have deployed the static site attached to this task. To complete the static site, you will need to click on each triangular section of the diamond until you have completed all eight areas of the diamond

Complete all eight areas of the diamond. What is the flag that is displayed to you?
*THM{DIAMOND_MODEL_ATTACK_CHAIN}*

![[Pasted image 20221203175131.png]]

###  Conclusion 



We hope you enjoyed this room and will apply the Diamond Model concepts in disrupting threat activity using the Diamond Model and bringing valuable information to your team and business executives (C-Suite), an audience, customer, or client that is not technical.

The Diamond Model is a scientific method to improve the efficiency and accuracy of intrusion analysis. With this in your arsenal, you will have opportunities to leverage real-time intelligence for network defence and predict adversary operations.



[[Pyramid Of Pain]]