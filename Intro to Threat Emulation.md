----
A look into threat emulation practices as a means of cyber security assessment.
----

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/407f155692f2e16814c8ae2e2151b143.png)

![](https://tryhackme-images.s3.amazonaws.com/room-icons/8d439e654727248c5de0f226e39b266c.png)

### Task 1  Introduction

Red and Blue Teams are essential in identifying, detecting and addressing vulnerabilities. In a continually evolving threat landscape, security operations centres (SOC) need to reduce the impact of the cyber security skills gap, gain confidence in their ability to prevent a data breach, and get real-world training through experience. This can be facilitated through effective collaboration between the teams while addressing security breaches and during training and emulation practices. Understanding the difference between cyber security simulation and emulation can help you build a more robust threat detection and response program that strengthens security.

## Learning Objectives

- Understand what Threat Emulation is.
- Identify various frameworks used in Threat Emulation.
- Understand how to plan, execute and report emulation exercises.

## Prerequisites

Before embarking on this room, it is highly recommended to review the rooms in the following modules:

- [Cyber Defence Frameworks](https://tryhackme.com/module/cyber-defence-frameworks).
- [Cyber Threat Intelligence](https://tryhackme.com/module/cyber-threat-intelligence).

Answer the questions below

Let's get into emulation.

 Completed

### Task 2  What is Threat Emulation?

## Purpose of Threat Emulation

Threat emulation is meant to assist security teams and organisations, in general, in better understanding their security posture and their defence mechanisms and performing due diligence in their compliance. This ensures they are provided with an adversary's perspective of an attack without the hassle of dealing with an actual threat with malicious intent. Additionally, the organisation will be well prepared if a real-time and sophisticated attack is initiated against them. With this know-how, the following common assumptions about an attack would be avoided:

- _"We applied all patches."_ 
- _"Our applications have multi-factor authentication applied."_ 
- _"We have the network segmented, implemented a DMZ, and traffic flows through a proxy."_ 
- _"Nothing will go through our firewalls, antivirus and IDS solutions."_

## Cyber Security Assessment Issues

Network owners and IT executives often wish to understand their cyber security effectiveness. They will usually line up the following common questions to be answered:

- _Are our people trained and alert?_
- _Are our internal processes effective?_
- _Has the technology in use properly configured and delivered value to the business?_

These questions are addressed through cyber security assessments, mainly red team engagements, vulnerability assessments and penetration tests. With that, let's understand how these practices contribute to security assessments.

Vulnerability assessments are conducted to identify vulnerabilities in assets under a defined scope. The focus here is comprehensive and based on the rules of engagement defined, as assessments do not include exploitation.

Penetration testing involves exploiting vulnerabilities within an organisation under strict control of the scope and rules of engagement. Pentests provide organisations with information about their security posture, patching vulnerabilities and where to invest in security training or practices.

Red teaming provides a means of looking at cyber security issues from an adversary's perspective. This generates attacks on the organisation as though the actual adversary is attacking. This is done in the hope of making the defensive measures better and improving their detections.

The challenge of these assessments is that they do not represent real-world threats. They commonly identify initial access vectors that attackers may use and do not facilitate the entire attack cycle.

Another challenge from these assessments is the lack of incentivisation of Red and Blue teams during engagements. No party wishes to share their intel and TTPs (Tactics, Techniques, and Procedures) even when the benefits overlap for both teams.

Emulation is here to address these challenges and provide a holistic security evaluation.

## Emulation vs Simulation

There is no standard definition of this discipline within the industry, as people use different terminologies to mean roughly the same thing. The familiar words used are **threat emulation**, **adversary emulation**, **attack simulation** and **purple teaming**. However, we shall use threat and adversary emulation interchangeably for this room and differentiate them from simulation. Therefore, what is Threat Emulation?

**Threat emulation** is an intelligence-driven impersonation of real-world attack scenarios and TTPs in a controlled environment to test, assess and improve an organisation's security defences and response capabilities. This means that you seek to behave as the adversary would. Threat emulation aims to identify and mitigate security gaps before attackers exploit them.

Emulation can be conducted as a blind operation - mainly as a Red Team engagement and unannounced to the rest of the defensive security team - or as a non-blind operation involving all security teams and ensuring knowledge sharing.

In contrast, **threat simulation** commonly represents adversary functions or behaviour through predefined and automated attack patterns that pretend to represent an adversary. This implies that the actions taken during the exercise will combine TTPs from one or more groups but not an exact imitation of a particular adversary.

### Key Concepts

Threat emulation would be seen to have several key characteristics which line up well with the Pyramid of Pain. For more information on the Pyramid, check out the [linked room](https://tryhackme.com/room/pyramidofpainax). The concepts include the following:

![Pyramid of Pain](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/57e50a5493e2e1826bc6c38bddcf205a.png)

- **Real-world threats:** The MITRE ATT&CK framework and cyber threat intelligence are common information sources to ensure threat TTPs are based on actual breaches, APTs and campaigns.
- **Behaviour-focused:** The execution of TTPs during an emulation exercise aims to tune defences based on behaviours and not signatures, thus adapting to the elements of the Pyramid.
- **Transparency:** Disclosure of activities between the Red and Blue teams during execution ensures that the security posture is improved holistically.
- **Collaborative:** Due to the common goal of improving organisational security, threat emulation allows teams to collaborate in their efforts.
- **Repeatable:** Some emulation tasks would be done multiple times in the course on an exercise or numerous exercises. These tasks can be automated, creating a baseline of continuous practical security assessments and deployment.

Emulation can be applied to numerous instances, each with its own goals:

- **Assessments & Improvement:** The goal is to test personnel, assess security processes and evaluate the technology adopted.
- **Capability Development:** Emulation enables the creation, modification and application of tools and analytics derived from TTPs.
- **Professional Development:** What better way to teach and promote knowledge sharing about adversary behaviours and frameworks? This breaks down the barriers between red and blue teams and fosters collaboration missions.

Threat emulation exercises provide vital insights to organisations to assess, manage and improve their abilities to protect their systems effectively against adversaries. At this point, one may ask how you conduct threat emulation and what methodologies can be followed for a successful exercise. We shall dive into that in the next task.

Answer the questions below

What can be defined as an intelligence-driven impersonation of real-world attacks?

*Threat Emulation*

What is the exercise of representing adversary functions through predefined and automated attack patterns?

*Threat simulation*


### Task 3  Emulation Methodologies

Threat emulation methodologies are strategies, plans and procedures used to simulate and test network defences and systems against adversaries. There are various methodologies, each with its unique approach and level of technicality, but all share the goal of discovering weaknesses in security. It is essential to know that no adversary is alike. However, they would follow a methodology and have their workflows. The methodologies described in this task seek to provide a knowledge base for organisations when dealing with threats and to plan their emulation exercises.

Additionally, these methodologies can be combined when formulating your emulation plan; as we shall see, some are already integrated. Let us take a look at some of the methodologies.

## MITRE ATT&CK  

﻿The [MITRE ATT&CK Framework](https://tryhackme.com/room/mitre) is an industry-known knowledge base that provides information about known adversarial TTPs observed in actual attacks and breaches. Threat emulation teams can extract many benefits from integrating ATT&CK with their engagements as it would make it efficient when writing reports and mitigations related to the behaviours experimented with.

The MITRE ATT&CK matrix visually represents attackers' techniques to accomplish a specific objective. It showcases 14 tactics, from reconnaissance to impact and within each tactic, several adversary techniques are listed and describe the activity carried out. An extension of the ATT&CK matrix is the Navigator, a web-based tool for exploring ATT&CK matrices by creating colour-coded heatmap layers of techniques and sub-techniques used by a particular adversary.

Click to enlarge the image.  

![MITRE ATT&CK Framework Matrix](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/805cefe1d44bc2b61cfcbb625ebdeaff.png)  

## Atomic Testing   

[The Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) is a library of emulation tests developed and curated by Red Canary that can be executed to test security defences within an organisation. The testing framework provides a mechanism for learning what malicious activities look like and provide telemetry from every test to facilitate defence improvements.

The atomics (individual tests) are mapped to the MITRE ATT&CK framework, providing a pivot between threat profiles and emulation. Atomic Red Team supports emulation on a wide range of platforms, not only on known Operating Systems but also in Cloud Environments. More on the Atomic Red Team has been covered in these rooms: [Atomic Red Team](https://tryhackme.com/room/atomicredteam) & [Caldera](https://tryhackme.com/room/caldera).

![The image shows the Atomic testing stages to be followed during an emulation planning process.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/01bfe3c6c5ca52e93a0f1ad09411521a.png)

## TIBER-EU Framework

The [Threat Intelligence-based Ethical Red Teaming (TIBER-EU)](https://www.ecb.europa.eu/paym/cyber-resilience/tiber-eu/html/index.en.html) is the European framework developed to deliver controlled, bespoke, intelligence-led emulation testing on entities and organisations' critical live production systems. It is meant to provide a guideline for stakeholders to test and improve cyber resilience through controlled adversary actions.

The TIBER_EU framework follows a three-phase process for end-to-end adversary testing:

#### **1. Preparation Phase**

During this phase, the security teams involved in the test are established, and the entity's management determines and approves the scope. This represents the formal launch of adversarial testing by ensuring all the planning and procurement processes are fulfilled.

#### **2. Testing Phase**

The Threat Intelligence team will prepare a detailed report to showcase the threat areas for the organisation and set up the necessary attack scenarios based on interested adversarial behaviour. Meanwhile, the Red Team will use this report to craft the emulation tests against the systems, people and processes that underpin critical functions. The Blue Team will look for the attacks and assess how their defence systems perform against them. This ultimately forms the aspect of collaboration between the various security teams.

#### **3. Closure Phase**

Once tests are run and defences measured, the emulation team must consider reporting and remediation measures. Each group will draft their analysis reports, including details of the tests conducted, findings and recommendations for technical controls, policies, procedures and awareness training.

![The flowchart shows the TIBER-EU Framework in action, highlighting the Preparation, Testing and Closure phases.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/b41e0b64b78018f1cfefa93fbf4aefc7.png)

## CTID Adversary Emulation Library

The [Center for Threat-Informed Defense](https://mitre-engenuity.org/cybersecurity/center-for-threat-informed-defense/) is a non-profit research and development organisation operated by MITRE Engenuity. Its mission is to promote the practice of threat-informed defence. With this mission, they have curated an open-source [adversary emulation plan library](https://github.com/center-for-threat-informed-defense/adversary_emulation_library), allowing organisations to use the plans to evaluate their capabilities against real-world threats.

The library provides users with two approaches to their emulation:

- **Full Emulation:** This is a comprehensive approach to emulating a particular adversary, for example, [APT29](https://attack.mitre.org/groups/G0016/), typically from initial access to exfiltration. An example of this approach can be found in this [APT29 Adversary Emulation](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/6a5b0413dbe2761d2cb08afe2729d6cf9d021ab6/apt29) repository.
- **Micro Emulation:** This approach is more focused, emulating behaviours across multiple adversaries, such as file access or process injection techniques. You can view existing emulation plans from [CTID micro emulation plans](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/6a5b0413dbe2761d2cb08afe2729d6cf9d021ab6/micro_emulation_plans) on the linked repository.

The Adversary Emulation Process tasks will look at developing an emulation plan for an adversary in ways that will utilise some of the methodologies discussed here.

Answer the questions below

Under TIBER-EU, under which phase would Engagement and Scoping fall?

*Preparation*

What is the library that provides technical emulation tests based on TTPs?

*Atomic Red Team*

### Task 4  Threat Emulation Process I

## Scenario

VASEPY Corp is a multi-billion dollar U.S. retail establishment who are aware of the numerous cyber threats plaguing the retail industry. As a result of the news of a recent breach of one of their competitors, executives have become more concerned about the company's security posture. They have hired you as a Threat Emulation Engineer to plan and execute an adversary emulation exercise based on known threat groups that would target their business.

Developing an internal emulation engagement process for an organisation must be iterative, aligned with recorded cyber security goals, intelligence-driven, and methodical. Security teams can revisit the iterative process, make adjustments where fit and improve the exercise while emulating a given adversary. As an overview, the process's steps are as follows:

- Define Objectives
- Research Adversary TTPs
- Planning the Threat Emulation Engagement
- Conducting the Emulation  
    
- Concluding and Reporting

## 1. Defining Emulation Objectives  
![A bullseye used to represent the function of defining emulation objectives and targets.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/68578a8aff10990ec0cb3331d5920aa0.png)

This step is crucial to ensure the exercise remains focused and on track. The objectives should be clearly defined, specific, and measurable. For example, the aim might be to identify how an attacker could gain access to sensitive data on a particular server or, in the case of VASEPY, have to set our objective to identify areas of protection against credit card fraud and ransomware attacks. The scope of the exercise should also be clearly defined, including what the emulation will target as specific systems and data.  

## 2. Research Adversary TTPs ![A Knight chess piece used to represent the function of researching the adversary.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/9d5d4cd0ba3ac86a3fa138227922b7c4.png)

This step aims to accurately model the behaviour of the target adversary so that the emulation team can conduct the exercise realistically and practically. It involves gathering as much information about the threat and identifying behaviours that can be tested based on the set environment. We can break down this process into the following steps:

### **2.1. Information Gathering**

This step starts by gathering information about threats you would be concerned about. This is to avoid instances of selecting arbitrary and non-concerning adversaries such as [APT41](https://attack.mitre.org/groups/G0096/) that deals with cyber espionage, as opposed to financial fraud. This information can be gathered from various sources, including threat intelligence reports, previous attacks, and publicly available information. More important to note is that as a threat emulation engineer, you would need to start with internal sources, such as network owners, CTI analysts, the cyber defence team and system administrators. These groups will provide information about threats they have seen or heard about and characterise threats based on threat intelligence reports and insights from prior incidents.

Using this for our case, we identify that in Vasepy Corp, security teams are more concerned about financially motivated threat actors that target retail businesses and utilise ransomware. We can establish a shortlist of candidate adversaries that can be emulated for this case using the ATT&CK framework. A quick search provides information about APT groups such as [FIN6](https://attack.mitre.org/groups/G0037/), [FIN7](https://attack.mitre.org/groups/G0046/) and [FIN8](https://attack.mitre.org/groups/G0061/), which all target retail organisations and compromise point-of-sale systems.

### **2.2. Select The Emulated Adversary**

With our shortlist of adversaries, we must narrow it down to one we can emulate. To do so, we can follow a set of critical factors that will influence our selection.

- **Relevance:** Here, we need to align the adversary to be selected to the engagement objectives and the company's goals. This may even include looking at the geographical relevance of particular APTs.
- **Available CTI:** Threat intelligence is vital for providing trustworthy information about a threat. For a robust emulation plan, you would need enough reliable resources around the TTPs.
- **TTP Complexity:** Executing a fruitful emulation plan for complex adversaries who use sophisticated tools and procedures may take a long time. Here, we must establish whether existing tools can handle the emulation or whether custom ones are required.
- **Available Resources:** These are primarily in-house resources that must be provisioned for a smooth operation. Budget, time and personnel must be allocated appropriately during the emulation process.

As the Emulation Engineer, you can review these factors, assessing the shortlist of TTPs against them and narrowing down to the appropriate selection. Based on our information, we can select FIN7 as our suitable adversary to emulate, as they target U.S based retail entities such as Vasepy Corp.

### **2.3. Select The Emulated TTPs**

This step aims to accurately model the behaviour of the target adversary so that the exercise can be conducted realistically and practically. The TTPs selected to emulate will drive the rules of engagement, implementations and operations flow of the emulation.

In the case of the FIN7 APT, their TTPs include spear phishing, social engineering, and watering hole attacks. To select which one to emulate, we must understand the TTPs to prioritise our selection. We can visualise these TTPs using the ATT&CK Navigator and look at the specific behaviours the threat group is known to use.

After this, pivoting to CTI resources, such as those listed within the ATT&CK description, would provide information about how the original TTP was executed. This will be followed by creating a scenario outline for the selected TTP, with appropriate context and sources to fulfil its emulation.

Click to enlarge the image.

![Snippet of the FIN7 Navigator Layer](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/51f3b337c34152a3ffbc3555a85883d5.png)  

### **2.4. Construct TTP Outline**

The outline aims to drive follow-up threat emulation activities, such as explaining the planned emulation activities, stating the scope and rules of engagement and how the TTPs will be implemented during the exercise. For emulating FIN7, the TTP outline would look similar to the image below:

Click to enlarge the image.

![Chart showing the TTP Outline for FIN7.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/cbb6a90e29edcaa51069389e164dbb12.png)  

For continuous emulation exercises, it is worth noting that adversary TTPs can change over time, so staying up-to-date with the latest threat intelligence is essential. For example, FIN7 has been known to alter their TTPs over time, so it is crucial to continually gather new information and update the emulation.

Answer the questions below

There's a set of 3 software used by FIN6 & FIN7. Can you identify them? Answers are in alphabetical order, separated by a comma.

Research about the APTs on ATT&CK.

*AdFind, Cobalt Strike, Mimikatz*

Which factor will be considered when analysing whether to use existing or custom tools during the emulation?

*TTP Complexity*

### Task 5  Threat Emulation Process II

 View Site

## 3. Planning the Threat Emulation Engagement

![The image of a clipboard and checklist representing the actions of planning an engagement.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/e3d2a526f0bbb46c923ed563e4ca2149.png)

Since threat emulation involves conducting and mimicking actual cyber attacks, significant problems may ensue if not properly planned and coordinated. The issues may include disclosure of private data, data loss and unplanned system downtime.

Planning the emulation activities through defining the rules of engagement for the exercise, including communication and approvals, is vital to avert these risks. Planning also involves determining the resources needed for the activity, such as personnel, time, and equipment.

## **3.1 Threat Emulation Plans**

Threat Emulation Plans are a collection of resources used to organise and set a step-by-step execution of instructions for adversary behaviours based on a particular set of TTPs. As discussed in the previous tasks, we can find available emulation plans from CTID that capture adversary behaviours based on specific scenarios and step-by-step procedures to execute the emulation using tools.

A well-defined plan will contain the elements of the threat emulation process as well as the following components:

- **Engagement Objectives:** We have seen that the objectives are defined at the beginning of the process to understand the need for threat emulation.
- **Scope:** The departments, users and devices upon which emulation activities are permitted should be defined explicitly.
- **Schedule:** The dates and times when the activities should occur and when deliverables are due should be defined. This helps avoid conflicts between emulation activities and legitimate business operations.
- **Rules of Engagement:** The acceptable adversary behaviour to be emulated must be planned and discussed. This also includes mitigation actions for any high-risk TTPs used during the exercise.
- **Permission to Execute:** Explicit written consent to conduct the emulation activities must be provided by sufficient authority from the organisation. This helps avoid acting out independently and risking legal or criminal problems.
- **Communication Plan:** The emulation team and organisation stakeholders must have a plan to communicate information concerning the emulation activities. You need to define the timings, communication channels, and any collaboration efforts to be included.

## 4. Conducting the Emulation![The image of building blocks represents the action of conducting an emulation engagement, similar to construction.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/91159be6c8b4f7c307e86f7edf55e853.png)

This step involves carrying out the attack using the TTPs identified in the research phase. This step requires skilled professionals who can accurately replicate the tactics and techniques of the target adversary. The exercise should be conducted controlled and safely, and any issues should be addressed immediately. 

We will not go through a technical implementation of TTPs in this room. However, we shall provide a decent breakdown of the process.   

During the execution of the emulation, some resources would be needed to implement the TTPs. This will be your emulation lab, comprising an attack platform, an analysis platform used to gather forensic details and analyse artefacts and your test systems where the TTPs would be deployed. 

### **4.1. Planning the Deployment**

As the emulation engineer for VASEPY, we can revisit the Research phase tackled in the previous task, where we identify the TTPs to emulate for FIN7. Let's say we wish to emulate the Initial Access TTPs. We can use ATT&CK to understand the TTPs and map them out using the Navigator. This would be combined with CTI resources, such as [Mandiant's FIN7 Evolution Report](https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html) and [ESentire FIN7 Report](https://www.esentire.com/security-advisories/notorious-cybercrime-gang-fin7-lands-malware-in-law-firm-using-fake-legal-complaint-against-jack-daniels-owner-brown-forman-inc), outlining how FIN7 used Windows document lures to execute their campaign.

The lab environment needed for the exercise should be effectively set up, and security teams should know their responsibilities.  

### **4.2. Implementation of TTP**

This is where the deployment of actual TTPs happens. In our case scenario, an Initial Access payload for FIN7 would be created and obfuscated using an RTF document, delivered through a spear phishing email. The lures used by attackers such as FIN7 tend to be convincing using DOCX and RTF files with malicious Windows Shortcut File (.LNK) embedded. A code snippet demonstrating this execution based on the [CTID FIN7 Emulation plan](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/master/fin7/Emulation_Plan/Scenario_1#step-1---initial-breach-evaluations-step-11) would look as follows:

Malicious File Execution: T1204.002

```shell-session
# Copy 2-list.rtf to <domain_admin> Desktop on hotelmanager.
sudo smbclient -U '<domain_full>\<domain_admin>' //<hotelmanager_ip>/C$ -c "put fin7/Resources/Step1/SQLRat/2-list.rtf Users\\<domain_admin>.<domain>\\Desktop\\2-list.rtf"

#Provide <domain_admin> password when prompted.
<domain_admin_password>

#Login to victim workstation as <domain_admin>
xfreerdp +clipboard /u:"<domain_admin>@<domain_full>" /p:"<domain_admin_password>" /v:<hotelmanager_ip>
```

  

### **4.3. Detections & Mitigations**

Since emulation is a cross-team and collaborative endeavour, the defence team must find ways to detect and mitigate against emulated TTPs. Depending on the organisational setup, the SOC would use standard cyber security tools to collect, correlate and analyse TTP behaviour and logs for detection. MITRE provides a list of mitigation efforts for the adversarial TTPs, and this can be provided as recommendations and implemented as part of the emulation. In our case, we can look at the [Malicious File T1204.002](https://attack.mitre.org/techniques/T1204/002/) mitigations and detection strategies.

Click to enlarge image.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/d616f4308f0e66ecf9242d070081cac5.png)  

To end the task, answer the questions provided based on what you have learnt. Click the **View Site** button at the top of the task to launch the static site and complete the activity.

Answer the questions below

```
## Instructions

There are **two** rounds, each round comprising of **three** questions related to a specific attack strategy that is being implemented. You have an option to utilize a **Special Ability Play** that will have more impact and help complete the exercise quicker.

## Assuming you're emulating Carbon Spider, what will you use to achieve Execution Techniques?

https://www.virustotal.com/gui/file/8279ce0eb52a9f5b5ab02322d1bb7cc9cb5b242b7359c3d4d754687069fcb7b8/community

https://www.crowdstrike.com/blog/carbon-spider-embraces-big-game-hunting-part-1/

https://attack.mitre.org/software/S0517/

THM{C4RB0N_$P1D3R_1$_F1N7}

## Assuming you're emulating Reaper, what will you use to achieve Initial Access Techniques?

https://attack.mitre.org/software/S0213/

https://attack.mitre.org/groups/G0067/

https://www2.fireeye.com/rs/848-DID-242/images/rpt_APT37.pdf

THM{3$P1ON4G3_F0R_R34P3R}
```
![[Pasted image 20230817204731.png]]
![[Pasted image 20230817204753.png]]
![[Pasted image 20230817204847.png]]
![[Pasted image 20230817205005.png]]
![[Pasted image 20230817205017.png]]
![[Pasted image 20230817205124.png]]
![[Pasted image 20230817205304.png]]
![[Pasted image 20230817205319.png]]
![[Pasted image 20230817205336.png]]

![[Pasted image 20230817204657.png]]

The emulation plan component determining which activities are to be conducted is known as the?

*Scope*

What is flag one obtained after completing the exercise?  

	*THM{C4RB0N_$P1D3R_1$_F1N7}*

What is flag two obtained after completing the exercise?

*THM{3$P1ON4G3_F0R_R34P3R}*

### Task 6  Threat Emulation Process III

 View Site

## 5. Observe Results

While going through the emulation engagement, the observing team (typically Blue Team) must identify artefacts that point to the emulation activity. This will be through the analysis of logs, evaluation of event logs and tracking of networking traffic.

Additionally, like in the case of FIN7, detection rules would be vital to detect the threat. One collection of rules useful for this would be the [YARA rules](https://tryhackme.com/room/yara). Have a look at the rules to detect the [pillowMint.exe](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/blob/master/fin7/yara-rules/pillowmint.txt) malware.

The output of these results would help to understand if the TTP was successful at its mission, blocked or detected by the security measures available.

## 6. Document & Report Findings

Once results have been obtained, the teams must document and report the findings. Documentation provides empirical evidence to demonstrate the cyber security effectiveness of the process.

Reporting should cover the exercise procedures, as outlined in the emulation plan and what was executed, the impact faced and recommendations that would be offered to avert the threat.

Answer the questions below

```
https://github.com/center-for-threat-informed-defense/adversary_emulation_library/blob/master/fin7/yara-rules/pillowmint.txt

https://attack.mitre.org/groups/G0125/

https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/
```
![[Pasted image 20230817205635.png]]
![[Pasted image 20230817205709.png]]
![[Pasted image 20230817205807.png]]
![[Pasted image 20230817205829.png]]
![[Pasted image 20230817205842.png]]
![[Pasted image 20230817211945.png]]
![[Pasted image 20230817212100.png]]
![[Pasted image 20230817212126.png]]
![[Pasted image 20230817212144.png]]
![[Pasted image 20230817212527.png]]

Click the **View Site** button at the top of the task to launch the static site. What is flag three obtained after completing the exercise?  

*THM{D3F3NC3_1N_3MUL4T10N}*

What is flag four obtained after completing the exercise?

*THM{S3CUR3_4LL_W3B_4553T5}*

### Task 7  Conclusion

Fantastic work going through the **Introduction to Threat Emulation** room. 

Throughout the room, we have seen how adversary behaviours can be emulated by following a detailed process and formulating a plan.  As the room covered these concepts in theory, you should expect to meet them more practically and technically in future rooms within the module. 

Threat Emulation is commonly viewed as a Red Team concept, yet it is all-rounded and involves every team in the security domain. Knowing how attackers do it simplifies understanding how to defend it, more like learning the moves in a video game.

Answer the questions below

Power to Threat Emulation.

 Completed


[[Dissecting PE Headers]]