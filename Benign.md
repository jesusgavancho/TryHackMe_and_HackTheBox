---
Challenge room to investigate a compromised host.
---

### Scenario: Identify and Investigate an Infected Host

One of the client’s IDS indicated a potentially suspicious process execution indicating one of the hosts from the HR department was compromised. Some tools related to network information gathering / scheduled tasks were executed which confirmed the suspicion. Due to limited resources, we could only pull the process execution logs with Event ID: 4688 and ingested them into Splunk with the index **win_eventlogs** for further investigation.  

About the Network Information

The network is divided into three logical segments. It will help in the investigation.  

**IT Department  
**

-   James
-   Moin
-   Katrina

**HR department  
**

-   Haroon
-   Chris
-   Diana

**Marketing department**

-   Bell
-   Amelia
-   Deepak

Answer the questions below

How many logs are ingested from the month of March?

![[Pasted image 20221215133527.png]]

*13959*

Imposter Alert: There seems to be an imposter account observed in the logs, what is the name of that user?

index=win_eventlogs| rare limit=20 UserName

![[Pasted image 20221215133941.png]]

*Amel1a*

Which user from the HR department was observed to be running scheduled tasks?

https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688

index=win_eventlogs EventID=4688

or

index=win_eventlogs "schtasks"

![[Pasted image 20221215140145.png]]

![[Pasted image 20221215143204.png]]
*Chris.fort*

Which user from the HR department executed a system process (LOLBIN) to download a payload from a file-sharing host.
Explore lolbas-project.github.io/ to find binaries used to download payloads

index=win_eventlogs| rare limit=20 ProcessName

![[Pasted image 20221215143345.png]]

https://lolbas-project.github.io/#certu

to download

![[Pasted image 20221215143445.png]]

index=win_eventlogs certutil.exe

![[Pasted image 20221215143555.png]]

*haroon*

To bypass the security controls, which system process (lolbin) was used to download a payload from the internet?

*certutil.exe*

What was the date that this binary was executed by the infected host? format (YYYY-MM-DD)

![[Pasted image 20221215143654.png]]

*2022-03-04*

Which third-party site was accessed to download the malicious payload?

*controlc.com*

What is the name of the file that was saved on the host machine from the C2 server during the post-exploitation phase?

*benign.exe*

The suspicious file downloaded from the C2 server contained malicious content with the pattern THM{..........}; what is that pattern?

https://controlc.com/548ab556

	*THM{KJ&*H^B0}*

What is the URL that the infected host connected to?

*https://controlc.com/548ab556*

[[Investigating with Splunk]]