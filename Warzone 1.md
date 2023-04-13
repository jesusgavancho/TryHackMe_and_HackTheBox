----
You received an IDS/IPS alert. Time to triage the alert to determine if its a true positive.
----

![](https://assets.tryhackme.com/additional/warzone/warzone-banner.png)

![111](https://tryhackme-images.s3.amazonaws.com/room-icons/3d6033aa286ac42fdb793c605ebbf3f0.png)

### Your shift just started and your first network alert comes in.

 Start Machine

![SOC Team](https://assets.tryhackme.com/additional/jrsecanalyst/task2.png)  

You work as a Tier 1 Security Analyst L1 for a Managed Security Service Provider (MSSP). Today you're tasked with monitoring network alerts.

A few minutes into your shift, you get your first network case: **Potentially Bad Traffic** and **Malware Command and Control Activity detected**.  Your race against the clock starts. Inspect the PCAP and retrieve the artifacts to confirm this alert is a true positive. 

**Your tools**:

-   [Brim](https://tryhackme.com/room/brim)
-   [Network Miner](https://tryhackme.com/room/networkminer)
-   [Wireshark](https://tryhackme.com/room/wireshark)

---

Deploy the machine attached to this task; it will be visible in the split-screen view once it is ready.

If you don't see a virtual machine load then click the Show Split View button.

![Split View](https://assets.tryhackme.com/additional/challs/warzone1-split-view.png)  

Answer the questions below

```
search with brim (Suricata alerts by ubnet then filet = value)
so final filter will be 169.239.0.0/16 
then the firt result

alert.signature
ET MALWARE MirrorBlast CnC Activity M3

src_ip
172.16.1.102

defanging ip 172[.]16[.]1[.]102

dest_ip
169.239.128.11

defanging ip 169[.]239[.]128[.]11

https://www.virustotal.com/gui/ip-address/169.239.128.11/relations

Date resolved
2021-11-12
Detections
14/ 87
Resolver
VirusTotal
Domain
www.fidufagios.com

defanging url without subdomain 
fidufagios[.]com

MirrorBlast TA505
Microsoft Themed TA505 malicious domains
TA505 Campaign

https://attack.mitre.org/groups/G0092/

https://threatresearch.ext.hp.com/mirrorblast-and-ta505-examining-similarities-in-tactics-techniques-and-procedures/

https://www.virustotal.com/gui/domain/fidufagios.com/relations

Scanned
2023-04-05
Detections
32/ 55
Type
Windows Installer
Name
malicious

using wireshark

filter: ip.dst == 169.239.128.11 && http

follow tcp stream
GET /r?x=bmFtZT1TVE9DS0lURk9SVVNcZHdpZ2h0Lm1vcmFsZXMmb3M9MTAuMCZhcmNoPXg4NiZidWlsZD0xLjAuMg== HTTP/1.0
Accept: */*
Connection: close
User-Agent: REBOL View 2.7.8.3.1
Host: fidufagios.com

HTTP/1.1 200 OK
Server: nginx/1.14.2
Date: Tue, 05 Oct 2021 22:42:03 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 38
Connection: close

1|f327b5b7-65ea-4f57-b323-a278f1637fb8

User-Agent: REBOL View 2.7.8.3.1

search with brim queries http requests

id.orig_h
172.16.1.102
id.resp_h
192.36.27.92
id.resp_p
80
method
GET
host
192.36.27.92
uri
/10opd3r_load.msi
_uniq
1

172.16.1.102
id.resp_h
185.10.68.235
id.resp_p
80
method
GET
host
185.10.68.235
uri
/
_uniq
1

search 185.10.68.235

defanging ips 185[.]10[.]68[.]235,192[.]36[.]27[.]92


filename
filter.msi   from 185.10.68.235

uri
/10opd3r_load.msi from 192.36.27.92

filter.msi,10opd3r_load.msi

using wireshark ip.dst == 185.10.68.235 
follow tcp (stream 14)

Never null or empty.RegistryPrimary key, non-localized token.RootThe predefined root key for the registry value, one of rrkEnum.KeyRegPathThe key for the registry value.The registry value name.The registry value.Foreign key into the Component table referencing component that controls the installing of the registry value.RemoveFileFileKeyPrimary key used to identify a particular file entryForeign key referencing Component that controls the file to be removed.WildCardFilenameName of the file to be removed.DirPropertyName of a property whose value is assumed to resolve to the full pathname to the folder of the file to be removed.InstallMode1;2;3Installation option, one of iimEnum.CostInitializeFileCostCostFinalizeInstallValidateInstallInitializeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProductComponent.CommonAppDataFolder{DEA88988-9EB8-4997-B469-14BBA2A13D95}CommonAppDataFolderComponent.INSTALLDIR{DEA88988-9EB8-4997-B469-14BB177F6F37}INSTALLDIRComponent.arab.bin{DEA88988-9EB8-4997-B469-14BB85EDB3C2}arab.binComponent.arab.exe{DEA88988-9EB8-4997-B469-14BBE3B5B3B3}arab.exeTempFolder.EmptyDirectory{DEA88988-9EB8-4997-B469-14BBAA73C431}TempFolderreg579EC8DF028069C30646A4022E297FB6TARGETDIR{DEA88988-9EB8-4997-B469-14BB57246387}Action1_arab.exeC:\ProgramData\001\arab.bin

C:\ProgramData\001\arab.bin,C:\ProgramData\001\arab.exe

using wireshark ip.dst == 169.239.128.11 && http
follow tcp (stream 17)
4

Never null or empty.RegistryPrimary key, non-localized token.RootThe predefined root key for the registry value, one of rrkEnum.KeyRegPathThe key for the registry value.The registry value name.The registry value.Foreign key into the Component table referencing component that controls the installing of the registry value.RemoveFileFileKeyPrimary key used to identify a particular file entryForeign key referencing Component that controls the file to be removed.WildCardFilenameName of the file to be removed.DirPropertyName of a property whose value is assumed to resolve to the full pathname to the folder of the file to be removed.InstallMode1;2;3Installation option, one of iimEnum.CostInitializeFileCostCostFinalizeInstallValidateInstallInitializeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProductComponent.CommonAppDataFolder{7DAD0B07-2406-4203-AE21-B3164EF4C02F}CommonAppDataFolderComponent.Local{7DAD0B07-2406-4203-AE21-B316AC8C445A}CommonAppDataFolder.LocalComponent.INSTALLDIR{7DAD0B07-2406-4203-AE21-B316C3D2F2D1}INSTALLDIRComponent.exemple.rb{7DAD0B07-2406-4203-AE21-B3165A3BDAD7}exemple.rbComponent.rebol_view_278_3_1.exe{7DAD0B07-2406-4203-AE21-B316DBE7EA0A}rebol_view_278_3_1.exeRegistry1{7DAD0B07-2406-4203-AE21-B3168DB34436}Registry2{7DAD0B07-2406-4203-AE21-B3168DB34439}Google__ChromeTempFolder.EmptyDirectory{7DAD0B07-2406-4203-AE21-B31656C647CB}TempFolderreg579EC8DF028069C30646A4022E297FB6TARGETDIR{7DAD0B07-2406-4203-AE21-B3160377E621}Action1_rebol_view_278_3_1.exe-w -i -s C:/ProgramData/Local/Google/exemple.rbGoogleLocalyhcj5x6n|CommonAppDataFoldert19mu-pt|TempFolderSourceDirPackage38yhbxk2.exe|rebol-view-278-3-1.exe2.7.8.31033ValidateProductIDProcessComponentsUnpublishFeaturesRemoveRegistryValuesRemoveFilesRemoveFoldersCreateFoldersWriteRegistryValues(NOT Installed)#Google_Chrome.cabManufacturerProductCode{7DAD0B07-2406-4203-AE21-B31650B1B6AE}ProductLanguageProductNameGoogle ChromeProductVersion92.0.4515UpgradeCode{A2F91B1E-5C5B-4BBC-85F0-16F8CCAD5E7E}RegValueSoftware\Microsoft\Windows\CurrentVersion\RunGoogle  ChromeC:\ProgramData\Local\Google\rebol-view-278-3-1.exe -w -i -s C:\ProgramData\Local\Google\exemple.rbSoftware\WixSharp\Used0

C:\ProgramData\Local\Google\rebol-view-278-3-1.exe,C:\ProgramData\Local\Google\exemple.rb


```

What was the alert signature for **Malware Command and Control Activity Detected**?

Brim

![[Pasted image 20230413115321.png]]

*ET MALWARE MirrorBlast CnC Activity M3*

What is the source IP address? Enter your answer in a **defanged** format. 

Cyberchef can defang.

	*172[.]16[.]1[.]102*

What IP address was the destination IP in the alert? Enter your answer in a **defanged** format. 

Cyberchef can defang.

	*169[.]239[.]128[.]11*

Inspect the IP address in VirsusTotal. Under **Relations > Passive DNS Replication**, which domain has the most detections? Enter your answer in a **defanged** format. 

Ensure you use VirusTotal’s Search, not the URL Search.

	*fidufagios[.]com*

Still in VirusTotal, under **Community**, what threat group is attributed to this IP address?

*TA505*

What is the malware family?

*MirrorBlast*

Do a search in VirusTotal for the domain from question 4. What was the majority file type listed under **Communicating Files**?

Check Relations

![[Pasted image 20230413120939.png]]

*Windows Installer*

Inspect the web traffic for the flagged IP address; what is the **user-agent** in the traffic?

![[Pasted image 20230413121816.png]]

*REBOL View 2.7.8.3.1*

Retrace the attack; there were multiple IP addresses associated with this attack. What were two other IP addresses? Enter the IP addressed **defanged** and in numerical order. (**format: IPADDR,IPADDR**)

Brim (HTTP logs) & VT (Community tab) can help you here. Cyberchef can defang.

![[Pasted image 20230413124247.png]]

	*185[.]10[.]68[.]235,192[.]36[.]27[.]92*

What were the file names of the downloaded files? Enter the answer in the order to the IP addresses from the previous question. (**format: file.xyz,file.xyz**)

The first character in the second filename is not a lowercase or uppercase "L".

*filter.msi,10opd3r_load.msi*

Inspect the traffic for the first downloaded file from the previous question. Two files will be saved to the same directory. What is the full file path of the directory and the name of the two files? (**format: C:\path\file.xyz,C:\path\file.xyz**)

Inspect the streams.

![[Pasted image 20230413130820.png]]

	*C:\ProgramData\001\arab.bin,C:\ProgramData\001\arab.exe*

	Now do the same and inspect the traffic from the second downloaded file. Two files will be saved to the same directory. What is the full file path of the directory and the name of the two files? (format: C:\path\file.xyz,C:\path\file.xyz)

Inspect the streams.

![[Pasted image 20230413132148.png]]

	*C:\ProgramData\Local\Google\rebol-view-278-3-1.exe,C:\ProgramData\Local\Google\exemple.rb*

[[Mindgames]]