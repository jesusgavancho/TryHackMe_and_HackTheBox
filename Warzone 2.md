----
You received another IDS/IPS alert. Time to triage the alert to determine if its a true positive.
----

![](https://assets.tryhackme.com/additional/warzone/warzone-banner.png)

###  Another day, another alert.

 Start Machine

![SOC Team](https://assets.tryhackme.com/additional/jrsecanalyst/task2.png)  

You work as a Tier 1 Security Analyst L1 for a Managed Security Service Provider (MSSP). Again, you're tasked with monitoring network alerts.

An alert triggered: **Misc activity**, **A Network Trojan Was Detected**, and **Potential Corporate Privacy Violation**. 

The case was assigned to you. Inspect the PCAP and retrieve the artifacts to confirm this alert is a true positive. 

Your tools:

-   [Brim](https://tryhackme.com/room/brim)
-   [Network Miner](https://tryhackme.com/room/networkminer)
-   [Wireshark](https://tryhackme.com/room/wireshark)

---

Deploy the machine attached to this task; it will be visible in the split-screen view once it is ready.

If you don't see a virtual machine load then click the Show Split View button.

![Show Split Screen if needed](https://assets.tryhackme.com/additional/challs/warzone2-split-view.png)  

Answer the questions below

```
using brim import pcap
then filter: event_type=="alert" alert.category=="A Network Trojan was detected" 

alert.signature
ET MALWARE Likely Evil EXE download from MSXMLHTTP non-exe extension M2

filter: event_type=="alert" alert.category=="Potential Corporate Privacy Violation"

alert.signature
ET POLICY PE EXE or DLL Windows file download HTTP

src_ip 185.118.164.8

defanging ip 185[.]118[.]164[.]8

filter 185.118.164.8

file_desc http://awh93dhkylps5ulnq-be.com/czwih/fxla.php?l=gap1.cab

full uri defanged so without http://

awh93dhkylps5ulnq-be[.]com/czwih/fxla[.]php?l=gap1[.]cab

go to query file activity 

filename
gap1.cab
md5
78e05075e686397097de69fb0402263e
sha1
f3e9e7f321deb1a3408053168a6a67c6cd70e114

let's search on virus total

https://www.virustotal.com/gui/file/3769a84dbe7ba74ad7b0b355a864483d3562888a67806082ff094a56ce73bf7e

draw.dll

filter 185.118.164.8 then go to 6 result

user_agent Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/8.0; .NET4.0C; .NET4.0E)

from  virustotal 

a-zcorner.com
d0d0abee1d18255e.com
d0d0f3d189430.com
knockoutlights.com
msnbot-207-46-194-33.search.msn.com
organicgreensfl.com

then comparing with brim 
defanging domains
a-zcorner[.]com,knockoutlights[.]com

filter 10.0.0.0/8 id.resp_h!=176.119.156.128
then defanged ips

64[.]225[.]65[.]166,142[.]93[.]211[.]176

https://www.virustotal.com/gui/ip-address/64.225.65.166/relations

nl-1.nodes.skey.network
fridomcoin.com
dagynalch.pw
antivarevare.top
ulcertification.xyz
tocsicambar.xyz
safebanktest.top
ns2.parcellsafebox.com
ns1.parcellsafebox.com
cadinstitute.com
www.cadinstitute.com

filter id.resp_h==64.225.65.166
defanged domains
safebanktest[.]top,tocsicambar[.]xyz,ulcertification[.]xyz

https://www.virustotal.com/gui/ip-address/142.93.211.176/relations

dev.carsinindia.in
admin.carsinindia.in
meeting230.krititech.com
www.woondly.com
woondly.com
crmtest.ibrook.in
biggfix.serveeazy.com
www.biggfix.serveeazy.com
myphone.serveeazy.com
bright.serveeazy.com
amtiaz.serveeazy.com
www.admin.serveeazy.com
www.myphone.serveeazy.com
admin.serveeazy.com
mobitronold.serveeazy.com
alrehan.serveeazy.com
www.bright.serveeazy.com
www.mobitronold.serveeazy.com
www.amtiaz.serveeazy.com
www.alrehan.serveeazy.com
ariesmobilecareold.serveeazy.com
www.ariesmobilecareold.serveeazy.com
www.image.serveeazy.com
image.serveeazy.com
webmail.serveeazy.com
alreef.serveeazy.com
www.alreef.serveeazy.com
cpanel.serveeazy.com
www.serveeazy.com
serveeazy.com
cpcontacts.serveeazy.com
mail.serveeazy.com
webdisk.serveeazy.com
cpcalendars.serveeazy.com
www.cellzone.serveeazy.com
crackfix.serveeazy.com
www.mobilecareold.serveeazy.com
techmobiles.serveeazy.com
smdsolutions.serveeazy.com
smartphonecare.serveeazy.com
www.mastersold.serveeazy.com
www.crackfix.serveeazy.com
www.smartphonecare.serveeazy.com
mastersold.serveeazy.com
www.techmobiles.serveeazy.com
www.smdsolutions.serveeazy.com
www.old.serveeazy.com
bst.serveeazy.com
www.bst.serveeazy.com
old.serveeazy.com
www.impt.serveeazy.com
cellzone.serveeazy.com
www.bserveold.serveeazy.com
www.techgarage.serveeazy.com
www.utsold.serveeazy.com
techgarage.serveeazy.com
impt.serveeazy.com
www.mksolutions.serveeazy.com
nextlevel.serveeazy.com
www.global.serveeazy.com
mksolutions.serveeazy.com
www.mobfixer.serveeazy.com
gallexy.serveeazy.com
www.gallexy.serveeazy.com
mobilecareold.serveeazy.com
mobfixer.serveeazy.com
technocure.serveeazy.com
www.nextlevel.serveeazy.com
www.hommo.serveeazy.com
hommo.serveeazy.com
global.serveeazy.com
www.hifixold.serveeazy.com
utsold.serveeazy.com
shrimobiles.serveeazy.com
www.technocure.serveeazy.com
hifixold.serveeazy.com
www.shrimobiles.serveeazy.com
www.kms.serveeazy.com
www.gcmtold.serveeazy.com
kms.serveeazy.com
gcmtold.serveeazy.com
bserveold.serveeazy.com
www.ifix.serveeazy.com
ifix.serveeazy.com
www.brkklold.serveeazy.com
brkklold.serveeazy.com
cellcraft.serveeazy.com
www.cellcraft.serveeazy.com
extremeold.serveeazy.com
www.extremeold.serveeazy.com
texmob.serveeazy.com
www.texmob.serveeazy.com
trad.serveeazy.com
www.trad.serveeazy.com
www.rdmobileold.serveeazy.com
www.repairmyphoneold.serveeazy.com
flash.serveeazy.com
www.flash.serveeazy.com
rdmobileold.serveeazy.com
www.developer.serveeazy.com
ius.serveeazy.com
www.ius.serveeazy.com
britcouaeold.serveeazy.com
repairmyphoneold.serveeazy.com
www.mobilehouseold.serveeazy.com
developer.serveeazy.com
www.britcouaeold.serveeazy.com
mobilehouseold.serveeazy.com
www.shezone.serveeazy.com
www.mobileguru.serveeazy.com
mobileguru.serveeazy.com
shezone.serveeazy.com
pubgmobiles.serveeazy.com
skybritco.serveeazy.com
www.pubgmobiles.serveeazy.com
www.gallexyold.serveeazy.com
www.skybritco.serveeazy.com
gallexyold.serveeazy.com
5gmobile.serveeazy.com
rdmobile.serveeazy.com
www.rdmobile.serveeazy.com
www.extreme.serveeazy.com
www.mobilecare.serveeazy.com
extreme.serveeazy.com
mobilecare.serveeazy.com
zonemobiles.serveeazy.com
www.demo.serveeazy.com
imac.serveeazy.com
britcouae.serveeazy.com
masters.serveeazy.com
www.britcouae.serveeazy.com
www.masters.serveeazy.com
demo.serveeazy.com
fixst.serveeazy.com
bserve.serveeazy.com
www.zonemobiles.serveeazy.com
www.reunion.serveeazy.com
reunion.serveeazy.com
sizzcomm.serveeazy.com
www.sizzcomm.serveeazy.com
www.imac.serveeazy.com
www.hifix.serveeazy.com
hifix.serveeazy.com
www.gcmt.serveeazy.com
www.fixst.serveeazy.com
www.mobilehouse.serveeazy.com
gcmt.serveeazy.com
uts.serveeazy.com
www.bserve.serveeazy.com
www.uts.serveeazy.com
mobilehouse.serveeazy.com
repairmyphone.serveeazy.com
www.repairmyphone.serveeazy.com
www.5gmobile.serveeazy.com
www.homepulse.serveeazy.com
magnus.serveeazy.com
ariesmobilecare.serveeazy.com
www.brkkl.serveeazy.com
www.unitell.serveeazy.com
unitell.serveeazy.com
www.magnus.serveeazy.com
www.smartsolutions.serveeazy.com
www.ariesmobilecare.serveeazy.com
homepulse.serveeazy.com
brkkl.serveeazy.com
mobitron.serveeazy.com
smartsolutions.serveeazy.com
www.mobitron.serveeazy.com
www.getfix.serveeazy.com
www.krishna.serveeazy.com
krishna.serveeazy.com
getfix.serveeazy.com
cloud.serveeazy.com
2partscow.top
influx.qft-iot.com
mqtt.qft-iot.com
qft-iot.com
api.qft-iot.com
www.cloud.qft-iot.com
cloud.qft-iot.com

id.resp_h==142.93.211.176
defanged domain
2partscow[.]top

was really fun :)

```


What was the alert signature for **A Network Trojan was Detected**?

![[Pasted image 20230414115851.png]]

*ET MALWARE Likely Evil EXE download from MSXMLHTTP non-exe extension M2*

What was the alert signature for **Potential Corporate Privacy Violation**?

*ET POLICY PE EXE or DLL Windows file download HTTP*

What was the IP to trigger either alert? Enter your answer in a **defanged** format. 

Cyberchef can defang.

![[Pasted image 20230414120125.png]]

	*185[.]118[.]164[.]8*

Provide the full URI for the malicious downloaded file. In your answer, **defang** the URI. 

Cyberchef can defang.

![[Pasted image 20230414120426.png]]

	*awh93dhkylps5ulnq-be[.]com/czwih/fxla[.]php?l=gap1[.]cab*

What is the name of the payload within the cab file? 

Extract the file from PCAP, get the hash, then hop to VirusTotal

*draw.dll*

What is the user-agent associated with this network traffic?

![[Pasted image 20230414121231.png]]

*Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/8.0; .NET4.0C; .NET4.0E)*

	What other domains do you see in the network traffic that are labelled as malicious by VirusTotal? Enter the domains **defanged** and in alphabetical order. (**format: domain[.]zzz,domain[.]zzz**)

Check the Misc Activity alert in Brim. Cyberchef can defang.

![[Pasted image 20230414121950.png]]

![[Pasted image 20230414122042.png]]

	*a-zcorner[.]com,knockoutlights[.]com*

There are IP addresses flagged as **Not Suspicious Traffic**. What are the IP addresses? Enter your answer in numerical order and **defanged**. (format: IPADDR,IPADDR)

![[Pasted image 20230414124754.png]]

	*64[.]225[.]65[.]166,142[.]93[.]211[.]176*

	For the first IP address flagged as Not Suspicious Traffic. According to VirusTotal, there are several domains associated with this one IP address that was flagged as malicious. What were the domains you spotted in the network traffic associated with this IP address? Enter your answer in a **defanged** format. Enter your answer in alphabetical order, in a defanged format. (**format: domain[.]zzz,domain[.]zzz,etc**)  

![[Pasted image 20230414125352.png]]

	*safebanktest[.]top,tocsicambar[.]xyz,ulcertification[.]xyz*

	Now for the second IP marked as Not Suspicious Traffic. What was the domain you spotted in the network traffic associated with this IP address? Enter your answer in a **defanged** format. (format: domain[.]zzz)

Brim, Network Miner, or Wireshark

	*2partscow[.]top*

[[Warzone 1]]