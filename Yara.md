---
Learn the applications and language that is Yara for everything threat intelligence, forensics, and threat hunting!
---

![](https://assets.tryhackme.com/additional/yara/yarabanner-final.png)

![](https://tryhackme-images.s3.amazonaws.com/room-icons/497c8f224596c3b4be59ddce65f65c93.png)

### Introduction 


Introduction
This room will expect you to understand basic Linux familiarity, such as installing software and commands for general navigation of the system. Moreso, this room isn't designed to test your knowledge or for point-scoring. It is here to encourage you to follow along and experiment with what you have learned here.

As always, I hope you take a few things away from this room, namely, the wonder that Yara (Yet Another Ridiculous Acronym) is and its importance in infosec today. Yara was developed by Victor M. Alvarez ([@plusvic](https://twitter.com/plusvic)) and [@VirusTotal](https://twitter.com/virustotal). Check the GitHub repo [here](https://github.com/virustotal/yara).


### What is Yara? 

All about Yara 
"The pattern matching swiss knife for malware researchers (and everyone else)" (Virustotal., 2020) https://virustotal.github.io/yara/

With such a fitting quote, Yara can identify information based on both binary and textual patterns, such as hexadecimal and strings contained within a file.

Rules are used to label these patterns. For example, Yara rules are frequently written to determine if a file is malicious or not, based upon the features - or patterns - it presents. Strings are a fundamental component of programming languages. Applications use strings to store data such as text.

For example, the code snippet below prints "Hello World" in Python. The text "Hello World" would be stored as a string.

print("Hello World!")


We could write a Yara rule to search for "hello world" in every program on our operating system if we would like. 

Why does Malware use Strings?
Malware, just like our "Hello World" application, uses strings to store textual data. Here are a few examples of the data that various malware types store within strings:

Type	Data	Description
Ransomware	12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw https://www.blockchain.com/btc/address/12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw
		Bitcoin Wallet for ransom payments
Botnet		12.34.56.7
	

	The IP address of the Command and Control (C&C) server

Caveat: Malware Analysis
Explaining the functionality of malware is vastly out of scope for this room due to the sheer size of the topic. I have covered strings in much more detail in "Task 12 - Strings" of my [MAL: Introductory room](https://tryhackme.com/room/malmalintroductory). In fact, I am creating a whole Learning Path for it. If you'd like to get a taster whilst learning the fundamentals, I'd recommend my room.


What is the name of the base-16 numbering system that Yara can detect?
*Hex*


Would the text "Enter your Name" be a string in an application? (Yay/Nay)
*Yay*

###  Deploy 

This room deploys an Instance with the tools being showcased already installed for you.  Press the "Start Machine" button and wait for an IP address to be displayed and connect in one of two ways:

In-Browser (No  VPN required)

Deploy your own instance by pressing the green "Start Machine" button and scroll up to the top of the room and await the timer. The machine will start in a split-screen view. In case the VM is not visible, use the blue "Show Split View" button at the top-right of the page.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/7c222bb437b106d862d93ce76117c9e8.png)

Using SSH (TryHackMe VPN required).

You must be connected to the TryHackMe VPN if you wish to connect your deployed Instance from your own device.  If you are unfamiliar with this process, please visit the TryHackMe OpenVPN room to get started. If you have any issues, please read our support articles.

IP Address: MACHINE_IP

Username: cmnatic

Password: yararules!

SSH Port: 22

```
┌──(kali㉿kali)-[~]
└─$ ssh cmnatic@10.10.148.188      
The authenticity of host '10.10.148.188 (10.10.148.188)' can't be established.
ED25519 key fingerprint is SHA256:RieZYTsQ1UtM4KeZPtl6iqUw/0na+7ckuREypwHYLjI.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.148.188' (ED25519) to the list of known hosts.
cmnatic@10.10.148.188's password: 
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-163-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Nov 27 16:00:48 UTC 2022

  System load:  0.65              Processes:           116
  Usage of /:   85.2% of 8.79GB   Users logged in:     0
  Memory usage: 5%                IP address for eth0: 10.10.148.188
  Swap usage:   0%

  => / is using 85.2% of 8.79GB

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

0 updates can be applied immediately.


Last login: Tue Nov 30 01:24:11 2021 from 10.9.163.253
cmnatic@thm-yara:~$ pwd
/home/cmnatic
cmnatic@thm-yara:~$ cd /root
-bash: cd: /root: Permission denied

```

### Introduction to Yara Rules 

Your First Yara Rule

The proprietary language that Yara uses for rules is fairly trivial to pick up, but hard to master. This is because your rule is only as effective as your understanding of the patterns you want to search for.

Using a Yara rule is simple. Every yara command requires two arguments to be valid, these are:
1) The rule file we create
2) Name of file, directory, or process ID to use the rule for.

Every rule must have a name and condition.

For example, if we wanted to use "myrule.yar" on directory "some directory", we would use the following command:
yara myrule.yar somedirectory

Note that .yar is the standard file extension for all Yara rules. We'll make one of the most basic rules you can make below.

1. Make a file named "somefile" via touch somefile
2. Create a new file and name it "myfirstrule.yar" like below:

```
 Creating a file named somefile

           
cmnatic@thm:~$ touch somefile

Creating a file named myfirstrule.yar

           
cmnatic@thm touch myfirstrule.yar
```
3. Open the "myfirstrule.yar" using a text editor such as nano and input the snippet below and save the file:

rule examplerule {
        condition: true
}

```

Inputting our first snippet into "myfirstrule.yar" using nano

           
cmnatic@thm nano myfirstrule.yar   GNU nano 4.8 myfirstrule.yar Modified
rule examplerule {
        condition: true
}

     
```

The name of the rule in this snippet is examplerule, where we have one condition - in this case, the condition is condition. As previously discussed, every rule requires both a name and a condition to be valid. This rule has satisfied those two requirements.

Simply, the rule we have made checks to see if the file/directory/PID that we specify exists via condition: true. If the file does exist, we are given the output of examplerule

Let's give this a try on the file "somefile" that we made in step one:
yara myfirstrule.yar somefile

If "somefile" exists, Yara will say examplerule because the pattern has been met - as we can see below:

```
 Verifying our the examplerule is correct

           
cmnatic@thm:~$ yara myfirstrule.yar somefile 
examplerule somefile
```

If the file does not exist, Yara will output an error such as that below:

```

Yara complaining that the file does not exist

           
cmnatic@thm:~$ yara myfirstrule.yar sometextfile
error scanning sometextfile: could not open file
       
```

Congrats! You've made your first rule.


One rule to - well - rule them all.


```
┌──(kali㉿kali)-[~]
└─$ mkdir yara     
                                                                                       
┌──(kali㉿kali)-[~]
└─$ cd yaraa               
cd: no such file or directory: yaraa
                                                                                       
┌──(kali㉿kali)-[~]
└─$ cd yara 
                                                                                       
┌──(kali㉿kali)-[~/yara]
└─$ touch somefile             
                                                                                       
┌──(kali㉿kali)-[~/yara]
└─$ touch myfirstrule.yar
                                                                                       
┌──(kali㉿kali)-[~/yara]
└─$ nano myfirstrule.yar      
                                                                                       
┌──(kali㉿kali)-[~/yara]
└─$ yara myfirstrule.yar somefile 
Command 'yara' not found, but can be installed with:
sudo apt install yara
Do you want to install it? (N/y)y
sudo apt install yara
[sudo] password for kali: 
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following package was automatically installed and is no longer required:
  libgvm21
Use 'sudo apt autoremove' to remove it.
The following NEW packages will be installed:
  yara
0 upgraded, 1 newly installed, 0 to remove and 7 not upgraded.
Need to get 27.0 kB of archives.
After this operation, 88.1 kB of additional disk space will be used.
Get:1 http://kali.download/kali kali-rolling/main amd64 yara amd64 4.2.3-1 [27.0 kB]
Fetched 27.0 kB in 1s (36.1 kB/s)
Selecting previously unselected package yara.
(Reading database ... 429201 files and directories currently installed.)
Preparing to unpack .../yara_4.2.3-1_amd64.deb ...
Unpacking yara (4.2.3-1) ...
Setting up yara (4.2.3-1) ...
Processing triggers for man-db (2.11.0-1+b1) ...
Processing triggers for kali-menu (2022.4.1) ...
Scanning processes...                                                                  
Scanning processor microcode...                                                        
Scanning linux images...                                                               

Running kernel seems to be up-to-date.

The processor microcode seems to be up-to-date.

No services need to be restarted.

No containers need to be restarted.

No user sessions are running outdated binaries.

No VM guests are running outdated hypervisor (qemu) binaries on this host.
                                                                                       
┌──(kali㉿kali)-[~/yara]
└─$ yara myfirstrule.yar somefile
examplerule somefile
                                                                                       
┌──(kali㉿kali)-[~/yara]
└─$ yara myfirstrule.yar sometextfile
error scanning sometextfile: could not open file

┌──(kali㉿kali)-[~/yara]
└─$ cat myfirstrule.yar 
rule examplerule{
        condition: true
}
   
```

### Expanding on Yara Rules 

Yara Conditions Continued...

Checking whether or not a file exists isn't all that helpful. After all, we can figure that out for ourselves...Using much better tools for the job.

Yara has a few conditions, which I encourage you to read [here](https://yara.readthedocs.io/en/stable/writingrules.html) at your own leisure. However, I'll detail a few below and explain their purpose.
Keyword
Desc
Meta
Strings
Conditions
Weight

Meta
This section of a Yara rule is reserved for descriptive information by the author of the rule. For example, you can use desc, short for description, to summarise what your rule checks for. Anything within this section does not influence the rule itself. Similar to commenting code, it is useful to summarise your rule.


Strings

Remember our discussion about strings in Task 2? Well, here we go. You can use strings to search for specific text or hexadecimal in files or programs. For example, say we wanted to search a directory for all files containing "Hello World!", we would create a rule such as below:

```
rule helloworld_checker{
	strings:
		$hello_world = "Hello World!"
}
```

We define the keyword Strings where the string that we want to search, i.e., "Hello World!" is stored within the variable $hello_world

Of course, we need a condition here to make the rule valid. In this example, to make this string the condition, we need to use the variable's name. In this case, $hello_world:

```
rule helloworld_checker{
	strings:
		$hello_world = "Hello World!"

	condition:
		$hello_world
}
```

Essentially, if any file has the string "Hello World!" then the rule will match. However, this is literally saying that it will only match if "Hello World!" is found and will not match if "hello world" or "HELLO WORLD."

To solve this, the condition any of them allows multiple strings to be searched for, like below:

```
rule helloworld_checker{
	strings:
		$hello_world = "Hello World!"
		$hello_world_lowercase = "hello world"
		$hello_world_uppercase = "HELLO WORLD"

	condition:
		any of them
}
```


Now, any file with the strings of:
1. Hello World!
2. hello world
3. HELLO WORLD

Will now trigger the rule.

Conditions

We have already used the true and any of them condition. Much like regular programming, you can use operators such as:
<= less than or equal to
>= more than or equal to
!= not equal to

For example, the rule below would do the following:

```
rule helloworld_checker{
	strings:
		$hello_world = "Hello World!"

	condition:
        #hello_world <= 10
}
```


The rule will now:

1. Look for the "Hello World!" string
2. Only say the rule matches if there are less than or equal to ten occurrences of the "Hello World!" string

Combining keywords

Moreover, you can use keywords such as:
and
not
or 

To combine multiple conditions. Say if you wanted to check if a file has a string and is of a certain size (in this example, the sample file we are checking is less than <10 kb and has "Hello World!" you can use a rule like below:

```
rule helloworld_checker{
	strings:
		$hello_world = "Hello World!" 
        
        condition:
	        $hello_world and filesize < 10KB 
}
```


The rule will only match if both conditions are true. To illustrate: below, the rule we created, in this case, did not match because although the file has "Hello World!", it has a file size larger than 10KB:

```

Yara failing to match the file mytextfile because it is larger than 10kb

           
cmnatic@thm:~$ <output intentionally left blank>

        
```

However, the rule matched this time because the file has both "Hello World!" and a file size of less than 10KB.

```

Yara successfully matching the file mytextfile because it has "Hello World" and a file size of less than 10KB

           
cmnatic@thm:~$ yara myfirstrule.yar mytextfile.txt
helloworld_textfile_checker mytextfile.txt

        
```

Remembering that the text within the red box is the name of our rule, and the text within the green is the matched file.

Anatomy of a Yara Rule

![](https://miro.medium.com/max/875/1*gThGNPenpT-AS-gjr8JCtA.png)

Information security researcher "fr0gger_" has recently created a [handy cheatsheet](https://blog.securitybreak.io/security-infographics-9c4d3bd891ef#18dd) that breaks down and visualises the elements of a YARA rule (shown above, all image credits go to him). It's a great reference point for getting started!


Upwards and onwards...

```
https://www.ibm.com/docs/es/qsip/7.4?topic=administration-managing-suspicious-content
┌──(kali㉿kali)-[~/yara]
└─$ ls
hello_world.yar  myfirstrule.yar  somefile
                                                                                       
┌──(kali㉿kali)-[~/yara]
└─$ cat hello_world.yar 
rule hello_world{
        meta:
                author = "WittyAle"
                description = "learning"
        strings:
                $hello_world = "Hello World!"
        condition:
                $hello_world
}
                                                                                       
┌──(kali㉿kali)-[~/yara]
└─$ cat somefile                 
Hello World!
                                                                                       
┌──(kali㉿kali)-[~/yara]
└─$ yara hello_world.yar somefile
hello_world somefile
                                                                                       
┌──(kali㉿kali)-[~/yara]
└─$ yara hello_world.yar somefile11
error scanning somefile11: could not open file


---

┌──(kali㉿kali)-[~/yara]
└─$ cat helloworld_checker.yar 
rule helloworld_checker{
        meta:
                author = "WittyAle"
                description = "Checking all hello world presents"
        strings:
                $hello_world = "Hello World!"
                $hello_world_lowercase = "hello world!"
                $hello_world_uppercase = "HELLO WORLD!"
        condition:
                any of them and filesize < 10KB
}
                                                                                       
┌──(kali㉿kali)-[~/yara]
└─$ ls
helloworld_checker.yar  hello_world.yar  myfirstrule.yar  somefile
                                                                                       
┌──(kali㉿kali)-[~/yara]
└─$ cat somefile              
Hello World!
                                                                                       
┌──(kali㉿kali)-[~/yara]
└─$ nano somefile2             
                                                                                       
┌──(kali㉿kali)-[~/yara]
└─$ cat somefile2 
hello world!
                                                                                       
┌──(kali㉿kali)-[~/yara]
└─$ nano somefile3
                                                                                       
┌──(kali㉿kali)-[~/yara]
└─$ cat somefile3 
HELLO WORLD!
                                                                                       
┌──(kali㉿kali)-[~/yara]
└─$ yara helloworld_checker.yar somefile
helloworld_checker somefile
                                                                                       
┌──(kali㉿kali)-[~/yara]
└─$ yara helloworld_checker.yar somefile2
helloworld_checker somefile2
                                                                                       
┌──(kali㉿kali)-[~/yara]
└─$ yara helloworld_checker.yar somefile3
helloworld_checker somefile3
                                                                                       
┌──(kali㉿kali)-[~/yara]
└─$ yara helloworld_checker.yar somefile4
error scanning somefile4: could not open file
                                                                                       
┌──(kali㉿kali)-[~/yara]
└─$ ls -lah
total 32K
drwxr-xr-x  2 kali kali 4.0K Nov 27 11:45 .
drwxr-xr-x 69 kali kali 4.0K Nov 27 11:04 ..
-rw-r--r--  1 kali kali  280 Nov 27 11:45 helloworld_checker.yar
-rw-r--r--  1 kali kali  145 Nov 27 11:39 hello_world.yar
-rw-r--r--  1 kali kali   40 Nov 27 11:06 myfirstrule.yar
-rw-r--r--  1 kali kali   13 Nov 27 11:31 somefile
-rw-r--r--  1 kali kali   13 Nov 27 11:45 somefile2
-rw-r--r--  1 kali kali   13 Nov 27 11:45 somefile3

---

┌──(kali㉿kali)-[~/yara]
└─$ nano helloworld_times.yar  
                                                                                       
┌──(kali㉿kali)-[~/yara]
└─$ nano checktimes          
                                                                                       
┌──(kali㉿kali)-[~/yara]
└─$ cat helloworld_times.yar 
rule helloworld_times{
        strings:
                $hello_world = "Hello World!"
        condition:
                #hello_world >= 3
}
                                                                                       
┌──(kali㉿kali)-[~/yara]
└─$ cat checktimes                          
Hello World!
Hello World!
Hello World!
                                                                                       
┌──(kali㉿kali)-[~/yara]
└─$ yara helloworld_times.yar checktimes                 
helloworld_times checktimes
                                                                                       
┌──(kali㉿kali)-[~/yara]
└─$ yara helloworld_times.yar somefile  
                                                                                       
┌──(kali㉿kali)-[~/yara]
└─$ yara helloworld_times.yar somefile2
                                                                                       
┌──(kali㉿kali)-[~/yara]
└─$ yara helloworld_times.yar somefile3
                                                                                       
┌──(kali㉿kali)-[~/yara]
└─$ yara helloworld_times.yar somefile4
error scanning somefile4: could not open file


```


### Yara Modules 


Integrating With Other Libraries
Frameworks such as the [Cuckoo Sandbox](https://cuckoosandbox.org/) or [Python's PE Module](https://pypi.org/project/pefile/) allow you to improve the technicality of your Yara rules ten-fold.


Cuckoo
Cuckoo Sandbox is an automated malware analysis environment. This module allows you to generate Yara rules based upon the behaviours discovered from Cuckoo Sandbox. As this environment executes malware, you can create rules on specific behaviours such as runtime strings and the like.


Python PE
Python's PE module allows you to create Yara rules from the various sections and elements of the Windows Portable Executable (PE) structure.

Explaining this structure is out of scope as it is covered in my [malware introductory room](https://tryhackme.com/room/malmalintroductory). However, this structure is the standard formatting of all executables and DLL files on windows. Including the programming libraries that are used. 

Examining a PE file's contents is an essential technique in malware analysis; this is because behaviours such as cryptography or worming can be largely identified without reverse engineering or execution of the sample.

### Other tools and Yara 

Yara Tools

Knowing how to create custom Yara rules is useful, but luckily you don't have to create many rules from scratch to begin using Yara to search for evil. There are plenty of GitHub [resources](https://github.com/InQuest/awesome-yara) and open-source tools (along with commercial products) that can be utilized to leverage Yara in hunt operations and/or incident response engagements. 

LOKI (What, not who, is Loki?)

LOKI is a free open-source IOC (Indicator of Compromise) scanner created/written by Florian Roth.

Based on the GitHub page, detection is based on 4 methods:

    File Name IOC Check
    Yara Rule Check (we are here)
    Hash Check
    C2 Back Connect Check

There are additional checks that LOKI can be used for. For a full rundown, please reference the [GitHub readme](https://github.com/Neo23x0/Loki/blob/master/README.md).

LOKI can be used on both Windows and Linux systems and can be downloaded [here](https://github.com/Neo23x0/Loki/releases).

Please note that you are not expected to use this tool in this room.

```

Displaying Loki's help menu

           
cmnatic@thm:~/Loki$ python3 loki.py -h
usage: loki.py [-h] [-p path] [-s kilobyte] [-l log-file] [-r remote-loghost]
               [-t remote-syslog-port] [-a alert-level] [-w warning-level]
               [-n notice-level] [--allhds] [--alldrives] [--printall]
               [--allreasons] [--noprocscan] [--nofilescan] [--vulnchecks]
               [--nolevcheck] [--scriptanalysis] [--rootkit] [--noindicator]
               [--dontwait] [--intense] [--csv] [--onlyrelevant] [--nolog]
               [--update] [--debug] [--maxworkingset MAXWORKINGSET]
               [--syslogtcp] [--logfolder log-folder] [--nopesieve]
               [--pesieveshellc] [--python PYTHON] [--nolisten]
               [--excludeprocess EXCLUDEPROCESS] [--force]

Loki - Simple IOC Scanner

optional arguments:
  -h, --help            show this help message and exit

        



```

THOR (superhero named programs for a superhero blue teamer)

THOR Lite is Florian's newest multi-platform IOC AND YARA scanner. There are precompiled versions for Windows, Linux, and macOS. A nice feature with THOR Lite is its scan throttling to limit exhausting CPU resources. For more information and/or to download the binary, start [here](https://www.nextron-systems.com/thor-lite/). You need to subscribe to their mailing list to obtain a copy of the binary. Note that THOR is geared towards corporate customers. THOR Lite is the free version.

Please note that you are not expected to use this tool in this room.

```

Displaying Thor Lite's help menu

           
cmnatic@thm:~$ ./thor-lite-linux-64 -h
Thor Lite
APT Scanner
Version 10.7.3 (2022-07-27 07:33:47)
cc) Nextron Systems GmbH
Lite Version

> Scan Options
  -t, --template string      Process default scan parameters from this YAML file
  -p, --path strings         Scan a specific file path. Define multiple paths by specifying this option multiple times. Append ':NOWALK' to the path for non-recursive scanning (default: only the system drive) (default [])
      --allhds               (Windows Only) Scan all local hard drives (default: only the system drive)
      --max_file_size uint   Max. file size to check (larger files are ignored). Increasing this limit will also increase memory usage of THOR. (default 30MB)

> Scan Modes
      --quick     Activate a number of flags to speed up the scan at cost of some detection.
                  This is equivalent to: --noeventlog --nofirewall --noprofiles --nowebdirscan --nologscan --noevtx --nohotfixes --nomft --lookback 3 --lookback-modules filescan

        


```

FENRIR (naming convention still mythical themed)

This is the 3rd [tool](https://github.com/Neo23x0/Fenrir) created by Neo23x0 (Florian Roth). You guessed it; the previous 2 are named above. The updated version was created to address the issue from its predecessors, where requirements must be met for them to function. Fenrir is a bash script; it will run on any system capable of running bash (nowadays even Windows). 

Please note that you are not expected to use this tool in this room.

```
 Running Fenrir

           
cmnatic@thm-yara:~/tools$ ./fenrir.sh
##############################################################
    ____             _
   / __/__ ___  ____(_)___
  / _// -_) _ \/ __/ / __/
 /_/  \__/_//_/_/ /_/_/
 v0.9.0-log4shell

 Simple Bash IOC Checker
 Florian Roth, Dec 2021
##############################################################

        
```

YAYA (Yet Another Yara Automaton)

YAYA was created by the EFF (Electronic Frontier Foundation) and released in September 2020. Based on their website, "YAYA is a new open-source tool to help researchers manage multiple YARA rule repositories. YAYA starts by importing a set of high-quality YARA rules and then lets researchers add their own rules, disable specific rulesets, and run scans of files."

Note: Currently, YAYA will only run on Linux systems. 

```

Running YAYA

           
cmnatic@thm-yara:~/tools$ yaya
YAYA - Yet Another Yara Automaton
Usage:
yaya [-h]  
    -h print this help screen
Commands:
   update - update rulesets
   edit - ban or remove rulesets
   add - add a custom ruleset, located at 
   scan - perform a yara scan on the directory at 

        


```

In the next section, we will examine LOKI further...

###  Using LOKI and its Yara rule set 

Using LOKI
As a security analyst, you may need to research various threat intelligence reports, blog postings, etc. and gather information on the latest tactics and techniques used in the wild, past or present. Typically in these readings, IOCs (hashes, IP addresses, domain names, etc.) will be shared so rules can be created to detect these threats in your environment, along with Yara rules. On the flip side, you might find yourself in a situation where you've encountered something unknown, that your security stack of tools can't/didn't detect. Using tools such as Loki, you will need to add your own rules based on your threat intelligence gathers or findings from an incident response engagement (forensics). 

As mentioned before, Loki already has a set of Yara rules that we can benefit from and start scanning for evil on the endpoint straightaway.

Navigate to the Loki directory. Loki is located in the tools.

```

Listing the tools directory

           
cmnatic@thm-yara:~/tools$ ls
Loki  yarGen

        
```

Run python loki.py -h to see what options are available. 

If you are running Loki on your own system, the first command you should run is --update. This will add the signature-base directory, which Loki uses to scan for known evil. This command was already executed within the attached VM. 

```

Listing Loki signature-base directory

           
cmnatic@thm-yara:~/tools/Loki/signature-base$ ls
iocs  misc  yara

        
```

Navigate to the yara directory. Feel free to inspect the different Yara files used by Loki to get an idea of what these rules will hunt for.

To run Loki, you can use the following command (note that I am calling Loki from within the file 1 directory)

```

Instructing Loki to scan the suspicious file

           
cmnatic@thm-yara:~/suspicious-files/file1$ python ../../tools/Loki/loki.py -p .

        
```

Scenario: You are the security analyst for a mid-size law firm. A co-worker discovered suspicious files on a web server within your organization. These files were discovered while performing updates to the corporate website. The files have been copied to your machine for analysis. The files are located in the suspicious-files directory. Use Loki to answer the questions below.

```
installing and updating

┌──(kali㉿kali)-[~/Downloads]
└─$ mv Loki-0.45.0.tar.gz loki            
                                                                                       
┌──(kali㉿kali)-[~/Downloads]
└─$ cd loki 
                                                                                       
┌──(kali㉿kali)-[~/Downloads/loki]
└─$ ls
Loki-0.45.0.tar.gz
                                                                                       
┌──(kali㉿kali)-[~/Downloads/loki]
└─$ tar xvzf Loki-0.45.0.tar.gz 
Loki-0.45.0/
Loki-0.45.0/.github/
Loki-0.45.0/.github/workflows/
Loki-0.45.0/.github/workflows/lint_python.yml
Loki-0.45.0/.gitignore
Loki-0.45.0/.gitmodules
Loki-0.45.0/.travis.yml
Loki-0.45.0/LICENSE
Loki-0.45.0/Pipfile
Loki-0.45.0/README.md
Loki-0.45.0/build.bat
Loki-0.45.0/build_sfx.bat
Loki-0.45.0/config/
Loki-0.45.0/config/excludes.cfg
Loki-0.45.0/docs/
Loki-0.45.0/docs/LICENSE-PE-Sieve
Loki-0.45.0/docs/LICENSE-doublepulsarcheck
Loki-0.45.0/lib/
Loki-0.45.0/lib/__init__.py
Loki-0.45.0/lib/doublepulsar.py
Loki-0.45.0/lib/helpers.py
Loki-0.45.0/lib/levenshtein.py
Loki-0.45.0/lib/lokilogger.py
Loki-0.45.0/lib/pesieve.py
Loki-0.45.0/lib/vuln_checker.py
Loki-0.45.0/loki-upgrader.py
Loki-0.45.0/loki-upgrader.spec
Loki-0.45.0/loki.ico
Loki-0.45.0/loki.py
Loki-0.45.0/loki.spec
Loki-0.45.0/lokiicon.jpg
Loki-0.45.0/plugins/
Loki-0.45.0/plugins/loki-plugin-wmi.py
Loki-0.45.0/prepare_push.sh
Loki-0.45.0/requirements.txt
Loki-0.45.0/screens/
Loki-0.45.0/screens/lokicmd.png
Loki-0.45.0/screens/lokiconf1.png
Loki-0.45.0/screens/lokiconf2.png
Loki-0.45.0/screens/lokiinit.png
Loki-0.45.0/screens/lokilog1.png
Loki-0.45.0/screens/lokiscan1.png
Loki-0.45.0/screens/lokiscan2.png
Loki-0.45.0/screens/lokiscan3.png
Loki-0.45.0/screens/lokititle.png
Loki-0.45.0/screens/scanner-comparison.png
Loki-0.45.0/test/
Loki-0.45.0/test/unicode-test/
Loki-0.45.0/test/unicode-test/dotfile/
Loki-0.45.0/test/unicode-test/dotfile/.txt
Loki-0.45.0/test/unicode-test/Иixdrin/
Loki-0.45.0/test/unicode-test/Иixdrin/webshell_tiny_Файл.asp
Loki-0.45.0/test/yara/
Loki-0.45.0/test/yara/JFolder.jsp
Loki-0.45.0/tools/
Loki-0.45.0/tools/pe-sieve32.exe
Loki-0.45.0/tools/pe-sieve64.exe
                                                                                       
┌──(kali㉿kali)-[~/Downloads/loki]
└─$ ls
Loki-0.45.0  Loki-0.45.0.tar.gz
                                                                                       
┌──(kali㉿kali)-[~/Downloads/loki]
└─$ cd Loki-0.45.0 
                                                                                       
┌──(kali㉿kali)-[~/Downloads/loki/Loki-0.45.0]
└─$ ls
build.bat      lib           loki.py             Pipfile          requirements.txt
build_sfx.bat  LICENSE       loki.spec           plugins          screens
config         loki.ico      loki-upgrader.py    prepare_push.sh  test
docs           lokiicon.jpg  loki-upgrader.spec  README.md        tools
                                                                                       
┌──(kali㉿kali)-[~/Downloads/loki/Loki-0.45.0]
└─$ pip install -r requirements.txt 
Defaulting to user installation because normal site-packages is not writeable
Ignoring wmi: markers 'sys_platform == "win32"' don't match your environment
Ignoring pywin32: markers 'sys_platform == "win32"' don't match your environment
Requirement already satisfied: colorama in /usr/lib/python3/dist-packages (from -r requirements.txt (line 1)) (0.4.5)
Requirement already satisfied: future in /usr/lib/python3/dist-packages (from -r requirements.txt (line 2)) (0.18.2)
Requirement already satisfied: netaddr in /usr/lib/python3/dist-packages (from -r requirements.txt (line 3)) (0.8.0)
Requirement already satisfied: psutil in /home/kali/.local/lib/python3.10/site-packages (from -r requirements.txt (line 4)) (5.9.1)
Collecting rfc5424-logging-handler
  Downloading rfc5424_logging_handler-1.4.3-py2.py3-none-any.whl (15 kB)
Requirement already satisfied: yara-python in /usr/lib/python3/dist-packages (from -r requirements.txt (line 8)) (4.2.0)
Requirement already satisfied: pytz in /usr/lib/python3/dist-packages (from rfc5424-logging-handler->-r requirements.txt (line 5)) (2022.6)
Requirement already satisfied: tzlocal in /usr/lib/python3/dist-packages (from rfc5424-logging-handler->-r requirements.txt (line 5)) (4.2)
Installing collected packages: rfc5424-logging-handler
Successfully installed rfc5424-logging-handler-1.4.3
                                                                                       
┌──(kali㉿kali)-[~/Downloads/loki/Loki-0.45.0]
└─$ ls
build.bat      lib           loki.py             Pipfile          requirements.txt
build_sfx.bat  LICENSE       loki.spec           plugins          screens
config         loki.ico      loki-upgrader.py    prepare_push.sh  test
docs           lokiicon.jpg  loki-upgrader.spec  README.md        tools
                                                                                       
┌──(kali㉿kali)-[~/Downloads/loki/Loki-0.45.0]
└─$ python loki.py -h              
usage: loki.py [-h] [-p path] [-s kilobyte] [-l log-file] [-r remote-loghost]
               [-t remote-syslog-port] [-a alert-level] [-w warning-level]
               [-n notice-level] [--allhds] [--alldrives] [--printall] [--allreasons]
               [--noprocscan] [--nofilescan] [--vulnchecks] [--nolevcheck]
               [--scriptanalysis] [--rootkit] [--noindicator] [--dontwait]
               [--intense] [--csv] [--onlyrelevant] [--nolog] [--update] [--debug]
               [--maxworkingset MAXWORKINGSET] [--syslogtcp] [--logfolder log-folder]
               [--nopesieve] [--pesieveshellc] [--python PYTHON] [--nolisten]
               [--excludeprocess EXCLUDEPROCESS] [--force]

Loki - Simple IOC Scanner

options:
  -h, --help            show this help message and exit
  -p path               Path to scan
  -s kilobyte           Maximum file size to check in KB (default 5000 KB)
  -l log-file           Log file
  -r remote-loghost     Remote syslog system
  -t remote-syslog-port
                        Remote syslog port
  -a alert-level        Alert score
  -w warning-level      Warning score
  -n notice-level       Notice score
  --allhds              Scan all local hard drives (Windows only)
  --alldrives           Scan all drives (including network drives and removable
                        media)
  --printall            Print all files that are scanned
  --allreasons          Print all reasons that caused the score
  --noprocscan          Skip the process scan
  --nofilescan          Skip the file scan
  --vulnchecks          Run the vulnerability checks
  --nolevcheck          Skip the Levenshtein distance check
  --scriptanalysis      Statistical analysis for scripts to detect obfuscated code
                        (beta)
  --rootkit             Skip the rootkit check
  --noindicator         Do not show a progress indicator
  --dontwait            Do not wait on exit
  --intense             Intense scan mode (also scan unknown file types and all
                        extensions)
  --csv                 Write CSV log format to STDOUT (machine processing)
  --onlyrelevant        Only print warnings or alerts
  --nolog               Don't write a local log file
  --update              Update the signatures from the "signature-base" sub
                        repository
  --debug               Debug output
  --maxworkingset MAXWORKINGSET
                        Maximum working set size of processes to scan (in MB, default
                        100 MB)
  --syslogtcp           Use TCP instead of UDP for syslog logging
  --logfolder log-folder
                        Folder to use for logging when log file is not specified
  --nopesieve           Do not perform pe-sieve scans
  --pesieveshellc       Perform pe-sieve shellcode scan
  --python PYTHON       Override default python path
  --nolisten            Dot not show listening connections
  --excludeprocess EXCLUDEPROCESS
                        Specify an executable name to exclude from scans, can be used
                        multiple times
  --force               Force the scan on a certain folder (even if excluded with
                        hard exclude in LOKI's code
                                                                                       
┌──(kali㉿kali)-[~/Downloads/loki/Loki-0.45.0]
└─$ ls
build.bat      lib           loki.py             Pipfile          requirements.txt
build_sfx.bat  LICENSE       loki.spec           plugins          screens
config         loki.ico      loki-upgrader.py    prepare_push.sh  test
docs           lokiicon.jpg  loki-upgrader.spec  README.md        tools
                                                                                       
┌──(kali㉿kali)-[~/Downloads/loki/Loki-0.45.0]
└─$ python loki.py --update

                                                                                       
      __   ____  __ ______                                                             
     / /  / __ \/ //_/  _/                                                             
    / /__/ /_/ / ,< _/ /                                                               
   /____/\____/_/|_/___/                                                               
   YARA and IOC Scanner                                                                
                                                                                       
   by Florian Roth, GNU General Public License                                         
   version 0.44.2 (Python 3 release)                                                   
                                                                                       
   DISCLAIMER - USE AT YOUR OWN RISK                                                   
                                                                                       
                                                                                       
                                                                                       
[INFO] Starting separate updater process ...                                           
                                                                                       
┌──(kali㉿kali)-[~/Downloads/loki/Loki-0.45.0]
└─$   
                                                                               
                                                                                       
  LOKI UPGRADER                                                                        
                                                                                       
                                                                                       
                                                                                       
[INFO] Updating LOKI ...                                                               
[INFO] Checking location of latest release https://api.github.com/repos/Neo23x0/Loki/releases/latest ...                                                                      
[INFO] Downloading latest release https://github.com/Neo23x0/Loki/releases/download/v0.45.0/loki_0.45.0.zip ...                                                               
[INFO] Extracting docs/LICENSE-doublepulsarcheck ...                                   
[INFO] Extracting docs/LICENSE-PE-Sieve ...                                            
[INFO] Extracting LICENSE ...                                                          
[INFO] Extracting loki.exe ...                                                         
[INFO] Extracting plugins/loki-plugin-wmi.py ...                                       
[INFO] Extracting README.md ...                                                        
[INFO] Extracting requirements.txt ...                                                 
[INFO] Extracting tools/pe-sieve32.exe ...                                             
[INFO] Extracting tools/pe-sieve64.exe ...                                             
[INFO] Updating Signatures ...                                                         
[INFO] Downloading https://github.com/Neo23x0/signature-base/archive/master.zip ...    
[INFO] New signature file: README.txt                                                  
[INFO] New signature file: c2-iocs.txt                                                 
[INFO] New signature file: falsepositive-hashes.txt                                    
[INFO] New signature file: filename-iocs.txt                                           
[INFO] New signature file: hash-iocs.txt                                               
[INFO] New signature file: keywords.txt                                                
[INFO] New signature file: otx-hash-iocs.txt                                           
[INFO] New signature file: file-type-signatures.txt                                    
[INFO] New signature file: airbnb_binaryalert.yar                                      
[INFO] New signature file: apt_aa19_024a.yar                                           
[INFO] New signature file: apt_agent_btz.yar                                           
[INFO] New signature file: apt_alienspy_rat.yar                                        
[INFO] New signature file: apt_apt10.yar                                               
[INFO] New signature file: apt_apt10_redleaves.yar                                     
[INFO] New signature file: apt_apt12_malware.yar                                       
[INFO] New signature file: apt_apt15.yar                                               
[INFO] New signature file: apt_apt17_mal_sep17.yar                                     
[INFO] New signature file: apt_apt17_malware.yar                                       
[INFO] New signature file: apt_apt19.yar                                               
[INFO] New signature file: apt_apt27_hyperbro.yar                                      
[INFO] New signature file: apt_apt28.yar                                               
[INFO] New signature file: apt_apt28_drovorub.yar                                      
[INFO] New signature file: apt_apt29_grizzly_steppe.yar                                
[INFO] New signature file: apt_apt29_nobelium_apr22.yar                                
[INFO] New signature file: apt_apt29_nobelium_may21.yar                                
[INFO] New signature file: apt_apt30_backspace.yar                                     
[INFO] New signature file: apt_apt32.yar                                               
[INFO] New signature file: apt_apt34.yar                                               
[INFO] New signature file: apt_apt37.yar                                               
[INFO] New signature file: apt_apt37_bluelight.yar                                     
[INFO] New signature file: apt_apt3_bemstour.yar                                       
[INFO] New signature file: apt_apt41.yar                                               
[INFO] New signature file: apt_apt6_malware.yar                                        
[INFO] New signature file: apt_ar18_165a.yar                                           
[INFO] New signature file: apt_area1_phishing_diplomacy.yar                            
[INFO] New signature file: apt_aus_parl_compromise.yar                                 
[INFO] New signature file: apt_babyshark.yar                                           
[INFO] New signature file: apt_backdoor_ssh_python.yar                                 
[INFO] New signature file: apt_backdoor_sunburst_fnv1a_experimental.yar                
[INFO] New signature file: apt_backspace.yar                                           
[INFO] New signature file: apt_beepservice.yar                                         
[INFO] New signature file: apt_between-hk-and-burma.yar                                
[INFO] New signature file: apt_bigbang.yar                                             
[INFO] New signature file: apt_bitter.yar                                              
[INFO] New signature file: apt_blackenergy.yar                                         
[INFO] New signature file: apt_blackenergy_installer.yar                               
[INFO] New signature file: apt_bluetermite_emdivi.yar                                  
[INFO] New signature file: apt_bronze_butler.yar                                       
[INFO] New signature file: apt_buckeye.yar                                             
[INFO] New signature file: apt_candiru.yar                                             
[INFO] New signature file: apt_carbon_paper_turla.yar                                  
[INFO] New signature file: apt_casper.yar                                              
[INFO] New signature file: apt_cheshirecat.yar                                         
[INFO] New signature file: apt_cloudatlas.yar                                          
[INFO] New signature file: apt_cloudduke.yar                                           
[INFO] New signature file: apt_cmstar.yar                                              
[INFO] New signature file: apt_cn_netfilter.yar                                        
[INFO] New signature file: apt_cn_pp_zerot.yar                                         
[INFO] New signature file: apt_cn_reddelta.yar                                         
[INFO] New signature file: apt_cn_twisted_panda.yar                                    
[INFO] New signature file: apt_cobaltstrike.yar                                        
[INFO] New signature file: apt_cobaltstrike_evasive.yar                                
[INFO] New signature file: apt_codoso.yar                                              
[INFO] New signature file: apt_coreimpact_agent.yar                                    
[INFO] New signature file: apt_danti_svcmondr.yar                                      
[INFO] New signature file: apt_darkcaracal.yar                                         
[INFO] New signature file: apt_darkhydrus.yar                                          
[INFO] New signature file: apt_deeppanda.yar                                           
[INFO] New signature file: apt_derusbi.yar                                             
[INFO] New signature file: apt_dnspionage.yar                                          
[INFO] New signature file: apt_donotteam_ytyframework.yar                              
[INFO] New signature file: apt_dragonfly.yar                                           
[INFO] New signature file: apt_dtrack.yar                                              
[INFO] New signature file: apt_dubnium.yar                                             
[INFO] New signature file: apt_duqu1_5_modules.yar                                     
[INFO] New signature file: apt_duqu2.yar                                               
[INFO] New signature file: apt_dustman.yar                                             
[INFO] New signature file: apt_emissary.yar                                            
[INFO] New signature file: apt_eqgrp.yar                                               
[INFO] New signature file: apt_eqgrp_apr17.yar                                         
[INFO] New signature file: apt_eternalblue_non_wannacry.yar                            
[INFO] New signature file: apt_exile_rat.yar                                           
[INFO] New signature file: apt_f5_bigip_expl_payloads.yar                              
[INFO] New signature file: apt_fakem_backdoor.yar                                      
[INFO] New signature file: apt_fancybear_computrace_agent.yar                          
[INFO] New signature file: apt_fancybear_dnc.yar                                       
[INFO] New signature file: apt_fancybear_osxagent.yar                                  
[INFO] New signature file: apt_fidelis_phishing_plain_sight.yar                        
[INFO] New signature file: apt_fin7.yar                                                
[INFO] New signature file: apt_fin7_backdoor.yar                                       
[INFO] New signature file: apt_fin8.yar                                                
[INFO] New signature file: apt_flame2_orchestrator.yar                                 
[INFO] New signature file: apt_foudre.yar                                              
[INFO] New signature file: apt_four_element_sword.yar                                  
[INFO] New signature file: apt_freemilk.yar                                            
[INFO] New signature file: apt_fujinama_rat.yar                                        
[INFO] New signature file: apt_furtim.yar                                              
[INFO] New signature file: apt_fvey_shadowbroker_dec16.yar                             
[INFO] New signature file: apt_fvey_shadowbroker_jan17.yar                             
[INFO] New signature file: apt_ghostdragon_gh0st_rat.yar                               
[INFO] New signature file: apt_glassRAT.yar                                            
[INFO] New signature file: apt_golddragon.yar                                          
[INFO] New signature file: apt_goldenspy.yar                                           
[INFO] New signature file: apt_greenbug.yar                                            
[INFO] New signature file: apt_greyenergy.yar                                          
[INFO] New signature file: apt_grizzlybear_uscert.yar                                  
[INFO] New signature file: apt_hackingteam_rules.yar                                   
[INFO] New signature file: apt_hafnium.yar                                             
[INFO] New signature file: apt_hafnium_log_sigs.yar                                    
[INFO] New signature file: apt_ham_tofu_chches.yar                                     
[INFO] New signature file: apt_hatman.yar                                              
[INFO] New signature file: apt_hellsing_kaspersky.yar                                  
[INFO] New signature file: apt_hidden_cobra.yar                                        
[INFO] New signature file: apt_hiddencobra_bankshot.yar                                
[INFO] New signature file: apt_hiddencobra_wiper.yar                                   
[INFO] New signature file: apt_hizor_rat.yar                                           
[INFO] New signature file: apt_hkdoor.yar                                              
[INFO] New signature file: apt_iamtheking.yar                                          
[INFO] New signature file: apt_icefog.yar                                              
[INFO] New signature file: apt_indetectables_rat.yar                                   
[INFO] New signature file: apt_industroyer.yar                                         
[INFO] New signature file: apt_inocnation.yar                                          
[INFO] New signature file: apt_irongate.yar                                            
[INFO] New signature file: apt_irontiger.yar                                           
[INFO] New signature file: apt_irontiger_trendmicro.yar                                
[INFO] New signature file: apt_ism_rat.yar                                             
[INFO] New signature file: apt_kaspersky_duqu2.yar                                     
[INFO] New signature file: apt_ke3chang.yar                                            
[INFO] New signature file: apt_keyboys.yar                                             
[INFO] New signature file: apt_keylogger_cn.yar                                        
[INFO] New signature file: apt_khrat.yar                                               
[INFO] New signature file: apt_korplug_fast.yar                                        
[INFO] New signature file: apt_kwampirs.yar                                            
[INFO] New signature file: apt_laudanum_webshells.yar                                  
[INFO] New signature file: apt_lazarus_applejeus.yar                                   
[INFO] New signature file: apt_lazarus_aug20.yar                                       
[INFO] New signature file: apt_lazarus_dec17.yar                                       
[INFO] New signature file: apt_lazarus_dec20.yar                                       
[INFO] New signature file: apt_lazarus_jan21.yar                                       
[INFO] New signature file: apt_lazarus_jun18.yar                                       
[INFO] New signature file: apt_lazarus_vhd_ransomware.yar                              
[INFO] New signature file: apt_leviathan.yar                                           
[INFO] New signature file: apt_lnx_kobalos.yar                                         
[INFO] New signature file: apt_lnx_linadoor_rootkit.yar                                
[INFO] New signature file: apt_lotusblossom_elise.yar                                  
[INFO] New signature file: apt_magichound.yar                                          
[INFO] New signature file: apt_mal_ilo_board_elf.yar                                   
[INFO] New signature file: apt_microcin.yar                                            
[INFO] New signature file: apt_middle_east_talosreport.yar                             
[INFO] New signature file: apt_miniasp.yar                                             
[INFO] New signature file: apt_minidionis.yar                                          
[INFO] New signature file: apt_mofang.yar                                              
[INFO] New signature file: apt_molerats_jul17.yar                                      
[INFO] New signature file: apt_monsoon.yar                                             
[INFO] New signature file: apt_moonlightmaze.yar                                       
[INFO] New signature file: apt_ms_platinum.yara                                        
[INFO] New signature file: apt_muddywater.yar                                          
[INFO] New signature file: apt_naikon.yar                                              
[INFO] New signature file: apt_nanocore_rat.yar                                        
[INFO] New signature file: apt_nazar.yar                                               
[INFO] New signature file: apt_ncsc_report_04_2018.yar                                 
[INFO] New signature file: apt_netwire_rat.yar                                         
[INFO] New signature file: apt_nk_gen.yar                                              
[INFO] New signature file: apt_nk_goldbackdoor.yar                                     
[INFO] New signature file: apt_nk_inkysquid.yar                                        
[INFO] New signature file: apt_oilrig.yar                                              
[INFO] New signature file: apt_oilrig_chafer_mar18.yar                                 
[INFO] New signature file: apt_oilrig_oct17.yar                                        
[INFO] New signature file: apt_oilrig_rgdoor.yar                                       
[INFO] New signature file: apt_olympic_destroyer.yar                                   
[INFO] New signature file: apt_onhat_proxy.yar                                         
[INFO] New signature file: apt_op_cleaver.yar                                          
[INFO] New signature file: apt_op_cloudhopper.yar                                      
[INFO] New signature file: apt_op_honeybee.yar                                         
[INFO] New signature file: apt_op_shadowhammer.yar                                     
[INFO] New signature file: apt_op_wocao.yar                                            
[INFO] New signature file: apt_passcv.yar                                              
[INFO] New signature file: apt_passthehashtoolkit.yar                                  
[INFO] New signature file: apt_patchwork.yar                                           
[INFO] New signature file: apt_plead_downloader.yar                                    
[INFO] New signature file: apt_plugx.yar                                               
[INFO] New signature file: apt_poisonivy.yar                                           
[INFO] New signature file: apt_poisonivy_gen3.yar                                      
[INFO] New signature file: apt_poseidon_group.yar                                      
[INFO] New signature file: apt_poshspy.yar                                             
[INFO] New signature file: apt_prikormka.yar                                           
[INFO] New signature file: apt_project_m.yar                                           
[INFO] New signature file: apt_project_sauron.yara                                     
[INFO] New signature file: apt_project_sauron_extras.yar                               
[INFO] New signature file: apt_promethium_neodymium.yar                                
[INFO] New signature file: apt_pulsesecure.yar                                         
[INFO] New signature file: apt_putterpanda.yar                                         
[INFO] New signature file: apt_quarkspwdump.yar                                        
[INFO] New signature file: apt_quasar_rat.yar                                          
[INFO] New signature file: apt_quasar_vermin.yar                                       
[INFO] New signature file: apt_rancor.yar                                              
[INFO] New signature file: apt_reaver_sunorcal.yar                                     
[INFO] New signature file: apt_rehashed_rat.yar                                        
[INFO] New signature file: apt_revenge_rat.yar                                         
[INFO] New signature file: apt_rocketkitten_keylogger.yar                              
[INFO] New signature file: apt_rokrat.yar                                              
[INFO] New signature file: apt_royalroad.yar                                           
[INFO] New signature file: apt_ruag.yar                                                
[INFO] New signature file: apt_rwmc_powershell_creddump.yar                            
[INFO] New signature file: apt_sakula.yar                                              
[INFO] New signature file: apt_sandworm_centreon.yar                                   
[INFO] New signature file: apt_sandworm_cyclops_blink.yar                              
[INFO] New signature file: apt_sandworm_exim_expl.yar                                  
[INFO] New signature file: apt_saudi_aramco_phish.yar                                  
[INFO] New signature file: apt_scanbox_deeppanda.yar                                   
[INFO] New signature file: apt_scarcruft.yar                                           
[INFO] New signature file: apt_seaduke_unit42.yar                                      
[INFO] New signature file: apt_sednit_delphidownloader.yar                             
[INFO] New signature file: apt_servantshell.yar                                        
[INFO] New signature file: apt_shadowpad.yar                                           
[INFO] New signature file: apt_shamoon.yar                                             
[INFO] New signature file: apt_shamoon2.yar                                            
[INFO] New signature file: apt_sharptongue.yar                                         
[INFO] New signature file: apt_shellcrew_streamex.yar                                  
[INFO] New signature file: apt_sidewinder.yar                                          
[INFO] New signature file: apt_silence.yar                                             
[INFO] New signature file: apt_skeletonkey.yar                                         
[INFO] New signature file: apt_slingshot.yar                                           
[INFO] New signature file: apt_snaketurla_osx.yar                                      
[INFO] New signature file: apt_snowglobe_babar.yar                                     
[INFO] New signature file: apt_sofacy.yar                                              
[INFO] New signature file: apt_sofacy_cannon.yar                                       
[INFO] New signature file: apt_sofacy_dec15.yar                                        
[INFO] New signature file: apt_sofacy_fysbis.yar                                       
[INFO] New signature file: apt_sofacy_hospitality.yar                                  
[INFO] New signature file: apt_sofacy_jun16.yar                                        
[INFO] New signature file: apt_sofacy_oct17_camp.yar                                   
[INFO] New signature file: apt_sofacy_xtunnel_bundestag.yar                            
[INFO] New signature file: apt_sofacy_zebrocy.yar                                      
[INFO] New signature file: apt_solarwinds_sunburst.yar                                 
[INFO] New signature file: apt_solarwinds_susp_sunburst.yar                            
[INFO] New signature file: apt_sphinx_moth.yar                                         
[INFO] New signature file: apt_stealer_cisa_ar22_277a.yar                              
[INFO] New signature file: apt_stonedrill.yar                                          
[INFO] New signature file: apt_strider.yara                                            
[INFO] New signature file: apt_stuxnet.yar                                             
[INFO] New signature file: apt_stuxshop.yar                                            
[INFO] New signature file: apt_suckfly.yar                                             
[INFO] New signature file: apt_sunspot.yar                                             
[INFO] New signature file: apt_sysscan.yar                                             
[INFO] New signature file: apt_ta17_293A.yar                                           
[INFO] New signature file: apt_ta17_318A.yar                                           
[INFO] New signature file: apt_ta17_318B.yar                                           
[INFO] New signature file: apt_ta18_074A.yar                                           
[INFO] New signature file: apt_ta18_149A.yar                                           
[INFO] New signature file: apt_ta459.yar                                               
[INFO] New signature file: apt_telebots.yar                                            
[INFO] New signature file: apt_terracotta.yar                                          
[INFO] New signature file: apt_terracotta_liudoor.yar                                  
[INFO] New signature file: apt_tetris.yar                                              
[INFO] New signature file: apt_threatgroup_3390.yar                                    
[INFO] New signature file: apt_thrip.yar                                               
[INFO] New signature file: apt_tick_datper.yar                                         
[INFO] New signature file: apt_tick_weaponized_usb.yar                                 
[INFO] New signature file: apt_tidepool.yar                                            
[INFO] New signature file: apt_tophat.yar                                              
[INFO] New signature file: apt_triton.yar                                              
[INFO] New signature file: apt_triton_mal_sshdoor.yar                                  
[INFO] New signature file: apt_turbo_campaign.yar                                      
[INFO] New signature file: apt_turla.yar                                               
[INFO] New signature file: apt_turla_gazer.yar                                         
[INFO] New signature file: apt_turla_kazuar.yar                                        
[INFO] New signature file: apt_turla_mosquito.yar                                      
[INFO] New signature file: apt_turla_neuron.yar                                        
[INFO] New signature file: apt_turla_penquin.yar                                       
[INFO] New signature file: apt_turla_png_dropper_nov18.yar                             
[INFO] New signature file: apt_ua_caddywiper.yar                                       
[INFO] New signature file: apt_ua_hermetic_wiper.yar                                   
[INFO] New signature file: apt_ua_isaacwiper.yar                                       
[INFO] New signature file: apt_ua_wiper_whispergate.yar                                
[INFO] New signature file: apt_uboat_rat.yar                                           
[INFO] New signature file: apt_unc1151_ua.yar                                          
[INFO] New signature file: apt_unc2447_sombrat.yar                                     
[INFO] New signature file: apt_unc2546_dewmode.yar                                     
[INFO] New signature file: apt_unc3886_virtualpita.yar                                 
[INFO] New signature file: apt_unit78020_malware.yar                                   
[INFO] New signature file: apt_uscert_ta17-1117a.yar                                   
[INFO] New signature file: apt_venom_linux_rootkit.yar                                 
[INFO] New signature file: apt_volatile_cedar.yar                                      
[INFO] New signature file: apt_vpnfilter.yar                                           
[INFO] New signature file: apt_waterbear.yar                                           
[INFO] New signature file: apt_waterbug.yar                                            
[INFO] New signature file: apt_webmonitor_rat.yar                                      
[INFO] New signature file: apt_webshell_chinachopper.yar                               
[INFO] New signature file: apt_wildneutron.yar                                         
[INFO] New signature file: apt_wilted_tulip.yar                                        
[INFO] New signature file: apt_win_plugx.yar                                           
[INFO] New signature file: apt_winnti.yar                                              
[INFO] New signature file: apt_winnti_br.yar                                           
[INFO] New signature file: apt_winnti_burning_umbrella.yar                             
[INFO] New signature file: apt_winnti_hdroot.yar                                       
[INFO] New signature file: apt_winnti_linux.yar                                        
[INFO] New signature file: apt_winnti_ms_report_201701.yar                             
[INFO] New signature file: apt_woolengoldfish.yar                                      
[INFO] New signature file: apt_xrat.yar                                                
[INFO] New signature file: apt_zxshell.yar                                             
[INFO] New signature file: cn_pentestset_scripts.yar                                   
[INFO] New signature file: cn_pentestset_tools.yar                                     
[INFO] New signature file: cn_pentestset_webshells.yar                                 
[INFO] New signature file: crime_academic_data_centers_camp_may20.yar                  
[INFO] New signature file: crime_andromeda_jun17.yar                                   
[INFO] New signature file: crime_antifw_installrex.yar                                 
[INFO] New signature file: crime_atm_dispenserxfs.yar                                  
[INFO] New signature file: crime_atm_javadipcash.yar                                   
[INFO] New signature file: crime_atm_loup.yar                                          
[INFO] New signature file: crime_atm_xfsadm.yar                                        
[INFO] New signature file: crime_atm_xfscashncr.yar                                    
[INFO] New signature file: crime_bad_patch.yar                                         
[INFO] New signature file: crime_badrabbit.yar                                         
[INFO] New signature file: crime_bazarbackdoor.yar                                     
[INFO] New signature file: crime_bernhard_pos.yar                                      
[INFO] New signature file: crime_bluenoroff_pos.yar                                    
[INFO] New signature file: crime_buzus_softpulse.yar                                   
[INFO] New signature file: crime_cmstar.yar                                            
[INFO] New signature file: crime_cn_campaign_njrat.yar                                 
[INFO] New signature file: crime_cn_group_btc.yar                                      
[INFO] New signature file: crime_cobalt_gang_pdf.yar                                   
[INFO] New signature file: crime_cobaltgang.yar                                        
[INFO] New signature file: crime_corkow_dll.yar                                        
[INFO] New signature file: crime_covid_ransom.yar                                      
[INFO] New signature file: crime_credstealer_generic.yar                               
[INFO] New signature file: crime_crypto_miner.yar                                      
[INFO] New signature file: crime_cryptowall_svg.yar                                    
[INFO] New signature file: crime_dearcry_ransom.yar                                    
[INFO] New signature file: crime_dexter_trojan.yar                                     
[INFO] New signature file: crime_dridex_xml.yar                                        
[INFO] New signature file: crime_emotet.yar                                            
[INFO] New signature file: crime_enfal.yar                                             
[INFO] New signature file: crime_envrial.yar                                           
[INFO] New signature file: crime_eternalrocks.yar                                      
[INFO] New signature file: crime_evilcorp_dridex_banker.yar                            
[INFO] New signature file: crime_fareit.yar                                            
[INFO] New signature file: crime_fireball.yar                                          
[INFO] New signature file: crime_floxif_flystudio.yar                                  
[INFO] New signature file: crime_gamaredon.yar                                         
[INFO] New signature file: crime_goldeneye.yar                                         
[INFO] New signature file: crime_gozi_crypter.yar                                      
[INFO] New signature file: crime_guloader.yar                                          
[INFO] New signature file: crime_h2miner_kinsing.yar                                   
[INFO] New signature file: crime_hermes_ransom.yar                                     
[INFO] New signature file: crime_icedid.yar                                            
[INFO] New signature file: crime_kasper_oct17.yar                                      
[INFO] New signature file: crime_kins_dropper.yar                                      
[INFO] New signature file: crime_kr_malware.yar                                        
[INFO] New signature file: crime_kraken_bot1.yar                                       
[INFO] New signature file: crime_kriskynote.yar                                        
[INFO] New signature file: crime_locky.yar                                             
[INFO] New signature file: crime_loki_bot.yar                                          
[INFO] New signature file: crime_mal_grandcrab.yar                                     
[INFO] New signature file: crime_mal_nitol.yar                                         
[INFO] New signature file: crime_mal_ransom_wadharma.yar                               
[INFO] New signature file: crime_malumpos.yar                                          
[INFO] New signature file: crime_malware_generic.yar                                   
[INFO] New signature file: crime_malware_set_oct16.yar                                 
[INFO] New signature file: crime_maze_ransomware.yar                                   
[INFO] New signature file: crime_mikey_trojan.yar                                      
[INFO] New signature file: crime_mirai.yar                                             
[INFO] New signature file: crime_mywscript_dropper.yar                                 
[INFO] New signature file: crime_nansh0u.yar                                           
[INFO] New signature file: crime_nkminer.yar                                           
[INFO] New signature file: crime_nopetya_jun17.yar                                     
[INFO] New signature file: crime_ole_loadswf_cve_2018_4878.yar                         
[INFO] New signature file: crime_parallax_rat.yar                                      
[INFO] New signature file: crime_phish_gina_dec15.yar                                  
[INFO] New signature file: crime_ransom_conti.yar                                      
[INFO] New signature file: crime_ransom_darkside.yar                                   
[INFO] New signature file: crime_ransom_generic.yar                                    
[INFO] New signature file: crime_ransom_germanwiper.yar                                
[INFO] New signature file: crime_ransom_lockergoga.yar                                 
[INFO] New signature file: crime_ransom_prolock.yar                                    
[INFO] New signature file: crime_ransom_ragna_locker.yar                               
[INFO] New signature file: crime_ransom_revil.yar                                      
[INFO] New signature file: crime_ransom_robinhood.yar                                  
[INFO] New signature file: crime_ransom_stealbit_lockbit.yar                           
[INFO] New signature file: crime_ransom_venus.yar                                      
[INFO] New signature file: crime_rat_parallax.yar                                      
[INFO] New signature file: crime_revil_general.yar                                     
[INFO] New signature file: crime_rombertik_carbongrabber.yar                           
[INFO] New signature file: crime_ryuk_ransomware.yar                                   
[INFO] New signature file: crime_shifu_trojan.yar                                      
[INFO] New signature file: crime_snarasite.yar                                         
[INFO] New signature file: crime_socgholish.yar                                        
[INFO] New signature file: crime_stealer_exfil_zip.yar                                 
[INFO] New signature file: crime_teledoor.yar                                          
[INFO] New signature file: crime_trickbot.yar                                          
[INFO] New signature file: crime_upatre_oct15.yar                                      
[INFO] New signature file: crime_wannacry.yar                                          
[INFO] New signature file: crime_wsh_rat.yar                                           
[INFO] New signature file: crime_xbash.yar                                             
[INFO] New signature file: crime_zeus_panda.yar                                        
[INFO] New signature file: crime_zloader_maldocs.yar                                   
[INFO] New signature file: expl_adselfservice_cve_2021_40539.yar                       
[INFO] New signature file: expl_cve_2021_1647.yar                                      
[INFO] New signature file: expl_cve_2021_26084_confluence_log.yar                      
[INFO] New signature file: expl_cve_2021_40444.yar                                     
[INFO] New signature file: expl_cve_2022_41040_proxynoshell.yar                        
[INFO] New signature file: expl_log4j_cve_2021_44228.yar                               
[INFO] New signature file: expl_proxyshell.yar                                         
[INFO] New signature file: expl_spring4shell.yar                                       
[INFO] New signature file: exploit_cve_2014_4076.yar                                   
[INFO] New signature file: exploit_cve_2015_1674.yar                                   
[INFO] New signature file: exploit_cve_2015_1701.yar                                   
[INFO] New signature file: exploit_cve_2015_2426.yar                                   
[INFO] New signature file: exploit_cve_2015_2545.yar                                   
[INFO] New signature file: exploit_cve_2015_5119.yar                                   
[INFO] New signature file: exploit_cve_2017_11882.yar                                  
[INFO] New signature file: exploit_cve_2017_8759.yar                                   
[INFO] New signature file: exploit_cve_2017_9800.yar                                   
[INFO] New signature file: exploit_cve_2018_0802.yar                                   
[INFO] New signature file: exploit_cve_2018_16858.yar                                  
[INFO] New signature file: exploit_cve_2021_31166.yar                                  
[INFO] New signature file: exploit_cve_2021_33766_proxytoken.yar                       
[INFO] New signature file: exploit_cve_2022_22954_vmware_workspace_one.yar             
[INFO] New signature file: exploit_f5_bigip_cve_2021_22986_log.yar                     
[INFO] New signature file: exploit_gitlab_cve_2021_22205.yar                           
[INFO] New signature file: exploit_rtf_ole2link.yar                                    
[INFO] New signature file: exploit_shitrix.yar                                         
[INFO] New signature file: exploit_tlb_scripts.yar                                     
[INFO] New signature file: exploit_uac_elevators.yar                                   
[INFO] New signature file: gen_Excel4Macro_Sharpshooter.yar                            
[INFO] New signature file: gen_ace_with_exe.yar                                        
[INFO] New signature file: gen_anomalies_keyword_combos.yar                            
[INFO] New signature file: gen_armitage.yar                                            
[INFO] New signature file: gen_autocad_lsp_malware.yar                                 
[INFO] New signature file: gen_b374k_extra.yar                                         
[INFO] New signature file: gen_bad_pdf.yar                                             
[INFO] New signature file: gen_case_anomalies.yar                                      
[INFO] New signature file: gen_cert_payloads.yar                                       
[INFO] New signature file: gen_chaos_payload.yar                                       
[INFO] New signature file: gen_cmd_script_obfuscated.yar                               
[INFO] New signature file: gen_cn_hacktool_scripts.yar                                 
[INFO] New signature file: gen_cn_hacktools.yar                                        
[INFO] New signature file: gen_cn_webshells.yar                                        
[INFO] New signature file: gen_cobaltstrike.yar                                        
[INFO] New signature file: gen_cobaltstrike_by_avast.yar                               
[INFO] New signature file: gen_crime_bitpaymer.yar                                     
[INFO] New signature file: gen_crimson_rat.yar                                         
[INFO] New signature file: gen_crunchrat.yar                                           
[INFO] New signature file: gen_dde_in_office_docs.yar                                  
[INFO] New signature file: gen_deviceguard_evasion.yar                                 
[INFO] New signature file: gen_doc_follina.yar                                         
[INFO] New signature file: gen_dropper_pdb.yar                                         
[INFO] New signature file: gen_elf_file_anomalies.yar                                  
[INFO] New signature file: gen_empire.yar                                              
[INFO] New signature file: gen_enigma_protector.yar                                    
[INFO] New signature file: gen_event_mute_hook.yar                                     
[INFO] New signature file: gen_excel_auto_open_evasion.yar                             
[INFO] New signature file: gen_excel_xll_addin_suspicious.yar                          
[INFO] New signature file: gen_excel_xor_obfuscation_velvetsweatshop.yar               
[INFO] New signature file: gen_exploit_cve_2017_10271_weblogic.yar                     
[INFO] New signature file: gen_faked_versions.yar                                      
[INFO] New signature file: gen_file_anomalies.yar                                      
[INFO] New signature file: gen_fireeye_redteam_tools.yar                               
[INFO] New signature file: gen_floxif.yar                                              
[INFO] New signature file: gen_frp_proxy.yar                                           
[INFO] New signature file: gen_gcti_cobaltstrike.yar                                   
[INFO] New signature file: gen_gcti_sliver.yar                                         
[INFO] New signature file: gen_gen_cactustorch.yar                                     
[INFO] New signature file: gen_github_net_redteam_tools_guids.yar                      
[INFO] New signature file: gen_github_net_redteam_tools_names.yar                      
[INFO] New signature file: gen_github_repo_compromise_myjino_ru.yar                    
[INFO] New signature file: gen_gobfuscate.yar                                          
[INFO] New signature file: gen_google_anomaly.yar                                      
[INFO] New signature file: gen_gpp_cpassword.yar                                       
[INFO] New signature file: gen_hawkeye.yar                                             
[INFO] New signature file: gen_hktl_koh_tokenstealer.yar                               
[INFO] New signature file: gen_hktl_roothelper.yar                                     
[INFO] New signature file: gen_hta_anomalies.yar                                       
[INFO] New signature file: gen_hunting_susp_rar.yar                                    
[INFO] New signature file: gen_icon_anomalies.yar                                      
[INFO] New signature file: gen_impacket_tools.yar                                      
[INFO] New signature file: gen_invoke_mimikatz.yar                                     
[INFO] New signature file: gen_invoke_psimage.yar                                      
[INFO] New signature file: gen_invoke_thehash.yar                                      
[INFO] New signature file: gen_javascript_powershell.yar                               
[INFO] New signature file: gen_kerberoast.yar                                          
[INFO] New signature file: gen_khepri.yar                                              
[INFO] New signature file: gen_kirbi_mimkatz.yar                                       
[INFO] New signature file: gen_lnx_malware_indicators.yar                              
[INFO] New signature file: gen_loaders.yar                                             
[INFO] New signature file: gen_macro_ShellExecute_action.yar                           
[INFO] New signature file: gen_macro_builders.yar                                      
[INFO] New signature file: gen_macro_staroffice_suspicious.yar                         
[INFO] New signature file: gen_mal_backnet.yar                                         
[INFO] New signature file: gen_mal_link.yar                                            
[INFO] New signature file: gen_mal_scripts.yar                                         
[INFO] New signature file: gen_maldoc.yar                                              
[INFO] New signature file: gen_malware_MacOS_plist_suspicious.yar                      
[INFO] New signature file: gen_malware_set_qa.yar                                      
[INFO] New signature file: gen_merlin_agent.yar                                        
[INFO] New signature file: gen_metasploit_loader_rsmudge.yar                           
[INFO] New signature file: gen_metasploit_payloads.yar                                 
[INFO] New signature file: gen_mimikatz.yar                                            
[INFO] New signature file: gen_mimikittenz.yar                                         
[INFO] New signature file: gen_mimipenguin.yar                                         
[INFO] New signature file: gen_nighthawk_c2.yar                                        
[INFO] New signature file: gen_nimpackt.yar                                            
[INFO] New signature file: gen_nopowershell.yar                                        
[INFO] New signature file: gen_nvidia_leaked_cert.yar                                  
[INFO] New signature file: gen_osx_backdoor_bella.yar                                  
[INFO] New signature file: gen_osx_evilosx.yar                                         
[INFO] New signature file: gen_osx_pyagent_persistence.yar                             
[INFO] New signature file: gen_p0wnshell.yar                                           
[INFO] New signature file: gen_phish_attachments.yar                                   
[INFO] New signature file: gen_pirpi.yar                                               
[INFO] New signature file: gen_powerkatz.yar                                           
[INFO] New signature file: gen_powershdll.yar                                          
[INFO] New signature file: gen_powershell_empire.yar                                   
[INFO] New signature file: gen_powershell_invocation.yar                               
[INFO] New signature file: gen_powershell_obfuscation.yar                              
[INFO] New signature file: gen_powershell_suite.yar                                    
[INFO] New signature file: gen_powershell_susp.yar                                     
[INFO] New signature file: gen_powershell_toolkit.yar                                  
[INFO] New signature file: gen_powersploit_dropper.yar                                 
[INFO] New signature file: gen_ps1_shellcode.yar                                       
[INFO] New signature file: gen_ps_empire_eval.yar                                      
[INFO] New signature file: gen_ps_osiris.yar                                           
[INFO] New signature file: gen_pua.yar                                                 
[INFO] New signature file: gen_pupy_rat.yar                                            
[INFO] New signature file: gen_python_encoded_adware.yar                               
[INFO] New signature file: gen_python_pty_shell.yar                                    
[INFO] New signature file: gen_python_pyminifier_encoded_payload.yar                   
[INFO] New signature file: gen_python_reverse_shell.yara                               
[INFO] New signature file: gen_rar_exfil.yar                                           
[INFO] New signature file: gen_rats_malwareconfig.yar                                  
[INFO] New signature file: gen_recon_indicators.yar                                    
[INFO] New signature file: gen_redmimicry.yar                                          
[INFO] New signature file: gen_redsails.yar                                            
[INFO] New signature file: gen_regsrv32_issue.yar                                      
[INFO] New signature file: gen_remote_potato0.yar                                      
[INFO] New signature file: gen_rottenpotato.yar                                        
[INFO] New signature file: gen_rtf_malver_objects.yar                                  
[INFO] New signature file: gen_sfx_with_microsoft_copyright.yar                        
[INFO] New signature file: gen_sharpcat.yar                                            
[INFO] New signature file: gen_shikataganai.yar                                        
[INFO] New signature file: gen_sign_anomalies.yar                                      
[INFO] New signature file: gen_solarwinds_credential_stealer.yar                       
[INFO] New signature file: gen_susp_bat2exe.yar                                        
[INFO] New signature file: gen_susp_bat_aux.yar                                        
[INFO] New signature file: gen_susp_cmd_var_expansion.yar                              
[INFO] New signature file: gen_susp_hacktool.yar                                       
[INFO] New signature file: gen_susp_js_obfuscatorio.yar                                
[INFO] New signature file: gen_susp_lnk.yar                                            
[INFO] New signature file: gen_susp_lnk_files.yar                                      
[INFO] New signature file: gen_susp_obfuscation.yar                                    
[INFO] New signature file: gen_susp_office_dropper.yar                                 
[INFO] New signature file: gen_susp_ps_jab.yar                                         
[INFO] New signature file: gen_susp_sfx.yar                                            
[INFO] New signature file: gen_susp_strings_in_ole.yar                                 
[INFO] New signature file: gen_susp_wer_files.yar                                      
[INFO] New signature file: gen_susp_xor.yar                                            
[INFO] New signature file: gen_suspicious_InPage_dropper.yar                           
[INFO] New signature file: gen_suspicious_strings.yar                                  
[INFO] New signature file: gen_sysinternals_anomaly.yar                                
[INFO] New signature file: gen_tempracer.yar                                           
[INFO] New signature file: gen_thumbs_cloaking.yar                                     
[INFO] New signature file: gen_transformed_strings.yar                                 
[INFO] New signature file: gen_tscookie_rat.yar                                        
[INFO] New signature file: gen_unicorn_obfuscated_powershell.yar                       
[INFO] New signature file: gen_unspecified_malware.yar                                 
[INFO] New signature file: gen_url_persitence.yar                                      
[INFO] New signature file: gen_url_to_local_exe.yar                                    
[INFO] New signature file: gen_vhd_anomaly.yar                                         
[INFO] New signature file: gen_webshells.yar                                           
[INFO] New signature file: gen_webshells_ext_vars.yar                                  
[INFO] New signature file: gen_win_privesc.yar                                         
[INFO] New signature file: gen_winpayloads.yar                                         
[INFO] New signature file: gen_winshells.yar                                           
[INFO] New signature file: gen_wmi_implant.yar                                         
[INFO] New signature file: gen_xor_hunting.yar                                         
[INFO] New signature file: gen_xored_pe.yar                                            
[INFO] New signature file: gen_xtreme_rat.yar                                          
[INFO] New signature file: gen_ysoserial_payloads.yar                                  
[INFO] New signature file: gen_zoho_rcef_logs.yar                                      
[INFO] New signature file: general_cloaking.yar                                        
[INFO] New signature file: general_officemacros.yar                                    
[INFO] New signature file: generic_anomalies.yar                                       
[INFO] New signature file: generic_cryptors.yar                                        
[INFO] New signature file: generic_dumps.yar                                           
[INFO] New signature file: generic_exe2hex_payload.yar                                 
[INFO] New signature file: hktl_bruteratel_c4.yar                                      
[INFO] New signature file: hktl_bruteratel_c4_badger.yar                               
[INFO] New signature file: mal_avemaria_rat.yar                                        
[INFO] New signature file: mal_codecov_hack.yar                                        
[INFO] New signature file: mal_crime_unknown.yar                                       
[INFO] New signature file: mal_cryp_rat.yar                                            
[INFO] New signature file: mal_lnx_implant_may22.yar                                   
[INFO] New signature file: mal_netsha.yar                                              
[INFO] New signature file: mal_passwordstate_backdoor.yar                              
[INFO] New signature file: mal_qbot_payloads.yar                                       
[INFO] New signature file: mal_ransom_lorenz.yar                                       
[INFO] New signature file: pua_cryptocoin_miner.yar                                    
[INFO] New signature file: pua_xmrig_monero_miner.yar                                  
[INFO] New signature file: pup_lightftp.yar                                            
[INFO] New signature file: spy_equation_fiveeyes.yar                                   
[INFO] New signature file: spy_querty_fiveeyes.yar                                     
[INFO] New signature file: spy_regin_fiveeyes.yar                                      
[INFO] New signature file: thor-hacktools.yar                                          
[INFO] New signature file: thor-webshells.yar                                          
[INFO] New signature file: thor_inverse_matches.yar                                    
[INFO] New signature file: threat_lenovo_superfish.yar                                 
[INFO] New signature file: vul_backdoor_antitheftweb.yar                               
[INFO] New signature file: vul_confluence_questions_plugin_cve_2022_26138.yar          
[INFO] New signature file: vul_cve_2020_0688.yar                                       
[INFO] New signature file: vul_cve_2020_1938.yar                                       
[INFO] New signature file: vul_cve_2021_3438_printdriver.yar                           
[INFO] New signature file: vul_cve_2021_386471_omi.yar                                 
[INFO] New signature file: vul_dell_bios_upd_driver.yar                                
[INFO] New signature file: vul_drivecrypt.yar                                          
[INFO] New signature file: vul_jquery_fileupload_cve_2018_9206.yar                     
[INFO] New signature file: vul_php_zlib_backdoor.yar                                   
[INFO] New signature file: vuln_gigabyte_driver.yar                                    
[INFO] New signature file: vuln_proxynotshell_cve_2022_41040.yar                       
[INFO] New signature file: webshell_regeorg.yar                                        
[INFO] New signature file: webshell_xsl_transform.yar                                  
[INFO] New signature file: yara_mixed_ext_vars.yar                                     
[INFO] Downloading https://github.com/reversinglabs/reversinglabs-yara-rules/archive/develop.zip ...                                                                          
[INFO] New signature file: blocklist.yara                                              
[INFO] New signature file: Win32.Downloader.dlMarlboro.yara                            
[INFO] New signature file: Win32.Exploit.CVE20200601.yara                              
[INFO] New signature file: Win32.Infostealer.MultigrainPOS.yara                        
[INFO] New signature file: Win32.Infostealer.ProjectHookPOS.yara                       
[INFO] New signature file: Win32.PUA.Domaiq.yara                                       
[INFO] New signature file: ByteCode.MSIL.Ransomware.Apis.yara                          
[INFO] New signature file: ByteCode.MSIL.Ransomware.ChupaCabra.yara                    
[INFO] New signature file: ByteCode.MSIL.Ransomware.Cring.yara                         
[INFO] New signature file: ByteCode.MSIL.Ransomware.Dusk.yara                          
[INFO] New signature file: ByteCode.MSIL.Ransomware.EAF.yara                           
[INFO] New signature file: ByteCode.MSIL.Ransomware.Eternity.yara                      
[INFO] New signature file: ByteCode.MSIL.Ransomware.Fantom.yara                        
[INFO] New signature file: ByteCode.MSIL.Ransomware.GhosTEncryptor.yara                
[INFO] New signature file: ByteCode.MSIL.Ransomware.Ghostbin.yara                      
[INFO] New signature file: ByteCode.MSIL.Ransomware.GoodWill.yara                      
[INFO] New signature file: ByteCode.MSIL.Ransomware.HarpoonLocker.yara                 
[INFO] New signature file: ByteCode.MSIL.Ransomware.Hog.yara                           
[INFO] New signature file: ByteCode.MSIL.Ransomware.Invert.yara                        
[INFO] New signature file: ByteCode.MSIL.Ransomware.Janelle.yara                       
[INFO] New signature file: ByteCode.MSIL.Ransomware.Khonsari.yara                      
[INFO] New signature file: ByteCode.MSIL.Ransomware.McBurglar.yara                     
[INFO] New signature file: ByteCode.MSIL.Ransomware.Moisha.yara                        
[INFO] New signature file: ByteCode.MSIL.Ransomware.Namaste.yara                       
[INFO] New signature file: ByteCode.MSIL.Ransomware.Oct.yara                           
[INFO] New signature file: ByteCode.MSIL.Ransomware.Pacman.yara                        
[INFO] New signature file: ByteCode.MSIL.Ransomware.PoliceRecords.yara                 
[INFO] New signature file: ByteCode.MSIL.Ransomware.Povlsomware.yara                   
[INFO] New signature file: ByteCode.MSIL.Ransomware.Retis.yara                         
[INFO] New signature file: ByteCode.MSIL.Ransomware.TaRRaK.yara                        
[INFO] New signature file: ByteCode.MSIL.Ransomware.Thanos.yara                        
[INFO] New signature file: ByteCode.MSIL.Ransomware.TimeCrypt.yara                     
[INFO] New signature file: ByteCode.MSIL.Ransomware.TimeTime.yara                      
[INFO] New signature file: ByteCode.MSIL.Ransomware.Venom.yara                         
[INFO] New signature file: ByteCode.MSIL.Ransomware.WildFire.yara                      
[INFO] New signature file: ByteCode.MSIL.Ransomware.WormLocker.yara                    
[INFO] New signature file: ByteCode.MSIL.Ransomware.ZeroLocker.yara                    
[INFO] New signature file: Bytecode.MSIL.Ransomware.CobraLocker.yara                   
[INFO] New signature file: Linux.Ransomware.GwisinLocker.yara                          
[INFO] New signature file: Linux.Ransomware.KillDisk.yara                              
[INFO] New signature file: Linux.Ransomware.LuckyJoe.yara                              
[INFO] New signature file: Linux.Ransomware.RedAlert.yara                              
[INFO] New signature file: Win32.Ransomware.5ss5c.yara                                 
[INFO] New signature file: Win32.Ransomware.ASN1Encoder.yara                           
[INFO] New signature file: Win32.Ransomware.Acepy.yara                                 
[INFO] New signature file: Win32.Ransomware.Afrodita.yara                              
[INFO] New signature file: Win32.Ransomware.Ako.yara                                   
[INFO] New signature file: Win32.Ransomware.Alcatraz.yara                              
[INFO] New signature file: Win32.Ransomware.AnteFrigus.yara                            
[INFO] New signature file: Win32.Ransomware.Archiveus.yara                             
[INFO] New signature file: Win32.Ransomware.Armage.yara                                
[INFO] New signature file: Win32.Ransomware.Atlas.yara                                 
[INFO] New signature file: Win32.Ransomware.Avaddon.yara                               
[INFO] New signature file: Win32.Ransomware.AvosLocker.yara                            
[INFO] New signature file: Win32.Ransomware.BKRansomware.yara                          
[INFO] New signature file: Win32.Ransomware.Babuk.yara                                 
[INFO] New signature file: Win32.Ransomware.BadBlock.yara                              
[INFO] New signature file: Win32.Ransomware.Badbeeteam.yara                            
[INFO] New signature file: Win32.Ransomware.Balaclava.yara                             
[INFO] New signature file: Win32.Ransomware.Bam2021.yara                               
[INFO] New signature file: Win32.Ransomware.BananaCrypt.yara                           
[INFO] New signature file: Win32.Ransomware.BandarChor.yara                            
[INFO] New signature file: Win32.Ransomware.BitCrypt.yara                              
[INFO] New signature file: Win32.Ransomware.BlackBasta.yara                            
[INFO] New signature file: Win32.Ransomware.BlackCat.yara                              
[INFO] New signature file: Win32.Ransomware.BlackMoon.yara                             
[INFO] New signature file: Win32.Ransomware.Blitzkrieg.yara                            
[INFO] New signature file: Win32.Ransomware.BlueLocker.yara                            
[INFO] New signature file: Win32.Ransomware.BrainCrypt.yara                            
[INFO] New signature file: Win32.Ransomware.Buran.yara                                 
[INFO] New signature file: Win32.Ransomware.ChiChi.yara                                
[INFO] New signature file: Win32.Ransomware.Cincoo.yara                                
[INFO] New signature file: Win32.Ransomware.Clop.yara                                  
[INFO] New signature file: Win32.Ransomware.Conti.yara                                 
[INFO] New signature file: Win32.Ransomware.Cryakl.yara                                
[INFO] New signature file: Win32.Ransomware.Crypmic.yara                               
[INFO] New signature file: Win32.Ransomware.Crypren.yara                               
[INFO] New signature file: Win32.Ransomware.CryptoBit.yara                             
[INFO] New signature file: Win32.Ransomware.CryptoFortress.yara                        
[INFO] New signature file: Win32.Ransomware.CryptoJoker.yara                           
[INFO] New signature file: Win32.Ransomware.CryptoLocker.yara                          
[INFO] New signature file: Win32.Ransomware.CryptoWall.yara                            
[INFO] New signature file: Win32.Ransomware.Crysis.yara                                
[INFO] New signature file: Win32.Ransomware.Cuba.yara                                  
[INFO] New signature file: Win32.Ransomware.DMALocker.yara                             
[INFO] New signature file: Win32.Ransomware.DMR.yara                                   
[INFO] New signature file: Win32.Ransomware.DarkSide.yara                              
[INFO] New signature file: Win32.Ransomware.DearCry.yara                               
[INFO] New signature file: Win32.Ransomware.Defray.yara                                
[INFO] New signature file: Win32.Ransomware.Delphimorix.yara                           
[INFO] New signature file: Win32.Ransomware.DenizKizi.yara                             
[INFO] New signature file: Win32.Ransomware.DesuCrypt.yara                             
[INFO] New signature file: Win32.Ransomware.Dharma.yara                                
[INFO] New signature file: Win32.Ransomware.DirtyDecrypt.yara                          
[INFO] New signature file: Win32.Ransomware.District.yara                              
[INFO] New signature file: Win32.Ransomware.DogeCrypt.yara                             
[INFO] New signature file: Win32.Ransomware.Dragon.yara                                
[INFO] New signature file: Win32.Ransomware.Dualshot.yara                              
[INFO] New signature file: Win32.Ransomware.Encoded01.yara                             
[INFO] New signature file: Win32.Ransomware.Erica.yara                                 
[INFO] New signature file: Win32.Ransomware.FCT.yara                                   
[INFO] New signature file: Win32.Ransomware.FLKR.yara                                  
[INFO] New signature file: Win32.Ransomware.FarAttack.yara                             
[INFO] New signature file: Win32.Ransomware.FenixLocker.yara                           
[INFO] New signature file: Win32.Ransomware.Ferrlock.yara                              
[INFO] New signature file: Win32.Ransomware.Flamingo.yara                              
[INFO] New signature file: Win32.Ransomware.FuxSocy.yara                               
[INFO] New signature file: Win32.Ransomware.GPGQwerty.yara                             
[INFO] New signature file: Win32.Ransomware.GandCrab.yara                              
[INFO] New signature file: Win32.Ransomware.GarrantyDecrypt.yara                       
[INFO] New signature file: Win32.Ransomware.Gibon.yara                                 
[INFO] New signature file: Win32.Ransomware.GlobeImposter.yara                         
[INFO] New signature file: Win32.Ransomware.Gomer.yara                                 
[INFO] New signature file: Win32.Ransomware.Good.yara                                  
[INFO] New signature file: Win32.Ransomware.Gpcode.yara                                
[INFO] New signature file: Win32.Ransomware.GusCrypter.yara                            
[INFO] New signature file: Win32.Ransomware.HDDCryptor.yara                            
[INFO] New signature file: Win32.Ransomware.HDMR.yara                                  
[INFO] New signature file: Win32.Ransomware.HakunaMatata.yara                          
[INFO] New signature file: Win32.Ransomware.Henry.yara                                 
[INFO] New signature file: Win32.Ransomware.HentaiOniichan.yara                        
[INFO] New signature file: Win32.Ransomware.Hermes.yara                                
[INFO] New signature file: Win32.Ransomware.Horsedeal.yara                             
[INFO] New signature file: Win32.Ransomware.HowAreYou.yara                             
[INFO] New signature file: Win32.Ransomware.HydraCrypt.yara                            
[INFO] New signature file: Win32.Ransomware.IFN643.yara                                
[INFO] New signature file: Win32.Ransomware.InfoDot.yara                               
[INFO] New signature file: Win32.Ransomware.JSWorm.yara                                
[INFO] New signature file: Win32.Ransomware.Jamper.yara                                
[INFO] New signature file: Win32.Ransomware.Jemd.yara                                  
[INFO] New signature file: Win32.Ransomware.Jormungand.yara                            
[INFO] New signature file: Win32.Ransomware.JuicyLemon.yara                            
[INFO] New signature file: Win32.Ransomware.Kangaroo.yara                              
[INFO] New signature file: Win32.Ransomware.KawaiiLocker.yara                          
[INFO] New signature file: Win32.Ransomware.KillDisk.yara                              
[INFO] New signature file: Win32.Ransomware.Knot.yara                                  
[INFO] New signature file: Win32.Ransomware.Kovter.yara                                
[INFO] New signature file: Win32.Ransomware.Koxic.yara                                 
[INFO] New signature file: Win32.Ransomware.Kraken.yara                                
[INFO] New signature file: Win32.Ransomware.Ladon.yara                                 
[INFO] New signature file: Win32.Ransomware.LeChiffre.yara                             
[INFO] New signature file: Win32.Ransomware.LockBit.yara                               
[INFO] New signature file: Win32.Ransomware.Lolkek.yara                                
[INFO] New signature file: Win32.Ransomware.LooCipher.yara                             
[INFO] New signature file: Win32.Ransomware.Lorenz.yara                                
[INFO] New signature file: Win32.Ransomware.MRAC.yara                                  
[INFO] New signature file: Win32.Ransomware.MZP.yara                                   
[INFO] New signature file: Win32.Ransomware.Mafia.yara                                 
[INFO] New signature file: Win32.Ransomware.Magniber.yara                              
[INFO] New signature file: Win32.Ransomware.Major.yara                                 
[INFO] New signature file: Win32.Ransomware.Makop.yara                                 
[INFO] New signature file: Win32.Ransomware.Maktub.yara                                
[INFO] New signature file: Win32.Ransomware.Marlboro.yara                              
[INFO] New signature file: Win32.Ransomware.MarsJoke.yara                              
[INFO] New signature file: Win32.Ransomware.Matsnu.yara                                
[INFO] New signature file: Win32.Ransomware.MedusaLocker.yara                          
[INFO] New signature file: Win32.Ransomware.Meow.yara                                  
[INFO] New signature file: Win32.Ransomware.Monalisa.yara                              
[INFO] New signature file: Win32.Ransomware.Montserrat.yara                            
[INFO] New signature file: Win32.Ransomware.Motocos.yara                               
[INFO] New signature file: Win32.Ransomware.MountLocker.yara                           
[INFO] New signature file: Win32.Ransomware.NB65.yara                                  
[INFO] New signature file: Win32.Ransomware.NanoLocker.yara                            
[INFO] New signature file: Win32.Ransomware.Nefilim.yara                               
[INFO] New signature file: Win32.Ransomware.Nemty.yara                                 
[INFO] New signature file: Win32.Ransomware.Networm.yara                               
[INFO] New signature file: Win32.Ransomware.NotPetya.yara                              
[INFO] New signature file: Win32.Ransomware.Oni.yara                                   
[INFO] New signature file: Win32.Ransomware.OphionLocker.yara                          
[INFO] New signature file: Win32.Ransomware.Ouroboros.yara                             
[INFO] New signature file: Win32.Ransomware.Outsider.yara                              
[INFO] New signature file: Win32.Ransomware.PXJ.yara                                   
[INFO] New signature file: Win32.Ransomware.Paradise.yara                              
[INFO] New signature file: Win32.Ransomware.Pay2Key.yara                               
[INFO] New signature file: Win32.Ransomware.Petya.yara                                 
[INFO] New signature file: Win32.Ransomware.Plague17.yara                              
[INFO] New signature file: Win32.Ransomware.PrincessLocker.yara                        
[INFO] New signature file: Win32.Ransomware.Prometey.yara                              
[INFO] New signature file: Win32.Ransomware.RagnarLocker.yara                          
[INFO] New signature file: Win32.Ransomware.Ragnarok.yara                              
[INFO] New signature file: Win32.Ransomware.Ransoc.yara                                
[INFO] New signature file: Win32.Ransomware.RansomPlus.yara                            
[INFO] New signature file: Win32.Ransomware.Ransomexx.yara                             
[INFO] New signature file: Win32.Ransomware.Redeemer.yara                              
[INFO] New signature file: Win32.Ransomware.RegretLocker.yara                          
[INFO] New signature file: Win32.Ransomware.RetMyData.yara                             
[INFO] New signature file: Win32.Ransomware.Reveton.yara                               
[INFO] New signature file: Win32.Ransomware.Revil.yara                                 
[INFO] New signature file: Win32.Ransomware.Rokku.yara                                 
[INFO] New signature file: Win32.Ransomware.Ryuk.yara                                  
[INFO] New signature file: Win32.Ransomware.Sage.yara                                  
[INFO] New signature file: Win32.Ransomware.Sanwai.yara                                
[INFO] New signature file: Win32.Ransomware.Sarbloh.yara                               
[INFO] New signature file: Win32.Ransomware.Satan.yara                                 
[INFO] New signature file: Win32.Ransomware.Satana.yara                                
[INFO] New signature file: Win32.Ransomware.Saturn.yara                                
[INFO] New signature file: Win32.Ransomware.Sepsis.yara                                
[INFO] New signature file: Win32.Ransomware.Serpent.yara                               
[INFO] New signature file: Win32.Ransomware.SevenSevenSeven.yara                       
[INFO] New signature file: Win32.Ransomware.ShadowCryptor.yara                         
[INFO] New signature file: Win32.Ransomware.Sherminator.yara                           
[INFO] New signature file: Win32.Ransomware.Sifrelendi.yara                            
[INFO] New signature file: Win32.Ransomware.Sifreli.yara                               
[INFO] New signature file: Win32.Ransomware.Sigrun.yara                                
[INFO] New signature file: Win32.Ransomware.Skystars.yara                              
[INFO] New signature file: Win32.Ransomware.Spora.yara                                 
[INFO] New signature file: Win32.Ransomware.TBLocker.yara                              
[INFO] New signature file: Win32.Ransomware.TargetCompany.yara                         
[INFO] New signature file: Win32.Ransomware.TechandStrat.yara                          
[INFO] New signature file: Win32.Ransomware.TeleCrypt.yara                             
[INFO] New signature file: Win32.Ransomware.Termite.yara                               
[INFO] New signature file: Win32.Ransomware.Teslacrypt.yara                            
[INFO] New signature file: Win32.Ransomware.Teslarvng.yara                             
[INFO] New signature file: Win32.Ransomware.Thanatos.yara                              
[INFO] New signature file: Win32.Ransomware.TorrentLocker.yara                         
[INFO] New signature file: Win32.Ransomware.VHDLocker.yara                             
[INFO] New signature file: Win32.Ransomware.VegaLocker.yara                            
[INFO] New signature file: Win32.Ransomware.Velso.yara                                 
[INFO] New signature file: Win32.Ransomware.WannaCry.yara                              
[INFO] New signature file: Win32.Ransomware.WaspLocker.yara                            
[INFO] New signature file: Win32.Ransomware.Wastedlocker.yara                          
[INFO] New signature file: Win32.Ransomware.WinWord64.yara                             
[INFO] New signature file: Win32.Ransomware.WsIR.yara                                  
[INFO] New signature file: Win32.Ransomware.Xorist.yara                                
[INFO] New signature file: Win32.Ransomware.Zeoticus.yara                              
[INFO] New signature file: Win32.Ransomware.Zeppelin.yara                              
[INFO] New signature file: Win32.Ransomware.ZeroCrypt.yara                             
[INFO] New signature file: Win32.Ransomware.Zhen.yara                                  
[INFO] New signature file: Win32.Ransomware.Zoldon.yara                                
[INFO] New signature file: Win64.Ransomware.Ako.yara                                   
[INFO] New signature file: Win64.Ransomware.AntiWar.yara                               
[INFO] New signature file: Win64.Ransomware.AwesomeScott.yara                          
[INFO] New signature file: Win64.Ransomware.Curator.yara                               
[INFO] New signature file: Win64.Ransomware.DST.yara                                   
[INFO] New signature file: Win64.Ransomware.HermeticRansom.yara                        
[INFO] New signature file: Win64.Ransomware.HotCoffee.yara                             
[INFO] New signature file: Win64.Ransomware.Nokoyawa.yara                              
[INFO] New signature file: Win64.Ransomware.Pandora.yara                               
[INFO] New signature file: Win64.Ransomware.RedRoman.yara                              
[INFO] New signature file: Win64.Ransomware.Rook.yara                                  
[INFO] New signature file: Win64.Ransomware.SeedLocker.yara                            
[INFO] New signature file: Win64.Ransomware.Seth.yara                                  
[INFO] New signature file: Win64.Ransomware.Solaso.yara                                
[INFO] New signature file: Win64.Ransomware.Vovalex.yara                               
[INFO] New signature file: Win64.Ransomware.WhiteBlackCrypt.yara                       
[INFO] New signature file: Win64.Ransomware.Wintenzz.yara                              
[INFO] New signature file: Win32.Trojan.CaddyWiper.yara                                
[INFO] New signature file: Win32.Trojan.Dridex.yara                                    
[INFO] New signature file: Win32.Trojan.Emotet.yara                                    
[INFO] New signature file: Win32.Trojan.HermeticWiper.yara                             
[INFO] New signature file: Win32.Trojan.IsaacWiper.yara                                
[INFO] New signature file: Win32.Trojan.TrickBot.yara                                  
[INFO] New signature file: Linux.Virus.Vit.yara                                        
[INFO] New signature file: Win32.Virus.Awfull.yara                                     
[INFO] New signature file: Win32.Virus.Cmay.yara                                       
[INFO] New signature file: Win32.Virus.DeadCode.yara                                   
[INFO] New signature file: Win32.Virus.Elerad.yara                                     
[INFO] New signature file: Win32.Virus.Greenp.yara                                     
[INFO] New signature file: Win32.Virus.Mocket.yara                                     
[INFO] New signature file: Win32.Virus.Negt.yara                                       
[INFO] Update complete                                                                 
[INFO] Press any key to return ...                                                     
                                                                                       
                                                                                       
┌──(kali㉿kali)-[~/Downloads/loki/Loki-0.45.0]
└─$ ls
build.bat      loki.exe                           loki-upgrade.log    README.md
build_sfx.bat  loki.ico                           loki-upgrader.py    requirements.txt
config         lokiicon.jpg                       loki-upgrader.spec  screens
docs           loki_kali_2022-11-27_13-41-17.log  Pipfile             signature-base
lib            loki.py                            plugins             test
LICENSE        loki.spec                          prepare_push.sh     tools
                                                                                       
┌──(kali㉿kali)-[~/Downloads/loki/Loki-0.45.0]
└─$ cd signature-base 
                                                                                       
┌──(kali㉿kali)-[~/Downloads/loki/Loki-0.45.0/signature-base]
└─$ ls
iocs  misc  yara
                                                                                       
┌──(kali㉿kali)-[~/Downloads/loki/Loki-0.45.0/signature-base]
└─$ cd yara          
                                                                                       
┌──(kali㉿kali)-[~/…/loki/Loki-0.45.0/signature-base/yara]
└─$ ls
airbnb_binaryalert.yar
apt_aa19_024a.yar
apt_agent_btz.yar
apt_alienspy_rat.yar
apt_apt10_redleaves.yar
apt_apt10.yar
apt_apt12_malware.yar
apt_apt15.yar
apt_apt17_mal_sep17.yar
apt_apt17_malware.yar
apt_apt19.yar
apt_apt27_hyperbro.yar
apt_apt28_drovorub.yar
apt_apt28.yar
apt_apt29_grizzly_steppe.yar
apt_apt29_nobelium_apr22.yar
apt_apt29_nobelium_may21.yar
apt_apt30_backspace.yar
apt_apt32.yar
apt_apt34.yar
apt_apt37_bluelight.yar
apt_apt37.yar
apt_apt3_bemstour.yar
apt_apt41.yar
apt_apt6_malware.yar
apt_ar18_165a.yar
apt_area1_phishing_diplomacy.yar
apt_aus_parl_compromise.yar
apt_babyshark.yar
apt_backdoor_ssh_python.yar
apt_backdoor_sunburst_fnv1a_experimental.yar
apt_backspace.yar
apt_beepservice.yar
apt_between-hk-and-burma.yar
apt_bigbang.yar
apt_bitter.yar
apt_blackenergy_installer.yar
apt_blackenergy.yar
apt_bluetermite_emdivi.yar
apt_bronze_butler.yar
apt_buckeye.yar
apt_candiru.yar
apt_carbon_paper_turla.yar
apt_casper.yar
apt_cheshirecat.yar
apt_cloudatlas.yar
apt_cloudduke.yar
apt_cmstar.yar
apt_cn_netfilter.yar
apt_cn_pp_zerot.yar
apt_cn_reddelta.yar
apt_cn_twisted_panda.yar
apt_cobaltstrike_evasive.yar
apt_cobaltstrike.yar
apt_codoso.yar
apt_coreimpact_agent.yar
apt_danti_svcmondr.yar
apt_darkcaracal.yar
apt_darkhydrus.yar
apt_deeppanda.yar
apt_derusbi.yar
apt_dnspionage.yar
apt_donotteam_ytyframework.yar
apt_dragonfly.yar
apt_dtrack.yar
apt_dubnium.yar
apt_duqu1_5_modules.yar
apt_duqu2.yar
apt_dustman.yar
apt_emissary.yar
apt_eqgrp_apr17.yar
apt_eqgrp.yar
apt_eternalblue_non_wannacry.yar
apt_exile_rat.yar
apt_f5_bigip_expl_payloads.yar
apt_fakem_backdoor.yar
apt_fancybear_computrace_agent.yar
apt_fancybear_dnc.yar
apt_fancybear_osxagent.yar
apt_fidelis_phishing_plain_sight.yar
apt_fin7_backdoor.yar
apt_fin7.yar
apt_fin8.yar
apt_flame2_orchestrator.yar
apt_foudre.yar
apt_four_element_sword.yar
apt_freemilk.yar
apt_fujinama_rat.yar
apt_furtim.yar
apt_fvey_shadowbroker_dec16.yar
apt_fvey_shadowbroker_jan17.yar
apt_ghostdragon_gh0st_rat.yar
apt_glassRAT.yar
apt_golddragon.yar
apt_goldenspy.yar
apt_greenbug.yar
apt_greyenergy.yar
apt_grizzlybear_uscert.yar
apt_hackingteam_rules.yar
apt_hafnium_log_sigs.yar
apt_hafnium.yar
apt_ham_tofu_chches.yar
apt_hatman.yar
apt_hellsing_kaspersky.yar
apt_hiddencobra_bankshot.yar
apt_hiddencobra_wiper.yar
apt_hidden_cobra.yar
apt_hizor_rat.yar
apt_hkdoor.yar
apt_iamtheking.yar
apt_icefog.yar
apt_indetectables_rat.yar
apt_industroyer.yar
apt_inocnation.yar
apt_irongate.yar
apt_irontiger_trendmicro.yar
apt_irontiger.yar
apt_ism_rat.yar
apt_kaspersky_duqu2.yar
apt_ke3chang.yar
apt_keyboys.yar
apt_keylogger_cn.yar
apt_khrat.yar
apt_korplug_fast.yar
apt_kwampirs.yar
apt_laudanum_webshells.yar
apt_lazarus_applejeus.yar
apt_lazarus_aug20.yar
apt_lazarus_dec17.yar
apt_lazarus_dec20.yar
apt_lazarus_jan21.yar
apt_lazarus_jun18.yar
apt_lazarus_vhd_ransomware.yar
apt_leviathan.yar
apt_lnx_kobalos.yar
apt_lnx_linadoor_rootkit.yar
apt_lotusblossom_elise.yar
apt_magichound.yar
apt_mal_ilo_board_elf.yar
apt_microcin.yar
apt_middle_east_talosreport.yar
apt_miniasp.yar
apt_minidionis.yar
apt_mofang.yar
apt_molerats_jul17.yar
apt_monsoon.yar
apt_moonlightmaze.yar
apt_ms_platinum.yara
apt_muddywater.yar
apt_naikon.yar
apt_nanocore_rat.yar
apt_nazar.yar
apt_ncsc_report_04_2018.yar
apt_netwire_rat.yar
apt_nk_gen.yar
apt_nk_goldbackdoor.yar
apt_nk_inkysquid.yar
apt_oilrig_chafer_mar18.yar
apt_oilrig_oct17.yar
apt_oilrig_rgdoor.yar
apt_oilrig.yar
apt_olympic_destroyer.yar
apt_onhat_proxy.yar
apt_op_cleaver.yar
apt_op_cloudhopper.yar
apt_op_honeybee.yar
apt_op_shadowhammer.yar
apt_op_wocao.yar
apt_passcv.yar
apt_passthehashtoolkit.yar
apt_patchwork.yar
apt_plead_downloader.yar
apt_plugx.yar
apt_poisonivy_gen3.yar
apt_poisonivy.yar
apt_poseidon_group.yar
apt_poshspy.yar
apt_prikormka.yar
apt_project_m.yar
apt_project_sauron_extras.yar
apt_project_sauron.yara
apt_promethium_neodymium.yar
apt_pulsesecure.yar
apt_putterpanda.yar
apt_quarkspwdump.yar
apt_quasar_rat.yar
apt_quasar_vermin.yar
apt_rancor.yar
apt_reaver_sunorcal.yar
apt_rehashed_rat.yar
apt_revenge_rat.yar
apt_rocketkitten_keylogger.yar
apt_rokrat.yar
apt_royalroad.yar
apt_ruag.yar
apt_rwmc_powershell_creddump.yar
apt_sakula.yar
apt_sandworm_centreon.yar
apt_sandworm_cyclops_blink.yar
apt_sandworm_exim_expl.yar
apt_saudi_aramco_phish.yar
apt_scanbox_deeppanda.yar
apt_scarcruft.yar
apt_seaduke_unit42.yar
apt_sednit_delphidownloader.yar
apt_servantshell.yar
apt_shadowpad.yar
apt_shamoon2.yar
apt_shamoon.yar
apt_sharptongue.yar
apt_shellcrew_streamex.yar
apt_sidewinder.yar
apt_silence.yar
apt_skeletonkey.yar
apt_slingshot.yar
apt_snaketurla_osx.yar
apt_snowglobe_babar.yar
apt_sofacy_cannon.yar
apt_sofacy_dec15.yar
apt_sofacy_fysbis.yar
apt_sofacy_hospitality.yar
apt_sofacy_jun16.yar
apt_sofacy_oct17_camp.yar
apt_sofacy_xtunnel_bundestag.yar
apt_sofacy.yar
apt_sofacy_zebrocy.yar
apt_solarwinds_sunburst.yar
apt_solarwinds_susp_sunburst.yar
apt_sphinx_moth.yar
apt_stealer_cisa_ar22_277a.yar
apt_stonedrill.yar
apt_strider.yara
apt_stuxnet.yar
apt_stuxshop.yar
apt_suckfly.yar
apt_sunspot.yar
apt_sysscan.yar
apt_ta17_293A.yar
apt_ta17_318A.yar
apt_ta17_318B.yar
apt_ta18_074A.yar
apt_ta18_149A.yar
apt_ta459.yar
apt_telebots.yar
apt_terracotta_liudoor.yar
apt_terracotta.yar
apt_tetris.yar
apt_threatgroup_3390.yar
apt_thrip.yar
apt_tick_datper.yar
apt_tick_weaponized_usb.yar
apt_tidepool.yar
apt_tophat.yar
apt_triton_mal_sshdoor.yar
apt_triton.yar
apt_turbo_campaign.yar
apt_turla_gazer.yar
apt_turla_kazuar.yar
apt_turla_mosquito.yar
apt_turla_neuron.yar
apt_turla_penquin.yar
apt_turla_png_dropper_nov18.yar
apt_turla.yar
apt_ua_caddywiper.yar
apt_ua_hermetic_wiper.yar
apt_ua_isaacwiper.yar
apt_ua_wiper_whispergate.yar
apt_uboat_rat.yar
apt_unc1151_ua.yar
apt_unc2447_sombrat.yar
apt_unc2546_dewmode.yar
apt_unc3886_virtualpita.yar
apt_unit78020_malware.yar
apt_uscert_ta17-1117a.yar
apt_venom_linux_rootkit.yar
apt_volatile_cedar.yar
apt_vpnfilter.yar
apt_waterbear.yar
apt_waterbug.yar
apt_webmonitor_rat.yar
apt_webshell_chinachopper.yar
apt_wildneutron.yar
apt_wilted_tulip.yar
apt_winnti_br.yar
apt_winnti_burning_umbrella.yar
apt_winnti_hdroot.yar
apt_winnti_linux.yar
apt_winnti_ms_report_201701.yar
apt_winnti.yar
apt_win_plugx.yar
apt_woolengoldfish.yar
apt_xrat.yar
apt_zxshell.yar
blocklist.yara
ByteCode.MSIL.Ransomware.Apis.yara
ByteCode.MSIL.Ransomware.ChupaCabra.yara
Bytecode.MSIL.Ransomware.CobraLocker.yara
ByteCode.MSIL.Ransomware.Cring.yara
ByteCode.MSIL.Ransomware.Dusk.yara
ByteCode.MSIL.Ransomware.EAF.yara
ByteCode.MSIL.Ransomware.Eternity.yara
ByteCode.MSIL.Ransomware.Fantom.yara
ByteCode.MSIL.Ransomware.Ghostbin.yara
ByteCode.MSIL.Ransomware.GhosTEncryptor.yara
ByteCode.MSIL.Ransomware.GoodWill.yara
ByteCode.MSIL.Ransomware.HarpoonLocker.yara
ByteCode.MSIL.Ransomware.Hog.yara
ByteCode.MSIL.Ransomware.Invert.yara
ByteCode.MSIL.Ransomware.Janelle.yara
ByteCode.MSIL.Ransomware.Khonsari.yara
ByteCode.MSIL.Ransomware.McBurglar.yara
ByteCode.MSIL.Ransomware.Moisha.yara
ByteCode.MSIL.Ransomware.Namaste.yara
ByteCode.MSIL.Ransomware.Oct.yara
ByteCode.MSIL.Ransomware.Pacman.yara
ByteCode.MSIL.Ransomware.PoliceRecords.yara
ByteCode.MSIL.Ransomware.Povlsomware.yara
ByteCode.MSIL.Ransomware.Retis.yara
ByteCode.MSIL.Ransomware.TaRRaK.yara
ByteCode.MSIL.Ransomware.Thanos.yara
ByteCode.MSIL.Ransomware.TimeCrypt.yara
ByteCode.MSIL.Ransomware.TimeTime.yara
ByteCode.MSIL.Ransomware.Venom.yara
ByteCode.MSIL.Ransomware.WildFire.yara
ByteCode.MSIL.Ransomware.WormLocker.yara
ByteCode.MSIL.Ransomware.ZeroLocker.yara
cn_pentestset_scripts.yar
cn_pentestset_tools.yar
cn_pentestset_webshells.yar
crime_academic_data_centers_camp_may20.yar
crime_andromeda_jun17.yar
crime_antifw_installrex.yar
crime_atm_dispenserxfs.yar
crime_atm_javadipcash.yar
crime_atm_loup.yar
crime_atm_xfsadm.yar
crime_atm_xfscashncr.yar
crime_bad_patch.yar
crime_badrabbit.yar
crime_bazarbackdoor.yar
crime_bernhard_pos.yar
crime_bluenoroff_pos.yar
crime_buzus_softpulse.yar
crime_cmstar.yar
crime_cn_campaign_njrat.yar
crime_cn_group_btc.yar
crime_cobalt_gang_pdf.yar
crime_cobaltgang.yar
crime_corkow_dll.yar
crime_covid_ransom.yar
crime_credstealer_generic.yar
crime_crypto_miner.yar
crime_cryptowall_svg.yar
crime_dearcry_ransom.yar
crime_dexter_trojan.yar
crime_dridex_xml.yar
crime_emotet.yar
crime_enfal.yar
crime_envrial.yar
crime_eternalrocks.yar
crime_evilcorp_dridex_banker.yar
crime_fareit.yar
crime_fireball.yar
crime_floxif_flystudio.yar
crime_gamaredon.yar
crime_goldeneye.yar
crime_gozi_crypter.yar
crime_guloader.yar
crime_h2miner_kinsing.yar
crime_hermes_ransom.yar
crime_icedid.yar
crime_kasper_oct17.yar
crime_kins_dropper.yar
crime_kraken_bot1.yar
crime_kriskynote.yar
crime_kr_malware.yar
crime_locky.yar
crime_loki_bot.yar
crime_mal_grandcrab.yar
crime_mal_nitol.yar
crime_mal_ransom_wadharma.yar
crime_malumpos.yar
crime_malware_generic.yar
crime_malware_set_oct16.yar
crime_maze_ransomware.yar
crime_mikey_trojan.yar
crime_mirai.yar
crime_mywscript_dropper.yar
crime_nansh0u.yar
crime_nkminer.yar
crime_nopetya_jun17.yar
crime_ole_loadswf_cve_2018_4878.yar
crime_parallax_rat.yar
crime_phish_gina_dec15.yar
crime_ransom_conti.yar
crime_ransom_darkside.yar
crime_ransom_generic.yar
crime_ransom_germanwiper.yar
crime_ransom_lockergoga.yar
crime_ransom_prolock.yar
crime_ransom_ragna_locker.yar
crime_ransom_revil.yar
crime_ransom_robinhood.yar
crime_ransom_stealbit_lockbit.yar
crime_ransom_venus.yar
crime_rat_parallax.yar
crime_revil_general.yar
crime_rombertik_carbongrabber.yar
crime_ryuk_ransomware.yar
crime_shifu_trojan.yar
crime_snarasite.yar
crime_socgholish.yar
crime_stealer_exfil_zip.yar
crime_teledoor.yar
crime_trickbot.yar
crime_upatre_oct15.yar
crime_wannacry.yar
crime_wsh_rat.yar
crime_xbash.yar
crime_zeus_panda.yar
crime_zloader_maldocs.yar
expl_adselfservice_cve_2021_40539.yar
expl_cve_2021_1647.yar
expl_cve_2021_26084_confluence_log.yar
expl_cve_2021_40444.yar
expl_cve_2022_41040_proxynoshell.yar
expl_log4j_cve_2021_44228.yar
exploit_cve_2014_4076.yar
exploit_cve_2015_1674.yar
exploit_cve_2015_1701.yar
exploit_cve_2015_2426.yar
exploit_cve_2015_2545.yar
exploit_cve_2015_5119.yar
exploit_cve_2017_11882.yar
exploit_cve_2017_8759.yar
exploit_cve_2017_9800.yar
exploit_cve_2018_0802.yar
exploit_cve_2018_16858.yar
exploit_cve_2021_31166.yar
exploit_cve_2021_33766_proxytoken.yar
exploit_cve_2022_22954_vmware_workspace_one.yar
exploit_f5_bigip_cve_2021_22986_log.yar
exploit_gitlab_cve_2021_22205.yar
exploit_rtf_ole2link.yar
exploit_shitrix.yar
exploit_tlb_scripts.yar
exploit_uac_elevators.yar
expl_proxyshell.yar
expl_spring4shell.yar
gen_ace_with_exe.yar
gen_anomalies_keyword_combos.yar
gen_armitage.yar
gen_autocad_lsp_malware.yar
gen_b374k_extra.yar
gen_bad_pdf.yar
gen_case_anomalies.yar
gen_cert_payloads.yar
gen_chaos_payload.yar
gen_cmd_script_obfuscated.yar
gen_cn_hacktool_scripts.yar
gen_cn_hacktools.yar
gen_cn_webshells.yar
gen_cobaltstrike_by_avast.yar
gen_cobaltstrike.yar
gen_crime_bitpaymer.yar
gen_crimson_rat.yar
gen_crunchrat.yar
gen_dde_in_office_docs.yar
gen_deviceguard_evasion.yar
gen_doc_follina.yar
gen_dropper_pdb.yar
gen_elf_file_anomalies.yar
gen_empire.yar
gen_enigma_protector.yar
general_cloaking.yar
general_officemacros.yar
generic_anomalies.yar
generic_cryptors.yar
generic_dumps.yar
generic_exe2hex_payload.yar
gen_event_mute_hook.yar
gen_Excel4Macro_Sharpshooter.yar
gen_excel_auto_open_evasion.yar
gen_excel_xll_addin_suspicious.yar
gen_excel_xor_obfuscation_velvetsweatshop.yar
gen_exploit_cve_2017_10271_weblogic.yar
gen_faked_versions.yar
gen_file_anomalies.yar
gen_fireeye_redteam_tools.yar
gen_floxif.yar
gen_frp_proxy.yar
gen_gcti_cobaltstrike.yar
gen_gcti_sliver.yar
gen_gen_cactustorch.yar
gen_github_net_redteam_tools_guids.yar
gen_github_net_redteam_tools_names.yar
gen_github_repo_compromise_myjino_ru.yar
gen_gobfuscate.yar
gen_google_anomaly.yar
gen_gpp_cpassword.yar
gen_hawkeye.yar
gen_hktl_koh_tokenstealer.yar
gen_hktl_roothelper.yar
gen_hta_anomalies.yar
gen_hunting_susp_rar.yar
gen_icon_anomalies.yar
gen_impacket_tools.yar
gen_invoke_mimikatz.yar
gen_invoke_psimage.yar
gen_invoke_thehash.yar
gen_javascript_powershell.yar
gen_kerberoast.yar
gen_khepri.yar
gen_kirbi_mimkatz.yar
gen_lnx_malware_indicators.yar
gen_loaders.yar
gen_macro_builders.yar
gen_macro_ShellExecute_action.yar
gen_macro_staroffice_suspicious.yar
gen_mal_backnet.yar
gen_maldoc.yar
gen_mal_link.yar
gen_mal_scripts.yar
gen_malware_MacOS_plist_suspicious.yar
gen_malware_set_qa.yar
gen_merlin_agent.yar
gen_metasploit_loader_rsmudge.yar
gen_metasploit_payloads.yar
gen_mimikatz.yar
gen_mimikittenz.yar
gen_mimipenguin.yar
gen_nighthawk_c2.yar
gen_nimpackt.yar
gen_nopowershell.yar
gen_nvidia_leaked_cert.yar
gen_osx_backdoor_bella.yar
gen_osx_evilosx.yar
gen_osx_pyagent_persistence.yar
gen_p0wnshell.yar
gen_phish_attachments.yar
gen_pirpi.yar
gen_powerkatz.yar
gen_powershdll.yar
gen_powershell_empire.yar
gen_powershell_invocation.yar
gen_powershell_obfuscation.yar
gen_powershell_suite.yar
gen_powershell_susp.yar
gen_powershell_toolkit.yar
gen_powersploit_dropper.yar
gen_ps1_shellcode.yar
gen_ps_empire_eval.yar
gen_ps_osiris.yar
gen_pua.yar
gen_pupy_rat.yar
gen_python_encoded_adware.yar
gen_python_pty_shell.yar
gen_python_pyminifier_encoded_payload.yar
gen_python_reverse_shell.yara
gen_rar_exfil.yar
gen_rats_malwareconfig.yar
gen_recon_indicators.yar
gen_redmimicry.yar
gen_redsails.yar
gen_regsrv32_issue.yar
gen_remote_potato0.yar
gen_rottenpotato.yar
gen_rtf_malver_objects.yar
gen_sfx_with_microsoft_copyright.yar
gen_sharpcat.yar
gen_shikataganai.yar
gen_sign_anomalies.yar
gen_solarwinds_credential_stealer.yar
gen_susp_bat2exe.yar
gen_susp_bat_aux.yar
gen_susp_cmd_var_expansion.yar
gen_susp_hacktool.yar
gen_suspicious_InPage_dropper.yar
gen_suspicious_strings.yar
gen_susp_js_obfuscatorio.yar
gen_susp_lnk_files.yar
gen_susp_lnk.yar
gen_susp_obfuscation.yar
gen_susp_office_dropper.yar
gen_susp_ps_jab.yar
gen_susp_sfx.yar
gen_susp_strings_in_ole.yar
gen_susp_wer_files.yar
gen_susp_xor.yar
gen_sysinternals_anomaly.yar
gen_tempracer.yar
gen_thumbs_cloaking.yar
gen_transformed_strings.yar
gen_tscookie_rat.yar
gen_unicorn_obfuscated_powershell.yar
gen_unspecified_malware.yar
gen_url_persitence.yar
gen_url_to_local_exe.yar
gen_vhd_anomaly.yar
gen_webshells_ext_vars.yar
gen_webshells.yar
gen_winpayloads.yar
gen_win_privesc.yar
gen_winshells.yar
gen_wmi_implant.yar
gen_xored_pe.yar
gen_xor_hunting.yar
gen_xtreme_rat.yar
gen_ysoserial_payloads.yar
gen_zoho_rcef_logs.yar
hktl_bruteratel_c4_badger.yar
hktl_bruteratel_c4.yar
Linux.Ransomware.GwisinLocker.yara
Linux.Ransomware.KillDisk.yara
Linux.Ransomware.LuckyJoe.yara
Linux.Ransomware.RedAlert.yara
Linux.Virus.Vit.yara
mal_avemaria_rat.yar
mal_codecov_hack.yar
mal_crime_unknown.yar
mal_cryp_rat.yar
mal_lnx_implant_may22.yar
mal_netsha.yar
mal_passwordstate_backdoor.yar
mal_qbot_payloads.yar
mal_ransom_lorenz.yar
pua_cryptocoin_miner.yar
pua_xmrig_monero_miner.yar
pup_lightftp.yar
spy_equation_fiveeyes.yar
spy_querty_fiveeyes.yar
spy_regin_fiveeyes.yar
thor-hacktools.yar
thor_inverse_matches.yar
thor-webshells.yar
threat_lenovo_superfish.yar
vul_backdoor_antitheftweb.yar
vul_confluence_questions_plugin_cve_2022_26138.yar
vul_cve_2020_0688.yar
vul_cve_2020_1938.yar
vul_cve_2021_3438_printdriver.yar
vul_cve_2021_386471_omi.yar
vul_dell_bios_upd_driver.yar
vul_drivecrypt.yar
vul_jquery_fileupload_cve_2018_9206.yar
vuln_gigabyte_driver.yar
vuln_proxynotshell_cve_2022_41040.yar
vul_php_zlib_backdoor.yar
webshell_regeorg.yar
webshell_xsl_transform.yar
Win32.Downloader.dlMarlboro.yara
Win32.Exploit.CVE20200601.yara
Win32.Infostealer.MultigrainPOS.yara
Win32.Infostealer.ProjectHookPOS.yara
Win32.PUA.Domaiq.yara
Win32.Ransomware.5ss5c.yara
Win32.Ransomware.Acepy.yara
Win32.Ransomware.Afrodita.yara
Win32.Ransomware.Ako.yara
Win32.Ransomware.Alcatraz.yara
Win32.Ransomware.AnteFrigus.yara
Win32.Ransomware.Archiveus.yara
Win32.Ransomware.Armage.yara
Win32.Ransomware.ASN1Encoder.yara
Win32.Ransomware.Atlas.yara
Win32.Ransomware.Avaddon.yara
Win32.Ransomware.AvosLocker.yara
Win32.Ransomware.Babuk.yara
Win32.Ransomware.Badbeeteam.yara
Win32.Ransomware.BadBlock.yara
Win32.Ransomware.Balaclava.yara
Win32.Ransomware.Bam2021.yara
Win32.Ransomware.BananaCrypt.yara
Win32.Ransomware.BandarChor.yara
Win32.Ransomware.BitCrypt.yara
Win32.Ransomware.BKRansomware.yara
Win32.Ransomware.BlackBasta.yara
Win32.Ransomware.BlackCat.yara
Win32.Ransomware.BlackMoon.yara
Win32.Ransomware.Blitzkrieg.yara
Win32.Ransomware.BlueLocker.yara
Win32.Ransomware.BrainCrypt.yara
Win32.Ransomware.Buran.yara
Win32.Ransomware.ChiChi.yara
Win32.Ransomware.Cincoo.yara
Win32.Ransomware.Clop.yara
Win32.Ransomware.Conti.yara
Win32.Ransomware.Cryakl.yara
Win32.Ransomware.Crypmic.yara
Win32.Ransomware.Crypren.yara
Win32.Ransomware.CryptoBit.yara
Win32.Ransomware.CryptoFortress.yara
Win32.Ransomware.CryptoJoker.yara
Win32.Ransomware.CryptoLocker.yara
Win32.Ransomware.CryptoWall.yara
Win32.Ransomware.Crysis.yara
Win32.Ransomware.Cuba.yara
Win32.Ransomware.DarkSide.yara
Win32.Ransomware.DearCry.yara
Win32.Ransomware.Defray.yara
Win32.Ransomware.Delphimorix.yara
Win32.Ransomware.DenizKizi.yara
Win32.Ransomware.DesuCrypt.yara
Win32.Ransomware.Dharma.yara
Win32.Ransomware.DirtyDecrypt.yara
Win32.Ransomware.District.yara
Win32.Ransomware.DMALocker.yara
Win32.Ransomware.DMR.yara
Win32.Ransomware.DogeCrypt.yara
Win32.Ransomware.Dragon.yara
Win32.Ransomware.Dualshot.yara
Win32.Ransomware.Encoded01.yara
Win32.Ransomware.Erica.yara
Win32.Ransomware.FarAttack.yara
Win32.Ransomware.FCT.yara
Win32.Ransomware.FenixLocker.yara
Win32.Ransomware.Ferrlock.yara
Win32.Ransomware.Flamingo.yara
Win32.Ransomware.FLKR.yara
Win32.Ransomware.FuxSocy.yara
Win32.Ransomware.GandCrab.yara
Win32.Ransomware.GarrantyDecrypt.yara
Win32.Ransomware.Gibon.yara
Win32.Ransomware.GlobeImposter.yara
Win32.Ransomware.Gomer.yara
Win32.Ransomware.Good.yara
Win32.Ransomware.Gpcode.yara
Win32.Ransomware.GPGQwerty.yara
Win32.Ransomware.GusCrypter.yara
Win32.Ransomware.HakunaMatata.yara
Win32.Ransomware.HDDCryptor.yara
Win32.Ransomware.HDMR.yara
Win32.Ransomware.Henry.yara
Win32.Ransomware.HentaiOniichan.yara
Win32.Ransomware.Hermes.yara
Win32.Ransomware.Horsedeal.yara
Win32.Ransomware.HowAreYou.yara
Win32.Ransomware.HydraCrypt.yara
Win32.Ransomware.IFN643.yara
Win32.Ransomware.InfoDot.yara
Win32.Ransomware.Jamper.yara
Win32.Ransomware.Jemd.yara
Win32.Ransomware.Jormungand.yara
Win32.Ransomware.JSWorm.yara
Win32.Ransomware.JuicyLemon.yara
Win32.Ransomware.Kangaroo.yara
Win32.Ransomware.KawaiiLocker.yara
Win32.Ransomware.KillDisk.yara
Win32.Ransomware.Knot.yara
Win32.Ransomware.Kovter.yara
Win32.Ransomware.Koxic.yara
Win32.Ransomware.Kraken.yara
Win32.Ransomware.Ladon.yara
Win32.Ransomware.LeChiffre.yara
Win32.Ransomware.LockBit.yara
Win32.Ransomware.Lolkek.yara
Win32.Ransomware.LooCipher.yara
Win32.Ransomware.Lorenz.yara
Win32.Ransomware.Mafia.yara
Win32.Ransomware.Magniber.yara
Win32.Ransomware.Major.yara
Win32.Ransomware.Makop.yara
Win32.Ransomware.Maktub.yara
Win32.Ransomware.Marlboro.yara
Win32.Ransomware.MarsJoke.yara
Win32.Ransomware.Matsnu.yara
Win32.Ransomware.MedusaLocker.yara
Win32.Ransomware.Meow.yara
Win32.Ransomware.Monalisa.yara
Win32.Ransomware.Montserrat.yara
Win32.Ransomware.Motocos.yara
Win32.Ransomware.MountLocker.yara
Win32.Ransomware.MRAC.yara
Win32.Ransomware.MZP.yara
Win32.Ransomware.NanoLocker.yara
Win32.Ransomware.NB65.yara
Win32.Ransomware.Nefilim.yara
Win32.Ransomware.Nemty.yara
Win32.Ransomware.Networm.yara
Win32.Ransomware.NotPetya.yara
Win32.Ransomware.Oni.yara
Win32.Ransomware.OphionLocker.yara
Win32.Ransomware.Ouroboros.yara
Win32.Ransomware.Outsider.yara
Win32.Ransomware.Paradise.yara
Win32.Ransomware.Pay2Key.yara
Win32.Ransomware.Petya.yara
Win32.Ransomware.Plague17.yara
Win32.Ransomware.PrincessLocker.yara
Win32.Ransomware.Prometey.yara
Win32.Ransomware.PXJ.yara
Win32.Ransomware.RagnarLocker.yara
Win32.Ransomware.Ragnarok.yara
Win32.Ransomware.Ransoc.yara
Win32.Ransomware.Ransomexx.yara
Win32.Ransomware.RansomPlus.yara
Win32.Ransomware.Redeemer.yara
Win32.Ransomware.RegretLocker.yara
Win32.Ransomware.RetMyData.yara
Win32.Ransomware.Reveton.yara
Win32.Ransomware.Revil.yara
Win32.Ransomware.Rokku.yara
Win32.Ransomware.Ryuk.yara
Win32.Ransomware.Sage.yara
Win32.Ransomware.Sanwai.yara
Win32.Ransomware.Sarbloh.yara
Win32.Ransomware.Satana.yara
Win32.Ransomware.Satan.yara
Win32.Ransomware.Saturn.yara
Win32.Ransomware.Sepsis.yara
Win32.Ransomware.Serpent.yara
Win32.Ransomware.SevenSevenSeven.yara
Win32.Ransomware.ShadowCryptor.yara
Win32.Ransomware.Sherminator.yara
Win32.Ransomware.Sifrelendi.yara
Win32.Ransomware.Sifreli.yara
Win32.Ransomware.Sigrun.yara
Win32.Ransomware.Skystars.yara
Win32.Ransomware.Spora.yara
Win32.Ransomware.TargetCompany.yara
Win32.Ransomware.TBLocker.yara
Win32.Ransomware.TechandStrat.yara
Win32.Ransomware.TeleCrypt.yara
Win32.Ransomware.Termite.yara
Win32.Ransomware.Teslacrypt.yara
Win32.Ransomware.Teslarvng.yara
Win32.Ransomware.Thanatos.yara
Win32.Ransomware.TorrentLocker.yara
Win32.Ransomware.VegaLocker.yara
Win32.Ransomware.Velso.yara
Win32.Ransomware.VHDLocker.yara
Win32.Ransomware.WannaCry.yara
Win32.Ransomware.WaspLocker.yara
Win32.Ransomware.Wastedlocker.yara
Win32.Ransomware.WinWord64.yara
Win32.Ransomware.WsIR.yara
Win32.Ransomware.Xorist.yara
Win32.Ransomware.Zeoticus.yara
Win32.Ransomware.Zeppelin.yara
Win32.Ransomware.ZeroCrypt.yara
Win32.Ransomware.Zhen.yara
Win32.Ransomware.Zoldon.yara
Win32.Trojan.CaddyWiper.yara
Win32.Trojan.Dridex.yara
Win32.Trojan.Emotet.yara
Win32.Trojan.HermeticWiper.yara
Win32.Trojan.IsaacWiper.yara
Win32.Trojan.TrickBot.yara
Win32.Virus.Awfull.yara
Win32.Virus.Cmay.yara
Win32.Virus.DeadCode.yara
Win32.Virus.Elerad.yara
Win32.Virus.Greenp.yara
Win32.Virus.Mocket.yara
Win32.Virus.Negt.yara
Win64.Ransomware.Ako.yara
Win64.Ransomware.AntiWar.yara
Win64.Ransomware.AwesomeScott.yara
Win64.Ransomware.Curator.yara
Win64.Ransomware.DST.yara
Win64.Ransomware.HermeticRansom.yara
Win64.Ransomware.HotCoffee.yara
Win64.Ransomware.Nokoyawa.yara
Win64.Ransomware.Pandora.yara
Win64.Ransomware.RedRoman.yara
Win64.Ransomware.Rook.yara
Win64.Ransomware.SeedLocker.yara
Win64.Ransomware.Seth.yara
Win64.Ransomware.Solaso.yara
Win64.Ransomware.Vovalex.yara
Win64.Ransomware.WhiteBlackCrypt.yara
Win64.Ransomware.Wintenzz.yara
yara_mixed_ext_vars.yar

getting files

┌──(kali㉿kali)-[~/Downloads/loki/Loki-0.45.0/suspicious-files]
└─$ scp cmnatic@10.10.148.188:/home/cmnatic/suspicious-files/file1/* .

cmnatic@10.10.148.188's password: 
ind3x.php                                            100%   79KB  82.5KB/s   00:00    
                                                                                       
┌──(kali㉿kali)-[~/Downloads/loki/Loki-0.45.0/suspicious-files]
└─$ scp cmnatic@10.10.148.188:/home/cmnatic/suspicious-files/file2/* .

cmnatic@10.10.148.188's password: 
1ndex.php                                            100%  219KB 162.3KB/s   00:01    
                                                                                       
┌──(kali㉿kali)-[~/Downloads/loki/Loki-0.45.0/suspicious-files]
└─$ ls
1ndex.php  ind3x.php

┌──(kali㉿kali)-[~/Downloads/loki/Loki-0.45.0/suspicious-files]
└─$ ls                     
1ndex.php  ind3x.php
                                                                                       
┌──(kali㉿kali)-[~/Downloads/loki/Loki-0.45.0/suspicious-files]
└─$ mkdir file1           
                                                                                       
┌──(kali㉿kali)-[~/Downloads/loki/Loki-0.45.0/suspicious-files]
└─$ mv ind3x.php file1        
                                                                                       
┌──(kali㉿kali)-[~/Downloads/loki/Loki-0.45.0/suspicious-files]
└─$ mkdir file2       
                                                                                       
┌──(kali㉿kali)-[~/Downloads/loki/Loki-0.45.0/suspicious-files]
└─$ mv 1ndex.php file2
                                                                                       
┌──(kali㉿kali)-[~/Downloads/loki/Loki-0.45.0/suspicious-files]
└─$ ls
file1  file2
                                                                                       
┌──(kali㉿kali)-[~/Downloads/loki/Loki-0.45.0/suspicious-files]
└─$ cd file1  

┌──(kali㉿kali)-[~/…/loki/Loki-0.45.0/suspicious-files/file1]
└─$ python ../../loki.py -p .

                                                                                       
      __   ____  __ ______                                                             
     / /  / __ \/ //_/  _/                                                             
    / /__/ /_/ / ,< _/ /                                                               
   /____/\____/_/|_/___/                                                               
   YARA and IOC Scanner                                                                
                                                                                       
   by Florian Roth, GNU General Public License                                         
   version 0.44.2 (Python 3 release)                                                   
                                                                                       
   DISCLAIMER - USE AT YOUR OWN RISK                                                   
                                                                                       
                                                                                       
                                                                                       
[NOTICE] Starting Loki Scan VERSION: 0.44.2 SYSTEM: kali TIME: 20221127T19:16:13Z PLATFORM:     PROC:  ARCH: 64bit ELF                                                        
[INFO] File Name Characteristics initialized with 3549 regex patterns                  
[INFO] C2 server indicators initialized with 1666 elements                             
[INFO] Malicious MD5 Hashes initialized with 19235 hashes                              
[INFO] Malicious SHA1 Hashes initialized with 7450 hashes                              
[INFO] Malicious SHA256 Hashes initialized with 23304 hashes                           
[INFO] False Positive Hashes initialized with 30 hashes                                
[INFO] Processing YARA rules folder /home/kali/Downloads/loki/Loki-0.45.0/signature-base/yara                                                                                 
[INFO] Initializing all YARA rules at once (composed string of all rule files)         
[INFO] Initialized 873 Yara rules                                                      
[NOTICE] Program should be run as 'root' to ensure all access rights to process memory and file objects.                                                                      
[INFO] Scanning Path . ...                                                             
[ALERT]                                                                                
FILE: ./ind3x.php SCORE: 260 TYPE: PHP SIZE: 80992                                     
FIRST_BYTES: 3c3f7068700a2f2a0a09623337346b20322e320a / <filter object at 0x7f617d46b220>                                                                                     
MD5: 1606bdac2cb613bf0b8a22690364fbc5                                                  
SHA1: 9383ed4ee7df17193f7a034c3190ecabc9000f9f                                         
SHA256: 5479f8cd1375364770df36e5a18262480a8f9d311e8eedb2c2390ecb233852ad CREATED: Sun Nov 27 14:15:39 2022 MODIFIED: Sun Nov 27 14:11:10 2022 ACCESSED: Sun Nov 27 14:16:21 2022                                                                                     
REASON_1: Yara Rule MATCH: webshell_metaslsoft SUBSCORE: 70                            
DESCRIPTION: Web Shell - file metaslsoft.php REF: - AUTHOR: Florian Roth               
MATCHES: Str1: $buff .= "<tr><td><a href=\"?d=".$pwd."\">[ $folder ]</a></td><td>LINK</t                                                                                      
REASON_2: Yara Rule MATCH: webshell_php_generic SUBSCORE: 70                           
DESCRIPTION: php webshell having some kind of input and some kind of payload. restricted to small files or big ones inclusing suspicious strings REF: - AUTHOR: Arnim Rupp    
MATCHES: Str1: <? Str2: <?php Str3: _REQUEST[ Str4: _SERVER["HTTP_ Str5: eval(e Str6: eval($ Str7: eval(" Str8: exec($ Str9: shell_exec($ Str10: pas ... (truncated)          
[NOTICE] Results: 1 alerts, 0 warnings, 2 notices                                      
[RESULT] Indicators detected!                                                          
[RESULT] Loki recommends checking the elements on virustotal.com or Google and triage with a professional tool like THOR https://nextron-systems.com/thor in corporate networks.                                                                                     
[INFO] Please report false positives via https://github.com/Neo23x0/signature-base     
[NOTICE] Finished LOKI Scan SYSTEM: kali TIME: 20221127T19:16:21Z                      


cmnatic@thm-yara:~/suspicious-files/file1$ python ../../tools/Loki/loki.py -p .
                                                                               
      __   ____  __ ______                                                             
     / /  / __ \/ //_/  _/                                                             
    / /__/ /_/ / ,< _/ /                                                               
   /____/\____/_/|_/___/                                                               
      ________  _____  ____                                                            
     /  _/ __ \/ ___/ / __/______ ____  ___  ___ ____                                  
    _/ // /_/ / /__  _\ \/ __/ _ `/ _ \/ _ \/ -_) __/                                  
   /___/\____/\___/ /___/\__/\_,_/_//_/_//_/\__/_/                                     
                                                                                       
   Copyright by Florian Roth, Released under the GNU General Public License            
   Version 0.32.1                                                                      
                                                                                       
   DISCLAIMER - USE AT YOUR OWN RISK                                                   
   Please report false positives via https://github.com/Neo23x0/Loki/issues            
                                                                                       
                                                                                       
                                                                                       
[NOTICE] Starting Loki Scan VERSION: 0.32.1 SYSTEM: thm-yara TIME: 20221127T19:21:00Z PLATFORM:     PROC: x86_64 ARCH: 64bit                                                  
[NOTICE] Registered plugin PluginWMI                                                   
[NOTICE] Loaded plugin /home/cmnatic/tools/Loki/plugins/loki-plugin-wmi.py             
[NOTICE] PE-Sieve successfully initialized BINARY: /home/cmnatic/tools/Loki/tools/pe-sieve64.exe SOURCE: https://github.com/hasherezade/pe-sieve                              
[INFO] File Name Characteristics initialized with 2841 regex patterns                  
[INFO] C2 server indicators initialized with 1541 elements                             
[INFO] Malicious MD5 Hashes initialized with 19034 hashes                              
[INFO] Malicious SHA1 Hashes initialized with 7159 hashes                              
[INFO] Malicious SHA256 Hashes initialized with 22841 hashes                           
[INFO] False Positive Hashes initialized with 30 hashes                                
[INFO] Processing YARA rules folder /home/cmnatic/tools/Loki/signature-base/yara       
[INFO] Initializing all YARA rules at once (composed string of all rule files)         
[INFO] Initialized 653 Yara rules                                                      
[INFO] Reading private rules from binary ...                                           
[NOTICE] Program should be run as 'root' to ensure all access rights to process memory and file objects.                                                                      
[NOTICE] Running plugin PluginWMI                                                      
[NOTICE] Finished running plugin PluginWMI                                             
[INFO] Scanning . ...                                                                  
[WARNING]                                                                              
FILE: ./ind3x.php SCORE: 70 TYPE: PHP SIZE: 80992                                      
FIRST_BYTES: 3c3f7068700a2f2a0a09623337346b20322e320a / <?php/*b374k 2.2               
MD5: 1606bdac2cb613bf0b8a22690364fbc5                                                  
SHA1: 9383ed4ee7df17193f7a034c3190ecabc9000f9f                                         
SHA256: 5479f8cd1375364770df36e5a18262480a8f9d311e8eedb2c2390ecb233852ad CREATED: Mon Nov  9 15:15:32 2020 MODIFIED: Mon Nov  9 13:06:56 2020 ACCESSED: Sun Nov 27 19:02:01 2022                                                                                     
REASON_1: Yara Rule MATCH: webshell_metaslsoft SUBSCORE: 70                            
DESCRIPTION: Web Shell - file metaslsoft.php REF: -                                    
MATCHES: Str1: $buff .= "<tr><td><a href=\\"?d=".$pwd."\\">[ $folder ]</a></td><td>LINK</t                                                                                    
[NOTICE] Results: 0 alerts, 1 warnings, 7 notices                                      
[RESULT] Suspicious objects detected!                                                  
[RESULT] Loki recommends a deeper analysis of the suspicious objects.                  
[INFO] Please report false positives via https://github.com/Neo23x0/signature-base     
[NOTICE] Finished LOKI Scan SYSTEM: thm-yara TIME: 20221127T19:21:05Z                  
                                                                                       
Press Enter to exit ...   

some nice links

https://xss.js.org/#/xss01

https://github.com/tennc/webshell

http://tennc.github.io/page/2/


cmnatic@thm-yara:~/suspicious-files/file2$ python ../../tools/Loki/loki.py -p .
                                                                               
      __   ____  __ ______                                                             
     / /  / __ \/ //_/  _/                                                             
    / /__/ /_/ / ,< _/ /                                                               
   /____/\____/_/|_/___/                                                               
      ________  _____  ____                                                            
     /  _/ __ \/ ___/ / __/______ ____  ___  ___ ____                                  
    _/ // /_/ / /__  _\ \/ __/ _ `/ _ \/ _ \/ -_) __/                                  
   /___/\____/\___/ /___/\__/\_,_/_//_/_//_/\__/_/                                     
                                                                                       
   Copyright by Florian Roth, Released under the GNU General Public License            
   Version 0.32.1                                                                      
                                                                                       
   DISCLAIMER - USE AT YOUR OWN RISK                                                   
   Please report false positives via https://github.com/Neo23x0/Loki/issues            
                                                                                       
                                                                                       
                                                                                       
[NOTICE] Starting Loki Scan VERSION: 0.32.1 SYSTEM: thm-yara TIME: 20221127T19:54:13Z PLATFORM:     PROC: x86_64 ARCH: 64bit                                                  
[NOTICE] Registered plugin PluginWMI                                                   
[NOTICE] Loaded plugin /home/cmnatic/tools/Loki/plugins/loki-plugin-wmi.py             
[NOTICE] PE-Sieve successfully initialized BINARY: /home/cmnatic/tools/Loki/tools/pe-sieve64.exe SOURCE: https://github.com/hasherezade/pe-sieve                              
[INFO] File Name Characteristics initialized with 2841 regex patterns                  
[INFO] C2 server indicators initialized with 1541 elements                             
[INFO] Malicious MD5 Hashes initialized with 19034 hashes                              
[INFO] Malicious SHA1 Hashes initialized with 7159 hashes                              
[INFO] Malicious SHA256 Hashes initialized with 22841 hashes                           
[INFO] False Positive Hashes initialized with 30 hashes                                
[INFO] Processing YARA rules folder /home/cmnatic/tools/Loki/signature-base/yara       
[INFO] Initializing all YARA rules at once (composed string of all rule files)         
[INFO] Initialized 653 Yara rules                                                      
[INFO] Reading private rules from binary ...                                           
[NOTICE] Program should be run as 'root' to ensure all access rights to process memory and file objects.                                                                      
[NOTICE] Running plugin PluginWMI                                                      
[NOTICE] Finished running plugin PluginWMI                                             
[INFO] Scanning . ...                                                                  
[NOTICE] Results: 0 alerts, 0 warnings, 7 notices                                      
[RESULT] SYSTEM SEEMS TO BE CLEAN.                                                     
[INFO] Please report false positives via https://github.com/Neo23x0/signature-base     
[NOTICE] Finished LOKI Scan SYSTEM: thm-yara TIME: 20221127T19:54:16Z  

┌──(kali㉿kali)-[~/…/loki/Loki-0.45.0/suspicious-files/file2]
└─$ head 1ndex.php                                       
<?php
/*
        b374k shell 3.2.3
        Jayalah Indonesiaku
        (c)2014
        https://github.com/b374k/b374k

*/


```


Scan file 1. Does Loki detect this file as suspicious/malicious or benign?
*suspicious*

What Yara rule did it match on?
*webshell_metaslsoft*
What does Loki classify this file as?
Check description
*Web Shell*

Based on the output, what string within the Yara rule did it match on?
*Str1*

What is the name and version of this hack tool?
Check first_bytes
*b374k 2.2*


Inspect the actual Yara file that flagged file 1. Within this rule, how many strings are there to flag this file?
yara/thor-webshells.yar
*1*


Scan file 2. Does Loki detect this file as suspicious/malicious or benign?
*benign*


Inspect file 2. What is the name and version of this web shell?
*b374k 3.2.3*

### Creating Yara rules with yarGen 

Creating Yara rules with yarGen

From the previous section, we realized that we have a file that Loki didn't flag on. At this point, we are unable to run Loki on other web servers because if file 2 exists in any of the webs servers, it will go undetected.

We need to create a Yara rule to detect this specific web shell in our environment. Typically this is what is done in the case of an incident, which is an event that affects/impacts the organization in a negative fashion.

We can manually open the file and attempt to sift through lines upon lines of code to find possible strings that can be used in our newly created Yara rule.

	Let's check how many lines this particular file has. You can run the following: strings <file name> | wc -l.

```

Using wc to count the amount of lines in the file

           
cmnatic@thm-yara:~/suspicious-files/file2$ strings 1ndex.php | wc -l
3580

        
```

If you try to go through each string, line by line manually, you should quickly realize that this can be a daunting task. 

```

Catting the output of 1ndex.php

           
if(res=='error'){
$('.ulProgress'+ulType+i).html('( failed )');
}
else{
$('.ulRes'+ulType+i).html(res);
}
loading_stop();
},
error: function(){
loading_stop();
$('.ulProgress'+ulType+i).html('( failed )');
$('.ulProgress'+ulType+i).removeClass('ulProgress'+ulType+i);
$('.ulFilename'+ulType+i).removeClass('ulFilename'+ulType+i);
}
});
}

function ul_go(ulType){
ulFile = (ulType=='comp')? $('.ulFileComp'):$('.ulFileUrl');
ulResult = (ulType=='comp')? $('.ulCompResult'):$('.ulUrlResult');
ulResult.html('');

ulFile.each(function(i){
if(((ulType=='comp')&&this.files[0])||((ulType=='url')&&(this.value!=''))){
file = (ulType=='comp')? this.files[0]: this.value;
filename = (ulType=='comp')? file.name: file.substring(file.lastIndexOf('/')+1);

ulSaveTo = (ulType=='comp')? $('.ulSaveToComp')[i].value:$('.ulSaveToUrl')[i].value;
ulFilename = (ulType=='comp')? $('.ulFilenameComp')[i].value:$('.ulFilenameUrl')[i].value;

--snippet cropped for brevity--

        


```

Luckily, we can use [yarGen](https://github.com/Neo23x0/yarGen) (yes, another tool created by Florian Roth) to aid us with this task.

What is yarGen? yarGen is a generator for YARA rules.

From the README - "The main principle is the creation of yara rules from strings found in malware files while removing all strings that also appear in goodware files. Therefore yarGen includes a big goodware strings and opcode database as ZIP archives that have to be extracted before the first use."

Navigate to the yarGen directory, which is within tools. If you are running yarGen on your own system, you need to update it first by running the following command: python3 yarGen.py --update.


This will update the good-opcodes and good-strings DB's from the online repository. This update will take a few minutes. 

 Once it has been updated successfully, you'll see the following message at the end of the output.


```

Updating yarGen

           
cmnatic@thm-yara:~/tools/yarGen$ python3 yarGen.py --update
------------------------------------------------------------------------
                   _____
    __ _____ _____/ ___/__ ___
   / // / _ `/ __/ (_ / -_) _ \
   \_, /\_,_/_/  \___/\__/_//_/
  /___/  Yara Rule Generator
         Florian Roth, July 2020, Version 0.23.3

  Note: Rules have to be post-processed
  See this post for details: https://medium.com/@cyb3rops/121d29322282
------------------------------------------------------------------------
Downloading good-opcodes-part1.db from https://www.bsk-consulting.de/yargen/good-opcodes-part1.db ...

        


```

To use yarGen to generate a Yara rule for file 2, you can run the following command:

python3 yarGen.py -m /home/cmnatic/suspicious-files/file2 --excludegood -o /home/cmnatic/suspicious-files/file2.yar 

A brief explanation of the parameters above:

    -m is the path to the files you want to generate rules for
    --excludegood force to exclude all goodware strings (these are strings found in legitimate software and can increase false positives)
    -o location & name you want to output the Yara rule

If all is well, you should see the following output.

```

Using yarGen to generate a rule for file2

           

           [=] Generated 1 SIMPLE rules.
           [=] All rules written to /home/cmnatic/suspicious-files/file2.yar
           [+] yarGen run finished

        


```

Generally, you would examine the Yara rule and remove any strings that you feel might generate false positives. For this exercise, we will leave the generated Yara rule as is and test to see if Yara will flag file 2 or no. 

Note: Another tool created to assist with this is called [yarAnalyzer](https://github.com/Neo23x0/yarAnalyzer/) (you guessed it - created by Florian Roth). We will not examine that tool in this room, but you should read up on it, especially if you decide to start creating your own Yara rules. 

Further Reading on creating Yara rules and using yarGen:

    https://www.bsk-consulting.de/2015/02/16/write-simple-sound-yara-rules/
    https://www.bsk-consulting.de/2015/10/17/how-to-write-simple-but-sound-yara-rules-part-2/
    https://www.bsk-consulting.de/2016/04/15/how-to-write-simple-but-sound-yara-rules-part-3/


```
┌──(kali㉿kali)-[~/Downloads]
└─$ mkdir yarGen                                       
                                                                                       
┌──(kali㉿kali)-[~/Downloads]
└─$ cd yarGen 
                                                                                       
┌──(kali㉿kali)-[~/Downloads/yarGen]
└─$ git clone https://github.com/Neo23x0/yarGen.git    
Cloning into 'yarGen'...
remote: Enumerating objects: 794, done.
remote: Counting objects: 100% (6/6), done.
remote: Compressing objects: 100% (6/6), done.
remote: Total 794 (delta 1), reused 1 (delta 0), pack-reused 788
Receiving objects: 100% (794/794), 1.15 MiB | 1.91 MiB/s, done.
Resolving deltas: 100% (359/359), done.
                                                                                       
┌──(kali㉿kali)-[~/Downloads/yarGen]
└─$ ls
yarGen
                                                                                       
┌──(kali㉿kali)-[~/Downloads/yarGen]
└─$ cd yarGen 
                                                                                       
┌──(kali㉿kali)-[~/Downloads/yarGen/yarGen]
└─$ ls
3rdparty  prepare-release.sh  requirements.txt  tools
LICENSE   README.md           screens           yarGen.py
                                                                                       
┌──(kali㉿kali)-[~/Downloads/yarGen/yarGen]
└─$ pip install -r requirements.txt
Defaulting to user installation because normal site-packages is not writeable
Collecting scandir
  Downloading scandir-1.10.0.tar.gz (33 kB)
  Preparing metadata (setup.py) ... done
Requirement already satisfied: pefile in /usr/lib/python3/dist-packages (from -r requirements.txt (line 2)) (2022.5.30)
Requirement already satisfied: lxml in /usr/lib/python3/dist-packages (from -r requirements.txt (line 3)) (4.9.1)
Building wheels for collected packages: scandir
  Building wheel for scandir (setup.py) ... done
  Created wheel for scandir: filename=scandir-1.10.0-cp310-cp310-linux_x86_64.whl size=11144 sha256=ae543195f8962636b1fdf2cc71070929e738995c589f17a1eb3b713de11aa81b
  Stored in directory: /home/kali/.cache/pip/wheels/d4/43/07/5543298a8c0e9d6d557c5c46b0175424898b17fa534c66f413
Successfully built scandir
Installing collected packages: scandir
Successfully installed scandir-1.10.0
                                                                                       
┌──(kali㉿kali)-[~/Downloads/yarGen/yarGen]
└─$ ls
3rdparty  prepare-release.sh  requirements.txt  tools
LICENSE   README.md           screens           yarGen.py
                                                                                       
┌──(kali㉿kali)-[~/Downloads/yarGen/yarGen]
└─$ python3 yarGen.py --update     
------------------------------------------------------------------------
                   _____            
    __ _____ _____/ ___/__ ___      
   / // / _ `/ __/ (_ / -_) _ \     
   \_, /\_,_/_/  \___/\__/_//_/     
  /___/  Yara Rule Generator        
         Florian Roth, July 2020, Version 0.23.3
   
  Note: Rules have to be post-processed
  See this post for details: https://medium.com/@cyb3rops/121d29322282
------------------------------------------------------------------------
Downloading good-opcodes-part1.db from https://www.bsk-consulting.de/yargen/good-opcodes-part1.db ...
Downloading good-opcodes-part2.db from https://www.bsk-consulting.de/yargen/good-opcodes-part2.db ...
Downloading good-opcodes-part3.db from https://www.bsk-consulting.de/yargen/good-opcodes-part3.db ...
Downloading good-opcodes-part4.db from https://www.bsk-consulting.de/yargen/good-opcodes-part4.db ...
Downloading good-opcodes-part5.db from https://www.bsk-consulting.de/yargen/good-opcodes-part5.db ...
Downloading good-opcodes-part6.db from https://www.bsk-consulting.de/yargen/good-opcodes-part6.db ...
Downloading good-opcodes-part7.db from https://www.bsk-consulting.de/yargen/good-opcodes-part7.db ...
Downloading good-opcodes-part8.db from https://www.bsk-consulting.de/yargen/good-opcodes-part8.db ...
Downloading good-opcodes-part9.db from https://www.bsk-consulting.de/yargen/good-opcodes-part9.db ...
Downloading good-strings-part1.db from https://www.bsk-consulting.de/yargen/good-strings-part1.db ...
Downloading good-strings-part2.db from https://www.bsk-consulting.de/yargen/good-strings-part2.db ...
Downloading good-strings-part3.db from https://www.bsk-consulting.de/yargen/good-strings-part3.db ...
Downloading good-strings-part4.db from https://www.bsk-consulting.de/yargen/good-strings-part4.db ...
Downloading good-strings-part5.db from https://www.bsk-consulting.de/yargen/good-strings-part5.db ...
Downloading good-strings-part6.db from https://www.bsk-consulting.de/yargen/good-strings-part6.db ...
Downloading good-strings-part7.db from https://www.bsk-consulting.de/yargen/good-strings-part7.db ...
Downloading good-strings-part8.db from https://www.bsk-consulting.de/yargen/good-strings-part8.db ...
Downloading good-strings-part9.db from https://www.bsk-consulting.de/yargen/good-strings-part9.db ...
Downloading good-exports-part1.db from https://www.bsk-consulting.de/yargen/good-exports-part1.db ...
Downloading good-exports-part2.db from https://www.bsk-consulting.de/yargen/good-exports-part2.db ...
Downloading good-exports-part3.db from https://www.bsk-consulting.de/yargen/good-exports-part3.db ...
Downloading good-exports-part4.db from https://www.bsk-consulting.de/yargen/good-exports-part4.db ...
Downloading good-exports-part5.db from https://www.bsk-consulting.de/yargen/good-exports-part5.db ...
Downloading good-exports-part6.db from https://www.bsk-consulting.de/yargen/good-exports-part6.db ...
Downloading good-exports-part7.db from https://www.bsk-consulting.de/yargen/good-exports-part7.db ...
Downloading good-exports-part8.db from https://www.bsk-consulting.de/yargen/good-exports-part8.db ...
Downloading good-exports-part9.db from https://www.bsk-consulting.de/yargen/good-exports-part9.db ...
Downloading good-imphashes-part1.db from https://www.bsk-consulting.de/yargen/good-imphashes-part1.db ...
Downloading good-imphashes-part2.db from https://www.bsk-consulting.de/yargen/good-imphashes-part2.db ...
Downloading good-imphashes-part3.db from https://www.bsk-consulting.de/yargen/good-imphashes-part3.db ...
Downloading good-imphashes-part4.db from https://www.bsk-consulting.de/yargen/good-imphashes-part4.db ...
Downloading good-imphashes-part5.db from https://www.bsk-consulting.de/yargen/good-imphashes-part5.db ...
Downloading good-imphashes-part6.db from https://www.bsk-consulting.de/yargen/good-imphashes-part6.db ...
Downloading good-imphashes-part7.db from https://www.bsk-consulting.de/yargen/good-imphashes-part7.db ...
Downloading good-imphashes-part8.db from https://www.bsk-consulting.de/yargen/good-imphashes-part8.db ...
Downloading good-imphashes-part9.db from https://www.bsk-consulting.de/yargen/good-imphashes-part9.db ...
[+] Updated databases - you can now start creating YARA rules


cmnatic@thm-yara:~/tools/yarGen$ python3 yarGen.py -m /home/cmnatic/suspicious-files/file2 --excludegood -o /home/cmnatic/suspicious-files/file2.yar
------------------------------------------------------------------------
                   _____            
    __ _____ _____/ ___/__ ___      
   / // / _ `/ __/ (_ / -_) _ \     
   \_, /\_,_/_/  \___/\__/_//_/     
  /___/  Yara Rule Generator        
         Florian Roth, July 2020, Version 0.23.3
   
  Note: Rules have to be post-processed
  See this post for details: https://medium.com/@cyb3rops/121d29322282
------------------------------------------------------------------------
[+] Using identifier 'file2'
[+] Using reference 'https://github.com/Neo23x0/yarGen'
[+] Using prefix 'file2'
[+] Processing PEStudio strings ...
[+] Reading goodware strings from database 'good-strings.db' ...
    (This could take some time and uses several Gigabytes of RAM depending on your db size)
[+] Loading ./dbs/good-imphashes-part9.db ...
[+] Total: 1 / Added 1 entries
[+] Loading ./dbs/good-exports-part6.db ...
[+] Total: 8065 / Added 8065 entries
[+] Loading ./dbs/good-imphashes-part2.db ...
[+] Total: 1056 / Added 1055 entries
[+] Loading ./dbs/good-imphashes-part7.db ...
[+] Total: 4648 / Added 3592 entries
[+] Loading ./dbs/good-imphashes-part1.db ...
[+] Total: 6227 / Added 1579 entries
[+] Loading ./dbs/good-imphashes-part6.db ...
[+] Total: 6256 / Added 29 entries
[+] Loading ./dbs/good-exports-part8.db ...
[+] Total: 22192 / Added 14127 entries
[+] Loading ./dbs/good-strings-part1.db ...
[+] Total: 1416757 / Added 1416757 entries
[+] Loading ./dbs/good-imphashes-part3.db ...
[+] Total: 10035 / Added 3779 entries
[+] Loading ./dbs/good-strings-part9.db ...
[+] Total: 1417513 / Added 756 entries
[+] Loading ./dbs/good-strings-part8.db ...
[+] Total: 1699743 / Added 282230 entries
[+] Loading ./dbs/good-strings-part5.db ...
[+] Total: 5764251 / Added 4064508 entries
[+] Loading ./dbs/good-strings-part6.db ...
[+] Total: 6382068 / Added 617817 entries
[+] Loading ./dbs/good-strings-part3.db ...
[+] Total: 9110194 / Added 2728126 entries
[+] Loading ./dbs/good-exports-part4.db ...
[+] Total: 110911 / Added 88719 entries
[+] Loading ./dbs/good-exports-part5.db ...
[+] Total: 236241 / Added 125330 entries
[+] Loading ./dbs/good-imphashes-part5.db ...
[+] Total: 17205 / Added 7170 entries
[+] Loading ./dbs/good-exports-part3.db ...
[+] Total: 279926 / Added 43685 entries
[+] Loading ./dbs/good-strings-part4.db ...
[+] Total: 10459690 / Added 1349496 entries
[+] Loading ./dbs/good-exports-part9.db ...
[+] Total: 279926 / Added 0 entries
[+] Loading ./dbs/good-exports-part2.db ...
[+] Total: 322362 / Added 42436 entries
[+] Loading ./dbs/good-strings-part2.db ...
[+] Total: 11433382 / Added 973692 entries
[+] Loading ./dbs/good-exports-part1.db ...
[+] Total: 381481 / Added 59119 entries
[+] Loading ./dbs/good-exports-part7.db ...
[+] Total: 404321 / Added 22840 entries
[+] Loading ./dbs/good-imphashes-part8.db ...
[+] Total: 17388 / Added 183 entries
[+] Loading ./dbs/good-imphashes-part4.db ...
[+] Total: 19764 / Added 2376 entries
[+] Loading ./dbs/good-strings-part7.db ...
[+] Total: 12284943 / Added 851561 entries
[+] Processing malware files ...
[+] Processing /home/cmnatic/suspicious-files/file2/1ndex.php ...
[+] Generating statistical data ...
[+] Generating Super Rules ... (a lot of foo magic)
[+] Generating Simple Rules ...
[-] Applying intelligent filters to string findings ...
[-] Filtering string set for /home/cmnatic/suspicious-files/file2/1ndex.php ...
[=] Generated 1 SIMPLE rules.
[=] All rules written to /home/cmnatic/suspicious-files/file2.yar
[+] yarGen run finished

cmnatic@thm-yara:~/suspicious-files/file2$ ls
1ndex.php
cmnatic@thm-yara:~/suspicious-files/file2$ cd ..
cmnatic@thm-yara:~/suspicious-files$ ls
file1  file2  file2.yar
cmnatic@thm-yara:~/suspicious-files$ yara file2.yar file2/1ndex.php
_home_cmnatic_suspicious_files_file2_1ndex file2/1ndex.php

cmnatic@thm-yara:~/suspicious-files$ cat file2.yar 
/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2022-11-27
   Identifier: file2
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _home_cmnatic_suspicious_files_file2_1ndex {
   meta:
      description = "file2 - file 1ndex.php"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2022-11-27"
      hash1 = "53fe44b4753874f079a936325d1fdc9b1691956a29c3aaf8643cdbd49f5984bf"
   strings:
      $x1 = "var Zepto=function(){function G(a){return a==null?String(a):z[A.call(a)]||\"object\"}function H(a){return G(a)==\"function\"}fun" ascii
      $s2 = "$cmd = trim(execute(\"ps -p \".$pid));" fullword ascii
      $s3 = "return (res = new RegExp('(?:^|; )' + encodeURIComponent(key) + '=([^;]*)').exec(document.cookie)) ? (res[1]) : null;" fullword ascii
      $s4 = "$cmd = execute(\"taskkill /F /PID \".$pid);" fullword ascii
      $s5 = "$buff = execute(\"wget \".$url.\" -O \".$saveas);" fullword ascii
      $s6 = "(d=\"0\"+d);dt2=y+m+d;return dt1==dt2?0:dt1<dt2?-1:1},r:function(a,b){for(var c=0,e=a.length-1,g=h;g;){for(var g=j,f=c;f<e;++f)0" ascii
      $s7 = "$buff = execute(\"curl \".$url.\" -o \".$saveas);" fullword ascii
      $s8 = "$cmd = execute(\"tasklist /FI \\\"PID eq \".$pid.\"\\\"\");" fullword ascii
      $s9 = "$cmd = execute(\"kill -9 \".$pid);" fullword ascii
      $s10 = "execute(\"tar xzf \\\"\".basename($archive).\"\\\" -C \\\"\".$target.\"\\\"\");" fullword ascii
      $s11 = "execute(\"tar xf \\\"\".basename($archive).\"\\\" -C \\\"\".$target.\"\\\"\");" fullword ascii
      $s12 = "$body = preg_replace(\"/<a href=\\\"http:\\/\\/www.zend.com\\/(.*?)<\\/a>/\", \"\", $body);" fullword ascii
      $s13 = "ngs.mimeType||xhr.getResponseHeader(\"content-type\")),result=xhr.responseText;try{dataType==\"script\"?(1,eval)(result):dataTyp" ascii
      $s14 = "$check = strtolower(execute(\"nodejs -h\"));" fullword ascii
      $s15 = "$check = strtolower(execute(\"ruby -h\"));" fullword ascii
      $s16 = "$buff = execute(\"lwp-download \".$url.\" \".$saveas);" fullword ascii
      $s17 = "$check = strtolower(execute(\"python -h\"));" fullword ascii
      $s18 = "$check = strtolower(execute(\"java -help\"));" fullword ascii
      $s19 = "$check = strtolower(execute(\"javac -help\"));" fullword ascii
      $s20 = "$check = strtolower(execute(\"perl -h\"));" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 700KB and
      1 of ($x*) and 4 of them
}

cmnatic@thm-yara:~/tools/Loki/signature-base/yara$ cp /home/cmnatic/suspicious-files/file2.yar file2.yar

cmnatic@thm-yara:~/suspicious-files/file2$ python ../../tools/Loki/loki.py -p .
                                                                               
      __   ____  __ ______                                                             
     / /  / __ \/ //_/  _/                                                             
    / /__/ /_/ / ,< _/ /                                                               
   /____/\____/_/|_/___/                                                               
      ________  _____  ____                                                            
     /  _/ __ \/ ___/ / __/______ ____  ___  ___ ____                                  
    _/ // /_/ / /__  _\ \/ __/ _ `/ _ \/ _ \/ -_) __/                                  
   /___/\____/\___/ /___/\__/\_,_/_//_/_//_/\__/_/                                     
                                                                                       
   Copyright by Florian Roth, Released under the GNU General Public License            
   Version 0.32.1                                                                      
                                                                                       
   DISCLAIMER - USE AT YOUR OWN RISK                                                   
   Please report false positives via https://github.com/Neo23x0/Loki/issues            
                                                                                       
                                                                                       
                                                                                       
[NOTICE] Starting Loki Scan VERSION: 0.32.1 SYSTEM: thm-yara TIME: 20221127T22:01:48Z PLATFORM:     PROC: x86_64 ARCH: 64bit                                                  
[NOTICE] Registered plugin PluginWMI                                                   
[NOTICE] Loaded plugin /home/cmnatic/tools/Loki/plugins/loki-plugin-wmi.py             
[NOTICE] PE-Sieve successfully initialized BINARY: /home/cmnatic/tools/Loki/tools/pe-sieve64.exe SOURCE: https://github.com/hasherezade/pe-sieve                              
[INFO] File Name Characteristics initialized with 2841 regex patterns                  
[INFO] C2 server indicators initialized with 1541 elements                             
[INFO] Malicious MD5 Hashes initialized with 19034 hashes                              
[INFO] Malicious SHA1 Hashes initialized with 7159 hashes                              
[INFO] Malicious SHA256 Hashes initialized with 22841 hashes                           
[INFO] False Positive Hashes initialized with 30 hashes                                
[INFO] Processing YARA rules folder /home/cmnatic/tools/Loki/signature-base/yara       
[INFO] Initializing all YARA rules at once (composed string of all rule files)         
[INFO] Initialized 654 Yara rules                                                      
[INFO] Reading private rules from binary ...                                           
[NOTICE] Program should be run as 'root' to ensure all access rights to process memory and file objects.                                                                      
[NOTICE] Running plugin PluginWMI                                                      
[NOTICE] Finished running plugin PluginWMI                                             
[INFO] Scanning . ...                                                                  
[WARNING]                                                                              
FILE: ./1ndex.php SCORE: 70 TYPE: PHP SIZE: 223978                                     
FIRST_BYTES: 3c3f7068700a2f2a0a09623337346b207368656c / <?php/*b374k shel              
MD5: c6a7ebafdbe239d65248e2b69b670157                                                  
SHA1: 3926ab64dcf04e87024011cf39902beac32711da                                         
SHA256: 53fe44b4753874f079a936325d1fdc9b1691956a29c3aaf8643cdbd49f5984bf CREATED: Mon Nov  9 15:16:03 2020 MODIFIED: Mon Nov  9 13:09:18 2020 ACCESSED: Sun Nov 27 21:52:55 2022                                                                                     
REASON_1: Yara Rule MATCH: _home_cmnatic_suspicious_files_file2_1ndex SUBSCORE: 70     
DESCRIPTION: file2 - file 1ndex.php REF: https://github.com/Neo23x0/yarGen             
MATCHES: Str1: var Zepto=function(){function G(a){return a==null?String(a):z[A.call(a)]||"object"}function H(a){return G(a)=="function"}fun Str2: $c ... (truncated)          
[NOTICE] Results: 0 alerts, 1 warnings, 7 notices                                      
[RESULT] Suspicious objects detected!                                                  
[RESULT] Loki recommends a deeper analysis of the suspicious objects.                  
[INFO] Please report false positives via https://github.com/Neo23x0/signature-base     
[NOTICE] Finished LOKI Scan SYSTEM: thm-yara TIME: 20221127T22:01:52Z  




```



From within the root of the suspicious files directory, what command would you run to test Yara and your Yara rule against file 2?
Use the same name I called the Yara file to answer this question
*yara file2.yar file2/1ndex.php*


Did Yara rule flag file 2? (Yay/Nay)
*Yay*


Copy the Yara rule you created into the Loki signatures directory.


Test the Yara rule with Loki, does it flag file 2? (Yay/Nay)
*Yay*


What is the name of the variable for the string that it matched on?
Look at $x1
*Zepto*


Inspect the Yara rule, how many strings were generated?
*20*


One of the conditions to match on the Yara rule specifies file size. The file has to be less than what amount?
*700KB*

###  Valhalla 

Valhalla

Valhalla is an online Yara feed created and hosted by [Nextron-Systems](https://www.nextron-systems.com/valhalla/) (erm, Florian Roth). By now, you should be aware of the ridiculous amount of time and energy Florian has dedicated to creating these tools for the community. Maybe we should have just called this the Florian Roth room. (lol)

Per the website, "Valhalla boosts your detection capabilities with the power of thousands of hand-crafted high-quality YARA rules."

https://valhalla.nextron-systems.com/

![](https://assets.tryhackme.com/additional/yara/yara13.png)

From the image above, we should denote that we can conduct searches based on a keyword, tag, ATT&CK technique, sha256, or rule name. 

Note: For more information on ATT&CK, please visit the MITRE room. 

Taking a look at the data provided to us, let's examine the rule in the screenshot below:

![](https://assets.tryhackme.com/additional/yara/yara14.png)

We are provided with the name of the rule, a brief description, a reference link for more information about the rule, along with the rule date. 

Feel free to look at some rules to become familiar with the usefulness of Valhalla. The best way to learn the product is by just jumping right in. 

Picking up from our scenario, at this point, you know that the 2 files are related. Even though Loki classified the files are suspicious, you know in your gut that they are malicious. Hence the reason you created a Yara rule using yarGen to detect it on other web servers. But let's further pretend that you are not code-savvy (FYI - not all security professionals know how to code/script or read it). You need to conduct further research regarding these files to receive approval to eradicate these files from the network. 

Time to use Valhalla for some threat intelligence gathering...

```
cmnatic@thm-yara:~/suspicious-files/file1$ python2 ../../tools/Loki/loki.py -p .
                                                                               
      __   ____  __ ______                                                             
     / /  / __ \/ //_/  _/                                                             
    / /__/ /_/ / ,< _/ /                                                               
   /____/\____/_/|_/___/                                                               
      ________  _____  ____                                                            
     /  _/ __ \/ ___/ / __/______ ____  ___  ___ ____                                  
    _/ // /_/ / /__  _\ \/ __/ _ `/ _ \/ _ \/ -_) __/                                  
   /___/\____/\___/ /___/\__/\_,_/_//_/_//_/\__/_/                                     
                                                                                       
   Copyright by Florian Roth, Released under the GNU General Public License            
   Version 0.32.1                                                                      
                                                                                       
   DISCLAIMER - USE AT YOUR OWN RISK                                                   
   Please report false positives via https://github.com/Neo23x0/Loki/issues            
                                                                                       
                                                                                       
                                                                                       
[NOTICE] Starting Loki Scan VERSION: 0.32.1 SYSTEM: thm-yara TIME: 20221127T22:47:20Z PLATFORM:     PROC: x86_64 ARCH: 64bit                                                  
[NOTICE] Registered plugin PluginWMI                                                   
[NOTICE] Loaded plugin /home/cmnatic/tools/Loki/plugins/loki-plugin-wmi.py             
[NOTICE] PE-Sieve successfully initialized BINARY: /home/cmnatic/tools/Loki/tools/pe-sieve64.exe SOURCE: https://github.com/hasherezade/pe-sieve                              
[INFO] File Name Characteristics initialized with 2841 regex patterns                  
[INFO] C2 server indicators initialized with 1541 elements                             
[INFO] Malicious MD5 Hashes initialized with 19034 hashes                              
[INFO] Malicious SHA1 Hashes initialized with 7159 hashes                              
[INFO] Malicious SHA256 Hashes initialized with 22841 hashes                           
[INFO] False Positive Hashes initialized with 30 hashes                                
[INFO] Processing YARA rules folder /home/cmnatic/tools/Loki/signature-base/yara       
[INFO] Initializing all YARA rules at once (composed string of all rule files)         
[INFO] Initialized 654 Yara rules                                                      
[INFO] Reading private rules from binary ...                                           
[NOTICE] Program should be run as 'root' to ensure all access rights to process memory and file objects.                                                                      
[NOTICE] Running plugin PluginWMI                                                      
[NOTICE] Finished running plugin PluginWMI                                             
[INFO] Scanning . ...                                                                  
[WARNING]                                                                              
FILE: ./ind3x.php SCORE: 70 TYPE: PHP SIZE: 80992                                      
FIRST_BYTES: 3c3f7068700a2f2a0a09623337346b20322e320a / <?php/*b374k 2.2               
MD5: 1606bdac2cb613bf0b8a22690364fbc5                                                  
SHA1: 9383ed4ee7df17193f7a034c3190ecabc9000f9f                                         
SHA256: 5479f8cd1375364770df36e5a18262480a8f9d311e8eedb2c2390ecb233852ad CREATED: Mon Nov  9 15:15:32 2020 MODIFIED: Mon Nov  9 13:06:56 2020 ACCESSED: Sun Nov 27 22:47:24 2022                                                                                     
REASON_1: Yara Rule MATCH: webshell_metaslsoft SUBSCORE: 70                            
DESCRIPTION: Web Shell - file metaslsoft.php REF: -                                    
MATCHES: Str1: $buff .= "<tr><td><a href=\\"?d=".$pwd."\\">[ $folder ]</a></td><td>LINK</t                                                                                    
[NOTICE] Results: 0 alerts, 1 warnings, 7 notices                                      
[RESULT] Suspicious objects detected!                                                  
[RESULT] Loki recommends a deeper analysis of the suspicious objects.                  
[INFO] Please report false positives via https://github.com/Neo23x0/signature-base     
[NOTICE] Finished LOKI Scan SYSTEM: thm-yara TIME: 20221127T22:47:24Z                  
                                                                                       
Press Enter to exit ...                         

SHA256: 5479f8cd1375364770df36e5a18262480a8f9d311e8eedb2c2390ecb233852ad
Chinese APT Group

C6A7EBAFDBE239D65248E2B69B670157.exe

https://github.com/b374k/b374k

/* JAVASCRIPT AND CSS FILES START */
$zepto_code = packer_read_file($GLOBALS['packer']['base_dir']."zepto.js");


```

![[Pasted image 20221127174955.png]]
![[Pasted image 20221127175021.png]]

Enter the SHA256 hash of file 1 into Valhalla. Is this file attributed to an APT group? (Yay/Nay)
*Yay*

![[Pasted image 20221127175458.png]]

Do the same for file 2. What is the name of the first Yara rule to detect file 2?
*Webshell_b374k_rule1*

![[Pasted image 20221127175621.png]]
![[Pasted image 20221127175633.png]]

Examine the information for file 2 from Virus Total (VT). The Yara Signature Match is from what scanner?
This information is on the Community tab of the VirusTotal page, and not on the Detection tab.
*THOR APT Scanner

![[Pasted image 20221127175744.png]]

Enter the SHA256 hash of file 2 into Virus Total. Did every AV detect this as malicious? (Yay/Nay)
*Nay*


Besides .PHP, what other extension is recorded for this file?
Look under the "details" tab in Virustotal to find out the extensions for this submission. 
*exe*

What JavaScript library is used by file 2?
Go to the Github page and search inside the index.php file
*Zepto*

Is this Yara rule in the default Yara file Loki uses to detect these type of hack tools? (Yay/Nay)
Examine thor-webshell.yar and search for the rule name
*Nay*

###  Conclusion 

In this room, we explored Yara, how to use Yara, and manually created basic Yara rules. We also explored various open-source tools to hit the ground running that utilizes Yara rules to detect evil on endpoints.

By going through the room scenario, you should understand the need (as a blue teamer) to know how to create Yara rules effectively if we rely on such tools. Commercial products, even though not perfect, will have a much richer Yara ruleset than an open-source product. Both commercial and open-source will allow you to add Yara rules to expand its capabilities further to detect threats. 

If it is not clear, the reason why file 2 was not detected is that the Yara rule was not in the Yara file used by Loki to detect the hack tool (web shell) even though its the hack tool has been around for years and has even been attributed to at least 1 nation-state. The Yara rule is present in the commercial variant of Loki, which is Thor. 

There is more that can be done with Yara and Yara rules. We encourage you to explore this tool further at your own leisure. 


[[Autopsy]]