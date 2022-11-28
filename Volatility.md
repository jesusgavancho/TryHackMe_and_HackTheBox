---
Learn how to perform memory forensics with Volatility!
---

![](https://assets.tryhackme.com/room-banners/volatility.png)

### Introduction 

Volatility is a free memory forensics tool developed and maintained by Volatility Foundation, commonly used by malware and SOC analysts within a blue team or as part of their detection and monitoring solutions. Volatility is written in Python and is made up of python plugins and modules designed as a plug-and-play way of analyzing memory dumps.

Volatility is available for Windows, Linux, and Mac OS and is written purely in Python.

Security Operations Center (SOC) is a team of IT security professionals tasked with monitoring, preventing , detecting , investigating, and responding to threats within a company’s network and systems. 

![333](https://i.imgur.com/5uximLP.png)

This room uses memory dumps from THM rooms and memory samples from Volatility Foundation.

Before completing this room, we recommend completing the Core Windows Processes room.

If you plan on using your own machine or the AttackBox to run Volatility, download the files attached to this task. If you plan to use the provided machine, you can deploy it in Task 3.

### Volatility Overview 

From the Volatility Foundation Wiki, "Volatility is the world's most widely used framework for extracting digital artifacts from volatile memory (RAM) samples. The extraction techniques are performed completely independent of the system being investigated but offer visibility into the runtime state of the system. The framework is intended to introduce people to the techniques and complexities associated with extracting digital artifacts from volatile memory samples and provide a platform for further work into this exciting area of research."

Volatility is built off of multiple plugins working together to obtain information from the memory dump. To begin analyzing a dump, you will first need to identify the image type; there are multiple ways of identifying this information that we will cover further in later tasks. Once you have your image type and other plugins sorted, you can then begin analyzing the dump by using various volatility plugins against it that will be covered in depth later in this room.

Since Volatility is entirely independent of the system under investigation, this allows complete segmentation but full insight into the runtime state of the system.

At the time of writing, there are two main repositories for Volatility; one built off of python 2 and another built off python 3. For this room, we recommend using the Volatility3 version build off of python 3. https://github.com/volatilityfoundation/volatility3

Note: When reading blog posts and articles about Volatility, you may see volatility2 syntax mentioned or used, all syntax changed in volatility3, and within this room, we will be using the most recent version of the plugin syntax for Volatility.

### Installing Volatility 

```
┌──(kali㉿kali)-[~]
└─$ mkdir volatility
                                                                                       
┌──(kali㉿kali)-[~]
└─$ cd volatility          
                                                                                       
┌──(kali㉿kali)-[~/volatility]
└─$ ls               
                                                                                       
┌──(kali㉿kali)-[~/volatility]
└─$ git clone https://github.com/volatilityfoundation/volatility3.git
Cloning into 'volatility3'...
remote: Enumerating objects: 28935, done.
remote: Counting objects: 100% (193/193), done.
remote: Compressing objects: 100% (110/110), done.
remote: Total 28935 (delta 98), reused 154 (delta 81), pack-reused 28742
Receiving objects: 100% (28935/28935), 5.58 MiB | 5.90 MiB/s, done.
Resolving deltas: 100% (21930/21930), done.
                                                                                       
┌──(kali㉿kali)-[~/volatility]
└─$ ls
volatility3
                                                                                       
┌──(kali㉿kali)-[~/volatility]
└─$ cd volatility3 
                                                                                       
┌──(kali㉿kali)-[~/volatility/volatility3]
└─$ ls
API_CHANGES.md  mypy.ini                  setup.py     volshell.spec
development     README.md                 test         vol.spec
doc             requirements-dev.txt      volatility3
LICENSE.txt     requirements-minimal.txt  vol.py
MANIFEST.in     requirements.txt          volshell.py
                                                                                       
┌──(kali㉿kali)-[~/volatility/volatility3]
└─$ pip install -r requirements.txt 

┌──(kali㉿kali)-[~/volatility/volatility3]
└─$ python3 vol.py -h
Volatility 3 Framework 2.4.1
usage: volatility [-h] [-c CONFIG] [--parallelism [{processes,threads,off}]]
                  [-e EXTEND] [-p PLUGIN_DIRS] [-s SYMBOL_DIRS] [-v] [-l LOG]
                  [-o OUTPUT_DIR] [-q] [-r RENDERER] [-f FILE] [--write-config]
                  [--save-config SAVE_CONFIG] [--clear-cache]
                  [--cache-path CACHE_PATH] [--offline]
                  [--single-location SINGLE_LOCATION] [--stackers [STACKERS ...]]
                  [--single-swap-locations [SINGLE_SWAP_LOCATIONS ...]]
                  plugin ...

An open-source memory forensics framework

options:
  -h, --help            Show this help message and exit, for specific plugin options
                        use 'volatility <pluginname> --help'
  -c CONFIG, --config CONFIG
                        Load the configuration from a json file
  --parallelism [{processes,threads,off}]
                        Enables parallelism (defaults to off if no argument given)
  -e EXTEND, --extend EXTEND
                        Extend the configuration with a new (or changed) setting
  -p PLUGIN_DIRS, --plugin-dirs PLUGIN_DIRS
                        Semi-colon separated list of paths to find plugins
  -s SYMBOL_DIRS, --symbol-dirs SYMBOL_DIRS
                        Semi-colon separated list of paths to find symbols
  -v, --verbosity       Increase output verbosity
  -l LOG, --log LOG     Log output to a file as well as the console
  -o OUTPUT_DIR, --output-dir OUTPUT_DIR
                        Directory in which to output any generated files
  -q, --quiet           Remove progress feedback
  -r RENDERER, --renderer RENDERER
                        Determines how to render the output (quick, none, csv,
                        pretty, json, jsonl)
  -f FILE, --file FILE  Shorthand for --single-location=file:// if single-location is
                        not defined
  --write-config        Write configuration JSON file out to config.json
  --save-config SAVE_CONFIG
                        Save configuration JSON file to a file
  --clear-cache         Clears out all short-term cached items
  --cache-path CACHE_PATH
                        Change the default path (/home/kali/.cache/volatility3) used
                        to store the cache
  --offline             Do not search online for additional JSON files
  --single-location SINGLE_LOCATION
                        Specifies a base location on which to stack
  --stackers [STACKERS ...]
                        List of stackers
  --single-swap-locations [SINGLE_SWAP_LOCATIONS ...]
                        Specifies a list of swap layer URIs for use with single-
                        location

Plugins:
  For plugin specific options, run 'volatility <plugin> --help'

  plugin
    banners.Banners     Attempts to identify potential linux banners in an image
    configwriter.ConfigWriter
                        Runs the automagics and both prints and outputs configuration
                        in the output directory.
    frameworkinfo.FrameworkInfo
                        Plugin to list the various modular components of Volatility
    isfinfo.IsfInfo     Determines information about the currently available ISF
                        files, or a specific one
    layerwriter.LayerWriter
                        Runs the automagics and writes out the primary layer produced
                        by the stacker.
    linux.bash.Bash     Recovers bash command history from memory.
    linux.check_afinfo.Check_afinfo
                        Verifies the operation function pointers of network
                        protocols.
    linux.check_creds.Check_creds
                        Checks if any processes are sharing credential structures
    linux.check_idt.Check_idt
                        Checks if the IDT has been altered
    linux.check_modules.Check_modules
                        Compares module list to sysfs info, if available
    linux.check_syscall.Check_syscall
                        Check system call table for hooks.
    linux.elfs.Elfs     Lists all memory mapped ELF files for all processes.
    linux.keyboard_notifiers.Keyboard_notifiers
                        Parses the keyboard notifier call chain
    linux.kmsg.Kmsg     Kernel log buffer reader
    linux.lsmod.Lsmod   Lists loaded kernel modules.
    linux.lsof.Lsof     Lists all memory maps for all processes.
    linux.malfind.Malfind
                        Lists process memory ranges that potentially contain injected
                        code.
    linux.mountinfo.MountInfo
                        Lists mount points on processes mount namespaces
    linux.proc.Maps     Lists all memory maps for all processes.
    linux.psaux.PsAux   Lists processes with their command line arguments
    linux.pslist.PsList
                        Lists the processes present in a particular linux memory
                        image.
    linux.pstree.PsTree
                        Plugin for listing processes in a tree based on their parent
                        process ID.
    linux.tty_check.tty_check
                        Checks tty devices for hooks
    mac.bash.Bash       Recovers bash command history from memory.
    mac.check_syscall.Check_syscall
                        Check system call table for hooks.
    mac.check_sysctl.Check_sysctl
                        Check sysctl handlers for hooks.
    mac.check_trap_table.Check_trap_table
                        Check mach trap table for hooks.
    mac.ifconfig.Ifconfig
                        Lists network interface information for all devices
    mac.kauth_listeners.Kauth_listeners
                        Lists kauth listeners and their status
    mac.kauth_scopes.Kauth_scopes
                        Lists kauth scopes and their status
    mac.kevents.Kevents
                        Lists event handlers registered by processes
    mac.list_files.List_Files
                        Lists all open file descriptors for all processes.
    mac.lsmod.Lsmod     Lists loaded kernel modules.
    mac.lsof.Lsof       Lists all open file descriptors for all processes.
    mac.malfind.Malfind
                        Lists process memory ranges that potentially contain injected
                        code.
    mac.mount.Mount     A module containing a collection of plugins that produce data
                        typically found in Mac's mount command
    mac.netstat.Netstat
                        Lists all network connections for all processes.
    mac.proc_maps.Maps  Lists process memory ranges that potentially contain injected
                        code.
    mac.psaux.Psaux     Recovers program command line arguments.
    mac.pslist.PsList   Lists the processes present in a particular mac memory image.
    mac.pstree.PsTree   Plugin for listing processes in a tree based on their parent
                        process ID.
    mac.socket_filters.Socket_filters
                        Enumerates kernel socket filters.
    mac.timers.Timers   Check for malicious kernel timers.
    mac.trustedbsd.Trustedbsd
                        Checks for malicious trustedbsd modules
    mac.vfsevents.VFSevents
                        Lists processes that are filtering file system events
    timeliner.Timeliner
                        Runs all relevant plugins that provide time related
                        information and orders the results by time.
    windows.bigpools.BigPools
                        List big page pools.
    windows.cachedump.Cachedump
                        Dumps lsa secrets from memory
    windows.callbacks.Callbacks
                        Lists kernel callbacks and notification routines.
    windows.cmdline.CmdLine
                        Lists process command line arguments.
    windows.crashinfo.Crashinfo
    windows.devicetree.DeviceTree
                        Listing tree based on drivers and attached devices in a
                        particular windows memory image.
    windows.dlllist.DllList
                        Lists the loaded modules in a particular windows memory
                        image.
    windows.driverirp.DriverIrp
                        List IRPs for drivers in a particular windows memory image.
    windows.driverscan.DriverScan
                        Scans for drivers present in a particular windows memory
                        image.
    windows.dumpfiles.DumpFiles
                        Dumps cached file contents from Windows memory samples.
    windows.envars.Envars
                        Display process environment variables
    windows.filescan.FileScan
                        Scans for file objects present in a particular windows memory
                        image.
    windows.getservicesids.GetServiceSIDs
                        Lists process token sids.
    windows.getsids.GetSIDs
                        Print the SIDs owning each process
    windows.handles.Handles
                        Lists process open handles.
    windows.hashdump.Hashdump
                        Dumps user hashes from memory
    windows.info.Info   Show OS & kernel details of the memory sample being analyzed.
    windows.joblinks.JobLinks
                        Print process job link information
    windows.ldrmodules.LdrModules
    windows.lsadump.Lsadump
                        Dumps lsa secrets from memory
    windows.malfind.Malfind
                        Lists process memory ranges that potentially contain injected
                        code.
    windows.mbrscan.MBRScan
                        Scans for and parses potential Master Boot Records (MBRs)
    windows.memmap.Memmap
                        Prints the memory map
    windows.mftscan.MFTScan
                        Scans for MFT FILE objects present in a particular windows
                        memory image.
    windows.modscan.ModScan
                        Scans for modules present in a particular windows memory
                        image.
    windows.modules.Modules
                        Lists the loaded kernel modules.
    windows.mutantscan.MutantScan
                        Scans for mutexes present in a particular windows memory
                        image.
    windows.netscan.NetScan
                        Scans for network objects present in a particular windows
                        memory image.
    windows.netstat.NetStat
                        Traverses network tracking structures present in a particular
                        windows memory image.
    windows.poolscanner.PoolScanner
                        A generic pool scanner plugin.
    windows.privileges.Privs
                        Lists process token privileges
    windows.pslist.PsList
                        Lists the processes present in a particular windows memory
                        image.
    windows.psscan.PsScan
                        Scans for processes present in a particular windows memory
                        image.
    windows.pstree.PsTree
                        Plugin for listing processes in a tree based on their parent
                        process ID.
    windows.registry.certificates.Certificates
                        Lists the certificates in the registry's Certificate Store.
    windows.registry.hivelist.HiveList
                        Lists the registry hives present in a particular memory
                        image.
    windows.registry.hivescan.HiveScan
                        Scans for registry hives present in a particular windows
                        memory image.
    windows.registry.printkey.PrintKey
                        Lists the registry keys under a hive or specific key value.
    windows.registry.userassist.UserAssist
                        Print userassist registry keys and information.
    windows.sessions.Sessions
                        lists Processes with Session information extracted from
                        Environmental Variables
    windows.skeleton_key_check.Skeleton_Key_Check
                        Looks for signs of Skeleton Key malware
    windows.ssdt.SSDT   Lists the system call table.
    windows.statistics.Statistics
    windows.strings.Strings
                        Reads output from the strings command and indicates which
                        process(es) each string belongs to.
    windows.svcscan.SvcScan
                        Scans for windows services.
    windows.symlinkscan.SymlinkScan
                        Scans for links present in a particular windows memory image.
    windows.vadinfo.VadInfo
                        Lists process memory ranges.
    windows.vadyarascan.VadYaraScan
                        Scans all the Virtual Address Descriptor memory maps using
                        yara.
    windows.verinfo.VerInfo
                        Lists version information from PE files.
    windows.virtmap.VirtMap
                        Lists virtual mapped sections.
    yarascan.YaraScan   Scans kernel memory using yara rules (string or file).

We have an Ubuntu machine with Volatility and Volatility 3 already present in the /opt directory, along with all the memory files you need throughout this room. The machine will start in a split-screen view. In case the VM is not visible, use the blue Show Split View button at the top-right of the page.

IP Address: 10.10.73.242

Username: thmanalyst

Password: infected
```

###  Memory Extraction 

Extracting a memory dump can be performed in numerous ways, varying based on the requirements of your investigation. Listed below are a few of the techniques and tools that can be used to extract a memory from a bare-metal machine.

    FTK Imager
    Redline
    DumpIt.exe
    win32dd.exe / win64dd.exe
    Memoryze
    FastDump

When using an extraction tool on a bare-metal host, it can usually take a considerable amount of time; take this into consideration during your investigation if time is a constraint.

Most of the tools mentioned above for memory extraction will output a .raw file with some exceptions like Redline that can use its own agent and session structure.

![](https://i.imgur.com/AbgGsci.png)

For virtual machines, gathering a memory file can easily be done by collecting the virtual memory file from the host machine’s drive. This file can change depending on the hypervisor used; listed below are a few of the hypervisor virtual memory files you may encounter.

    VMWare - .vmem
    Hyper-V - .bin
    Parallels - .mem
    VirtualBox - .sav file *this is only a partial memory file

Exercise caution whenever attempting to extract or move memory from both bare-metal and virtual machines.

```
┌──(kali㉿kali)-[~/volatility/volatility3]
└─$ unzip 'Practical Investigation Memory Files.zip' 
Archive:  Practical Investigation Memory Files.zip
  inflating: Investigation-1.vmem    

  inflating: Investigation-2.raw     
                                                                                       
┌──(kali㉿kali)-[~/volatility/volatility3]
└─$ 
                                                                                       
┌──(kali㉿kali)-[~/volatility/volatility3]
└─$ ls
 API_CHANGES.md         mypy.ini                                    test
 development           'Practical Investigation Memory Files.zip'   volatility3
 doc                    README.md                                   vol.py
 Investigation-1.vmem   requirements-dev.txt                        volshell.py
 Investigation-2.raw    requirements-minimal.txt                    volshell.spec
 LICENSE.txt            requirements.txt                            vol.spec
 MANIFEST.in            setup.py
                                                                                       
┌──(kali㉿kali)-[~/volatility/volatility3]
└─$ ls -lah
total 1.1G
drwxr-xr-x 8 kali kali 4.0K Nov 27 19:19  .
drwxr-xr-x 3 kali kali 4.0K Nov 27 19:12  ..
-rw-r--r-- 1 kali kali 1.4K Nov 27 19:12  API_CHANGES.md
drwxr-xr-x 3 kali kali 4.0K Nov 27 19:12  development
drwxr-xr-x 3 kali kali 4.0K Nov 27 19:12  doc
drwxr-xr-x 8 kali kali 4.0K Nov 27 19:12  .git
drwxr-xr-x 4 kali kali 4.0K Nov 27 19:12  .github
-rw-r--r-- 1 kali kali  514 Nov 27 19:12  .gitignore
-rw-r--r-- 1 kali kali 512M Mar 12  2021  Investigation-1.vmem
-rw-r--r-- 1 kali kali 512M May 13  2017  Investigation-2.raw

```

### Plugins Overview 

Operating System (OS) is a layer between the hardware and the applications. From the application's perspective, the OS provides an interface to access the different hardware components, such as CPU, RAM, and disk storage. Examples of OS are Android, FreeBSD, Linux, macOS, and Windows. 

Since converting to Python 3, the plugin structure for Volatility has changed quite drastically. In previous Volatility versions, you would need to identify a specific OS profile exact to the operating system and build version of the host, which could be hard to find or used with a plugin that could provide false positives. With Volatility3, profiles have been scrapped, and Volatility will automatically identify the host and build of the memory file.

The naming structure of plugins has also changed. In previous versions of Volatility, the naming convention has been simply the name of the plugin and was universal for all operating systems and profiles. Now with Volatility3, you need to specify the operating system prior to specifying the plugin to be used, for example, windows.info vs linux.info. This is because there are no longer profiles to distinguish between various operating systems for plugins as each operating system has drastically different memory structures and operations. Look below for options of operating system plugin syntax.

    .windows
    .linux
    .mac

There are several plugins available with Volatility as well as third-party plugins; we will only be covering a small portion of the plugins that Volatility has to offer.

To get familiar with the plugins available, utilize the help menu. As Volatility3 is currently in active development, there is still a short list of plugins compared to its python 2 counterpart; however, the current list still allows you to do all of your analysis as needed.

### Identifying Image Info and Profiles 

By default, Volatility comes with all existing Windows profiles from Windows XP to Windows 10.

Image profiles can be hard to determine if you don't know exactly what version and build the machine you extracted a memory dump from was. In some cases, you may be given a memory file with no other context, and it is up to you to figure out where to go from there. In that case, Volatility has your back and comes with the imageinfo plugin. This plugin will take the provided memory dump and assign it a list of the best possible OS profiles. OS profiles have since been deprecated with Volatility3, so we will only need to worry about identifying the profile if using Volatility2; this makes life much easier for analyzing memory dumps.

Note: imageinfo is not always correct and can have varied results depending on the provided dump; use with caution and test multiple profiles from the provided list.

If we are still looking to get information about what the host is running from the memory dump, we can use the following three plugins windows.info linux.info mac.info. This plugin will provide information about the host from the memory dump.

	Syntax: python3 vol.py -f <file> windows.info


```

──(kali㉿kali)-[~/volatility/volatility3]
└─$ python3 vol.py -f Investigation-1.vmem windows.info 
Volatility 3 Framework 2.4.1


Progress:   99.99               Reading Symbol layer                                   Progress:  100.00               PDB scanning finished                                                                                              
Variable        Value

Kernel Base     0x804d7000
DTB     0x2fe000
Symbols file:///home/kali/volatility/volatility3/volatility3/symbols/windows/ntkrnlpa.pdb/30B5FB31AE7E4ACAABA750AA241FF331-1.json.xz
Is64Bit False
IsPAE   True
layer_name      0 WindowsIntelPAE
memory_layer    1 FileLayer
KdDebuggerDataBlock     0x80545ae0
NTBuildLab      2600.xpsp.080413-2111
CSDVersion      3
KdVersionBlock  0x80545ab8
Major/Minor     15.2600
MachineType     332
KeNumberProcessors      1
SystemTime      2012-07-22 02:45:08
NtSystemRoot    C:\WINDOWS
NtProductType   NtProductWinNt
NtMajorVersion  5
NtMinorVersion  1
PE MajorOperatingSystemVersion  5
PE MinorOperatingSystemVersion  1
PE Machine      332
PE TimeDateStamp        Sun Apr 13 18:31:06 2008


thmanalyst@ubuntu:/opt/volatility3$ python3 vol.py -f dump.vmem windows.info
Volatility 3 Framework 1.0.1
Progress:  100.00               PDB scanning finished                     
Variable        Value

Kernel Base     0x804d7000
DTB     0x2fe000
Symbols file:///opt/volatility3/volatility3/symbols/windows/ntkrnlpa.pdb/30B5FB31AE7E4ACAABA750AA241FF331-1.json.xz
Is64Bit False
IsPAE   True
primary 0 WindowsIntelPAE
memory_layer    1 FileLayer
KdDebuggerDataBlock     0x80545ae0
NTBuildLab      2600.xpsp.080413-2111
CSDVersion      3
KdVersionBlock  0x80545ab8
Major/Minor     15.2600
MachineType     332
KeNumberProcessors      1
SystemTime      2012-07-22 02:45:08
NtSystemRoot    C:\WINDOWS
NtProductType   NtProductWinNt
NtMajorVersion  5
NtMinorVersion  1
PE MajorOperatingSystemVersion  5
PE MinorOperatingSystemVersion  1
PE Machine      332
PE TimeDateStamp        Sun Apr 13 18:31:06 2008


```

### Listing Processes and Connections 

Five different plugins within Volatility allow you to dump processes and network connections, each with varying techniques used. In this task, we will be discussing each and its pros and cons when it comes to evasion techniques used by adversaries.

The most basic way of listing processes is using pslist; this plugin will get the list of processes from the doubly-linked list that keeps track of processes in memory, equivalent to the process list in task manager. The output from this plugin will include all current processes and terminated processes with their exit times.

	Syntax: python3 vol.py -f <file> windows.pslist

Some malware, typically rootkits, will, in an attempt to hide their processes, unlink itself from the list. By unlinking themselves from the list you will no longer see their processes when using pslist. To combat this evasion technique, we can use psscan;this technique of listing processes will locate processes by finding data structures that match _EPROCESS. While this technique can help with evasion countermeasures, it can also cause false positives.

	Syntax: python3 vol.py -f <file> windows.psscan

The third process plugin, pstree, does not offer any other kind of special techniques to help identify evasion like the last two plugins; however, this plugin will list all processes based on their parent process ID, using the same methods as pslist. This can be useful for an analyst to get a full story of the processes and what may have been occurring at the time of extraction.

	Syntax: python3 vol.py -f <file> windows.pstree

Now that we know how to identify processes, we also need to have a way to identify the network connections present at the time of extraction on the host machine. netstat will attempt to identify all memory structures with a network connection.

	Syntax: python3 vol.py -f <file> windows.netstat

Packet capture (PCAP) is a networking practice involving the interception of data packets travelling over a network. Once the packets are captured, they can be stored by IT teams for further analysis. The inspection of these packets allows IT teams to identify issues and solve network problems affecting daily operations. 

This command in the current state of volatility3 can be very unstable, particularly around old Windows builds. To combat this, you can utilize other tools like bulk_extractor to extract a PCAP file from the memory file. In some cases, this is preferred in network connections that you cannot identify from Volatility alone. https://tools.kali.org/forensics/bulk-extractor

The last plugin we will cover is dlllist. This plugin will list all DLLs associated with processes at the time of extraction. This can be especially useful once you have done further analysis and can filter output to a specific DLL that might be an indicator for a specific type of malware you believe to be present on the system.

	Syntax: python3 vol.py -f <file> windows.dlllist


```
thmanalyst@ubuntu:/opt/volatility3$ python3 vol.py -f dump.vmem windows.pslist
Volatility 3 Framework 1.0.1
Progress:  100.00               PDB scanning finished                     
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64 CreateTime       ExitTime        File output

4       0       System  0x823c89c8      53      240     N/A     False   N/A     N/A   Disabled
368     4       smss.exe        0x822f1020      3       19      N/A     False   2012-07-22 02:42:31.000000     N/A     Disabled
584     368     csrss.exe       0x822a0598      9       326     0       False   2012-07-22 02:42:32.000000     N/A     Disabled
608     368     winlogon.exe    0x82298700      23      519     0       False   2012-07-22 02:42:32.000000     N/A     Disabled
652     608     services.exe    0x81e2ab28      16      243     0       False   2012-07-22 02:42:32.000000     N/A     Disabled
664     608     lsass.exe       0x81e2a3b8      24      330     0       False   2012-07-22 02:42:32.000000     N/A     Disabled
824     652     svchost.exe     0x82311360      20      194     0       False   2012-07-22 02:42:33.000000     N/A     Disabled
908     652     svchost.exe     0x81e29ab8      9       226     0       False   2012-07-22 02:42:33.000000     N/A     Disabled
1004    652     svchost.exe     0x823001d0      64      1118    0       False   2012-07-22 02:42:33.000000     N/A     Disabled
1056    652     svchost.exe     0x821dfda0      5       60      0       False   2012-07-22 02:42:33.000000     N/A     Disabled
1220    652     svchost.exe     0x82295650      15      197     0       False   2012-07-22 02:42:35.000000     N/A     Disabled
1484    1464    explorer.exe    0x821dea70      17      415     0       False   2012-07-22 02:42:36.000000     N/A     Disabled
1512    652     spoolsv.exe     0x81eb17b8      14      113     0       False   2012-07-22 02:42:36.000000     N/A     Disabled
1640    1484    reader_sl.exe   0x81e7bda0      5       39      0       False   2012-07-22 02:42:36.000000     N/A     Disabled
788     652     alg.exe 0x820e8da0      7       104     0       False   2012-07-22 02:43:01.000000     N/A     Disabled
1136    1004    wuauclt.exe     0x821fcda0      8       173     0       False   2012-07-22 02:43:46.000000     N/A     Disabled
1588    1004    wuauclt.exe     0x8205bda0      5       132     0       False   2012-07-22 02:44:01.000000     N/A     Disabled


thmanalyst@ubuntu:/opt/volatility3$ python3 vol.py -f dump.vmem windows.psscan
Volatility 3 Framework 1.0.1
Progress:  100.00               PDB scanning finished                     
PID     PPID    ImageFileName   Offset  Threads Handles SessionId       Wow64   CreateTime     ExitTime        File output

908     652     svchost.exe     0x2029ab8       9       226     0       False   2012-07-22 02:42:33.000000     N/A     Disabled
664     608     lsass.exe       0x202a3b8       24      330     0       False   2012-07-22 02:42:32.000000     N/A     Disabled
652     608     services.exe    0x202ab28       16      243     0       False   2012-07-22 02:42:32.000000     N/A     Disabled
1640    1484    reader_sl.exe   0x207bda0       5       39      0       False   2012-07-22 02:42:36.000000     N/A     Disabled
1512    652     spoolsv.exe     0x20b17b8       14      113     0       False   2012-07-22 02:42:36.000000     N/A     Disabled
1588    1004    wuauclt.exe     0x225bda0       5       132     0       False   2012-07-22 02:44:01.000000     N/A     Disabled
788     652     alg.exe 0x22e8da0       7       104     0       False   2012-07-22 02:43:01.000000     N/A     Disabled
1484    1464    explorer.exe    0x23dea70       17      415     0       False   2012-07-22 02:42:36.000000     N/A     Disabled
1056    652     svchost.exe     0x23dfda0       5       60      0       False   2012-07-22 02:42:33.000000     N/A     Disabled
1136    1004    wuauclt.exe     0x23fcda0       8       173     0       False   2012-07-22 02:43:46.000000     N/A     Disabled
1220    652     svchost.exe     0x2495650       15      197     0       False   2012-07-22 02:42:35.000000     N/A     Disabled
608     368     winlogon.exe    0x2498700       23      519     0       False   2012-07-22 02:42:32.000000     N/A     Disabled
584     368     csrss.exe       0x24a0598       9       326     0       False   2012-07-22 02:42:32.000000     N/A     Disabled
368     4       smss.exe        0x24f1020       3       19      N/A     False   2012-07-22 02:42:31.000000     N/A     Disabled
1004    652     svchost.exe     0x25001d0       64      1118    0       False   2012-07-22 02:42:33.000000     N/A     Disabled
824     652     svchost.exe     0x2511360       20      194     0       False   2012-07-22 02:42:33.000000     N/A     Disabled
4       0       System  0x25c89c8       53      240     N/A     False   N/A     N/A   Disabled

thmanalyst@ubuntu:/opt/volatility3$ python3 vol.py -f dump.vmem windows.pstree
Volatility 3 Framework 1.0.1
Progress:  100.00               PDB scanning finished                     
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64 CreateTime       ExitTime

4       0       System  0x8205bda0      53      240     N/A     False   N/A     N/A
* 368   4       smss.exe        0x8205bda0      3       19      N/A     False   2012-07-22 02:42:31.000000     N/A
** 584  368     csrss.exe       0x8205bda0      9       326     0       False   2012-07-22 02:42:32.000000     N/A
** 608  368     winlogon.exe    0x8205bda0      23      519     0       False   2012-07-22 02:42:32.000000     N/A
*** 664 608     lsass.exe       0x8205bda0      24      330     0       False   2012-07-22 02:42:32.000000     N/A
*** 652 608     services.exe    0x8205bda0      16      243     0       False   2012-07-22 02:42:32.000000     N/A
**** 1056       652     svchost.exe     0x8205bda0      5       60      0       False 2012-07-22 02:42:33.000000       N/A
**** 1220       652     svchost.exe     0x8205bda0      15      197     0       False 2012-07-22 02:42:35.000000       N/A
**** 1512       652     spoolsv.exe     0x8205bda0      14      113     0       False 2012-07-22 02:42:36.000000       N/A
**** 908        652     svchost.exe     0x8205bda0      9       226     0       False 2012-07-22 02:42:33.000000       N/A
**** 1004       652     svchost.exe     0x8205bda0      64      1118    0       False 2012-07-22 02:42:33.000000       N/A
***** 1136      1004    wuauclt.exe     0x8205bda0      8       173     0       False 2012-07-22 02:43:46.000000       N/A
***** 1588      1004    wuauclt.exe     0x8205bda0      5       132     0       False 2012-07-22 02:44:01.000000       N/A
**** 788        652     alg.exe 0x8205bda0      7       104     0       False   2012-07-22 02:43:01.000000     N/A
**** 824        652     svchost.exe     0x8205bda0      20      194     0       False 2012-07-22 02:42:33.000000       N/A
1484    1464    explorer.exe    0x8205bda0      17      415     0       False   2012-07-22 02:42:36.000000     N/A
* 1640  1484    reader_sl.exe   0x8205bda0      5       39      0       False   2012-07-22 02:42:36.000000     N/A


thmanalyst@ubuntu:/opt/volatility3$ python3 vol.py -f dump.vmem windows.dlllist
Volatility 3 Framework 1.0.1
Progress:  100.00               PDB scanning finished                     
PID     Process Base    Size    Name    Path    LoadTime        File output

368     smss.exe        0x48580000      0xf000  smss.exe        \SystemRoot\System32\smss.exe  N/A     Disabled
368     smss.exe        0x7c900000      0xaf000 ntdll.dll       C:\WINDOWS\system32\ntdll.dll  N/A     Disabled
584     csrss.exe       0x4a680000      0x5000  csrss.exe       \??\C:\WINDOWS\system32\csrss.exe      N/A     Disabled
584     csrss.exe       0x7c900000      0xaf000 ntdll.dll       C:\WINDOWS\system32\ntdll.dll  N/A     Disabled
584     csrss.exe       0x75b40000      0xb000  CSRSRV.dll      C:\WINDOWS\system32\CSRSRV.dll N/A     Disabled
584     csrss.exe       0x75b50000      0x10000 basesrv.dll     C:\WINDOWS\system32\basesrv.dll        N/A     Disabled
584     csrss.exe       0x75b60000      0x4b000 winsrv.dll      C:\WINDOWS\system32\winsrv.dll N/A     Disabled
584     csrss.exe       0x77f10000      0x49000 GDI32.dll       C:\WINDOWS\system32\GDI32.dll  N/A     Disabled
584     csrss.exe       0x7c800000      0xf6000 KERNEL32.dll    C:\WINDOWS\system32\KERNEL32.dll       N/A     Disabled
584     csrss.exe       0x7e410000      0x91000 USER32.dll      C:\WINDOWS\system32\USER32.dll N/A     Disabled
584     csrss.exe       0x7e720000      0xb0000 sxs.dll C:\WINDOWS\system32\sxs.dll   N/A      Disabled
584     csrss.exe       0x77dd0000      0x9b000 ADVAPI32.dll    C:\WINDOWS\system32\ADVAPI32.dll       N/A     Disabled
584     csrss.exe       0x77e70000      0x92000 RPCRT4.dll      C:\WINDOWS\system32\RPCRT4.dll N/A     Disabled
584     csrss.exe       0x77fe0000      0x11000 Secur32.dll     C:\WINDOWS\system32\Secur32.dll        N/A     Disabled
608     winlogon.exe    0x1000000       0x81000 winlogon.exe    \??\C:\WINDOWS\system32\winlogon.exe   N/A     Disabled
608     winlogon.exe    0x7c900000      0xaf000 ntdll.dll       C:\WINDOWS\system32\ntdll.dll  N/A     Disabled
608     winlogon.exe    0x7c800000      0xf6000 kernel32.dll    C:\WINDOWS\system32\kernel32.dll       N/A     Disabled
608     winlogon.exe    0x77dd0000      0x9b000 ADVAPI32.dll    C:\WINDOWS\system32\ADVAPI32.dll       N/A     Disabled
608     winlogon.exe    0x77e70000      0x92000 RPCRT4.dll      C:\WINDOWS\system32\RPCRT4.dll N/A     Disabled
608     winlogon.exe    0x77fe0000      0x11000 Secur32.dll     C:\WINDOWS\system32\Secur32.dll        N/A     Disabled
608     winlogon.exe    0x776c0000      0x12000 AUTHZ.dll       C:\WINDOWS\system32\AUTHZ.dll  N/A     Disabled
608     winlogon.exe    0x77c10000      0x58000 msvcrt.dll      C:\WINDOWS\system32\msvcrt.dll N/A     Disabled
608     winlogon.exe    0x77a80000      0x95000 CRYPT32.dll     C:\WINDOWS\system32\CRYPT32.dll        N/A     Disabled
608     winlogon.exe    0x77b20000      0x12000 MSASN1.dll      C:\WINDOWS\system32\MSASN1.dll N/A     Disabled
608     winlogon.exe    0x7e410000      0x91000 USER32.dll      C:\WINDOWS\system32\USER32.dll N/A     Disabled
608     winlogon.exe    0x77f10000      0x49000 GDI32.dll       C:\WINDOWS\system32\GDI32.dll  N/A     Disabled
608     winlogon.exe    0x75940000      0x8000  NDdeApi.dll     C:\WINDOWS\system32\NDdeApi.dll        N/A     Disabled
608     winlogon.exe    0x75930000      0xa000  PROFMAP.dll     C:\WINDOWS\system32\PROFMAP.dll        N/A     Disabled
608     winlogon.exe    0x5b860000      0x55000 NETAPI32.dll    C:\WINDOWS\system32\NETAPI32.dll       N/A     Disabled
608     winlogon.exe    0x769c0000      0xb4000 USERENV.dll     C:\WINDOWS\system32\USERENV.dll        N/A     Disabled
608     winlogon.exe    0x76bf0000      0xb000  PSAPI.DLL       C:\WINDOWS\system32\PSAPI.DLL  N/A     Disabled
608     winlogon.exe    0x76bc0000      0xf000  REGAPI.dll      C:\WINDOWS\system32\REGAPI.dll N/A     Disabled
608     winlogon.exe    0x77920000      0xf3000 SETUPAPI.dll    C:\WINDOWS\system32\SETUPAPI.dll       N/A     Disabled
608     winlogon.exe    0x77c00000      0x8000  VERSION.dll     C:\WINDOWS\system32\VERSION.dll        N/A     Disabled
608     winlogon.exe    0x76360000      0x10000 WINSTA.dll      C:\WINDOWS\system32\WINSTA.dll N/A     Disabled
608     winlogon.exe    0x76c30000      0x2e000 WINTRUST.dll    C:\WINDOWS\system32\WINTRUST.dll       N/A     Disabled
608     winlogon.exe    0x76c90000      0x28000 IMAGEHLP.dll    C:\WINDOWS\system32\IMAGEHLP.dll       N/A     Disabled
608     winlogon.exe    0x71ab0000      0x17000 WS2_32.dll      C:\WINDOWS\system32\WS2_32.dll N/A     Disabled
608     winlogon.exe    0x71aa0000      0x8000  WS2HELP.dll     C:\WINDOWS\system32\WS2HELP.dll        N/A     Disabled
608     winlogon.exe    0x75970000      0xf8000 MSGINA.dll      C:\WINDOWS\system32\MSGINA.dll N/A     Disabled
608     winlogon.exe    0x5d090000      0x9a000 COMCTL32.dll    C:\WINDOWS\system32\COMCTL32.dll       N/A     Disabled
608     winlogon.exe    0x74320000      0x3d000 ODBC32.dll      C:\WINDOWS\system32\ODBC32.dll N/A     Disabled
608     winlogon.exe    0x763b0000      0x49000 comdlg32.dll    C:\WINDOWS\system32\comdlg32.dll       N/A     Disabled
608     winlogon.exe    0x7c9c0000      0x817000        SHELL32.dll     C:\WINDOWS\system32\SHELL32.dll        N/A     Disabled
608     winlogon.exe    0x77f60000      0x76000 SHLWAPI.dll     C:\WINDOWS\system32\SHLWAPI.dll        N/A     Disabled
608     winlogon.exe    0x773d0000      0x103000        comctl32.dll    C:\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83\comctl32.dll     N/A     Disabled
608     winlogon.exe    0x930000        0x17000 odbcint.dll     C:\WINDOWS\system32\odbcint.dll        N/A     Disabled
608     winlogon.exe    0x776e0000      0x23000 SHSVCS.dll      C:\WINDOWS\system32\SHSVCS.dll N/A     Disabled
608     winlogon.exe    0x76bb0000      0x5000  sfc.dll C:\WINDOWS\system32\sfc.dll   N/A      Disabled
608     winlogon.exe    0x76c60000      0x2a000 sfc_os.dll      C:\WINDOWS\system32\sfc_os.dll N/A     Disabled
608     winlogon.exe    0x774e0000      0x13d000        ole32.dll       C:\WINDOWS\system32\ole32.dll  N/A     Disabled
608     winlogon.exe    0x77b40000      0x22000 Apphelp.dll     C:\WINDOWS\system32\Apphelp.dll        N/A     Disabled
608     winlogon.exe    0x723d0000      0x1c000 WINSCARD.DLL    C:\WINDOWS\system32\WINSCARD.DLL       N/A     Disabled
608     winlogon.exe    0x76f50000      0x8000  WTSAPI32.dll    C:\WINDOWS\system32\WTSAPI32.dll       N/A     Disabled
608     winlogon.exe    0x7e720000      0xb0000 sxs.dll C:\WINDOWS\system32\sxs.dll   N/A      Disabled
608     winlogon.exe    0x5ad70000      0x38000 uxtheme.dll     C:\WINDOWS\system32\uxtheme.dll        N/A     Disabled
608     winlogon.exe    0x76b40000      0x2d000 WINMM.dll       C:\WINDOWS\system32\WINMM.dll  N/A     Disabled
608     winlogon.exe    0x76600000      0x1d000 cscdll.dll      C:\WINDOWS\system32\cscdll.dll N/A     Disabled
608     winlogon.exe    0x47020000      0x8000  dimsntfy.dll    C:\WINDOWS\System32\dimsntfy.dll       N/A     Disabled
608     winlogon.exe    0x75950000      0x1a000 WlNotify.dll    C:\WINDOWS\system32\WlNotify.dll       N/A     Disabled
608     winlogon.exe    0x71b20000      0x12000 MPR.dll C:\WINDOWS\system32\MPR.dll   N/A      Disabled
608     winlogon.exe    0x73000000      0x26000 WINSPOOL.DRV    C:\WINDOWS\system32\WINSPOOL.DRV       N/A     Disabled
608     winlogon.exe    0x68000000      0x36000 rsaenh.dll      C:\WINDOWS\system32\rsaenh.dll N/A     Disabled
608     winlogon.exe    0x71bf0000      0x13000 SAMLIB.dll      C:\WINDOWS\system32\SAMLIB.dll N/A     Disabled
608     winlogon.exe    0x77a20000      0x54000 cscui.dll       C:\WINDOWS\system32\cscui.dll  N/A     Disabled
608     winlogon.exe    0x77c70000      0x24000 msv1_0.dll      C:\WINDOWS\system32\msv1_0.dll N/A     Disabled
608     winlogon.exe    0x76d60000      0x19000 iphlpapi.dll    C:\WINDOWS\system32\iphlpapi.dll       N/A     Disabled
608     winlogon.exe    0x76d40000      0x18000 MPRAPI.dll      C:\WINDOWS\system32\MPRAPI.dll N/A     Disabled
608     winlogon.exe    0x77cc0000      0x32000 ACTIVEDS.dll    C:\WINDOWS\system32\ACTIVEDS.dll       N/A     Disabled
608     winlogon.exe    0x76e10000      0x25000 adsldpc.dll     C:\WINDOWS\system32\adsldpc.dll        N/A     Disabled
608     winlogon.exe    0x76f60000      0x2c000 WLDAP32.dll     C:\WINDOWS\system32\WLDAP32.dll        N/A     Disabled
608     winlogon.exe    0x76b20000      0x11000 ATL.DLL C:\WINDOWS\system32\ATL.DLL   N/A      Disabled
608     winlogon.exe    0x77120000      0x8b000 OLEAUT32.dll    C:\WINDOWS\system32\OLEAUT32.dll       N/A     Disabled
608     winlogon.exe    0x76e80000      0xe000  rtutils.dll     C:\WINDOWS\system32\rtutils.dll        N/A     Disabled
608     winlogon.exe    0x1630000       0x2c5000        xpsp2res.dll    C:\WINDOWS\system32\xpsp2res.dll       N/A     Disabled
608     winlogon.exe    0x77690000      0x21000 NTMARTA.DLL     C:\WINDOWS\system32\NTMARTA.DLL        N/A     Disabled
608     winlogon.exe    0x72d20000      0x9000  wdmaud.drv      C:\WINDOWS\system32\wdmaud.drv N/A     Disabled
608     winlogon.exe    0x72d10000      0x8000  msacm32.drv     C:\WINDOWS\system32\msacm32.drv        N/A     Disabled
608     winlogon.exe    0x77be0000      0x15000 MSACM32.dll     C:\WINDOWS\system32\MSACM32.dll        N/A     Disabled
608     winlogon.exe    0x77bd0000      0x7000  midimap.dll     C:\WINDOWS\system32\midimap.dll        N/A     Disabled
608     winlogon.exe    0x77050000      0xc5000 COMRes.dll      C:\WINDOWS\system32\COMRes.dll N/A     Disabled
608     winlogon.exe    0x76fd0000      0x7f000 CLBCATQ.DLL     C:\WINDOWS\system32\CLBCATQ.DLL        N/A     Disabled
652     services.exe    0x1000000       0x1c000 services.exe    C:\WINDOWS\system32\services.exe       N/A     Disabled
652     services.exe    0x7c900000      0xaf000 ntdll.dll       C:\WINDOWS\system32\ntdll.dll  N/A     Disabled
652     services.exe    0x7c800000      0xf6000 kernel32.dll    C:\WINDOWS\system32\kernel32.dll       N/A     Disabled
652     services.exe    0x77dd0000      0x9b000 ADVAPI32.dll    C:\WINDOWS\system32\ADVAPI32.dll       N/A     Disabled
652     services.exe    0x77e70000      0x92000 RPCRT4.dll      C:\WINDOWS\system32\RPCRT4.dll N/A     Disabled
652     services.exe    0x77fe0000      0x11000 Secur32.dll     C:\WINDOWS\system32\Secur32.dll        N/A     Disabled
652     services.exe    0x77c10000      0x58000 msvcrt.dll      C:\WINDOWS\system32\msvcrt.dll N/A     Disabled
652     services.exe    0x5f770000      0xc000  NCObjAPI.DLL    C:\WINDOWS\system32\NCObjAPI.DLL       N/A     Disabled
652     services.exe    0x76080000      0x65000 MSVCP60.dll     C:\WINDOWS\system32\MSVCP60.dll        N/A     Disabled
652     services.exe    0x7dbd0000      0x51000 SCESRV.dll      C:\WINDOWS\system32\SCESRV.dll N/A     Disabled
652     services.exe    0x776c0000      0x12000 AUTHZ.dll       C:\WINDOWS\system32\AUTHZ.dll  N/A     Disabled
652     services.exe    0x7e410000      0x91000 USER32.dll      C:\WINDOWS\system32\USER32.dll N/A     Disabled
652     services.exe    0x77f10000      0x49000 GDI32.dll       C:\WINDOWS\system32\GDI32.dll  N/A     Disabled
652     services.exe    0x769c0000      0xb4000 USERENV.dll     C:\WINDOWS\system32\USERENV.dll        N/A     Disabled
652     services.exe    0x7dba0000      0x21000 umpnpmgr.dll    C:\WINDOWS\system32\umpnpmgr.dll       N/A     Disabled
652     services.exe    0x76360000      0x10000 WINSTA.dll      C:\WINDOWS\system32\WINSTA.dll N/A     Disabled
652     services.exe    0x5b860000      0x55000 NETAPI32.dll    C:\WINDOWS\system32\NETAPI32.dll       N/A     Disabled
652     services.exe    0x5cb70000      0x26000 ShimEng.dll     C:\WINDOWS\system32\ShimEng.dll        N/A     Disabled
652     services.exe    0x47260000      0xf000  AcAdProc.dll    C:\WINDOWS\AppPatch\AcAdProc.dll       N/A     Disabled
652     services.exe    0x77b40000      0x22000 Apphelp.dll     C:\WINDOWS\system32\Apphelp.dll        N/A     Disabled
652     services.exe    0x77c00000      0x8000  VERSION.dll     C:\WINDOWS\system32\VERSION.dll        N/A     Disabled
652     services.exe    0x77b70000      0x11000 eventlog.dll    C:\WINDOWS\system32\eventlog.dll       N/A     Disabled
652     services.exe    0x76bf0000      0xb000  PSAPI.DLL       C:\WINDOWS\system32\PSAPI.DLL  N/A     Disabled
652     services.exe    0x71ab0000      0x17000 WS2_32.dll      C:\WINDOWS\system32\WS2_32.dll N/A     Disabled
652     services.exe    0x71aa0000      0x8000  WS2HELP.dll     C:\WINDOWS\system32\WS2HELP.dll        N/A     Disabled
652     services.exe    0x76f50000      0x8000  wtsapi32.dll    C:\WINDOWS\system32\wtsapi32.dll       N/A     Disabled
664     lsass.exe       0x1000000       0x6000  lsass.exe       C:\WINDOWS\system32\lsass.exe  N/A     Disabled
664     lsass.exe       0x7c900000      0xaf000 ntdll.dll       C:\WINDOWS\system32\ntdll.dll  N/A     Disabled
664     lsass.exe       0x7c800000      0xf6000 kernel32.dll    C:\WINDOWS\system32\kernel32.dll       N/A     Disabled
664     lsass.exe       0x77dd0000      0x9b000 ADVAPI32.dll    C:\WINDOWS\system32\ADVAPI32.dll       N/A     Disabled
664     lsass.exe       0x77e70000      0x92000 RPCRT4.dll      C:\WINDOWS\system32\RPCRT4.dll N/A     Disabled
664     lsass.exe       0x77fe0000      0x11000 Secur32.dll     C:\WINDOWS\system32\Secur32.dll        N/A     Disabled
664     lsass.exe       0x75730000      0xb5000 LSASRV.dll      C:\WINDOWS\system32\LSASRV.dll N/A     Disabled
664     lsass.exe       0x71b20000      0x12000 MPR.dll C:\WINDOWS\system32\MPR.dll   N/A      Disabled
664     lsass.exe       0x7e410000      0x91000 USER32.dll      C:\WINDOWS\system32\USER32.dll N/A     Disabled
664     lsass.exe       0x77f10000      0x49000 GDI32.dll       C:\WINDOWS\system32\GDI32.dll  N/A     Disabled
664     lsass.exe       0x77b20000      0x12000 MSASN1.dll      C:\WINDOWS\system32\MSASN1.dll N/A     Disabled
664     lsass.exe       0x77c10000      0x58000 msvcrt.dll      C:\WINDOWS\system32\msvcrt.dll N/A     Disabled
664     lsass.exe       0x5b860000      0x55000 NETAPI32.dll    C:\WINDOWS\system32\NETAPI32.dll       N/A     Disabled
664     lsass.exe       0x767a0000      0x13000 NTDSAPI.dll     C:\WINDOWS\system32\NTDSAPI.dll        N/A     Disabled
664     lsass.exe       0x76f20000      0x27000 DNSAPI.dll      C:\WINDOWS\system32\DNSAPI.dll N/A     Disabled
664     lsass.exe       0x71ab0000      0x17000 WS2_32.dll      C:\WINDOWS\system32\WS2_32.dll N/A     Disabled
664     lsass.exe       0x71aa0000      0x8000  WS2HELP.dll     C:\WINDOWS\system32\WS2HELP.dll        N/A     Disabled
664     lsass.exe       0x76f60000      0x2c000 WLDAP32.dll     C:\WINDOWS\system32\WLDAP32.dll        N/A     Disabled
664     lsass.exe       0x71bf0000      0x13000 SAMLIB.dll      C:\WINDOWS\system32\SAMLIB.dll N/A     Disabled
664     lsass.exe       0x74440000      0x6a000 SAMSRV.dll      C:\WINDOWS\system32\SAMSRV.dll N/A     Disabled
664     lsass.exe       0x76790000      0xc000  cryptdll.dll    C:\WINDOWS\system32\cryptdll.dll       N/A     Disabled
664     lsass.exe       0x5cb70000      0x26000 ShimEng.dll     C:\WINDOWS\system32\ShimEng.dll        N/A     Disabled
664     lsass.exe       0x6f880000      0x1ca000        AcGenral.DLL    C:\WINDOWS\AppPatch\AcGenral.DLL       N/A     Disabled
664     lsass.exe       0x76b40000      0x2d000 WINMM.dll       C:\WINDOWS\system32\WINMM.dll  N/A     Disabled
664     lsass.exe       0x774e0000      0x13d000        ole32.dll       C:\WINDOWS\system32\ole32.dll  N/A     Disabled
664     lsass.exe       0x77120000      0x8b000 OLEAUT32.dll    C:\WINDOWS\system32\OLEAUT32.dll       N/A     Disabled
664     lsass.exe       0x77be0000      0x15000 MSACM32.dll     C:\WINDOWS\system32\MSACM32.dll        N/A     Disabled
664     lsass.exe       0x77c00000      0x8000  VERSION.dll     C:\WINDOWS\system32\VERSION.dll        N/A     Disabled
664     lsass.exe       0x7c9c0000      0x817000        SHELL32.dll     C:\WINDOWS\system32\SHELL32.dll        N/A     Disabled
664     lsass.exe       0x77f60000      0x76000 SHLWAPI.dll     C:\WINDOWS\system32\SHLWAPI.dll        N/A     Disabled
664     lsass.exe       0x769c0000      0xb4000 USERENV.dll     C:\WINDOWS\system32\USERENV.dll        N/A     Disabled
664     lsass.exe       0x5ad70000      0x38000 UxTheme.dll     C:\WINDOWS\system32\UxTheme.dll        N/A     Disabled
664     lsass.exe       0x773d0000      0x103000        comctl32.dll    C:\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83\comctl32.dll     N/A     Disabled
664     lsass.exe       0x5d090000      0x9a000 comctl32.dll    C:\WINDOWS\system32\comctl32.dll       N/A     Disabled
664     lsass.exe       0x4d200000      0xe000  msprivs.dll     C:\WINDOWS\system32\msprivs.dll        N/A     Disabled
664     lsass.exe       0x71cf0000      0x4c000 kerberos.dll    C:\WINDOWS\system32\kerberos.dll       N/A     Disabled
664     lsass.exe       0x77c70000      0x24000 msv1_0.dll      C:\WINDOWS\system32\msv1_0.dll N/A     Disabled
664     lsass.exe       0x76d60000      0x19000 iphlpapi.dll    C:\WINDOWS\system32\iphlpapi.dll       N/A     Disabled
664     lsass.exe       0x744b0000      0x65000 netlogon.dll    C:\WINDOWS\system32\netlogon.dll       N/A     Disabled
664     lsass.exe       0x767c0000      0x2c000 w32time.dll     C:\WINDOWS\system32\w32time.dll        N/A     Disabled
664     lsass.exe       0x76080000      0x65000 MSVCP60.dll     C:\WINDOWS\system32\MSVCP60.dll        N/A     Disabled
664     lsass.exe       0x767f0000      0x27000 schannel.dll    C:\WINDOWS\system32\schannel.dll       N/A     Disabled
664     lsass.exe       0x77a80000      0x95000 CRYPT32.dll     C:\WINDOWS\system32\CRYPT32.dll        N/A     Disabled
664     lsass.exe       0x74380000      0xf000  wdigest.dll     C:\WINDOWS\system32\wdigest.dll        N/A     Disabled
664     lsass.exe       0x68000000      0x36000 rsaenh.dll      C:\WINDOWS\system32\rsaenh.dll N/A     Disabled
664     lsass.exe       0x77920000      0xf3000 setupapi.dll    C:\WINDOWS\system32\setupapi.dll       N/A     Disabled
664     lsass.exe       0x74410000      0x2f000 scecli.dll      C:\WINDOWS\system32\scecli.dll N/A     Disabled
664     lsass.exe       0x743e0000      0x2f000 ipsecsvc.dll    C:\WINDOWS\system32\ipsecsvc.dll       N/A     Disabled
664     lsass.exe       0x776c0000      0x12000 AUTHZ.dll       C:\WINDOWS\system32\AUTHZ.dll  N/A     Disabled
664     lsass.exe       0x75d90000      0xd0000 oakley.DLL      C:\WINDOWS\system32\oakley.DLL N/A     Disabled
664     lsass.exe       0x74370000      0xb000  WINIPSEC.DLL    C:\WINDOWS\system32\WINIPSEC.DLL       N/A     Disabled
664     lsass.exe       0x71a50000      0x3f000 mswsock.dll     C:\WINDOWS\system32\mswsock.dll        N/A     Disabled
664     lsass.exe       0x662b0000      0x58000 hnetcfg.dll     C:\WINDOWS\system32\hnetcfg.dll        N/A     Disabled
664     lsass.exe       0x71a90000      0x8000  wshtcpip.dll    C:\WINDOWS\System32\wshtcpip.dll       N/A     Disabled
664     lsass.exe       0x743a0000      0xb000  pstorsvc.dll    C:\WINDOWS\system32\pstorsvc.dll       N/A     Disabled
664     lsass.exe       0x743c0000      0x1b000 psbase.dll      C:\WINDOWS\system32\psbase.dll N/A     Disabled
664     lsass.exe       0x68100000      0x26000 dssenh.dll      C:\WINDOWS\system32\dssenh.dll N/A     Disabled
824     svchost.exe     0x1000000       0x6000  svchost.exe     C:\WINDOWS\system32\svchost.exe        N/A     Disabled
824     svchost.exe     0x7c900000      0xaf000 ntdll.dll       C:\WINDOWS\system32\ntdll.dll  N/A     Disabled
824     svchost.exe     0x7c800000      0xf6000 kernel32.dll    C:\WINDOWS\system32\kernel32.dll       N/A     Disabled
824     svchost.exe     0x77dd0000      0x9b000 ADVAPI32.dll    C:\WINDOWS\system32\ADVAPI32.dll       N/A     Disabled
824     svchost.exe     0x77e70000      0x92000 RPCRT4.dll      C:\WINDOWS\system32\RPCRT4.dll N/A     Disabled
824     svchost.exe     0x77fe0000      0x11000 Secur32.dll     C:\WINDOWS\system32\Secur32.dll        N/A     Disabled
824     svchost.exe     0x5cb70000      0x26000 ShimEng.dll     C:\WINDOWS\system32\ShimEng.dll        N/A     Disabled
824     svchost.exe     0x6f880000      0x1ca000        AcGenral.DLL    C:\WINDOWS\AppPatch\AcGenral.DLL       N/A     Disabled
824     svchost.exe     0x7e410000      0x91000 USER32.dll      C:\WINDOWS\system32\USER32.dll N/A     Disabled
824     svchost.exe     0x77f10000      0x49000 GDI32.dll       C:\WINDOWS\system32\GDI32.dll  N/A     Disabled
824     svchost.exe     0x76b40000      0x2d000 WINMM.dll       C:\WINDOWS\system32\WINMM.dll  N/A     Disabled
824     svchost.exe     0x774e0000      0x13d000        ole32.dll       C:\WINDOWS\system32\ole32.dll  N/A     Disabled
824     svchost.exe     0x77c10000      0x58000 msvcrt.dll      C:\WINDOWS\system32\msvcrt.dll N/A     Disabled
824     svchost.exe     0x77120000      0x8b000 OLEAUT32.dll    C:\WINDOWS\system32\OLEAUT32.dll       N/A     Disabled
824     svchost.exe     0x77be0000      0x15000 MSACM32.dll     C:\WINDOWS\system32\MSACM32.dll        N/A     Disabled
824     svchost.exe     0x77c00000      0x8000  VERSION.dll     C:\WINDOWS\system32\VERSION.dll        N/A     Disabled
824     svchost.exe     0x7c9c0000      0x817000        SHELL32.dll     C:\WINDOWS\system32\SHELL32.dll        N/A     Disabled
824     svchost.exe     0x77f60000      0x76000 SHLWAPI.dll     C:\WINDOWS\system32\SHLWAPI.dll        N/A     Disabled
824     svchost.exe     0x769c0000      0xb4000 USERENV.dll     C:\WINDOWS\system32\USERENV.dll        N/A     Disabled
824     svchost.exe     0x5ad70000      0x38000 UxTheme.dll     C:\WINDOWS\system32\UxTheme.dll        N/A     Disabled
824     svchost.exe     0x773d0000      0x103000        comctl32.dll    C:\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83\comctl32.dll     N/A     Disabled
824     svchost.exe     0x5d090000      0x9a000 comctl32.dll    C:\WINDOWS\system32\comctl32.dll       N/A     Disabled
824     svchost.exe     0x77690000      0x21000 NTMARTA.DLL     C:\WINDOWS\system32\NTMARTA.DLL        N/A     Disabled
824     svchost.exe     0x71bf0000      0x13000 SAMLIB.dll      C:\WINDOWS\system32\SAMLIB.dll N/A     Disabled
824     svchost.exe     0x76f60000      0x2c000 WLDAP32.dll     C:\WINDOWS\system32\WLDAP32.dll        N/A     Disabled
824     svchost.exe     0x76a80000      0x64000 rpcss.dll       c:\windows\system32\rpcss.dll  N/A     Disabled
824     svchost.exe     0x71ab0000      0x17000 WS2_32.dll      c:\windows\system32\WS2_32.dll N/A     Disabled
824     svchost.exe     0x71aa0000      0x8000  WS2HELP.dll     c:\windows\system32\WS2HELP.dll        N/A     Disabled
824     svchost.exe     0x670000        0x2c5000        xpsp2res.dll    C:\WINDOWS\system32\xpsp2res.dll       N/A     Disabled
824     svchost.exe     0x76fd0000      0x7f000 CLBCATQ.DLL     C:\WINDOWS\system32\CLBCATQ.DLL        N/A     Disabled
824     svchost.exe     0x77050000      0xc5000 COMRes.dll      C:\WINDOWS\system32\COMRes.dll N/A     Disabled
824     svchost.exe     0x760f0000      0x53000 termsrv.dll     c:\windows\system32\termsrv.dll        N/A     Disabled
824     svchost.exe     0x74f70000      0x6000  ICAAPI.dll      c:\windows\system32\ICAAPI.dll N/A     Disabled
824     svchost.exe     0x77920000      0xf3000 SETUPAPI.dll    c:\windows\system32\SETUPAPI.dll       N/A     Disabled
824     svchost.exe     0x76c30000      0x2e000 WINTRUST.dll    C:\WINDOWS\system32\WINTRUST.dll       N/A     Disabled
824     svchost.exe     0x77a80000      0x95000 CRYPT32.dll     C:\WINDOWS\system32\CRYPT32.dll        N/A     Disabled
824     svchost.exe     0x77b20000      0x12000 MSASN1.dll      C:\WINDOWS\system32\MSASN1.dll N/A     Disabled
824     svchost.exe     0x76c90000      0x28000 IMAGEHLP.dll    C:\WINDOWS\system32\IMAGEHLP.dll       N/A     Disabled
824     svchost.exe     0x776c0000      0x12000 AUTHZ.dll       c:\windows\system32\AUTHZ.dll  N/A     Disabled
824     svchost.exe     0x75110000      0x1f000 mstlsapi.dll    c:\windows\system32\mstlsapi.dll       N/A     Disabled
824     svchost.exe     0x77cc0000      0x32000 ACTIVEDS.dll    c:\windows\system32\ACTIVEDS.dll       N/A     Disabled
824     svchost.exe     0x76e10000      0x25000 adsldpc.dll     c:\windows\system32\adsldpc.dll        N/A     Disabled
824     svchost.exe     0x5b860000      0x55000 NETAPI32.dll    C:\WINDOWS\system32\NETAPI32.dll       N/A     Disabled
824     svchost.exe     0x76b20000      0x11000 ATL.DLL c:\windows\system32\ATL.DLL   N/A      Disabled
824     svchost.exe     0x76bc0000      0xf000  REGAPI.dll      C:\WINDOWS\system32\REGAPI.dll N/A     Disabled
824     svchost.exe     0x68000000      0x36000 rsaenh.dll      C:\WINDOWS\system32\rsaenh.dll N/A     Disabled
908     svchost.exe     0x1000000       0x6000  svchost.exe     C:\WINDOWS\system32\svchost.exe        N/A     Disabled
908     svchost.exe     0x7c900000      0xaf000 ntdll.dll       C:\WINDOWS\system32\ntdll.dll  N/A     Disabled
908     svchost.exe     0x7c800000      0xf6000 kernel32.dll    C:\WINDOWS\system32\kernel32.dll       N/A     Disabled
908     svchost.exe     0x77dd0000      0x9b000 ADVAPI32.dll    C:\WINDOWS\system32\ADVAPI32.dll       N/A     Disabled
908     svchost.exe     0x77e70000      0x92000 RPCRT4.dll      C:\WINDOWS\system32\RPCRT4.dll N/A     Disabled
908     svchost.exe     0x77fe0000      0x11000 Secur32.dll     C:\WINDOWS\system32\Secur32.dll        N/A     Disabled
908     svchost.exe     0x5cb70000      0x26000 ShimEng.dll     C:\WINDOWS\system32\ShimEng.dll        N/A     Disabled
908     svchost.exe     0x6f880000      0x1ca000        AcGenral.DLL    C:\WINDOWS\AppPatch\AcGenral.DLL       N/A     Disabled
908     svchost.exe     0x7e410000      0x91000 USER32.dll      C:\WINDOWS\system32\USER32.dll N/A     Disabled
908     svchost.exe     0x77f10000      0x49000 GDI32.dll       C:\WINDOWS\system32\GDI32.dll  N/A     Disabled
908     svchost.exe     0x76b40000      0x2d000 WINMM.dll       C:\WINDOWS\system32\WINMM.dll  N/A     Disabled
908     svchost.exe     0x774e0000      0x13d000        ole32.dll       C:\WINDOWS\system32\ole32.dll  N/A     Disabled
908     svchost.exe     0x77c10000      0x58000 msvcrt.dll      C:\WINDOWS\system32\msvcrt.dll N/A     Disabled
908     svchost.exe     0x77120000      0x8b000 OLEAUT32.dll    C:\WINDOWS\system32\OLEAUT32.dll       N/A     Disabled
908     svchost.exe     0x77be0000      0x15000 MSACM32.dll     C:\WINDOWS\system32\MSACM32.dll        N/A     Disabled
908     svchost.exe     0x77c00000      0x8000  VERSION.dll     C:\WINDOWS\system32\VERSION.dll        N/A     Disabled
908     svchost.exe     0x7c9c0000      0x817000        SHELL32.dll     C:\WINDOWS\system32\SHELL32.dll        N/A     Disabled
908     svchost.exe     0x77f60000      0x76000 SHLWAPI.dll     C:\WINDOWS\system32\SHLWAPI.dll        N/A     Disabled
908     svchost.exe     0x769c0000      0xb4000 USERENV.dll     C:\WINDOWS\system32\USERENV.dll        N/A     Disabled
908     svchost.exe     0x5ad70000      0x38000 UxTheme.dll     C:\WINDOWS\system32\UxTheme.dll        N/A     Disabled
908     svchost.exe     0x773d0000      0x103000        comctl32.dll    C:\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83\comctl32.dll     N/A     Disabled
908     svchost.exe     0x5d090000      0x9a000 comctl32.dll    C:\WINDOWS\system32\comctl32.dll       N/A     Disabled
908     svchost.exe     0x76a80000      0x64000 rpcss.dll       c:\windows\system32\rpcss.dll  N/A     Disabled
908     svchost.exe     0x71ab0000      0x17000 WS2_32.dll      c:\windows\system32\WS2_32.dll N/A     Disabled
908     svchost.exe     0x71aa0000      0x8000  WS2HELP.dll     c:\windows\system32\WS2HELP.dll        N/A     Disabled
908     svchost.exe     0x670000        0x2c5000        xpsp2res.dll    C:\WINDOWS\system32\xpsp2res.dll       N/A     Disabled
908     svchost.exe     0x68000000      0x36000 rsaenh.dll      C:\WINDOWS\system32\rsaenh.dll N/A     Disabled
908     svchost.exe     0x71a50000      0x3f000 mswsock.dll     C:\WINDOWS\system32\mswsock.dll        N/A     Disabled
908     svchost.exe     0x662b0000      0x58000 hnetcfg.dll     C:\WINDOWS\system32\hnetcfg.dll        N/A     Disabled
908     svchost.exe     0x71a90000      0x8000  wshtcpip.dll    C:\WINDOWS\System32\wshtcpip.dll       N/A     Disabled
908     svchost.exe     0x76f20000      0x27000 DNSAPI.dll      C:\WINDOWS\system32\DNSAPI.dll N/A     Disabled
908     svchost.exe     0x76d60000      0x19000 iphlpapi.dll    C:\WINDOWS\system32\iphlpapi.dll       N/A     Disabled
908     svchost.exe     0x76fb0000      0x8000  winrnr.dll      C:\WINDOWS\System32\winrnr.dll N/A     Disabled
908     svchost.exe     0x76f60000      0x2c000 WLDAP32.dll     C:\WINDOWS\system32\WLDAP32.dll        N/A     Disabled
908     svchost.exe     0x76fc0000      0x6000  rasadhlp.dll    C:\WINDOWS\system32\rasadhlp.dll       N/A     Disabled
908     svchost.exe     0x76fd0000      0x7f000 CLBCATQ.DLL     C:\WINDOWS\system32\CLBCATQ.DLL        N/A     Disabled
908     svchost.exe     0x77050000      0xc5000 COMRes.dll      C:\WINDOWS\system32\COMRes.dll N/A     Disabled
1004    svchost.exe     0x1000000       0x6000  svchost.exe     C:\WINDOWS\System32\svchost.exe        N/A     Disabled
1004    svchost.exe     0x7c900000      0xaf000 ntdll.dll       C:\WINDOWS\system32\ntdll.dll  N/A     Disabled
1004    svchost.exe     0x7c800000      0xf6000 kernel32.dll    C:\WINDOWS\system32\kernel32.dll       N/A     Disabled
1004    svchost.exe     0x77dd0000      0x9b000 ADVAPI32.dll    C:\WINDOWS\system32\ADVAPI32.dll       N/A     Disabled
1004    svchost.exe     0x77e70000      0x92000 RPCRT4.dll      C:\WINDOWS\system32\RPCRT4.dll N/A     Disabled
1004    svchost.exe     0x77fe0000      0x11000 Secur32.dll     C:\WINDOWS\system32\Secur32.dll        N/A     Disabled
1004    svchost.exe     0x5cb70000      0x26000 ShimEng.dll     C:\WINDOWS\System32\ShimEng.dll        N/A     Disabled
1004    svchost.exe     0x6f880000      0x1ca000        AcGenral.DLL    C:\WINDOWS\AppPatch\AcGenral.DLL       N/A     Disabled
1004    svchost.exe     0x7e410000      0x91000 USER32.dll      C:\WINDOWS\system32\USER32.dll N/A     Disabled
1004    svchost.exe     0x77f10000      0x49000 GDI32.dll       C:\WINDOWS\system32\GDI32.dll  N/A     Disabled
1004    svchost.exe     0x76b40000      0x2d000 WINMM.dll       C:\WINDOWS\System32\WINMM.dll  N/A     Disabled
1004    svchost.exe     0x774e0000      0x13d000        ole32.dll       C:\WINDOWS\system32\ole32.dll  N/A     Disabled
1004    svchost.exe     0x77c10000      0x58000 msvcrt.dll      C:\WINDOWS\system32\msvcrt.dll N/A     Disabled
1004    svchost.exe     0x77120000      0x8b000 OLEAUT32.dll    C:\WINDOWS\system32\OLEAUT32.dll       N/A     Disabled
1004    svchost.exe     0x77be0000      0x15000 MSACM32.dll     C:\WINDOWS\System32\MSACM32.dll        N/A     Disabled
1004    svchost.exe     0x77c00000      0x8000  VERSION.dll     C:\WINDOWS\system32\VERSION.dll        N/A     Disabled
1004    svchost.exe     0x7c9c0000      0x817000        SHELL32.dll     C:\WINDOWS\system32\SHELL32.dll        N/A     Disabled
1004    svchost.exe     0x77f60000      0x76000 SHLWAPI.dll     C:\WINDOWS\system32\SHLWAPI.dll        N/A     Disabled
1004    svchost.exe     0x769c0000      0xb4000 USERENV.dll     C:\WINDOWS\system32\USERENV.dll        N/A     Disabled
1004    svchost.exe     0x5ad70000      0x38000 UxTheme.dll     C:\WINDOWS\System32\UxTheme.dll        N/A     Disabled
1004    svchost.exe     0x773d0000      0x103000        comctl32.dll    C:\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83\comctl32.dll     N/A     Disabled
1004    svchost.exe     0x5d090000      0x9a000 comctl32.dll    C:\WINDOWS\system32\comctl32.dll       N/A     Disabled
1004    svchost.exe     0x77690000      0x21000 NTMARTA.DLL     C:\WINDOWS\System32\NTMARTA.DLL        N/A     Disabled
1004    svchost.exe     0x71bf0000      0x13000 SAMLIB.dll      C:\WINDOWS\System32\SAMLIB.dll N/A     Disabled
1004    svchost.exe     0x76f60000      0x2c000 WLDAP32.dll     C:\WINDOWS\system32\WLDAP32.dll        N/A     Disabled
1004    svchost.exe     0x630000        0x2c5000        xpsp2res.dll    C:\WINDOWS\System32\xpsp2res.dll       N/A     Disabled
1004    svchost.exe     0x776e0000      0x23000 shsvcs.dll      c:\windows\system32\shsvcs.dll N/A     Disabled
1004    svchost.exe     0x76360000      0x10000 WINSTA.dll      C:\WINDOWS\System32\WINSTA.dll N/A     Disabled
1004    svchost.exe     0x5b860000      0x55000 NETAPI32.dll    C:\WINDOWS\system32\NETAPI32.dll       N/A     Disabled
1004    svchost.exe     0x7d4b0000      0x22000 dhcpcsvc.dll    c:\windows\system32\dhcpcsvc.dll       N/A     Disabled
1004    svchost.exe     0x76f20000      0x27000 DNSAPI.dll      c:\windows\system32\DNSAPI.dll N/A     Disabled
1004    svchost.exe     0x71ab0000      0x17000 WS2_32.dll      c:\windows\system32\WS2_32.dll N/A     Disabled
1004    svchost.exe     0x71aa0000      0x8000  WS2HELP.dll     c:\windows\system32\WS2HELP.dll        N/A     Disabled
1004    svchost.exe     0x76d60000      0x19000 iphlpapi.dll    c:\windows\system32\iphlpapi.dll       N/A     Disabled
1004    svchost.exe     0x68000000      0x36000 rsaenh.dll      C:\WINDOWS\System32\rsaenh.dll N/A     Disabled
1004    svchost.exe     0x71a50000      0x3f000 mswsock.dll     C:\WINDOWS\system32\mswsock.dll        N/A     Disabled
1004    svchost.exe     0x662b0000      0x58000 hnetcfg.dll     C:\WINDOWS\System32\hnetcfg.dll        N/A     Disabled
1004    svchost.exe     0x71a90000      0x8000  wshtcpip.dll    C:\WINDOWS\System32\wshtcpip.dll       N/A     Disabled
1004    svchost.exe     0x7db10000      0x8c000 wzcsvc.dll      c:\windows\system32\wzcsvc.dll N/A     Disabled
1004    svchost.exe     0x76e80000      0xe000  rtutils.dll     c:\windows\system32\rtutils.dll        N/A     Disabled
1004    svchost.exe     0x76d30000      0x4000  WMI.dll c:\windows\system32\WMI.dll   N/A      Disabled
1004    svchost.exe     0x77a80000      0x95000 CRYPT32.dll     C:\WINDOWS\system32\CRYPT32.dll        N/A     Disabled
1004    svchost.exe     0x77b20000      0x12000 MSASN1.dll      C:\WINDOWS\system32\MSASN1.dll N/A     Disabled
1004    svchost.exe     0x72810000      0xb000  EapolQec.dll    c:\windows\system32\EapolQec.dll       N/A     Disabled
1004    svchost.exe     0x76b20000      0x11000 ATL.DLL c:\windows\system32\ATL.DLL   N/A      Disabled
1004    svchost.exe     0x726c0000      0x16000 QUtil.dll       c:\windows\system32\QUtil.dll  N/A     Disabled
1004    svchost.exe     0x76080000      0x65000 MSVCP60.dll     c:\windows\system32\MSVCP60.dll        N/A     Disabled
1004    svchost.exe     0x478c0000      0xa000  dot3api.dll     c:\windows\system32\dot3api.dll        N/A     Disabled
1004    svchost.exe     0x76f50000      0x8000  WTSAPI32.dll    c:\windows\system32\WTSAPI32.dll       N/A     Disabled
1004    svchost.exe     0x606b0000      0x10d000        ESENT.dll       c:\windows\system32\ESENT.dll  N/A     Disabled
1004    svchost.exe     0x76fd0000      0x7f000 CLBCATQ.DLL     C:\WINDOWS\System32\CLBCATQ.DLL        N/A     Disabled
1004    svchost.exe     0x77050000      0xc5000 COMRes.dll      C:\WINDOWS\System32\COMRes.dll N/A     Disabled
1004    svchost.exe     0x76b70000      0x27000 rastls.dll      C:\WINDOWS\System32\rastls.dll N/A     Disabled
1004    svchost.exe     0x754d0000      0x80000 CRYPTUI.dll     C:\WINDOWS\system32\CRYPTUI.dll        N/A     Disabled
1004    svchost.exe     0x771b0000      0xaa000 WININET.dll     C:\WINDOWS\system32\WININET.dll        N/A     Disabled
1004    svchost.exe     0x76c30000      0x2e000 WINTRUST.dll    C:\WINDOWS\system32\WINTRUST.dll       N/A     Disabled
1004    svchost.exe     0x76c90000      0x28000 IMAGEHLP.dll    C:\WINDOWS\system32\IMAGEHLP.dll       N/A     Disabled
1004    svchost.exe     0x76d40000      0x18000 MPRAPI.dll      C:\WINDOWS\System32\MPRAPI.dll N/A     Disabled
1004    svchost.exe     0x77cc0000      0x32000 ACTIVEDS.dll    C:\WINDOWS\System32\ACTIVEDS.dll       N/A     Disabled
1004    svchost.exe     0x76e10000      0x25000 adsldpc.dll     C:\WINDOWS\System32\adsldpc.dll        N/A     Disabled
1004    svchost.exe     0x77920000      0xf3000 SETUPAPI.dll    C:\WINDOWS\System32\SETUPAPI.dll       N/A     Disabled
1004    svchost.exe     0x76ee0000      0x3c000 RASAPI32.dll    C:\WINDOWS\System32\RASAPI32.dll       N/A     Disabled
1004    svchost.exe     0x76e90000      0x12000 rasman.dll      C:\WINDOWS\System32\rasman.dll N/A     Disabled
1004    svchost.exe     0x76eb0000      0x2f000 TAPI32.dll      C:\WINDOWS\System32\TAPI32.dll N/A     Disabled
1004    svchost.exe     0x767f0000      0x27000 SCHANNEL.dll    C:\WINDOWS\System32\SCHANNEL.dll       N/A     Disabled
1004    svchost.exe     0x723d0000      0x1c000 WinSCard.dll    C:\WINDOWS\System32\WinSCard.dll       N/A     Disabled
1004    svchost.exe     0x76bf0000      0xb000  PSAPI.DLL       C:\WINDOWS\System32\PSAPI.DLL  N/A     Disabled
1004    svchost.exe     0x76bd0000      0x16000 raschap.dll     C:\WINDOWS\System32\raschap.dll        N/A     Disabled
1004    svchost.exe     0x77c70000      0x24000 msv1_0.dll      C:\WINDOWS\system32\msv1_0.dll N/A     Disabled
1004    svchost.exe     0x77300000      0x33000 schedsvc.dll    c:\windows\system32\schedsvc.dll       N/A     Disabled
1004    svchost.exe     0x767a0000      0x13000 NTDSAPI.dll     c:\windows\system32\NTDSAPI.dll        N/A     Disabled
1004    svchost.exe     0x74f50000      0x5000  MSIDLE.DLL      C:\WINDOWS\System32\MSIDLE.DLL N/A     Disabled
1004    svchost.exe     0x708b0000      0xd000  audiosrv.dll    c:\windows\system32\audiosrv.dll       N/A     Disabled
1004    svchost.exe     0x76e40000      0x23000 wkssvc.dll      c:\windows\system32\wkssvc.dll N/A     Disabled
1004    svchost.exe     0x76ce0000      0x12000 cryptsvc.dll    c:\windows\system32\cryptsvc.dll       N/A     Disabled
1004    svchost.exe     0x77b90000      0x32000 certcli.dll     c:\windows\system32\certcli.dll        N/A     Disabled
1004    svchost.exe     0x74f90000      0x9000  dmserver.dll    c:\windows\system32\dmserver.dll       N/A     Disabled
1004    svchost.exe     0x74f80000      0x9000  ersvc.dll       c:\windows\system32\ersvc.dll  N/A     Disabled
1004    svchost.exe     0x77710000      0x42000 es.dll  c:\windows\system32\es.dll    N/A      Disabled
1004    svchost.exe     0x74f40000      0xc000  pchsvc.dll      c:\windows\pchealth\helpctr\binaries\pchsvc.dll        N/A     Disabled
1004    svchost.exe     0x75090000      0x1a000 srvsvc.dll      c:\windows\system32\srvsvc.dll N/A     Disabled
1004    svchost.exe     0x77d00000      0x33000 netman.dll      c:\windows\system32\netman.dll N/A     Disabled
1004    svchost.exe     0x76400000      0x1a5000        netshell.dll    c:\windows\system32\netshell.dll       N/A     Disabled
1004    svchost.exe     0x76c00000      0x2e000 credui.dll      c:\windows\system32\credui.dll N/A     Disabled
1004    svchost.exe     0x736d0000      0x6000  dot3dlg.dll     c:\windows\system32\dot3dlg.dll        N/A     Disabled
1004    svchost.exe     0x5dca0000      0x28000 OneX.DLL        c:\windows\system32\OneX.DLL   N/A     Disabled
1004    svchost.exe     0x745b0000      0x22000 eappcfg.dll     c:\windows\system32\eappcfg.dll        N/A     Disabled
1004    svchost.exe     0x5dcd0000      0xe000  eappprxy.dll    c:\windows\system32\eappprxy.dll       N/A     Disabled
1004    svchost.exe     0x73030000      0x10000 WZCSAPI.DLL     c:\windows\system32\WZCSAPI.DLL        N/A     Disabled
1004    svchost.exe     0x73d20000      0x8000  seclogon.dll    c:\windows\system32\seclogon.dll       N/A     Disabled
1004    svchost.exe     0x722d0000      0xd000  sens.dll        c:\windows\system32\sens.dll   N/A     Disabled
1004    svchost.exe     0x751a0000      0x2e000 srsvc.dll       c:\windows\system32\srsvc.dll  N/A     Disabled
1004    svchost.exe     0x74ad0000      0x8000  POWRPROF.dll    c:\windows\system32\POWRPROF.dll       N/A     Disabled
1004    svchost.exe     0x75070000      0x19000 trkwks.dll      c:\windows\system32\trkwks.dll N/A     Disabled
1004    svchost.exe     0x767c0000      0x2c000 w32time.dll     c:\windows\system32\w32time.dll        N/A     Disabled
1004    svchost.exe     0x59490000      0x28000 wmisvc.dll      c:\windows\system32\wbem\wmisvc.dll    N/A     Disabled
1004    svchost.exe     0x753e0000      0x6d000 VSSAPI.DLL      C:\WINDOWS\system32\VSSAPI.DLL N/A     Disabled
1004    svchost.exe     0x50000000      0x5000  wuauserv.dll    c:\windows\system32\wuauserv.dll       N/A     Disabled
1004    svchost.exe     0x50040000      0x119000        wuaueng.dll     C:\WINDOWS\system32\wuaueng.dll        N/A     Disabled
1004    svchost.exe     0x75260000      0x29000 ADVPACK.dll     C:\WINDOWS\System32\ADVPACK.dll        N/A     Disabled
1004    svchost.exe     0x75150000      0x13000 Cabinet.dll     C:\WINDOWS\System32\Cabinet.dll        N/A     Disabled
1004    svchost.exe     0x600a0000      0xb000  mspatcha.dll    C:\WINDOWS\System32\mspatcha.dll       N/A     Disabled
1004    svchost.exe     0x76bb0000      0x5000  sfc.dll C:\WINDOWS\System32\sfc.dll   N/A      Disabled
1004    svchost.exe     0x76c60000      0x2a000 sfc_os.dll      C:\WINDOWS\System32\sfc_os.dll N/A     Disabled
1004    svchost.exe     0x76780000      0x9000  SHFOLDER.dll    C:\WINDOWS\System32\SHFOLDER.dll       N/A     Disabled
1004    svchost.exe     0x4d4f0000      0x59000 WINHTTP.dll     C:\WINDOWS\System32\WINHTTP.dll        N/A     Disabled
1004    svchost.exe     0x73000000      0x26000 WINSPOOL.DRV    C:\WINDOWS\System32\WINSPOOL.DRV       N/A     Disabled
1004    svchost.exe     0x4c0a0000      0x17000 wscsvc.dll      c:\windows\system32\wscsvc.dll N/A     Disabled
1004    svchost.exe     0x7d1e0000      0x2bc000        msi.dll c:\windows\system32\msi.dll    N/A     Disabled
1004    svchost.exe     0x7e720000      0xb0000 SXS.DLL C:\WINDOWS\System32\SXS.DLL   N/A      Disabled
1004    svchost.exe     0x76da0000      0x16000 browser.dll     c:\windows\system32\browser.dll        N/A     Disabled
1004    svchost.exe     0x75290000      0x37000 wbemcomn.dll    C:\WINDOWS\system32\wbem\wbemcomn.dll  N/A     Disabled
1004    svchost.exe     0x762c0000      0x85000 wbemcore.dll    C:\WINDOWS\System32\Wbem\wbemcore.dll  N/A     Disabled
1004    svchost.exe     0x75310000      0x3f000 esscli.dll      C:\WINDOWS\System32\Wbem\esscli.dll    N/A     Disabled
1004    svchost.exe     0x75690000      0x76000 FastProx.dll    C:\WINDOWS\System32\Wbem\FastProx.dll  N/A     Disabled
1004    svchost.exe     0x75020000      0x1b000 wmiutils.dll    C:\WINDOWS\system32\wbem\wmiutils.dll  N/A     Disabled
1004    svchost.exe     0x75200000      0x2f000 repdrvfs.dll    C:\WINDOWS\system32\wbem\repdrvfs.dll  N/A     Disabled
1004    svchost.exe     0x76620000      0x13c000        comsvcs.dll     C:\WINDOWS\system32\comsvcs.dll        N/A     Disabled
1004    svchost.exe     0x75130000      0x14000 colbact.DLL     C:\WINDOWS\system32\colbact.DLL        N/A     Disabled
1004    svchost.exe     0x750f0000      0x13000 MTXCLU.DLL      C:\WINDOWS\system32\MTXCLU.DLL N/A     Disabled
1004    svchost.exe     0x71ad0000      0x9000  WSOCK32.dll     C:\WINDOWS\system32\WSOCK32.dll        N/A     Disabled
1004    svchost.exe     0x76d10000      0x12000 CLUSAPI.DLL     C:\WINDOWS\System32\CLUSAPI.DLL        N/A     Disabled
1004    svchost.exe     0x750b0000      0x12000 RESUTILS.DLL    C:\WINDOWS\System32\RESUTILS.DLL       N/A     Disabled
1004    svchost.exe     0x597f0000      0x6d000 wmiprvsd.dll    C:\WINDOWS\system32\wbem\wmiprvsd.dll  N/A     Disabled
1004    svchost.exe     0x5f770000      0xc000  NCObjAPI.DLL    C:\WINDOWS\system32\NCObjAPI.DLL       N/A     Disabled
1004    svchost.exe     0x75390000      0x46000 wbemess.dll     C:\WINDOWS\system32\wbem\wbemess.dll   N/A     Disabled
1004    svchost.exe     0x5f740000      0xe000  ncprov.dll      C:\WINDOWS\system32\wbem\ncprov.dll    N/A     Disabled
1004    svchost.exe     0x66460000      0x55000 ipnathlp.dll    c:\windows\system32\ipnathlp.dll       N/A     Disabled
1004    svchost.exe     0x776c0000      0x12000 AUTHZ.dll       c:\windows\system32\AUTHZ.dll  N/A     Disabled
1004    svchost.exe     0x76de0000      0x24000 upnp.dll        C:\WINDOWS\system32\upnp.dll   N/A     Disabled
1004    svchost.exe     0x74f00000      0xc000  SSDPAPI.dll     C:\WINDOWS\system32\SSDPAPI.dll        N/A     Disabled
1004    svchost.exe     0x76fc0000      0x6000  rasadhlp.dll    C:\WINDOWS\System32\rasadhlp.dll       N/A     Disabled
1004    svchost.exe     0x768d0000      0xa4000 RASDLG.dll      C:\WINDOWS\System32\RASDLG.dll N/A     Disabled
1004    svchost.exe     0x77b40000      0x22000 Apphelp.dll     C:\WINDOWS\system32\Apphelp.dll        N/A     Disabled
1004    svchost.exe     0x50640000      0xc000  wups.dll        C:\WINDOWS\system32\wups.dll   N/A     Disabled
1056    svchost.exe     0x1000000       0x6000  svchost.exe     C:\WINDOWS\system32\svchost.exe        N/A     Disabled
1056    svchost.exe     0x7c900000      0xaf000 ntdll.dll       C:\WINDOWS\system32\ntdll.dll  N/A     Disabled
1056    svchost.exe     0x7c800000      0xf6000 kernel32.dll    C:\WINDOWS\system32\kernel32.dll       N/A     Disabled
1056    svchost.exe     0x77dd0000      0x9b000 ADVAPI32.dll    C:\WINDOWS\system32\ADVAPI32.dll       N/A     Disabled
1056    svchost.exe     0x77e70000      0x92000 RPCRT4.dll      C:\WINDOWS\system32\RPCRT4.dll N/A     Disabled
1056    svchost.exe     0x77fe0000      0x11000 Secur32.dll     C:\WINDOWS\system32\Secur32.dll        N/A     Disabled
1056    svchost.exe     0x5cb70000      0x26000 ShimEng.dll     C:\WINDOWS\system32\ShimEng.dll        N/A     Disabled
1056    svchost.exe     0x6f880000      0x1ca000        AcGenral.DLL    C:\WINDOWS\AppPatch\AcGenral.DLL       N/A     Disabled
1056    svchost.exe     0x7e410000      0x91000 USER32.dll      C:\WINDOWS\system32\USER32.dll N/A     Disabled
1056    svchost.exe     0x77f10000      0x49000 GDI32.dll       C:\WINDOWS\system32\GDI32.dll  N/A     Disabled
1056    svchost.exe     0x76b40000      0x2d000 WINMM.dll       C:\WINDOWS\system32\WINMM.dll  N/A     Disabled
1056    svchost.exe     0x774e0000      0x13d000        ole32.dll       C:\WINDOWS\system32\ole32.dll  N/A     Disabled
1056    svchost.exe     0x77c10000      0x58000 msvcrt.dll      C:\WINDOWS\system32\msvcrt.dll N/A     Disabled
1056    svchost.exe     0x77120000      0x8b000 OLEAUT32.dll    C:\WINDOWS\system32\OLEAUT32.dll       N/A     Disabled
1056    svchost.exe     0x77be0000      0x15000 MSACM32.dll     C:\WINDOWS\system32\MSACM32.dll        N/A     Disabled
1056    svchost.exe     0x77c00000      0x8000  VERSION.dll     C:\WINDOWS\system32\VERSION.dll        N/A     Disabled
1056    svchost.exe     0x7c9c0000      0x817000        SHELL32.dll     C:\WINDOWS\system32\SHELL32.dll        N/A     Disabled
1056    svchost.exe     0x77f60000      0x76000 SHLWAPI.dll     C:\WINDOWS\system32\SHLWAPI.dll        N/A     Disabled
1056    svchost.exe     0x769c0000      0xb4000 USERENV.dll     C:\WINDOWS\system32\USERENV.dll        N/A     Disabled
1056    svchost.exe     0x5ad70000      0x38000 UxTheme.dll     C:\WINDOWS\system32\UxTheme.dll        N/A     Disabled
1056    svchost.exe     0x773d0000      0x103000        comctl32.dll    C:\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83\comctl32.dll     N/A     Disabled
1056    svchost.exe     0x5d090000      0x9a000 comctl32.dll    C:\WINDOWS\system32\comctl32.dll       N/A     Disabled
1056    svchost.exe     0x76770000      0xd000  dnsrslvr.dll    c:\windows\system32\dnsrslvr.dll       N/A     Disabled
1056    svchost.exe     0x76f20000      0x27000 DNSAPI.dll      c:\windows\system32\DNSAPI.dll N/A     Disabled
1056    svchost.exe     0x71ab0000      0x17000 WS2_32.dll      c:\windows\system32\WS2_32.dll N/A     Disabled
1056    svchost.exe     0x71aa0000      0x8000  WS2HELP.dll     c:\windows\system32\WS2HELP.dll        N/A     Disabled
1056    svchost.exe     0x76d60000      0x19000 iphlpapi.dll    c:\windows\system32\iphlpapi.dll       N/A     Disabled
1220    svchost.exe     0x1000000       0x6000  svchost.exe     C:\WINDOWS\system32\svchost.exe        N/A     Disabled
1220    svchost.exe     0x7c900000      0xaf000 ntdll.dll       C:\WINDOWS\system32\ntdll.dll  N/A     Disabled
1220    svchost.exe     0x7c800000      0xf6000 kernel32.dll    C:\WINDOWS\system32\kernel32.dll       N/A     Disabled
1220    svchost.exe     0x77dd0000      0x9b000 ADVAPI32.dll    C:\WINDOWS\system32\ADVAPI32.dll       N/A     Disabled
1220    svchost.exe     0x77e70000      0x92000 RPCRT4.dll      C:\WINDOWS\system32\RPCRT4.dll N/A     Disabled
1220    svchost.exe     0x77fe0000      0x11000 Secur32.dll     C:\WINDOWS\system32\Secur32.dll        N/A     Disabled
1220    svchost.exe     0x5cb70000      0x26000 ShimEng.dll     C:\WINDOWS\system32\ShimEng.dll        N/A     Disabled
1220    svchost.exe     0x6f880000      0x1ca000        AcGenral.DLL    C:\WINDOWS\AppPatch\AcGenral.DLL       N/A     Disabled
1220    svchost.exe     0x7e410000      0x91000 USER32.dll      C:\WINDOWS\system32\USER32.dll N/A     Disabled
1220    svchost.exe     0x77f10000      0x49000 GDI32.dll       C:\WINDOWS\system32\GDI32.dll  N/A     Disabled
1220    svchost.exe     0x76b40000      0x2d000 WINMM.dll       C:\WINDOWS\system32\WINMM.dll  N/A     Disabled
1220    svchost.exe     0x774e0000      0x13d000        ole32.dll       C:\WINDOWS\system32\ole32.dll  N/A     Disabled
1220    svchost.exe     0x77c10000      0x58000 msvcrt.dll      C:\WINDOWS\system32\msvcrt.dll N/A     Disabled
1220    svchost.exe     0x77120000      0x8b000 OLEAUT32.dll    C:\WINDOWS\system32\OLEAUT32.dll       N/A     Disabled
1220    svchost.exe     0x77be0000      0x15000 MSACM32.dll     C:\WINDOWS\system32\MSACM32.dll        N/A     Disabled
1220    svchost.exe     0x77c00000      0x8000  VERSION.dll     C:\WINDOWS\system32\VERSION.dll        N/A     Disabled
1220    svchost.exe     0x7c9c0000      0x817000        SHELL32.dll     C:\WINDOWS\system32\SHELL32.dll        N/A     Disabled
1220    svchost.exe     0x77f60000      0x76000 SHLWAPI.dll     C:\WINDOWS\system32\SHLWAPI.dll        N/A     Disabled
1220    svchost.exe     0x769c0000      0xb4000 USERENV.dll     C:\WINDOWS\system32\USERENV.dll        N/A     Disabled
1220    svchost.exe     0x5ad70000      0x38000 UxTheme.dll     C:\WINDOWS\system32\UxTheme.dll        N/A     Disabled
1220    svchost.exe     0x773d0000      0x103000        comctl32.dll    C:\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83\comctl32.dll     N/A     Disabled
1220    svchost.exe     0x5d090000      0x9a000 comctl32.dll    C:\WINDOWS\system32\comctl32.dll       N/A     Disabled
1220    svchost.exe     0x77690000      0x21000 NTMARTA.DLL     C:\WINDOWS\system32\NTMARTA.DLL        N/A     Disabled
1220    svchost.exe     0x71bf0000      0x13000 SAMLIB.dll      C:\WINDOWS\system32\SAMLIB.dll N/A     Disabled
1220    svchost.exe     0x76f60000      0x2c000 WLDAP32.dll     C:\WINDOWS\system32\WLDAP32.dll        N/A     Disabled
1220    svchost.exe     0x630000        0x2c5000        xpsp2res.dll    C:\WINDOWS\system32\xpsp2res.dll       N/A     Disabled
1220    svchost.exe     0x74c40000      0x6000  lmhsvc.dll      c:\windows\system32\lmhsvc.dll N/A     Disabled
1220    svchost.exe     0x76d60000      0x19000 iphlpapi.dll    c:\windows\system32\iphlpapi.dll       N/A     Disabled
1220    svchost.exe     0x71ab0000      0x17000 WS2_32.dll      c:\windows\system32\WS2_32.dll N/A     Disabled
1220    svchost.exe     0x71aa0000      0x8000  WS2HELP.dll     c:\windows\system32\WS2HELP.dll        N/A     Disabled
1220    svchost.exe     0x5a6e0000      0x15000 webclnt.dll     c:\windows\system32\webclnt.dll        N/A     Disabled
1220    svchost.exe     0x771b0000      0xaa000 WININET.dll     C:\WINDOWS\system32\WININET.dll        N/A     Disabled
1220    svchost.exe     0x77a80000      0x95000 CRYPT32.dll     C:\WINDOWS\system32\CRYPT32.dll        N/A     Disabled
1220    svchost.exe     0x77b20000      0x12000 MSASN1.dll      C:\WINDOWS\system32\MSASN1.dll N/A     Disabled
1220    svchost.exe     0x71ad0000      0x9000  wsock32.dll     C:\WINDOWS\system32\wsock32.dll        N/A     Disabled
1220    svchost.exe     0x76af0000      0x12000 regsvc.dll      c:\windows\system32\regsvc.dll N/A     Disabled
1220    svchost.exe     0x765e0000      0x14000 ssdpsrv.dll     c:\windows\system32\ssdpsrv.dll        N/A     Disabled
1220    svchost.exe     0x662b0000      0x58000 hnetcfg.dll     C:\WINDOWS\system32\hnetcfg.dll        N/A     Disabled
1220    svchost.exe     0x76fd0000      0x7f000 CLBCATQ.DLL     C:\WINDOWS\system32\CLBCATQ.DLL        N/A     Disabled
1220    svchost.exe     0x77050000      0xc5000 COMRes.dll      C:\WINDOWS\system32\COMRes.dll N/A     Disabled
1220    svchost.exe     0x71a50000      0x3f000 mswsock.dll     C:\WINDOWS\system32\mswsock.dll        N/A     Disabled
1220    svchost.exe     0x71a90000      0x8000  wshtcpip.dll    C:\WINDOWS\System32\wshtcpip.dll       N/A     Disabled
1484    explorer.exe    0x1000000       0xff000 Explorer.EXE    C:\WINDOWS\Explorer.EXEN/A     Disabled
1484    explorer.exe    0x7c900000      0xaf000 ntdll.dll       C:\WINDOWS\system32\ntdll.dll  N/A     Disabled
1484    explorer.exe    0x7c800000      0xf6000 kernel32.dll    C:\WINDOWS\system32\kernel32.dll       N/A     Disabled
1484    explorer.exe    0x77dd0000      0x9b000 ADVAPI32.dll    C:\WINDOWS\system32\ADVAPI32.dll       N/A     Disabled
1484    explorer.exe    0x77e70000      0x92000 RPCRT4.dll      C:\WINDOWS\system32\RPCRT4.dll N/A     Disabled
1484    explorer.exe    0x77fe0000      0x11000 Secur32.dll     C:\WINDOWS\system32\Secur32.dll        N/A     Disabled
1484    explorer.exe    0x75f80000      0xfd000 BROWSEUI.dll    C:\WINDOWS\system32\BROWSEUI.dll       N/A     Disabled
1484    explorer.exe    0x77f10000      0x49000 GDI32.dll       C:\WINDOWS\system32\GDI32.dll  N/A     Disabled
1484    explorer.exe    0x7e410000      0x91000 USER32.dll      C:\WINDOWS\system32\USER32.dll N/A     Disabled
1484    explorer.exe    0x77c10000      0x58000 msvcrt.dll      C:\WINDOWS\system32\msvcrt.dll N/A     Disabled
1484    explorer.exe    0x774e0000      0x13d000        ole32.dll       C:\WINDOWS\system32\ole32.dll  N/A     Disabled
1484    explorer.exe    0x77f60000      0x76000 SHLWAPI.dll     C:\WINDOWS\system32\SHLWAPI.dll        N/A     Disabled
1484    explorer.exe    0x77120000      0x8b000 OLEAUT32.dll    C:\WINDOWS\system32\OLEAUT32.dll       N/A     Disabled
1484    explorer.exe    0x7e290000      0x171000        SHDOCVW.dll     C:\WINDOWS\system32\SHDOCVW.dll        N/A     Disabled
1484    explorer.exe    0x77a80000      0x95000 CRYPT32.dll     C:\WINDOWS\system32\CRYPT32.dll        N/A     Disabled
1484    explorer.exe    0x77b20000      0x12000 MSASN1.dll      C:\WINDOWS\system32\MSASN1.dll N/A     Disabled
1484    explorer.exe    0x754d0000      0x80000 CRYPTUI.dll     C:\WINDOWS\system32\CRYPTUI.dll        N/A     Disabled
1484    explorer.exe    0x5b860000      0x55000 NETAPI32.dll    C:\WINDOWS\system32\NETAPI32.dll       N/A     Disabled
1484    explorer.exe    0x77c00000      0x8000  VERSION.dll     C:\WINDOWS\system32\VERSION.dll        N/A     Disabled
1484    explorer.exe    0x771b0000      0xaa000 WININET.dll     C:\WINDOWS\system32\WININET.dll        N/A     Disabled
1484    explorer.exe    0x76c30000      0x2e000 WINTRUST.dll    C:\WINDOWS\system32\WINTRUST.dll       N/A     Disabled
1484    explorer.exe    0x76c90000      0x28000 IMAGEHLP.dll    C:\WINDOWS\system32\IMAGEHLP.dll       N/A     Disabled
1484    explorer.exe    0x76f60000      0x2c000 WLDAP32.dll     C:\WINDOWS\system32\WLDAP32.dll        N/A     Disabled
1484    explorer.exe    0x7c9c0000      0x817000        SHELL32.dll     C:\WINDOWS\system32\SHELL32.dll        N/A     Disabled
1484    explorer.exe    0x5ad70000      0x38000 UxTheme.dll     C:\WINDOWS\system32\UxTheme.dll        N/A     Disabled
1484    explorer.exe    0x5cb70000      0x26000 ShimEng.dll     C:\WINDOWS\system32\ShimEng.dll        N/A     Disabled
1484    explorer.exe    0x6f880000      0x1ca000        AcGenral.DLL    C:\WINDOWS\AppPatch\AcGenral.DLL       N/A     Disabled
1484    explorer.exe    0x76b40000      0x2d000 WINMM.dll       C:\WINDOWS\system32\WINMM.dll  N/A     Disabled
1484    explorer.exe    0x77be0000      0x15000 MSACM32.dll     C:\WINDOWS\system32\MSACM32.dll        N/A     Disabled
1484    explorer.exe    0x769c0000      0xb4000 USERENV.dll     C:\WINDOWS\system32\USERENV.dll        N/A     Disabled
1484    explorer.exe    0x773d0000      0x103000        comctl32.dll    C:\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83\comctl32.dll     N/A     Disabled
1484    explorer.exe    0x5d090000      0x9a000 comctl32.dll    C:\WINDOWS\system32\comctl32.dll       N/A     Disabled
1484    explorer.exe    0x77b40000      0x22000 appHelp.dll     C:\WINDOWS\system32\appHelp.dll        N/A     Disabled
1484    explorer.exe    0x76fd0000      0x7f000 CLBCATQ.DLL     C:\WINDOWS\system32\CLBCATQ.DLL        N/A     Disabled
1484    explorer.exe    0x77050000      0xc5000 COMRes.dll      C:\WINDOWS\system32\COMRes.dll N/A     Disabled
1484    explorer.exe    0x77a20000      0x54000 cscui.dll       C:\WINDOWS\System32\cscui.dll  N/A     Disabled
1484    explorer.exe    0x76600000      0x1d000 CSCDLL.dll      C:\WINDOWS\System32\CSCDLL.dll N/A     Disabled
1484    explorer.exe    0x5ba60000      0x71000 themeui.dll     C:\WINDOWS\system32\themeui.dll        N/A     Disabled
1484    explorer.exe    0x76380000      0x5000  MSIMG32.dll     C:\WINDOWS\system32\MSIMG32.dll        N/A     Disabled
1484    explorer.exe    0x1100000       0x2c5000        xpsp2res.dll    C:\WINDOWS\system32\xpsp2res.dll       N/A     Disabled
1484    explorer.exe    0x71d40000      0x1b000 actxprxy.dll    C:\WINDOWS\system32\actxprxy.dll       N/A     Disabled
1484    explorer.exe    0x7d1e0000      0x2bc000        msi.dll C:\WINDOWS\system32\msi.dll    N/A     Disabled
1484    explorer.exe    0x77920000      0xf3000 SETUPAPI.dll    C:\WINDOWS\system32\SETUPAPI.dll       N/A     Disabled
1484    explorer.exe    0x76980000      0x8000  LINKINFO.dll    C:\WINDOWS\system32\LINKINFO.dll       N/A     Disabled
1484    explorer.exe    0x76990000      0x25000 ntshrui.dll     C:\WINDOWS\system32\ntshrui.dll        N/A     Disabled
1484    explorer.exe    0x76b20000      0x11000 ATL.DLL C:\WINDOWS\system32\ATL.DLL   N/A      Disabled
1484    explorer.exe    0x7e1e0000      0xa2000 urlmon.dll      C:\WINDOWS\system32\urlmon.dll N/A     Disabled
1484    explorer.exe    0x68000000      0x36000 rsaenh.dll      C:\WINDOWS\system32\rsaenh.dll N/A     Disabled
1484    explorer.exe    0x76400000      0x1a5000        NETSHELL.dll    C:\WINDOWS\system32\NETSHELL.dll       N/A     Disabled
1484    explorer.exe    0x76c00000      0x2e000 credui.dll      C:\WINDOWS\system32\credui.dll N/A     Disabled
1484    explorer.exe    0x478c0000      0xa000  dot3api.dll     C:\WINDOWS\system32\dot3api.dll        N/A     Disabled
1484    explorer.exe    0x76e80000      0xe000  rtutils.dll     C:\WINDOWS\system32\rtutils.dll        N/A     Disabled
1484    explorer.exe    0x736d0000      0x6000  dot3dlg.dll     C:\WINDOWS\system32\dot3dlg.dll        N/A     Disabled
1484    explorer.exe    0x5dca0000      0x28000 OneX.DLL        C:\WINDOWS\system32\OneX.DLL   N/A     Disabled
1484    explorer.exe    0x76f50000      0x8000  WTSAPI32.dll    C:\WINDOWS\system32\WTSAPI32.dll       N/A     Disabled
1484    explorer.exe    0x76360000      0x10000 WINSTA.dll      C:\WINDOWS\system32\WINSTA.dll N/A     Disabled
1484    explorer.exe    0x745b0000      0x22000 eappcfg.dll     C:\WINDOWS\system32\eappcfg.dll        N/A     Disabled
1484    explorer.exe    0x76080000      0x65000 MSVCP60.dll     C:\WINDOWS\system32\MSVCP60.dll        N/A     Disabled
1484    explorer.exe    0x5dcd0000      0xe000  eappprxy.dll    C:\WINDOWS\system32\eappprxy.dll       N/A     Disabled
1484    explorer.exe    0x76d60000      0x19000 iphlpapi.dll    C:\WINDOWS\system32\iphlpapi.dll       N/A     Disabled
1484    explorer.exe    0x71ab0000      0x17000 WS2_32.dll      C:\WINDOWS\system32\WS2_32.dll N/A     Disabled
1484    explorer.exe    0x71aa0000      0x8000  WS2HELP.dll     C:\WINDOWS\system32\WS2HELP.dll        N/A     Disabled
1484    explorer.exe    0x75e60000      0x13000 cryptnet.dll    C:\WINDOWS\system32\cryptnet.dll       N/A     Disabled
1484    explorer.exe    0x76bf0000      0xb000  PSAPI.DLL       C:\WINDOWS\system32\PSAPI.DLL  N/A     Disabled
1484    explorer.exe    0x722b0000      0x5000  SensApi.dll     C:\WINDOWS\system32\SensApi.dll        N/A     Disabled
1484    explorer.exe    0x4d4f0000      0x59000 WINHTTP.dll     C:\WINDOWS\system32\WINHTTP.dll        N/A     Disabled
1484    explorer.exe    0x75150000      0x13000 Cabinet.dll     C:\WINDOWS\system32\Cabinet.dll        N/A     Disabled
1484    explorer.exe    0x74b30000      0x46000 webcheck.dll    C:\WINDOWS\system32\webcheck.dll       N/A     Disabled
1484    explorer.exe    0x71ad0000      0x9000  WSOCK32.dll     C:\WINDOWS\system32\WSOCK32.dll        N/A     Disabled
1484    explorer.exe    0x76280000      0x21000 stobject.dll    C:\WINDOWS\system32\stobject.dll       N/A     Disabled
1484    explorer.exe    0x74af0000      0xa000  BatMeter.dll    C:\WINDOWS\system32\BatMeter.dll       N/A     Disabled
1484    explorer.exe    0x74ad0000      0x8000  POWRPROF.dll    C:\WINDOWS\system32\POWRPROF.dll       N/A     Disabled
1484    explorer.exe    0x72d20000      0x9000  wdmaud.drv      C:\WINDOWS\system32\wdmaud.drv N/A     Disabled
1484    explorer.exe    0x72d10000      0x8000  msacm32.drv     C:\WINDOWS\system32\msacm32.drv        N/A     Disabled
1484    explorer.exe    0x77bd0000      0x7000  midimap.dll     C:\WINDOWS\system32\midimap.dll        N/A     Disabled
1484    explorer.exe    0x71b20000      0x12000 MPR.dll C:\WINDOWS\system32\MPR.dll   N/A      Disabled
1484    explorer.exe    0x75f60000      0x7000  drprov.dll      C:\WINDOWS\System32\drprov.dll N/A     Disabled
1484    explorer.exe    0x71c10000      0xe000  ntlanman.dll    C:\WINDOWS\System32\ntlanman.dll       N/A     Disabled
1484    explorer.exe    0x71cd0000      0x17000 NETUI0.dll      C:\WINDOWS\System32\NETUI0.dll N/A     Disabled
1484    explorer.exe    0x71c90000      0x40000 NETUI1.dll      C:\WINDOWS\System32\NETUI1.dll N/A     Disabled
1484    explorer.exe    0x71c80000      0x7000  NETRAP.dll      C:\WINDOWS\System32\NETRAP.dll N/A     Disabled
1484    explorer.exe    0x71bf0000      0x13000 SAMLIB.dll      C:\WINDOWS\System32\SAMLIB.dll N/A     Disabled
1484    explorer.exe    0x75f70000      0xa000  davclnt.dll     C:\WINDOWS\System32\davclnt.dll        N/A     Disabled
1484    explorer.exe    0x76ee0000      0x3c000 RASAPI32.DLL    C:\WINDOWS\system32\RASAPI32.DLL       N/A     Disabled
1484    explorer.exe    0x76e90000      0x12000 rasman.dll      C:\WINDOWS\system32\rasman.dll N/A     Disabled
1484    explorer.exe    0x76eb0000      0x2f000 TAPI32.dll      C:\WINDOWS\system32\TAPI32.dll N/A     Disabled
1484    explorer.exe    0x71a50000      0x3f000 mswsock.dll     C:\WINDOWS\System32\mswsock.dll        N/A     Disabled
1484    explorer.exe    0x76f20000      0x27000 DNSAPI.dll      C:\WINDOWS\system32\DNSAPI.dll N/A     Disabled
1484    explorer.exe    0x76fb0000      0x8000  winrnr.dll      C:\WINDOWS\System32\winrnr.dll N/A     Disabled
1484    explorer.exe    0x662b0000      0x58000 hnetcfg.dll     C:\WINDOWS\system32\hnetcfg.dll        N/A     Disabled
1484    explorer.exe    0x71a90000      0x8000  wshtcpip.dll    C:\WINDOWS\System32\wshtcpip.dll       N/A     Disabled
1512    spoolsv.exe     0x1000000       0x10000 spoolsv.exe     C:\WINDOWS\system32\spoolsv.exe        N/A     Disabled
1512    spoolsv.exe     0x7c900000      0xaf000 ntdll.dll       C:\WINDOWS\system32\ntdll.dll  N/A     Disabled
1512    spoolsv.exe     0x7c800000      0xf6000 kernel32.dll    C:\WINDOWS\system32\kernel32.dll       N/A     Disabled
1512    spoolsv.exe     0x77dd0000      0x9b000 ADVAPI32.dll    C:\WINDOWS\system32\ADVAPI32.dll       N/A     Disabled
1512    spoolsv.exe     0x77e70000      0x92000 RPCRT4.dll      C:\WINDOWS\system32\RPCRT4.dll N/A     Disabled
1512    spoolsv.exe     0x77fe0000      0x11000 Secur32.dll     C:\WINDOWS\system32\Secur32.dll        N/A     Disabled
1512    spoolsv.exe     0x77f10000      0x49000 GDI32.dll       C:\WINDOWS\system32\GDI32.dll  N/A     Disabled
1512    spoolsv.exe     0x7e410000      0x91000 USER32.dll      C:\WINDOWS\system32\USER32.dll N/A     Disabled
1512    spoolsv.exe     0x77c10000      0x58000 msvcrt.dll      C:\WINDOWS\system32\msvcrt.dll N/A     Disabled
1512    spoolsv.exe     0x5cb70000      0x26000 ShimEng.dll     C:\WINDOWS\system32\ShimEng.dll        N/A     Disabled
1512    spoolsv.exe     0x6f880000      0x1ca000        AcGenral.DLL    C:\WINDOWS\AppPatch\AcGenral.DLL       N/A     Disabled
1512    spoolsv.exe     0x76b40000      0x2d000 WINMM.dll       C:\WINDOWS\system32\WINMM.dll  N/A     Disabled
1512    spoolsv.exe     0x774e0000      0x13d000        ole32.dll       C:\WINDOWS\system32\ole32.dll  N/A     Disabled
1512    spoolsv.exe     0x77120000      0x8b000 OLEAUT32.dll    C:\WINDOWS\system32\OLEAUT32.dll       N/A     Disabled
1512    spoolsv.exe     0x77be0000      0x15000 MSACM32.dll     C:\WINDOWS\system32\MSACM32.dll        N/A     Disabled
1512    spoolsv.exe     0x77c00000      0x8000  VERSION.dll     C:\WINDOWS\system32\VERSION.dll        N/A     Disabled
1512    spoolsv.exe     0x7c9c0000      0x817000        SHELL32.dll     C:\WINDOWS\system32\SHELL32.dll        N/A     Disabled
1512    spoolsv.exe     0x77f60000      0x76000 SHLWAPI.dll     C:\WINDOWS\system32\SHLWAPI.dll        N/A     Disabled
1512    spoolsv.exe     0x769c0000      0xb4000 USERENV.dll     C:\WINDOWS\system32\USERENV.dll        N/A     Disabled
1512    spoolsv.exe     0x5ad70000      0x38000 UxTheme.dll     C:\WINDOWS\system32\UxTheme.dll        N/A     Disabled
1512    spoolsv.exe     0x773d0000      0x103000        comctl32.dll    C:\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83\comctl32.dll     N/A     Disabled
1512    spoolsv.exe     0x5d090000      0x9a000 comctl32.dll    C:\WINDOWS\system32\comctl32.dll       N/A     Disabled
1512    spoolsv.exe     0x742e0000      0x15000 SPOOLSS.DLL     C:\WINDOWS\system32\SPOOLSS.DLL        N/A     Disabled
1512    spoolsv.exe     0x71ab0000      0x17000 WS2_32.dll      C:\WINDOWS\system32\WS2_32.dll N/A     Disabled
1512    spoolsv.exe     0x71aa0000      0x8000  WS2HELP.dll     C:\WINDOWS\system32\WS2HELP.dll        N/A     Disabled
1512    spoolsv.exe     0x76f20000      0x27000 DNSAPI.dll      C:\WINDOWS\system32\DNSAPI.dll N/A     Disabled
1512    spoolsv.exe     0x76fc0000      0x6000  rasadhlp.dll    C:\WINDOWS\system32\rasadhlp.dll       N/A     Disabled
1512    spoolsv.exe     0x75bb0000      0x56000 localspl.dll    C:\WINDOWS\system32\localspl.dll       N/A     Disabled
1512    spoolsv.exe     0x76c60000      0x2a000 sfc_os.dll      C:\WINDOWS\system32\sfc_os.dll N/A     Disabled
1512    spoolsv.exe     0x76c30000      0x2e000 WINTRUST.dll    C:\WINDOWS\system32\WINTRUST.dll       N/A     Disabled
1512    spoolsv.exe     0x77a80000      0x95000 CRYPT32.dll     C:\WINDOWS\system32\CRYPT32.dll        N/A     Disabled
1512    spoolsv.exe     0x77b20000      0x12000 MSASN1.dll      C:\WINDOWS\system32\MSASN1.dll N/A     Disabled
1512    spoolsv.exe     0x76c90000      0x28000 IMAGEHLP.dll    C:\WINDOWS\system32\IMAGEHLP.dll       N/A     Disabled
1512    spoolsv.exe     0x73000000      0x26000 winspool.drv    C:\WINDOWS\system32\winspool.drv       N/A     Disabled
1512    spoolsv.exe     0x5b860000      0x55000 netapi32.dll    C:\WINDOWS\system32\netapi32.dll       N/A     Disabled
1512    spoolsv.exe     0x742a0000      0xe000  cnbjmon.dll     C:\WINDOWS\system32\cnbjmon.dll        N/A     Disabled
1512    spoolsv.exe     0x74280000      0x7000  pjlmon.dll      C:\WINDOWS\system32\pjlmon.dll N/A     Disabled
1512    spoolsv.exe     0x72400000      0xe000  tcpmon.dll      C:\WINDOWS\system32\tcpmon.dll N/A     Disabled
1512    spoolsv.exe     0x723f0000      0x7000  usbmon.dll      C:\WINDOWS\system32\usbmon.dll N/A     Disabled
1512    spoolsv.exe     0x71a50000      0x3f000 mswsock.dll     C:\WINDOWS\System32\mswsock.dll        N/A     Disabled
1512    spoolsv.exe     0x76fb0000      0x8000  winrnr.dll      C:\WINDOWS\System32\winrnr.dll N/A     Disabled
1512    spoolsv.exe     0x76f60000      0x2c000 WLDAP32.dll     C:\WINDOWS\system32\WLDAP32.dll        N/A     Disabled
1512    spoolsv.exe     0x75c10000      0x24000 win32spl.dll    C:\WINDOWS\system32\win32spl.dll       N/A     Disabled
1512    spoolsv.exe     0x71c80000      0x7000  NETRAP.dll      C:\WINDOWS\system32\NETRAP.dll N/A     Disabled
1512    spoolsv.exe     0x767a0000      0x13000 NTDSAPI.dll     C:\WINDOWS\system32\NTDSAPI.dll        N/A     Disabled
1512    spoolsv.exe     0x76fd0000      0x7f000 CLBCATQ.DLL     C:\WINDOWS\system32\CLBCATQ.DLL        N/A     Disabled
1512    spoolsv.exe     0x77050000      0xc5000 COMRes.dll      C:\WINDOWS\system32\COMRes.dll N/A     Disabled
1512    spoolsv.exe     0x74300000      0x15000 inetpp.dll      C:\WINDOWS\system32\inetpp.dll N/A     Disabled
1512    spoolsv.exe     0x1010000       0x2c5000        xpsp2res.dll    C:\WINDOWS\system32\xpsp2res.dll       N/A     Disabled
1640    reader_sl.exe   0x400000        0xa000  Reader_sl.exe   C:\Program Files\Adobe\Reader 9.0\Reader\Reader_sl.exe N/A     Disabled
1640    reader_sl.exe   0x7c900000      0xaf000 ntdll.dll       C:\WINDOWS\system32\ntdll.dll  N/A     Disabled
1640    reader_sl.exe   0x7c800000      0xf6000 kernel32.dll    C:\WINDOWS\system32\kernel32.dll       N/A     Disabled
1640    reader_sl.exe   0x7e410000      0x91000 USER32.dll      C:\WINDOWS\system32\USER32.dll N/A     Disabled
1640    reader_sl.exe   0x77f10000      0x49000 GDI32.dll       C:\WINDOWS\system32\GDI32.dll  N/A     Disabled
1640    reader_sl.exe   0x77dd0000      0x9b000 ADVAPI32.dll    C:\WINDOWS\system32\ADVAPI32.dll       N/A     Disabled
1640    reader_sl.exe   0x77e70000      0x92000 RPCRT4.dll      C:\WINDOWS\system32\RPCRT4.dll N/A     Disabled
1640    reader_sl.exe   0x77fe0000      0x11000 Secur32.dll     C:\WINDOWS\system32\Secur32.dll        N/A     Disabled
1640    reader_sl.exe   0x7c9c0000      0x817000        SHELL32.dll     C:\WINDOWS\system32\SHELL32.dll        N/A     Disabled
1640    reader_sl.exe   0x77c10000      0x58000 msvcrt.dll      C:\WINDOWS\system32\msvcrt.dll N/A     Disabled
1640    reader_sl.exe   0x77f60000      0x76000 SHLWAPI.dll     C:\WINDOWS\system32\SHLWAPI.dll        N/A     Disabled
1640    reader_sl.exe   0x7c420000      0x87000 MSVCP80.dll     C:\WINDOWS\WinSxS\x86_Microsoft.VC80.CRT_1fc8b3b9a1e18e3b_8.0.50727.762_x-ww_6b128700\MSVCP80.dll      N/A   Disabled
1640    reader_sl.exe   0x78130000      0x9b000 MSVCR80.dll     C:\WINDOWS\WinSxS\x86_Microsoft.VC80.CRT_1fc8b3b9a1e18e3b_8.0.50727.762_x-ww_6b128700\MSVCR80.dll      N/A   Disabled
1640    reader_sl.exe   0x773d0000      0x103000        comctl32.dll    C:\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83\comctl32.dll     N/A     Disabled
1640    reader_sl.exe   0x5d090000      0x9a000 comctl32.dll    C:\WINDOWS\system32\comctl32.dll       N/A     Disabled
1640    reader_sl.exe   0x5ad70000      0x38000 uxtheme.dll     C:\WINDOWS\system32\uxtheme.dll        N/A     Disabled
1640    reader_sl.exe   0x71ab0000      0x17000 WS2_32.dll      C:\WINDOWS\system32\WS2_32.dll N/A     Disabled
1640    reader_sl.exe   0x71aa0000      0x8000  WS2HELP.dll     C:\WINDOWS\system32\WS2HELP.dll        N/A     Disabled
788     alg.exe 0x1000000       0xd000  alg.exe C:\WINDOWS\System32\alg.exe     N/A   Disabled
788     alg.exe 0x7c900000      0xaf000 ntdll.dll       C:\WINDOWS\system32\ntdll.dll N/A      Disabled
788     alg.exe 0x7c800000      0xf6000 kernel32.dll    C:\WINDOWS\system32\kernel32.dll       N/A     Disabled
788     alg.exe 0x77c10000      0x58000 msvcrt.dll      C:\WINDOWS\system32\msvcrt.dllN/A      Disabled
788     alg.exe 0x76b20000      0x11000 ATL.DLL C:\WINDOWS\System32\ATL.DLL     N/A   Disabled
788     alg.exe 0x7e410000      0x91000 USER32.dll      C:\WINDOWS\system32\USER32.dllN/A      Disabled
788     alg.exe 0x77f10000      0x49000 GDI32.dll       C:\WINDOWS\system32\GDI32.dll N/A      Disabled
788     alg.exe 0x77dd0000      0x9b000 ADVAPI32.dll    C:\WINDOWS\system32\ADVAPI32.dll       N/A     Disabled
788     alg.exe 0x77e70000      0x92000 RPCRT4.dll      C:\WINDOWS\system32\RPCRT4.dllN/A      Disabled
788     alg.exe 0x77fe0000      0x11000 Secur32.dll     C:\WINDOWS\system32\Secur32.dllN/A     Disabled
788     alg.exe 0x774e0000      0x13d000        ole32.dll       C:\WINDOWS\system32\ole32.dll  N/A     Disabled
788     alg.exe 0x77120000      0x8b000 OLEAUT32.dll    C:\WINDOWS\system32\OLEAUT32.dll       N/A     Disabled
788     alg.exe 0x71ad0000      0x9000  WSOCK32.dll     C:\WINDOWS\System32\WSOCK32.dllN/A     Disabled
788     alg.exe 0x71ab0000      0x17000 WS2_32.dll      C:\WINDOWS\System32\WS2_32.dllN/A      Disabled
788     alg.exe 0x71aa0000      0x8000  WS2HELP.dll     C:\WINDOWS\System32\WS2HELP.dllN/A     Disabled
788     alg.exe 0x71a50000      0x3f000 MSWSOCK.DLL     C:\WINDOWS\System32\MSWSOCK.DLLN/A     Disabled
788     alg.exe 0x5cb70000      0x26000 ShimEng.dll     C:\WINDOWS\System32\ShimEng.dllN/A     Disabled
788     alg.exe 0x6f880000      0x1ca000        AcGenral.DLL    C:\WINDOWS\AppPatch\AcGenral.DLL       N/A     Disabled
788     alg.exe 0x76b40000      0x2d000 WINMM.dll       C:\WINDOWS\System32\WINMM.dll N/A      Disabled
788     alg.exe 0x77be0000      0x15000 MSACM32.dll     C:\WINDOWS\System32\MSACM32.dllN/A     Disabled
788     alg.exe 0x77c00000      0x8000  VERSION.dll     C:\WINDOWS\system32\VERSION.dllN/A     Disabled
788     alg.exe 0x7c9c0000      0x817000        SHELL32.dll     C:\WINDOWS\system32\SHELL32.dll        N/A     Disabled
788     alg.exe 0x77f60000      0x76000 SHLWAPI.dll     C:\WINDOWS\system32\SHLWAPI.dllN/A     Disabled
788     alg.exe 0x769c0000      0xb4000 USERENV.dll     C:\WINDOWS\system32\USERENV.dllN/A     Disabled
788     alg.exe 0x5ad70000      0x38000 UxTheme.dll     C:\WINDOWS\System32\UxTheme.dllN/A     Disabled
788     alg.exe 0x773d0000      0x103000        comctl32.dll    C:\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83\comctl32.dll     N/A     Disabled
788     alg.exe 0x5d090000      0x9a000 comctl32.dll    C:\WINDOWS\system32\comctl32.dll       N/A     Disabled
788     alg.exe 0x76fd0000      0x7f000 CLBCATQ.DLL     C:\WINDOWS\System32\CLBCATQ.DLLN/A     Disabled
788     alg.exe 0x77050000      0xc5000 COMRes.dll      C:\WINDOWS\System32\COMRes.dllN/A      Disabled
788     alg.exe 0x680000        0x2c5000        xpsp2res.dll    C:\WINDOWS\System32\xpsp2res.dll       N/A     Disabled
788     alg.exe 0x662b0000      0x58000 hnetcfg.dll     C:\WINDOWS\system32\hnetcfg.dllN/A     Disabled
788     alg.exe 0x71a90000      0x8000  wshtcpip.dll    C:\WINDOWS\System32\wshtcpip.dll       N/A     Disabled
1136    wuauclt.exe     0x400000        0x1e000 wuauclt.exe     C:\WINDOWS\system32\wuauclt.exe        N/A     Disabled
1136    wuauclt.exe     0x7c900000      0xaf000 ntdll.dll       C:\WINDOWS\system32\ntdll.dll  N/A     Disabled
1136    wuauclt.exe     0x7c800000      0xf6000 kernel32.dll    C:\WINDOWS\system32\kernel32.dll       N/A     Disabled
1136    wuauclt.exe     0x77c10000      0x58000 msvcrt.dll      C:\WINDOWS\system32\msvcrt.dll N/A     Disabled
1136    wuauclt.exe     0x76b20000      0x11000 ATL.DLL C:\WINDOWS\system32\ATL.DLL   N/A      Disabled
1136    wuauclt.exe     0x7e410000      0x91000 USER32.dll      C:\WINDOWS\system32\USER32.dll N/A     Disabled
1136    wuauclt.exe     0x77f10000      0x49000 GDI32.dll       C:\WINDOWS\system32\GDI32.dll  N/A     Disabled
1136    wuauclt.exe     0x77dd0000      0x9b000 ADVAPI32.dll    C:\WINDOWS\system32\ADVAPI32.dll       N/A     Disabled
1136    wuauclt.exe     0x77e70000      0x92000 RPCRT4.dll      C:\WINDOWS\system32\RPCRT4.dll N/A     Disabled
1136    wuauclt.exe     0x77fe0000      0x11000 Secur32.dll     C:\WINDOWS\system32\Secur32.dll        N/A     Disabled
1136    wuauclt.exe     0x773d0000      0x103000        COMCTL32.dll    C:\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83\COMCTL32.dll     N/A     Disabled
1136    wuauclt.exe     0x77f60000      0x76000 SHLWAPI.dll     C:\WINDOWS\system32\SHLWAPI.dll        N/A     Disabled
1136    wuauclt.exe     0x774e0000      0x13d000        ole32.dll       C:\WINDOWS\system32\ole32.dll  N/A     Disabled
1136    wuauclt.exe     0x77120000      0x8b000 OLEAUT32.dll    C:\WINDOWS\system32\OLEAUT32.dll       N/A     Disabled
1136    wuauclt.exe     0x50940000      0x2a000 wuaucpl.cpl     C:\WINDOWS\system32\wuaucpl.cpl        N/A     Disabled
1136    wuauclt.exe     0x76780000      0x9000  SHFOLDER.dll    C:\WINDOWS\system32\SHFOLDER.dll       N/A     Disabled
1136    wuauclt.exe     0x50040000      0x119000        wuaueng.dll     C:\WINDOWS\system32\wuaueng.dll        N/A     Disabled
1136    wuauclt.exe     0x75260000      0x29000 ADVPACK.dll     C:\WINDOWS\system32\ADVPACK.dll        N/A     Disabled
1136    wuauclt.exe     0x77c00000      0x8000  VERSION.dll     C:\WINDOWS\system32\VERSION.dll        N/A     Disabled
1136    wuauclt.exe     0x75150000      0x13000 Cabinet.dll     C:\WINDOWS\system32\Cabinet.dll        N/A     Disabled
1136    wuauclt.exe     0x77a80000      0x95000 CRYPT32.dll     C:\WINDOWS\system32\CRYPT32.dll        N/A     Disabled
1136    wuauclt.exe     0x77b20000      0x12000 MSASN1.dll      C:\WINDOWS\system32\MSASN1.dll N/A     Disabled
1136    wuauclt.exe     0x606b0000      0x10d000        ESENT.dll       C:\WINDOWS\system32\ESENT.dll  N/A     Disabled
1136    wuauclt.exe     0x600a0000      0xb000  mspatcha.dll    C:\WINDOWS\system32\mspatcha.dll       N/A     Disabled
1136    wuauclt.exe     0x77920000      0xf3000 SETUPAPI.dll    C:\WINDOWS\system32\SETUPAPI.dll       N/A     Disabled
1136    wuauclt.exe     0x76bb0000      0x5000  sfc.dll C:\WINDOWS\system32\sfc.dll   N/A      Disabled
1136    wuauclt.exe     0x76c60000      0x2a000 sfc_os.dll      C:\WINDOWS\system32\sfc_os.dll N/A     Disabled
1136    wuauclt.exe     0x76c30000      0x2e000 WINTRUST.dll    C:\WINDOWS\system32\WINTRUST.dll       N/A     Disabled
1136    wuauclt.exe     0x76c90000      0x28000 IMAGEHLP.dll    C:\WINDOWS\system32\IMAGEHLP.dll       N/A     Disabled
1136    wuauclt.exe     0x769c0000      0xb4000 USERENV.dll     C:\WINDOWS\system32\USERENV.dll        N/A     Disabled
1136    wuauclt.exe     0x4d4f0000      0x59000 WINHTTP.dll     C:\WINDOWS\system32\WINHTTP.dll        N/A     Disabled
1136    wuauclt.exe     0x73000000      0x26000 WINSPOOL.DRV    C:\WINDOWS\system32\WINSPOOL.DRV       N/A     Disabled
1136    wuauclt.exe     0x76360000      0x10000 WINSTA.dll      C:\WINDOWS\system32\WINSTA.dll N/A     Disabled
1136    wuauclt.exe     0x5b860000      0x55000 NETAPI32.dll    C:\WINDOWS\system32\NETAPI32.dll       N/A     Disabled
1136    wuauclt.exe     0x71ab0000      0x17000 WS2_32.dll      C:\WINDOWS\system32\WS2_32.dll N/A     Disabled
1136    wuauclt.exe     0x71aa0000      0x8000  WS2HELP.dll     C:\WINDOWS\system32\WS2HELP.dll        N/A     Disabled
1136    wuauclt.exe     0x76f50000      0x8000  WTSAPI32.dll    C:\WINDOWS\system32\WTSAPI32.dll       N/A     Disabled
1136    wuauclt.exe     0x76380000      0x5000  MSIMG32.dll     C:\WINDOWS\system32\MSIMG32.dll        N/A     Disabled
1136    wuauclt.exe     0x7c9c0000      0x817000        SHELL32.dll     C:\WINDOWS\system32\SHELL32.dll        N/A     Disabled
1136    wuauclt.exe     0x5cb70000      0x26000 ShimEng.dll     C:\WINDOWS\system32\ShimEng.dll        N/A     Disabled
1136    wuauclt.exe     0x6f880000      0x1ca000        AcGenral.DLL    C:\WINDOWS\AppPatch\AcGenral.DLL       N/A     Disabled
1136    wuauclt.exe     0x76b40000      0x2d000 WINMM.dll       C:\WINDOWS\system32\WINMM.dll  N/A     Disabled
1136    wuauclt.exe     0x77be0000      0x15000 MSACM32.dll     C:\WINDOWS\system32\MSACM32.dll        N/A     Disabled
1136    wuauclt.exe     0x5ad70000      0x38000 UxTheme.dll     C:\WINDOWS\system32\UxTheme.dll        N/A     Disabled
1136    wuauclt.exe     0xfb0000        0x2c5000        xpsp2res.dll    C:\WINDOWS\system32\xpsp2res.dll       N/A     Disabled
1136    wuauclt.exe     0x76fd0000      0x7f000 CLBCATQ.DLL     C:\WINDOWS\system32\CLBCATQ.DLL        N/A     Disabled
1136    wuauclt.exe     0x77050000      0xc5000 COMRes.dll      C:\WINDOWS\system32\COMRes.dll N/A     Disabled
1136    wuauclt.exe     0x50640000      0xc000  wups.dll        C:\WINDOWS\system32\wups.dll   N/A     Disabled
1588    wuauclt.exe     0x400000        0x1e000 wuauclt.exe     C:\WINDOWS\system32\wuauclt.exe        N/A     Disabled
1588    wuauclt.exe     0x7c900000      0xaf000 ntdll.dll       C:\WINDOWS\system32\ntdll.dll  N/A     Disabled
1588    wuauclt.exe     0x7c800000      0xf6000 kernel32.dll    C:\WINDOWS\system32\kernel32.dll       N/A     Disabled
1588    wuauclt.exe     0x77c10000      0x58000 msvcrt.dll      C:\WINDOWS\system32\msvcrt.dll N/A     Disabled
1588    wuauclt.exe     0x76b20000      0x11000 ATL.DLL C:\WINDOWS\system32\ATL.DLL   N/A      Disabled
1588    wuauclt.exe     0x7e410000      0x91000 USER32.dll      C:\WINDOWS\system32\USER32.dll N/A     Disabled
1588    wuauclt.exe     0x77f10000      0x49000 GDI32.dll       C:\WINDOWS\system32\GDI32.dll  N/A     Disabled
1588    wuauclt.exe     0x77dd0000      0x9b000 ADVAPI32.dll    C:\WINDOWS\system32\ADVAPI32.dll       N/A     Disabled
1588    wuauclt.exe     0x77e70000      0x92000 RPCRT4.dll      C:\WINDOWS\system32\RPCRT4.dll N/A     Disabled
1588    wuauclt.exe     0x77fe0000      0x11000 Secur32.dll     C:\WINDOWS\system32\Secur32.dll        N/A     Disabled
1588    wuauclt.exe     0x773d0000      0x103000        COMCTL32.dll    C:\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83\COMCTL32.dll     N/A     Disabled
1588    wuauclt.exe     0x77f60000      0x76000 SHLWAPI.dll     C:\WINDOWS\system32\SHLWAPI.dll        N/A     Disabled
1588    wuauclt.exe     0x774e0000      0x13d000        ole32.dll       C:\WINDOWS\system32\ole32.dll  N/A     Disabled
1588    wuauclt.exe     0x77120000      0x8b000 OLEAUT32.dll    C:\WINDOWS\system32\OLEAUT32.dll       N/A     Disabled
1588    wuauclt.exe     0x50940000      0x2a000 wuaucpl.cpl     C:\WINDOWS\system32\wuaucpl.cpl        N/A     Disabled
1588    wuauclt.exe     0x76780000      0x9000  SHFOLDER.dll    C:\WINDOWS\system32\SHFOLDER.dll       N/A     Disabled
1588    wuauclt.exe     0x50040000      0x119000        wuaueng.dll     C:\WINDOWS\system32\wuaueng.dll        N/A     Disabled
1588    wuauclt.exe     0x75260000      0x29000 ADVPACK.dll     C:\WINDOWS\system32\ADVPACK.dll        N/A     Disabled
1588    wuauclt.exe     0x77c00000      0x8000  VERSION.dll     C:\WINDOWS\system32\VERSION.dll        N/A     Disabled
1588    wuauclt.exe     0x75150000      0x13000 Cabinet.dll     C:\WINDOWS\system32\Cabinet.dll        N/A     Disabled
1588    wuauclt.exe     0x77a80000      0x95000 CRYPT32.dll     C:\WINDOWS\system32\CRYPT32.dll        N/A     Disabled
1588    wuauclt.exe     0x77b20000      0x12000 MSASN1.dll      C:\WINDOWS\system32\MSASN1.dll N/A     Disabled
1588    wuauclt.exe     0x606b0000      0x10d000        ESENT.dll       C:\WINDOWS\system32\ESENT.dll  N/A     Disabled
1588    wuauclt.exe     0x600a0000      0xb000  mspatcha.dll    C:\WINDOWS\system32\mspatcha.dll       N/A     Disabled
1588    wuauclt.exe     0x77920000      0xf3000 SETUPAPI.dll    C:\WINDOWS\system32\SETUPAPI.dll       N/A     Disabled
1588    wuauclt.exe     0x76bb0000      0x5000  sfc.dll C:\WINDOWS\system32\sfc.dll   N/A      Disabled
1588    wuauclt.exe     0x76c60000      0x2a000 sfc_os.dll      C:\WINDOWS\system32\sfc_os.dll N/A     Disabled
1588    wuauclt.exe     0x76c30000      0x2e000 WINTRUST.dll    C:\WINDOWS\system32\WINTRUST.dll       N/A     Disabled
1588    wuauclt.exe     0x76c90000      0x28000 IMAGEHLP.dll    C:\WINDOWS\system32\IMAGEHLP.dll       N/A     Disabled
1588    wuauclt.exe     0x769c0000      0xb4000 USERENV.dll     C:\WINDOWS\system32\USERENV.dll        N/A     Disabled
1588    wuauclt.exe     0x4d4f0000      0x59000 WINHTTP.dll     C:\WINDOWS\system32\WINHTTP.dll        N/A     Disabled
1588    wuauclt.exe     0x73000000      0x26000 WINSPOOL.DRV    C:\WINDOWS\system32\WINSPOOL.DRV       N/A     Disabled
1588    wuauclt.exe     0x76360000      0x10000 WINSTA.dll      C:\WINDOWS\system32\WINSTA.dll N/A     Disabled
1588    wuauclt.exe     0x5b860000      0x55000 NETAPI32.dll    C:\WINDOWS\system32\NETAPI32.dll       N/A     Disabled
1588    wuauclt.exe     0x71ab0000      0x17000 WS2_32.dll      C:\WINDOWS\system32\WS2_32.dll N/A     Disabled
1588    wuauclt.exe     0x71aa0000      0x8000  WS2HELP.dll     C:\WINDOWS\system32\WS2HELP.dll        N/A     Disabled
1588    wuauclt.exe     0x76f50000      0x8000  WTSAPI32.dll    C:\WINDOWS\system32\WTSAPI32.dll       N/A     Disabled
1588    wuauclt.exe     0x76380000      0x5000  MSIMG32.dll     C:\WINDOWS\system32\MSIMG32.dll        N/A     Disabled
1588    wuauclt.exe     0x7c9c0000      0x817000        SHELL32.dll     C:\WINDOWS\system32\SHELL32.dll        N/A     Disabled
1588    wuauclt.exe     0x5cb70000      0x26000 ShimEng.dll     C:\WINDOWS\system32\ShimEng.dll        N/A     Disabled
1588    wuauclt.exe     0x6f880000      0x1ca000        AcGenral.DLL    C:\WINDOWS\AppPatch\AcGenral.DLL       N/A     Disabled
1588    wuauclt.exe     0x76b40000      0x2d000 WINMM.dll       C:\WINDOWS\system32\WINMM.dll  N/A     Disabled
1588    wuauclt.exe     0x77be0000      0x15000 MSACM32.dll     C:\WINDOWS\system32\MSACM32.dll        N/A     Disabled
1588    wuauclt.exe     0x5ad70000      0x38000 UxTheme.dll     C:\WINDOWS\system32\UxTheme.dll        N/A     Disabled
1588    wuauclt.exe     0x76fd0000      0x7f000 CLBCATQ.DLL     C:\WINDOWS\system32\CLBCATQ.DLL        N/A     Disabled
1588    wuauclt.exe     0x77050000      0xc5000 COMRes.dll      C:\WINDOWS\system32\COMRes.dll N/A     Disabled
1588    wuauclt.exe     0x1290000       0x2c5000        xpsp2res.dll    C:\WINDOWS\system32\xpsp2res.dll       N/A     Disabled
1588    wuauclt.exe     0x50640000      0xc000  wups.dll        C:\WINDOWS\system32\wups.dll   N/A     Disabled


```

### Volatility Hunting and Detection Capabilities 

Volatility offers a plethora of plugins that can be used to aid in your hunting and detection capabilities when hunting for malware or other anomalies within a system's memory.

It is recommended that you have a basic understanding of how evasion techniques and various malware techniques are employed by adversaries, as well as how to hunt and detect them before going through this section.

The first plugin we will be talking about that is one of the most useful when hunting for code injection is malfind. This plugin will attempt to identify injected processes and their PIDs along with the offset address and a Hex, Ascii, and Disassembly view of the infected area. The plugin works by scanning the heap and identifying processes that have the executable bit set RWE or RX and/or no memory-mapped file on disk (file-less malware).

Based on what malfind identifies, the injected area will change. An MZ header is an indicator of a Windows executable file. The injected area could also be directed towards shellcode which requires further analysis.

	Syntax: python3 vol.py -f <file> windows.malfind

```
thmanalyst@ubuntu:/opt/volatility3$ python3 vol.py -f dump.vmem windows.malfind
Volatility 3 Framework 1.0.1
Progress:  100.00               PDB scanning finished                     
PID     Process Start VPN       End VPN Tag     Protection      CommitCharge    PrivateMemory  File output     Hexdump Disasm

584     csrss.exe       0x7f6f0000      0x7f7effff      Vad     PAGE_EXECUTE_READWRITE00       Disabled
c8 00 00 00 91 01 00 00 ........
ff ee ff ee 08 70 00 00 .....p..
08 00 00 00 00 fe 00 00 ........
00 00 10 00 00 20 00 00 ........
00 02 00 00 00 20 00 00 ........
8d 01 00 00 ff ef fd 7f ........
03 00 08 06 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........        c8 00 00 00 91 01 00 00 ff ee ff ee 08 70 00 00 08 00 00 00 00 fe 00 00 00 00 10 00 00 20 00 00 00 02 00 00 00 20 00 00 8d 01 00 00 ff ef fd 7f 03 00 08 06 00 00 00 00 00 00 00 00 00 00 00 00
608     winlogon.exe    0x13410000      0x13413fff      VadS    PAGE_EXECUTE_READWRITE41       Disabled
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 25 00 25 00 ....%.%.
01 00 00 00 00 00 00 00 ........        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 25 00 25 00 01 00 00 00 00 00 00 00
608     winlogon.exe    0xf9e0000       0xf9e3fff       VadS    PAGE_EXECUTE_READWRITE41       Disabled
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 25 00 25 00 ....%.%.
01 00 00 00 00 00 00 00 ........        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 25 00 25 00 01 00 00 00 00 00 00 00
608     winlogon.exe    0x4ee0000       0x4ee3fff       VadS    PAGE_EXECUTE_READWRITE41       Disabled
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 25 00 25 00 ....%.%.
01 00 00 00 00 00 00 00 ........        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 25 00 25 00 01 00 00 00 00 00 00 00
608     winlogon.exe    0x554c0000      0x554c3fff      VadS    PAGE_EXECUTE_READWRITE41       Disabled
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 28 00 28 00 ....(.(.
01 00 00 00 00 00 00 00 ........        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 28 00 28 00 01 00 00 00 00 00 00 00
608     winlogon.exe    0x4dc40000      0x4dc43fff      VadS    PAGE_EXECUTE_READWRITE41       Disabled
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 23 00 23 00 ....#.#.
01 00 00 00 00 00 00 00 ........        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 23 00 23 00 01 00 00 00 00 00 00 00
608     winlogon.exe    0x4c540000      0x4c543fff      VadS    PAGE_EXECUTE_READWRITE41       Disabled
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 22 00 22 00 ....".".
01 00 00 00 00 00 00 00 ........        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 22 00 22 00 01 00 00 00 00 00 00 00
608     winlogon.exe    0x5de10000      0x5de13fff      VadS    PAGE_EXECUTE_READWRITE41       Disabled
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 22 00 22 00 ....".".
01 00 00 00 00 00 00 00 ........        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 22 00 22 00 01 00 00 00 00 00 00 00
608     winlogon.exe    0x6a230000      0x6a233fff      VadS    PAGE_EXECUTE_READWRITE41       Disabled
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 2b 00 2b 00 ....+.+.
01 00 00 00 00 00 00 00 ........        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 2b 00 2b 00 01 00 00 00 00 00 00 00
608     winlogon.exe    0x73f40000      0x73f43fff      VadS    PAGE_EXECUTE_READWRITE41       Disabled
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 2a 00 2a 00 ....*.*.
01 00 00 00 00 00 00 00 ........        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 2a 00 2a 00 01 00 00 00 00 00 00 00
1484    explorer.exe    0x1460000       0x1480fff       VadS    PAGE_EXECUTE_READWRITE33       1       Disabled
4d 5a 90 00 03 00 00 00 MZ......
04 00 00 00 ff ff 00 00 ........
b8 00 00 00 00 00 00 00 ........
40 00 00 00 00 00 00 00 @.......
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 e0 00 00 00 ........        4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 e0 00 00 00
1640    reader_sl.exe   0x3d0000        0x3f0fff        VadS    PAGE_EXECUTE_READWRITE33       1       Disabled
4d 5a 90 00 03 00 00 00 MZ......
04 00 00 00 ff ff 00 00 ........
b8 00 00 00 00 00 00 00 ........
40 00 00 00 00 00 00 00 @.......
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 e0 00 00 00 ........        4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 e0 00 00 00


```

Volatility also offers the capability to compare the memory file against YARA rules. yarascan will search for strings, patterns, and compound rules against a rule set. You can either use a YARA file as an argument or list rules within the command line.

	Syntax: python3 vol.py -f <file> windows.yarascan

There are other plugins that can be considered part of Volatility's hunting and detection capabilities; however, we will be covering them in the next task. 


### Advanced Memory Forensics 

Advanced Memory Forensics can become confusing when you begin talking about system objects and how malware interacts directly with the system, especially if you do not have prior experience hunting some of the techniques used such as hooking and driver manipulation. When dealing with an advanced adversary, you may encounter malware, most of the time rootkits that will employ very nasty evasion measures that will require you as an analyst to dive into the drivers, mutexes, and hooked functions. A number of modules can help us in this journey to further uncover malware hiding within memory.

The first evasion technique we will be hunting is hooking; there are five methods of hooking employed by adversaries, outlined below:

    SSDT Hooks
    IRP Hooks
    IAT Hooks
    EAT Hooks
    Inline Hooks

We will only be focusing on hunting SSDT hooking as this one of the most common techniques when dealing with malware evasion and the easiest plugin to use with the base volatility plugins.

The ssdt plugin will search for hooking and output its results. Hooking can be used by legitimate applications, so it is up to you as the analyst to identify what is evil. As a brief overview of what SSDT hooking is: SSDT stands for System Service Descriptor Table; the Windows kernel uses this table to look up system functions. An adversary can hook into this table and modify pointers to point to a location the rootkit controls.

There can be hundreds of table entries that ssdt will dump; you will then have to analyze the output further or compare against a baseline. A suggestion is to use this plugin after investigating the initial compromise and working off it as part of your lead investigation.

	Syntax: python3 vol.py -f <file> windows.ssdt 

Adversaries will also use malicious driver files as part of their evasion. Volatility offers two plugins to list drivers.

The modules plugin will dump a list of loaded kernel modules; this can be useful in identifying active malware. However, if a malicious file is idly waiting or hidden, this plugin may miss it.

This plugin is best used once you have further investigated and found potential indicators to use as input for searching and filtering.

	Syntax: python3 vol.py -f <file> windows.modules

The driverscan plugin will scan for drivers present on the system at the time of extraction. This plugin can help to identify driver files in the kernel that the modules plugin might have missed or were hidden.

As with the last plugin, it is again recommended to have a prior investigation before moving on to this plugin. It is also recommended to look through the modules plugin before driverscan.

	Syntax: python3 vol.py -f <file> windows.driverscan

In most cases, driverscan will come up with no output; however, if you do not find anything with the modules plugin, it can be useful to attempt using this plugin.

There are also other plugins listed below that can be helpful when attempting to hunt for advanced malware in memory.

    modscan
    driverirp
    callbacks
    idt
    apihooks
    moddump
    handles

Note: Some of these are only present on Volatility2 or are part of third-party plugins. To get the most out of Volatility, you may need to move to some third-party or custom plugins.

```
thmanalyst@ubuntu:/opt/volatility3$ python3 vol.py -f dump.vmem windows.ssdt
Volatility 3 Framework 1.0.1
Progress:  100.00               PDB scanning finished                     
Index   Address Module  Symbol

0       0x80599948      ntoskrnl        NtAcceptConnectPort
1       0x805e6db6      ntoskrnl        NtAccessCheck
2       0x805ea5fc      ntoskrnl        NtAccessCheckAndAuditAlarm
3       0x805e6de8      ntoskrnl        NtAccessCheckByType
4       0x805ea636      ntoskrnl        NtAccessCheckByTypeAndAuditAlarm
5       0x805e6e1e      ntoskrnl        NtAccessCheckByTypeResultList
6       0x805ea67a      ntoskrnl        NtAccessCheckByTypeResultListAndAuditAlarm
7       0x805ea6be      ntoskrnl        NtAccessCheckByTypeResultListAndAuditAlarmByHandle
8       0x8060bdfe      ntoskrnl        NtAddAtom
9       0x8060cb50      ntoskrnl        NtAddBootEntry
9       0x8060cb50      ntoskrnl        NtEnumerateBootEntries
9       0x8060cb50      ntoskrnl        NtQueryBootEntryOrder
9       0x8060cb50      ntoskrnl        NtQueryBootOptions
9       0x8060cb50      ntoskrnl        NtSetBootEntryOrder
9       0x8060cb50      ntoskrnl        NtSetBootOptions
10      0x805e21b4      ntoskrnl        NtAdjustGroupsToken
11      0x805e1e0c      ntoskrnl        NtAdjustPrivilegesToken
12      0x805cade6      ntoskrnl        NtAlertResumeThread
13      0x805cad96      ntoskrnl        NtAlertThread
14      0x8060c424      ntoskrnl        NtAllocateLocallyUniqueId
15      0x805ab5ae      ntoskrnl        NtAllocateUserPhysicalPages
16      0x8060ba3c      ntoskrnl        NtAllocateUuids
17      0x8059ddbe      ntoskrnl        NtAllocateVirtualMemory
18      0x805a5a00      ntoskrnl        NtAreMappedFilesTheSame
19      0x805cc8c4      ntoskrnl        NtAssignProcessToJobObject
20      0x804ff828      ntoskrnl        NtCallbackReturn
21      0x8060cb42      ntoskrnl        NtCancelDeviceWakeupRequest
21      0x8060cb42      ntoskrnl        NtDeleteBootEntry
21      0x8060cb42      ntoskrnl        NtModifyBootEntry
22      0x8056bcd6      ntoskrnl        NtCancelIoFile
23      0x8053500e      ntoskrnl        NtCancelTimer
24      0x806050d4      ntoskrnl        NtClearEvent
25      0x805b1c3a      ntoskrnl        NtClose
26      0x805eab36      ntoskrnl        NtCloseObjectAuditAlarm
27      0x80619e56      ntoskrnl        NtCompactKeys
28      0x805ef028      ntoskrnl        NtCompareTokens
29      0x8059a036      ntoskrnl        NtCompleteConnectPort
30      0x8061a0aa      ntoskrnl        NtCompressKey
31      0x805998e8      ntoskrnl        NtConnectPort
32      0x80540e00      ntoskrnl        NtContinue
33      0x806389aa      ntoskrnl        NtCreateDebugObject
34      0x805b3c6e      ntoskrnl        NtCreateDirectoryObject
35      0x80605124      ntoskrnl        NtCreateEvent
36      0x8060d3c6      ntoskrnl        NtCreateEventPair
37      0x8056e27c      ntoskrnl        NtCreateFile
38      0x8056dc5a      ntoskrnl        NtCreateIoCompletion
39      0x805cb888      ntoskrnl        NtCreateJobObject
40      0x805cb5c0      ntoskrnl        NtCreateJobSet
41      0x8061a286      ntoskrnl        NtCreateKey
42      0x8056e38a      ntoskrnl        NtCreateMailslotFile
43      0x8060d7be      ntoskrnl        NtCreateMutant
44      0x8056e2b6      ntoskrnl        NtCreateNamedPipeFile
45      0x805a0da8      ntoskrnl        NtCreatePagingFile
46      0x8059a404      ntoskrnl        NtCreatePort
47      0x805c7420      ntoskrnl        NtCreateProcess
48      0x805c736a      ntoskrnl        NtCreateProcessEx
49      0x8060dbde      ntoskrnl        NtCreateProfile
50      0x805a06ec      ntoskrnl        NtCreateSection
51      0x8060b15a      ntoskrnl        NtCreateSemaphore
52      0x805b9594      ntoskrnl        NtCreateSymbolicLinkObject
53      0x805c7208      ntoskrnl        NtCreateThread
54      0x8060d08e      ntoskrnl        NtCreateTimer
55      0x805ef3d0      ntoskrnl        NtCreateToken
56      0x8059a428      ntoskrnl        NtCreateWaitablePort
57      0x80639a86      ntoskrnl        NtDebugActiveProcess
58      0x80639bd6      ntoskrnl        NtDebugContinue
59      0x8060ca92      ntoskrnl        NtDelayExecution
60      0x8060c2b4      ntoskrnl        NtDeleteAtom
61      0x8060cb42      ntoskrnl        NtCancelDeviceWakeupRequest
61      0x8060cb42      ntoskrnl        NtDeleteBootEntry
61      0x8060cb42      ntoskrnl        NtModifyBootEntry
62      0x8056be1c      ntoskrnl        NtDeleteFile
63      0x8061a716      ntoskrnl        NtDeleteKey
64      0x805eac42      ntoskrnl        NtDeleteObjectAuditAlarm
65      0x8061a8e6      ntoskrnl        NtDeleteValueKey
66      0x8056e442      ntoskrnl        NtDeviceIoControlFile
67      0x806090ce      ntoskrnl        NtDisplayString
68      0x805b384e      ntoskrnl        NtDuplicateObject
69      0x805e3062      ntoskrnl        NtDuplicateToken
70      0x8060cb50      ntoskrnl        NtAddBootEntry
70      0x8060cb50      ntoskrnl        NtEnumerateBootEntries
70      0x8060cb50      ntoskrnl        NtQueryBootEntryOrder
70      0x8060cb50      ntoskrnl        NtQueryBootOptions
70      0x8060cb50      ntoskrnl        NtSetBootEntryOrder
70      0x8060cb50      ntoskrnl        NtSetBootOptions
71      0x8061aac6      ntoskrnl        NtEnumerateKey
72      0x8060cb34      ntoskrnl        NtEnumerateSystemEnvironmentValuesEx
73      0x8061ad30      ntoskrnl        NtEnumerateValueKey
74      0x805a9126      ntoskrnl        NtExtendSection
75      0x805e320e      ntoskrnl        NtFilterToken
76      0x8060c068      ntoskrnl        NtFindAtom
77      0x8056bee8      ntoskrnl        NtFlushBuffersFile
78      0x805abe38      ntoskrnl        NtFlushInstructionCache
79      0x8061af9a      ntoskrnl        NtFlushKey
80      0x805a1ab8      ntoskrnl        NtFlushVirtualMemory
81      0x805abdda      ntoskrnl        NtFlushWriteBuffer
82      0x805ab94a      ntoskrnl        NtFreeUserPhysicalPages
83      0x805a8400      ntoskrnl        NtFreeVirtualMemory
84      0x8056e476      ntoskrnl        NtFsControlFile
85      0x805c771a      ntoskrnl        NtGetContextThread
86      0x805be4d8      ntoskrnl        NtGetDevicePowerState
87      0x8058e588      ntoskrnl        NtGetPlugPlayEvent
88      0x8051d9a2      ntoskrnl        NtGetWriteWatch
89      0x805eed1c      ntoskrnl        NtImpersonateAnonymousToken
90      0x8059a492      ntoskrnl        NtImpersonateClientOfPort
91      0x805cda5c      ntoskrnl        NtImpersonateThread
92      0x806183dc      ntoskrnl        NtInitializeRegistry
93      0x805be2be      ntoskrnl        NtInitiatePowerAction
94      0x805cb484      ntoskrnl        NtIsProcessInJob
95      0x805be4c4      ntoskrnl        NtIsSystemResumeAutomatic
96      0x8059a69e      ntoskrnl        NtListenPort
97      0x80579588      ntoskrnl        NtLoadDriver
98      0x8061c482      ntoskrnl        NtLoadKey
99      0x8061c08e      ntoskrnl        NtLoadKey2
100     0x8056e4aa      ntoskrnl        NtLockFile
101     0x80609630      ntoskrnl        NtLockProductActivationKeys
102     0x8061a156      ntoskrnl        NtLockRegistryKey
103     0x805abf40      ntoskrnl        NtLockVirtualMemory
104     0x805b50ee      ntoskrnl        NtMakePermanentObject
105     0x805b1cde      ntoskrnl        NtMakeTemporaryObject
106     0x805aa8a2      ntoskrnl        NtMapUserPhysicalPages
107     0x805aae7a      ntoskrnl        NtMapUserPhysicalPagesScatter
108     0x805a7480      ntoskrnl        NtMapViewOfSection
109     0x8060cb42      ntoskrnl        NtCancelDeviceWakeupRequest
109     0x8060cb42      ntoskrnl        NtDeleteBootEntry
109     0x8060cb42      ntoskrnl        NtModifyBootEntry
110     0x8056f0da      ntoskrnl        NtNotifyChangeDirectoryFile
111     0x8061c44c      ntoskrnl        NtNotifyChangeKey
112     0x8061b09c      ntoskrnl        NtNotifyChangeMultipleKeys
113     0x805b3d40      ntoskrnl        NtOpenDirectoryObject
114     0x80605224      ntoskrnl        NtOpenEvent
115     0x8060d49e      ntoskrnl        NtOpenEventPair
116     0x8056f39a      ntoskrnl        NtOpenFile
117     0x8056dd32      ntoskrnl        NtOpenIoCompletion
118     0x805cba0e      ntoskrnl        NtOpenJobObject
119     0x8061b658      ntoskrnl        NtOpenKey
120     0x8060d896      ntoskrnl        NtOpenMutant
121     0x805ea704      ntoskrnl        NtOpenObjectAuditAlarm
122     0x805c1296      ntoskrnl        NtOpenProcess
123     0x805e39fc      ntoskrnl        NtOpenProcessToken
124     0x805e3660      ntoskrnl        NtOpenProcessTokenEx
125     0x8059f722      ntoskrnl        NtOpenSection
126     0x8060b254      ntoskrnl        NtOpenSemaphore
127     0x805b977a      ntoskrnl        NtOpenSymbolicLinkObject
128     0x805c1522      ntoskrnl        NtOpenThread
129     0x805e3a1a      ntoskrnl        NtOpenThreadToken
130     0x805e37d0      ntoskrnl        NtOpenThreadTokenEx
131     0x8060d1b0      ntoskrnl        NtOpenTimer
132     0x8063bc78      ntoskrnl        NtPlugPlayControl
133     0x805bf346      ntoskrnl        NtPowerInformation
134     0x805eddce      ntoskrnl        NtPrivilegeCheck
135     0x805e9a16      ntoskrnl        NtPrivilegeObjectAuditAlarm
136     0x805e9c02      ntoskrnl        NtPrivilegedServiceAuditAlarm
137     0x805ada08      ntoskrnl        NtProtectVirtualMemory
138     0x806052dc      ntoskrnl        NtPulseEvent
139     0x8056c0ce      ntoskrnl        NtQueryAttributesFile
140     0x8060cb50      ntoskrnl        NtAddBootEntry
140     0x8060cb50      ntoskrnl        NtEnumerateBootEntries
140     0x8060cb50      ntoskrnl        NtQueryBootEntryOrder
140     0x8060cb50      ntoskrnl        NtQueryBootOptions
140     0x8060cb50      ntoskrnl        NtSetBootEntryOrder
140     0x8060cb50      ntoskrnl        NtSetBootOptions
141     0x8060cb50      ntoskrnl        NtAddBootEntry
141     0x8060cb50      ntoskrnl        NtEnumerateBootEntries
141     0x8060cb50      ntoskrnl        NtQueryBootEntryOrder
141     0x8060cb50      ntoskrnl        NtQueryBootOptions
141     0x8060cb50      ntoskrnl        NtSetBootEntryOrder
141     0x8060cb50      ntoskrnl        NtSetBootOptions
142     0x8053c02e      ntoskrnl        NtQueryDebugFilterState
143     0x80606e68      ntoskrnl        NtQueryDefaultLocale
144     0x80607ac8      ntoskrnl        NtQueryDefaultUILanguage
145     0x8056f074      ntoskrnl        NtQueryDirectoryFile
146     0x805b3de0      ntoskrnl        NtQueryDirectoryObject
147     0x8056f3ca      ntoskrnl        NtQueryEaFile
148     0x806053a4      ntoskrnl        NtQueryEvent
149     0x8056c222      ntoskrnl        NtQueryFullAttributesFile
150     0x8060c2dc      ntoskrnl        NtQueryInformationAtom
151     0x8056fc46      ntoskrnl        NtQueryInformationFile
152     0x805cbee0      ntoskrnl        NtQueryInformationJobObject
153     0x8059a6fc      ntoskrnl        NtQueryInformationPort
154     0x805c2bfc      ntoskrnl        NtQueryInformationProcess
155     0x805c17c8      ntoskrnl        NtQueryInformationThread
156     0x805e3afa      ntoskrnl        NtQueryInformationToken
157     0x80607266      ntoskrnl        NtQueryInstallUILanguage
158     0x8060e060      ntoskrnl        NtQueryIntervalProfile
159     0x8056ddda      ntoskrnl        NtQueryIoCompletion
160     0x8061b97e      ntoskrnl        NtQueryKey
161     0x806193d4      ntoskrnl        NtQueryMultipleValueKey
162     0x8060d93e      ntoskrnl        NtQueryMutant
163     0x805bb04c      ntoskrnl        NtQueryObject
164     0x80619a80      ntoskrnl        NtQueryOpenSubKeys
165     0x8060e0ee      ntoskrnl        NtQueryPerformanceCounter
166     0x80570af2      ntoskrnl        NtQueryQuotaInformationFile
167     0x805adbca      ntoskrnl        NtQuerySection
168     0x805b5a16      ntoskrnl        NtQuerySecurityObject
169     0x8060b30c      ntoskrnl        NtQuerySemaphore
170     0x805b981a      ntoskrnl        NtQuerySymbolicLinkObject
171     0x8060cb6c      ntoskrnl        NtQuerySystemEnvironmentValue
172     0x8060cb26      ntoskrnl        NtQuerySystemEnvironmentValueEx
172     0x8060cb26      ntoskrnl        NtSetSystemEnvironmentValueEx
173     0x80607b48      ntoskrnl        NtQuerySystemInformation
174     0x806099e4      ntoskrnl        NtQuerySystemTime
175     0x8060d268      ntoskrnl        NtQueryTimer
176     0x8060929c      ntoskrnl        NtQueryTimerResolution
177     0x806184be      ntoskrnl        NtQueryValueKey
178     0x805ae250      ntoskrnl        NtQueryVirtualMemory
179     0x80570fe2      ntoskrnl        NtQueryVolumeInformationFile
180     0x805c7466      ntoskrnl        NtQueueApcThread
181     0x80540e48      ntoskrnl        NtRaiseException
182     0x8060af7e      ntoskrnl        NtRaiseHardError
183     0x805717aa      ntoskrnl        NtReadFile
184     0x80571d38      ntoskrnl        NtReadFileScatter
185     0x8059b184      ntoskrnl        NtReadRequestData
186     0x805a9712      ntoskrnl        NtReadVirtualMemory
187     0x805c89e0      ntoskrnl        NtRegisterThreadTerminatePort
188     0x8060da76      ntoskrnl        NtReleaseMutant
189     0x8060b43c      ntoskrnl        NtReleaseSemaphore
190     0x8056e0d2      ntoskrnl        NtRemoveIoCompletion
191     0x80639b56      ntoskrnl        NtRemoveProcessDebug
192     0x80619ca8      ntoskrnl        NtRenameKey
193     0x8061c332      ntoskrnl        NtReplaceKey
194     0x8059a804      ntoskrnl        NtReplyPort
195     0x8059b7cc      ntoskrnl        NtReplyWaitReceivePort
196     0x8059b1d4      ntoskrnl        NtReplyWaitReceivePortEx
197     0x8059aaee      ntoskrnl        NtReplyWaitReplyPort
198     0x805be456      ntoskrnl        NtRequestDeviceWakeup
199     0x80597d62      ntoskrnl        NtRequestPort
200     0x8059808e      ntoskrnl        NtRequestWaitReplyPort
201     0x805be264      ntoskrnl        NtRequestWakeupLatency
202     0x806054b6      ntoskrnl        NtResetEvent
203     0x8051de82      ntoskrnl        NtResetWriteWatch
204     0x8061bc3e      ntoskrnl        NtRestoreKey
205     0x805cad40      ntoskrnl        NtResumeProcess
206     0x805cac22      ntoskrnl        NtResumeThread
207     0x8061bd3a      ntoskrnl        NtSaveKey
208     0x8061be20      ntoskrnl        NtSaveKeyEx
209     0x8061bf48      ntoskrnl        NtSaveMergedKeys
210     0x8059907c      ntoskrnl        NtSecureConnectPort
211     0x8060cb50      ntoskrnl        NtAddBootEntry
211     0x8060cb50      ntoskrnl        NtEnumerateBootEntries
211     0x8060cb50      ntoskrnl        NtQueryBootEntryOrder
211     0x8060cb50      ntoskrnl        NtQueryBootOptions
211     0x8060cb50      ntoskrnl        NtSetBootEntryOrder
211     0x8060cb50      ntoskrnl        NtSetBootOptions
212     0x8060cb50      ntoskrnl        NtAddBootEntry
212     0x8060cb50      ntoskrnl        NtEnumerateBootEntries
212     0x8060cb50      ntoskrnl        NtQueryBootEntryOrder
212     0x8060cb50      ntoskrnl        NtQueryBootOptions
212     0x8060cb50      ntoskrnl        NtSetBootEntryOrder
212     0x8060cb50      ntoskrnl        NtSetBootOptions
213     0x805c792a      ntoskrnl        NtSetContextThread
214     0x8063c80e      ntoskrnl        NtSetDebugFilterState
215     0x8060ae28      ntoskrnl        NtSetDefaultHardErrorPort
216     0x80606fb8      ntoskrnl        NtSetDefaultLocale
217     0x8060782a      ntoskrnl        NtSetDefaultUILanguage
218     0x8056f8e6      ntoskrnl        NtSetEaFile
219     0x80605576      ntoskrnl        NtSetEvent
220     0x80605640      ntoskrnl        NtSetEventBoostPriority
221     0x8060d75a      ntoskrnl        NtSetHighEventPair
222     0x8060d68a      ntoskrnl        NtSetHighWaitLowEventPair
223     0x80639520      ntoskrnl        NtSetInformationDebugObject
224     0x80570284      ntoskrnl        NtSetInformationFile
225     0x805ccbf0      ntoskrnl        NtSetInformationJobObject
226     0x80618fa0      ntoskrnl        NtSetInformationKey
227     0x805ba490      ntoskrnl        NtSetInformationObject
228     0x805c3d54      ntoskrnl        NtSetInformationProcess
229     0x805c1d14      ntoskrnl        NtSetInformationThread
230     0x805f014a      ntoskrnl        NtSetInformationToken
231     0x8060dbc2      ntoskrnl        NtSetIntervalProfile
232     0x8056e070      ntoskrnl        NtSetIoCompletion
233     0x805c9b6c      ntoskrnl        NtSetLdtEntries
234     0x8060d6f6      ntoskrnl        NtSetLowEventPair
235     0x8060d61e      ntoskrnl        NtSetLowWaitHighEventPair
236     0x80570ad0      ntoskrnl        NtSetQuotaInformationFile
237     0x805b5fc0      ntoskrnl        NtSetSecurityObject
238     0x8060cdf0      ntoskrnl        NtSetSystemEnvironmentValue
239     0x8060cb26      ntoskrnl        NtQuerySystemEnvironmentValueEx
239     0x8060cb26      ntoskrnl        NtSetSystemEnvironmentValueEx
240     0x80605e76      ntoskrnl        NtSetSystemInformation
241     0x80648dd6      ntoskrnl        NtSetSystemPowerState
242     0x8060a5a4      ntoskrnl        NtSetSystemTime
243     0x805be178      ntoskrnl        NtSetThreadExecutionState
244     0x8053514a      ntoskrnl        NtSetTimer
245     0x80609a76      ntoskrnl        NtSetTimerResolution
246     0x8060b8f2      ntoskrnl        NtSetUuidSeed
247     0x8061880c      ntoskrnl        NtSetValueKey
248     0x80571406      ntoskrnl        NtSetVolumeInformationFile
249     0x80609092      ntoskrnl        NtShutdownSystem
250     0x80522c50      ntoskrnl        NtSignalAndWaitForSingleObject
251     0x8060de0c      ntoskrnl        NtStartProfile
252     0x8060dfb6      ntoskrnl        NtStopProfile
253     0x805cacea      ntoskrnl        NtSuspendProcess
254     0x805cab5c      ntoskrnl        NtSuspendThread
255     0x8060e1da      ntoskrnl        NtSystemDebugControl
256     0x805cd75a      ntoskrnl        NtTerminateJobObject
257     0x805c8c2a      ntoskrnl        NtTerminateProcess
258     0x805c8e24      ntoskrnl        NtTerminateThread
259     0x805caeaa      ntoskrnl        NtTestAlert
260     0x80531828      ntoskrnl        NtTraceEvent
261     0x8060cb5e      ntoskrnl        NtTranslateFilePath
262     0x8057971c      ntoskrnl        NtUnloadDriver
263     0x80618b36      ntoskrnl        NtUnloadKey
264     0x80618d50      ntoskrnl        NtUnloadKeyEx
265     0x8056e856      ntoskrnl        NtUnlockFile
266     0x805ac4ce      ntoskrnl        NtUnlockVirtualMemory
267     0x805a8296      ntoskrnl        NtUnmapViewOfSection
268     0x805f1502      ntoskrnl        NtVdmControl
269     0x80639288      ntoskrnl        NtWaitForDebugEvent
270     0x805b6176      ntoskrnl        NtWaitForMultipleObjects
271     0x805b608c      ntoskrnl        NtWaitForSingleObject
272     0x8060d5ba      ntoskrnl        NtWaitHighEventPair
273     0x8060d556      ntoskrnl        NtWaitLowEventPair
274     0x80572248      ntoskrnl        NtWriteFile
275     0x80572858      ntoskrnl        NtWriteFileGather
276     0x8059b1ac      ntoskrnl        NtWriteRequestData
277     0x805a981c      ntoskrnl        NtWriteVirtualMemory
278     0x8050222c      ntoskrnl        NtYieldExecution
279     0x8060e632      ntoskrnl        NtCreateKeyedEvent
280     0x8060e71c      ntoskrnl        NtOpenKeyedEvent
281     0x8060e7ce      ntoskrnl        NtReleaseKeyedEvent
282     0x8060ea5a      ntoskrnl        NtWaitForKeyedEvent
283     0x805c1798      ntoskrnl        NtQueryPortInformationProcess

thmanalyst@ubuntu:/opt/volatility3$ python3 vol.py -f dump.vmem windows.modules
Volatility 3 Framework 1.0.1
Progress:  100.00               PDB scanning finished                     
Offset  Base    Size    Name    Path    File output

0x823fc3b0      0x804d7000      0x1f8580        ntoskrnl.exe    \WINDOWS\system32\ntkrnlpa.exe Disabled
0x823fc348      0x806d0000      0x20300 hal.dll \WINDOWS\system32\hal.dll       Disabled
0x823fc2e0      0xf8b9a000      0x2000  kdcom.dll       \WINDOWS\system32\KDCOM.DLL   Disabled
0x823fc270      0xf8aaa000      0x3000  BOOTVID.dll     \WINDOWS\system32\BOOTVID.dll Disabled
0x823fc208      0xf856b000      0x2e000 ACPI.sys        ACPI.sys        Disabled
0x823fc198      0xf8b9c000      0x2000  WMILIB.SYS      \WINDOWS\system32\DRIVERS\WMILIB.SYS   Disabled
0x823fc130      0xf855a000      0x11000 pci.sys pci.sys Disabled
0x823fc0c0      0xf869a000      0xa000  isapnp.sys      isapnp.sys      Disabled
0x823fc050      0xf8aae000      0x3000  compbatt.sys    compbatt.sys    Disabled
0x823ed008      0xf8ab2000      0x4000  BATTC.SYS       \WINDOWS\system32\DRIVERS\BATTC.SYS    Disabled
0x823edf98      0xf8b9e000      0x2000  intelide.sys    intelide.sys    Disabled
0x823edf28      0xf891a000      0x7000  PCIIDEX.SYS     \WINDOWS\system32\DRIVERS\PCIIDEX.SYS  Disabled
0x823edeb8      0xf86aa000      0xb000  MountMgr.sys    MountMgr.sys    Disabled
0x823ede48      0xf853b000      0x1f000 ftdisk.sys      ftdisk.sys      Disabled
0x823eddd8      0xf8ba0000      0x2000  dmload.sys      dmload.sys      Disabled
0x823edd70      0xf8515000      0x26000 dmio.sys        dmio.sys        Disabled
0x823edd00      0xf8922000      0x5000  PartMgr.sys     PartMgr.sys     Disabled
0x823edc90      0xf86ba000      0xd000  VolSnap.sys     VolSnap.sys     Disabled
0x823edc28      0xf84fd000      0x18000 atapi.sys       atapi.sys       Disabled
0x823edbc0      0xf86ca000      0x9000  disk.sys        disk.sys        Disabled
0x823edb50      0xf86da000      0xd000  CLASSPNP.SYS    \WINDOWS\system32\DRIVERS\CLASSPNP.SYS Disabled
0x823edae0      0xf84dd000      0x20000 fltMgr.sys      fltMgr.sys      Disabled
0x823eda78      0xf84cb000      0x12000 sr.sys  sr.sys  Disabled
0x823eda08      0xf84b4000      0x17000 KSecDD.sys      KSecDD.sys      Disabled
0x823ed9a0      0xf8427000      0x8d000 Ntfs.sys        Ntfs.sys        Disabled
0x823ed938      0xf83fa000      0x2d000 NDIS.sys        NDIS.sys        Disabled
0x823ed8d0      0xf83e0000      0x1a000 Mup.sys Mup.sys Disabled
0x823ed860      0xf86ea000      0xb000  agp440.sys      agp440.sys      Disabled
0x82147bf8      0xf874a000      0xd000  i8042prt.sys    \SystemRoot\system32\DRIVERS\i8042prt.sys      Disabled
0x81ea11d8      0xf8942000      0x6000  kbdclass.sys    \SystemRoot\system32\DRIVERS\kbdclass.sys      Disabled
0x82234b48      0xf894a000      0x6000  mouclass.sys    \SystemRoot\system32\DRIVERS\mouclass.sys      Disabled
0x820c1b20      0xf8373000      0x14000 parport.sys     \SystemRoot\system32\DRIVERS\parport.sys       Disabled
0x81e85b10      0xf875a000      0x10000 serial.sys      \SystemRoot\system32\DRIVERS\serial.sys        Disabled
0x82217790      0xf8b3a000      0x4000  serenum.sys     \SystemRoot\system32\DRIVERS\serenum.sys       Disabled
0x82234f00      0xf8952000      0x7000  fdc.sys \SystemRoot\system32\DRIVERS\fdc.sys  Disabled
0x82262988      0xf876a000      0x10000 cdrom.sys       \SystemRoot\system32\DRIVERS\cdrom.sys Disabled
0x81e858d8      0xf877a000      0xf000  redbook.sys     \SystemRoot\system32\DRIVERS\redbook.sys       Disabled
0x82262720      0xf8350000      0x23000 ks.sys  \SystemRoot\system32\DRIVERS\ks.sys   Disabled
0x821455d8      0xf895a000      0x6000  usbuhci.sys     \SystemRoot\system32\DRIVERS\usbuhci.sys       Disabled
0x82236778      0xf832c000      0x24000 USBPORT.SYS     \SystemRoot\system32\DRIVERS\USBPORT.SYS       Disabled
0x822363a8      0xf878a000      0x9000  pcntpci5.sys    \SystemRoot\system32\DRIVERS\pcntpci5.sys      Disabled
0x822362c8      0xf879a000      0xa000  es1371mp.sys    \SystemRoot\system32\drivers\es1371mp.sys      Disabled
0x82235d00      0xf8308000      0x24000 portcls.sys     \SystemRoot\system32\drivers\portcls.sys       Disabled
0x82216ce8      0xf87aa000      0xf000  drmk.sys        \SystemRoot\system32\drivers\drmk.sys  Disabled
0x82234f98      0xf8962000      0x8000  usbehci.sys     \SystemRoot\system32\DRIVERS\usbehci.sys       Disabled
0x82234cf0      0xf8b42000      0x4000  CmBatt.sys      \SystemRoot\system32\DRIVERS\CmBatt.sys        Disabled
0x82234ad8      0xf87ba000      0x9000  intelppm.sys    \SystemRoot\system32\DRIVERS\intelppm.sys      Disabled
0x822349c0      0xf8cd2000      0x1000  audstub.sys     \SystemRoot\system32\DRIVERS\audstub.sys       Disabled
0x82233170      0xf87ca000      0xd000  rasl2tp.sys     \SystemRoot\system32\DRIVERS\rasl2tp.sys       Disabled
0x81e2fe80      0xf8b46000      0x3000  ndistapi.sys    \SystemRoot\system32\DRIVERS\ndistapi.sys      Disabled
0x822fe8c8      0xf82f1000      0x17000 ndiswan.sys     \SystemRoot\system32\DRIVERS\ndiswan.sys       Disabled
0x822fecf0      0xf87da000      0xb000  raspppoe.sys    \SystemRoot\system32\DRIVERS\raspppoe.sys      Disabled
0x82138420      0xf87ea000      0xc000  raspptp.sys     \SystemRoot\system32\DRIVERS\raspptp.sys       Disabled
0x82308cd0      0xf896a000      0x5000  TDI.SYS \SystemRoot\system32\DRIVERS\TDI.SYS  Disabled
0x82339c60      0xf82e0000      0x11000 psched.sys      \SystemRoot\system32\DRIVERS\psched.sys        Disabled
0x82261578      0xf87fa000      0x9000  msgpc.sys       \SystemRoot\system32\DRIVERS\msgpc.sys Disabled
0x82259258      0xf8972000      0x5000  ptilink.sys     \SystemRoot\system32\DRIVERS\ptilink.sys       Disabled
0x81ea6520      0xf897a000      0x5000  raspti.sys      \SystemRoot\system32\DRIVERS\raspti.sys        Disabled
0x821c1320      0xf8288000      0x30000 rdpdr.sys       \SystemRoot\system32\DRIVERS\rdpdr.sys Disabled
0x8207c0a8      0xf880a000      0xa000  termdd.sys      \SystemRoot\system32\DRIVERS\termdd.sys        Disabled
0x81ea6d78      0xf8ba2000      0x2000  swenum.sys      \SystemRoot\system32\DRIVERS\swenum.sys        Disabled
0x822030e8      0xf818a000      0x5e000 update.sys      \SystemRoot\system32\DRIVERS\update.sys        Disabled
0x8213dce8      0xf8b5e000      0x4000  mssmbios.sys    \SystemRoot\system32\DRIVERS\mssmbios.sys      Disabled
0x82260190      0xf881a000      0xa000  NDProxy.SYS     \SystemRoot\System32\Drivers\NDProxy.SYS       Disabled
0x81e78108      0xf8982000      0x5000  flpydisk.sys    \SystemRoot\system32\DRIVERS\flpydisk.sys      Disabled
0x822ee108      0xf883a000      0xf000  usbhub.sys      \SystemRoot\system32\DRIVERS\usbhub.sys        Disabled
0x821b9440      0xf8ba4000      0x2000  USBD.SYS        \SystemRoot\system32\DRIVERS\USBD.SYS  Disabled
0x821ea108      0xf8b86000      0x3000  gameenum.sys    \SystemRoot\system32\DRIVERS\gameenum.sys      Disabled
0x821b5e20      0xf8ba6000      0x2000  Fs_Rec.SYS      \SystemRoot\System32\Drivers\Fs_Rec.SYS        Disabled
0x82271b20      0xf8d05000      0x1000  Null.SYS        \SystemRoot\System32\Drivers\Null.SYS  Disabled
0x82271528      0xf8ba8000      0x2000  Beep.SYS        \SystemRoot\System32\Drivers\Beep.SYS  Disabled
0x82271308      0xf8992000      0x6000  vga.sys \SystemRoot\System32\drivers\vga.sys  Disabled
0x821f2e78      0xf814e000      0x14000 VIDEOPRT.SYS    \SystemRoot\System32\drivers\VIDEOPRT.SYS      Disabled
0x82271078      0xf8baa000      0x2000  mnmdd.SYS       \SystemRoot\System32\Drivers\mnmdd.SYS Disabled
0x82258e58      0xf8bac000      0x2000  RDPCDD.sys      \SystemRoot\System32\DRIVERS\RDPCDD.sys        Disabled
0x82314cc8      0xf899a000      0x5000  Msfs.SYS        \SystemRoot\System32\Drivers\Msfs.SYS  Disabled
0x82314880      0xf89a2000      0x8000  Npfs.SYS        \SystemRoot\System32\Drivers\Npfs.SYS  Disabled
0x821498c0      0xf8b96000      0x3000  rasacd.sys      \SystemRoot\system32\DRIVERS\rasacd.sys        Disabled
0x82314678      0xf811b000      0x13000 ipsec.sys       \SystemRoot\system32\DRIVERS\ipsec.sys Disabled
0x823142d8      0xf80c2000      0x59000 tcpip.sys       \SystemRoot\system32\DRIVERS\tcpip.sys Disabled
0x82314108      0xf809a000      0x28000 netbt.sys       \SystemRoot\system32\DRIVERS\netbt.sys Disabled
0x821d4be8      0xf8078000      0x22000 afd.sys \SystemRoot\System32\drivers\afd.sys  Disabled
0x823cb1d8      0xf884a000      0x9000  netbios.sys     \SystemRoot\system32\DRIVERS\netbios.sys       Disabled
0x821d4668      0xf804d000      0x2b000 rdbss.sys       \SystemRoot\system32\DRIVERS\rdbss.sys Disabled
0x82225d50      0xf7fdd000      0x70000 mrxsmb.sys      \SystemRoot\system32\DRIVERS\mrxsmb.sys        Disabled
0x821d4498      0xf886a000      0xb000  Fips.SYS        \SystemRoot\System32\Drivers\Fips.SYS  Disabled
0x823088f0      0xf7f8f000      0x26000 ipnat.sys       \SystemRoot\system32\DRIVERS\ipnat.sys Disabled
0x8205f2f8      0xf888a000      0x9000  wanarp.sys      \SystemRoot\system32\DRIVERS\wanarp.sys        Disabled
0x822095b8      0xf889a000      0x10000 Cdfs.SYS        \SystemRoot\System32\Drivers\Cdfs.SYS  Disabled
0x82291110      0xf89aa000      0x8000  usbccgp.sys     \SystemRoot\system32\DRIVERS\usbccgp.sys       Disabled
0x82250cc8      0xf82d4000      0x3000  hidusb.sys      \SystemRoot\system32\DRIVERS\hidusb.sys        Disabled
0x81e86090      0xf88aa000      0x9000  HIDCLASS.SYS    \SystemRoot\system32\DRIVERS\HIDCLASS.SYS      Disabled
0x81e350c8      0xf89b2000      0x7000  HIDPARSE.SYS    \SystemRoot\system32\DRIVERS\HIDPARSE.SYS      Disabled
0x82303488      0xf82d0000      0x3000  mouhid.sys      \SystemRoot\system32\DRIVERS\mouhid.sys        Disabled
0x8224e700      0xf7f77000      0x18000 dump_atapi.sys  \SystemRoot\System32\Drivers\dump_atapi.sys    Disabled
0x821488a8      0xf8bae000      0x2000  dump_WMILIB.SYS \SystemRoot\System32\Drivers\dump_WMILIB.SYS   Disabled
0x8224d280      0xbf800000      0x1c3000        win32k.sys      \SystemRoot\System32\win32k.sys        Disabled
0x820c21f8      0xf82c0000      0x3000  Dxapi.sys       \SystemRoot\System32\drivers\Dxapi.sys Disabled
0x82219e78      0xf89ba000      0x5000  watchdog.sys    \SystemRoot\System32\watchdog.sys      Disabled
0x822f31d8      0xbf9c3000      0x12000 dxg.sys \SystemRoot\System32\drivers\dxg.sys  Disabled
0x82066e80      0xf8d43000      0x1000  dxgthk.sys      \SystemRoot\System32\drivers\dxgthk.sys        Disabled
0x81e85008      0xbff50000      0x3000  framebuf.dll    \SystemRoot\System32\framebuf.dll      Disabled
0x81e296b8      0xf7c6f000      0x4000  ndisuio.sys     \SystemRoot\system32\DRIVERS\ndisuio.sys       Disabled
0x8227aa38      0xf792a000      0x15000 wdmaud.sys      \SystemRoot\system32\drivers\wdmaud.sys        Disabled
0x822d64a8      0xf7bdf000      0xf000  sysaudio.sys    \SystemRoot\system32\drivers\sysaudio.sys      Disabled
0x822937c0      0xf7887000      0x2d000 mrxdav.sys      \SystemRoot\system32\DRIVERS\mrxdav.sys        Disabled
0x82198138      0xf8be0000      0x2000  ParVdm.SYS      \SystemRoot\System32\Drivers\ParVdm.SYS        Disabled
0x82259430      0xf780d000      0x52000 srv.sys \SystemRoot\system32\DRIVERS\srv.sys  Disabled
0x821c5120      0xf75c4000      0x41000 HTTP.sys        \SystemRoot\System32\Drivers\HTTP.sys  Disabled

thmanalyst@ubuntu:/opt/volatility3$ python3 vol.py -f dump.vmem windows.driverscan
Volatility 3 Framework 1.0.1
Progress:  100.00               PDB scanning finished                     
Offset  Start   Size    Service Key     Driver Name     Name

thmanalyst@ubuntu:/opt/volatility3$ python3 vol.py -f dump.vmem windows.modscan
Volatility 3 Framework 1.0.1
Progress:  100.00               PDB scanning finished                     
Offset  Base    Size    Name    Path    File output

0x59ca40        0x89607b8d      0x89662c46                      Disabled
0x5a3890        0x6600000c      0x8d50a045                      Disabled
0x5a3e06        0x400   0x66000010                      Disabled
0x20296b8       0xf7c6f000      0x4000  ndisuio.sys     \SystemRoot\system32\DRIVERS\ndisuio.sys       Disabled
0x202fe80       0xf8b46000      0x3000  ndistapi.sys    \SystemRoot\system32\DRIVERS\ndistapi.sys      Disabled
0x20350c8       0xf89b2000      0x7000  HIDPARSE.SYS    \SystemRoot\system32\DRIVERS\HIDPARSE.SYS      Disabled
0x2078108       0xf8982000      0x5000  flpydisk.sys    \SystemRoot\system32\DRIVERS\flpydisk.sys      Disabled
0x2085008       0xbff50000      0x3000  framebuf.dll    \SystemRoot\System32\framebuf.dll      Disabled
0x20858d8       0xf877a000      0xf000  redbook.sys     \SystemRoot\system32\DRIVERS\redbook.sys       Disabled
0x2085b10       0xf875a000      0x10000 serial.sys      \SystemRoot\system32\DRIVERS\serial.sys        Disabled
0x2086090       0xf88aa000      0x9000  HIDCLASS.SYS    \SystemRoot\system32\DRIVERS\HIDCLASS.SYS      Disabled
0x20a11d8       0xf8942000      0x6000  kbdclass.sys    \SystemRoot\system32\DRIVERS\kbdclass.sys      Disabled
0x20a6520       0xf897a000      0x5000  raspti.sys      \SystemRoot\system32\DRIVERS\raspti.sys        Disabled
0x20a6d78       0xf8ba2000      0x2000  swenum.sys      \SystemRoot\system32\DRIVERS\swenum.sys        Disabled
0x225f2f8       0xf888a000      0x9000  wanarp.sys      \SystemRoot\system32\DRIVERS\wanarp.sys        Disabled
0x2266e80       0xf8d43000      0x1000  dxgthk.sys      \SystemRoot\System32\drivers\dxgthk.sys        Disabled
0x227c0a8       0xf880a000      0xa000  termdd.sys      \SystemRoot\system32\DRIVERS\termdd.sys        Disabled
0x22c1b20       0xf8373000      0x14000 parport.sys     \SystemRoot\system32\DRIVERS\parport.sys       Disabled
0x22c21f8       0xf82c0000      0x3000  Dxapi.sys       \SystemRoot\System32\drivers\Dxapi.sys Disabled
0x2338420       0xf87ea000      0xc000  raspptp.sys     \SystemRoot\system32\DRIVERS\raspptp.sys       Disabled
0x233dce8       0xf8b5e000      0x4000  mssmbios.sys    \SystemRoot\system32\DRIVERS\mssmbios.sys      Disabled
0x23455d8       0xf895a000      0x6000  usbuhci.sys     \SystemRoot\system32\DRIVERS\usbuhci.sys       Disabled
0x2347bf8       0xf874a000      0xd000  i8042prt.sys    \SystemRoot\system32\DRIVERS\i8042prt.sys      Disabled
0x23488a8       0xf8bae000      0x2000  dump_WMILIB.SYS \SystemRoot\System32\Drivers\dump_WMILIB.SYS   Disabled
0x23498c0       0xf8b96000      0x3000  rasacd.sys      \SystemRoot\system32\DRIVERS\rasacd.sys        Disabled
0x2398138       0xf8be0000      0x2000  ParVdm.SYS      \SystemRoot\System32\Drivers\ParVdm.SYS        Disabled
0x23b5e20       0xf8ba6000      0x2000  Fs_Rec.SYS      \SystemRoot\System32\Drivers\Fs_Rec.SYS        Disabled
0x23b9440       0xf8ba4000      0x2000  USBD.SYS        \SystemRoot\system32\DRIVERS\USBD.SYS  Disabled
0x23c1320       0xf8288000      0x30000 rdpdr.sys       \SystemRoot\system32\DRIVERS\rdpdr.sys Disabled
0x23c5120       0xf75c4000      0x41000 HTTP.sys        \SystemRoot\System32\Drivers\HTTP.sys  Disabled
0x23d4498       0xf886a000      0xb000  Fips.SYS        \SystemRoot\System32\Drivers\Fips.SYS  Disabled
0x23d4668       0xf804d000      0x2b000 rdbss.sys       \SystemRoot\system32\DRIVERS\rdbss.sys Disabled
0x23d4be8       0xf8078000      0x22000 afd.sys \SystemRoot\System32\drivers\afd.sys  Disabled
0x23ea108       0xf8b86000      0x3000  gameenum.sys    \SystemRoot\system32\DRIVERS\gameenum.sys      Disabled
0x23f2e78       0xf814e000      0x14000 VIDEOPRT.SYS    \SystemRoot\System32\drivers\VIDEOPRT.SYS      Disabled
0x24030e8       0xf818a000      0x5e000 update.sys      \SystemRoot\system32\DRIVERS\update.sys        Disabled
0x24095b8       0xf889a000      0x10000 Cdfs.SYS        \SystemRoot\System32\Drivers\Cdfs.SYS  Disabled
0x2416ce8       0xf87aa000      0xf000  drmk.sys        \SystemRoot\system32\drivers\drmk.sys  Disabled
0x2417790       0xf8b3a000      0x4000  serenum.sys     \SystemRoot\system32\DRIVERS\serenum.sys       Disabled
0x2419e78       0xf89ba000      0x5000  watchdog.sys    \SystemRoot\System32\watchdog.sys      Disabled
0x2425d50       0xf7fdd000      0x70000 mrxsmb.sys      \SystemRoot\system32\DRIVERS\mrxsmb.sys        Disabled
0x2433170       0xf87ca000      0xd000  rasl2tp.sys     \SystemRoot\system32\DRIVERS\rasl2tp.sys       Disabled
0x24349c0       0xf8cd2000      0x1000  audstub.sys     \SystemRoot\system32\DRIVERS\audstub.sys       Disabled
0x2434ad8       0xf87ba000      0x9000  intelppm.sys    \SystemRoot\system32\DRIVERS\intelppm.sys      Disabled
0x2434b48       0xf894a000      0x6000  mouclass.sys    \SystemRoot\system32\DRIVERS\mouclass.sys      Disabled
0x2434cf0       0xf8b42000      0x4000  CmBatt.sys      \SystemRoot\system32\DRIVERS\CmBatt.sys        Disabled
0x2434f00       0xf8952000      0x7000  fdc.sys \SystemRoot\system32\DRIVERS\fdc.sys  Disabled
0x2434f98       0xf8962000      0x8000  usbehci.sys     \SystemRoot\system32\DRIVERS\usbehci.sys       Disabled
0x2435d00       0xf8308000      0x24000 portcls.sys     \SystemRoot\system32\drivers\portcls.sys       Disabled
0x24362c8       0xf879a000      0xa000  es1371mp.sys    \SystemRoot\system32\drivers\es1371mp.sys      Disabled
0x24363a8       0xf878a000      0x9000  pcntpci5.sys    \SystemRoot\system32\DRIVERS\pcntpci5.sys      Disabled
0x2436778       0xf832c000      0x24000 USBPORT.SYS     \SystemRoot\system32\DRIVERS\USBPORT.SYS       Disabled
0x244d280       0xbf800000      0x1c3000        win32k.sys      \SystemRoot\System32\win32k.sys        Disabled
0x244e700       0xf7f77000      0x18000 dump_atapi.sys  \SystemRoot\System32\Drivers\dump_atapi.sys    Disabled
0x2450cc8       0xf82d4000      0x3000  hidusb.sys      \SystemRoot\system32\DRIVERS\hidusb.sys        Disabled
0x2458e58       0xf8bac000      0x2000  RDPCDD.sys      \SystemRoot\System32\DRIVERS\RDPCDD.sys        Disabled
0x2459258       0xf8972000      0x5000  ptilink.sys     \SystemRoot\system32\DRIVERS\ptilink.sys       Disabled
0x2459430       0xf780d000      0x52000 srv.sys \SystemRoot\system32\DRIVERS\srv.sys  Disabled
0x2460190       0xf881a000      0xa000  NDProxy.SYS     \SystemRoot\System32\Drivers\NDProxy.SYS       Disabled
0x2461578       0xf87fa000      0x9000  msgpc.sys       \SystemRoot\system32\DRIVERS\msgpc.sys Disabled
0x2462720       0xf8350000      0x23000 ks.sys  \SystemRoot\system32\DRIVERS\ks.sys   Disabled
0x2462988       0xf876a000      0x10000 cdrom.sys       \SystemRoot\system32\DRIVERS\cdrom.sys Disabled
0x2471078       0xf8baa000      0x2000  mnmdd.SYS       \SystemRoot\System32\Drivers\mnmdd.SYS Disabled
0x2471308       0xf8992000      0x6000  vga.sys \SystemRoot\System32\drivers\vga.sys  Disabled
0x2471528       0xf8ba8000      0x2000  Beep.SYS        \SystemRoot\System32\Drivers\Beep.SYS  Disabled
0x2471b20       0xf8d05000      0x1000  Null.SYS        \SystemRoot\System32\Drivers\Null.SYS  Disabled
0x247aa38       0xf792a000      0x15000 wdmaud.sys      \SystemRoot\system32\drivers\wdmaud.sys        Disabled
0x2491110       0xf89aa000      0x8000  usbccgp.sys     \SystemRoot\system32\DRIVERS\usbccgp.sys       Disabled
0x24937c0       0xf7887000      0x2d000 mrxdav.sys      \SystemRoot\system32\DRIVERS\mrxdav.sys        Disabled
0x24d64a8       0xf7bdf000      0xf000  sysaudio.sys    \SystemRoot\system32\drivers\sysaudio.sys      Disabled
0x24ee108       0xf883a000      0xf000  usbhub.sys      \SystemRoot\system32\DRIVERS\usbhub.sys        Disabled
0x24f31d8       0xbf9c3000      0x12000 dxg.sys \SystemRoot\System32\drivers\dxg.sys  Disabled
0x24fe8c8       0xf82f1000      0x17000 ndiswan.sys     \SystemRoot\system32\DRIVERS\ndiswan.sys       Disabled
0x24fecf0       0xf87da000      0xb000  raspppoe.sys    \SystemRoot\system32\DRIVERS\raspppoe.sys      Disabled
0x2503488       0xf82d0000      0x3000  mouhid.sys      \SystemRoot\system32\DRIVERS\mouhid.sys        Disabled
0x25088f0       0xf7f8f000      0x26000 ipnat.sys       \SystemRoot\system32\DRIVERS\ipnat.sys Disabled
0x2508cd0       0xf896a000      0x5000  TDI.SYS \SystemRoot\system32\DRIVERS\TDI.SYS  Disabled
0x2514108       0xf809a000      0x28000 netbt.sys       \SystemRoot\system32\DRIVERS\netbt.sys Disabled
0x25142d8       0xf80c2000      0x59000 tcpip.sys       \SystemRoot\system32\DRIVERS\tcpip.sys Disabled
0x2514678       0xf811b000      0x13000 ipsec.sys       \SystemRoot\system32\DRIVERS\ipsec.sys Disabled
0x2514880       0xf89a2000      0x8000  Npfs.SYS        \SystemRoot\System32\Drivers\Npfs.SYS  Disabled
0x2514cc8       0xf899a000      0x5000  Msfs.SYS        \SystemRoot\System32\Drivers\Msfs.SYS  Disabled
0x2539c60       0xf82e0000      0x11000 psched.sys      \SystemRoot\system32\DRIVERS\psched.sys        Disabled
0x25cb1d8       0xf884a000      0x9000  netbios.sys     \SystemRoot\system32\DRIVERS\netbios.sys       Disabled
0x25ed008       0xf8ab2000      0x4000  BATTC.SYS       \WINDOWS\system32\DRIVERS\BATTC.SYS    Disabled
0x25ed860       0xf86ea000      0xb000  agp440.sys      agp440.sys      Disabled
0x25ed8d0       0xf83e0000      0x1a000 Mup.sys Mup.sys Disabled
0x25ed938       0xf83fa000      0x2d000 NDIS.sys        NDIS.sys        Disabled
0x25ed9a0       0xf8427000      0x8d000 Ntfs.sys        Ntfs.sys        Disabled
0x25eda08       0xf84b4000      0x17000 KSecDD.sys      KSecDD.sys      Disabled
0x25eda78       0xf84cb000      0x12000 sr.sys  sr.sys  Disabled
0x25edae0       0xf84dd000      0x20000 fltMgr.sys      fltMgr.sys      Disabled
0x25edb50       0xf86da000      0xd000  CLASSPNP.SYS    \WINDOWS\system32\DRIVERS\CLASSPNP.SYS Disabled
0x25edbc0       0xf86ca000      0x9000  disk.sys        disk.sys        Disabled
0x25edc28       0xf84fd000      0x18000 atapi.sys       atapi.sys       Disabled
0x25edc90       0xf86ba000      0xd000  VolSnap.sys     VolSnap.sys     Disabled
0x25edd00       0xf8922000      0x5000  PartMgr.sys     PartMgr.sys     Disabled
0x25edd70       0xf8515000      0x26000 dmio.sys        dmio.sys        Disabled
0x25eddd8       0xf8ba0000      0x2000  dmload.sys      dmload.sys      Disabled
0x25ede48       0xf853b000      0x1f000 ftdisk.sys      ftdisk.sys      Disabled
0x25edeb8       0xf86aa000      0xb000  MountMgr.sys    MountMgr.sys    Disabled
0x25edf28       0xf891a000      0x7000  PCIIDEX.SYS     \WINDOWS\system32\DRIVERS\PCIIDEX.SYS  Disabled
0x25edf98       0xf8b9e000      0x2000  intelide.sys    intelide.sys    Disabled
0x25fc050       0xf8aae000      0x3000  compbatt.sys    compbatt.sys    Disabled
0x25fc0c0       0xf869a000      0xa000  isapnp.sys      isapnp.sys      Disabled
0x25fc130       0xf855a000      0x11000 pci.sys pci.sys Disabled
0x25fc198       0xf8b9c000      0x2000  WMILIB.SYS      \WINDOWS\system32\DRIVERS\WMILIB.SYS   Disabled
0x25fc208       0xf856b000      0x2e000 ACPI.sys        ACPI.sys        Disabled
0x25fc270       0xf8aaa000      0x3000  BOOTVID.dll     \WINDOWS\system32\BOOTVID.dll Disabled
0x25fc2e0       0xf8b9a000      0x2000  kdcom.dll       \WINDOWS\system32\KDCOM.DLL   Disabled
0x25fc348       0x806d0000      0x20300 hal.dll \WINDOWS\system32\hal.dll       Disabled
0x25fc3b0       0x804d7000      0x1f8580        ntoskrnl.exe    \WINDOWS\system32\ntkrnlpa.exe Disabled

thmanalyst@ubuntu:/opt/volatility3$ python3 vol.py -f dump.vmem windows.driverirp
Volatility 3 Framework 1.0.1
Progress:  100.00               PDB scanning finished                     
Offset  Driver Name     IRP     Address Module  Symbol


```

### Practical Investigations 

Case 001 - BOB! THIS ISN'T A HORSE!

Your SOC has informed you that they have gathered a memory dump from a quarantined endpoint thought to have been compromised by a banking trojan masquerading as an Adobe document. Your job is to use your knowledge of threat intelligence and reverse engineering to perform memory forensics on the infected host. 

You have been informed of a suspicious IP in connection to the file that could be helpful. 41.168.5.140

The memory file is located in /Scenarios/Investigations/Investigation-1.vmem 
Case 002 - That Kind of Hurt my Feelings

You have been informed that your corporation has been hit with a chain of ransomware that has been hitting corporations internationally. Your team has already retrieved the decryption key and recovered from the attack. Still, your job is to perform post-incident analysis and identify what actors were at play and what occurred on your systems. You have been provided with a raw memory dump from your team to begin your analysis.

The memory file is located in /Scenarios/Investigations/Investigation-2.raw


```
┌──(kali㉿kali)-[~/volatility/volatility3]
└─$ python3 vol.py -f Investigation-1.vmem windows.info             
Volatility 3 Framework 2.4.1
Progress:  100.00               PDB scanning finished                        
Variable        Value

Kernel Base     0x804d7000
DTB     0x2fe000
Symbols file:///home/kali/volatility/volatility3/volatility3/symbols/windows/ntkrnlpa.pdb/30B5FB31AE7E4ACAABA750AA241FF331-1.json.xz
Is64Bit False
IsPAE   True
layer_name      0 WindowsIntelPAE
memory_layer    1 FileLayer
KdDebuggerDataBlock     0x80545ae0
NTBuildLab      2600.xpsp.080413-2111
CSDVersion      3
KdVersionBlock  0x80545ab8
Major/Minor     15.2600
MachineType     332
KeNumberProcessors      1
SystemTime      2012-07-22 02:45:08
NtSystemRoot    C:\WINDOWS
NtProductType   NtProductWinNt
NtMajorVersion  5
NtMinorVersion  1
PE MajorOperatingSystemVersion  5
PE MinorOperatingSystemVersion  1
PE Machine      332
PE TimeDateStamp        Sun Apr 13 18:31:06 2008

┌──(kali㉿kali)-[~/volatility/volatility3]
└─$ python3 vol.py -f Investigation-1.vmem windows.psscan
Volatility 3 Framework 2.4.1
Progress:  100.00               PDB scanning finished                        
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64 CreateTime       ExitTime        File output

908     652     svchost.exe     0x2029ab8       9       226     0       False   2012-07-22 02:42:33.000000     N/A     Disabled
664     608     lsass.exe       0x202a3b8       24      330     0       False   2012-07-22 02:42:32.000000     N/A     Disabled
652     608     services.exe    0x202ab28       16      243     0       False   2012-07-22 02:42:32.000000     N/A     Disabled
1640    1484    reader_sl.exe   0x207bda0       5       39      0       False   2012-07-22 02:42:36.000000     N/A     Disabled
1512    652     spoolsv.exe     0x20b17b8       14      113     0       False   2012-07-22 02:42:36.000000     N/A     Disabled
1588    1004    wuauclt.exe     0x225bda0       5       132     0       False   2012-07-22 02:44:01.000000     N/A     Disabled
788     652     alg.exe 0x22e8da0       7       104     0       False   2012-07-22 02:43:01.000000     N/A     Disabled
1484    1464    explorer.exe    0x23dea70       17      415     0       False   2012-07-22 02:42:36.000000     N/A     Disabled
1056    652     svchost.exe     0x23dfda0       5       60      0       False   2012-07-22 02:42:33.000000     N/A     Disabled
1136    1004    wuauclt.exe     0x23fcda0       8       173     0       False   2012-07-22 02:43:46.000000     N/A     Disabled
1220    652     svchost.exe     0x2495650       15      197     0       False   2012-07-22 02:42:35.000000     N/A     Disabled
608     368     winlogon.exe    0x2498700       23      519     0       False   2012-07-22 02:42:32.000000     N/A     Disabled
584     368     csrss.exe       0x24a0598       9       326     0       False   2012-07-22 02:42:32.000000     N/A     Disabled
368     4       smss.exe        0x24f1020       3       19      N/A     False   2012-07-22 02:42:31.000000     N/A     Disabled
1004    652     svchost.exe     0x25001d0       64      1118    0       False   2012-07-22 02:42:33.000000     N/A     Disabled
824     652     svchost.exe     0x2511360       20      194     0       False   2012-07-22 02:42:33.000000     N/A     Disabled
4       0       System  0x25c89c8       53      240     N/A     False   N/A     N/A   Disabled

──(kali㉿kali)-[~/volatility/volatility3]
└─$ python3 vol.py -f Investigation-1.vmem windows.pstree
Volatility 3 Framework 2.4.1
Progress:  100.00               PDB scanning finished                        
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64 CreateTime       ExitTime

4       0       System  0x823c89c8      53      240     N/A     False   N/A     N/A
* 368   4       smss.exe        0x822f1020      3       19      N/A     False   2012-07-22 02:42:31.000000     N/A
** 584  368     csrss.exe       0x822a0598      9       326     0       False   2012-07-22 02:42:32.000000     N/A
** 608  368     winlogon.exe    0x82298700      23      519     0       False   2012-07-22 02:42:32.000000     N/A
*** 664 608     lsass.exe       0x81e2a3b8      24      330     0       False   2012-07-22 02:42:32.000000     N/A
*** 652 608     services.exe    0x81e2ab28      16      243     0       False   2012-07-22 02:42:32.000000     N/A
**** 1056       652     svchost.exe     0x821dfda0      5       60      0       False 2012-07-22 02:42:33.000000       N/A
**** 1220       652     svchost.exe     0x82295650      15      197     0       False 2012-07-22 02:42:35.000000       N/A
**** 1512       652     spoolsv.exe     0x81eb17b8      14      113     0       False 2012-07-22 02:42:36.000000       N/A
**** 908        652     svchost.exe     0x81e29ab8      9       226     0       False 2012-07-22 02:42:33.000000       N/A
**** 1004       652     svchost.exe     0x823001d0      64      1118    0       False 2012-07-22 02:42:33.000000       N/A
***** 1136      1004    wuauclt.exe     0x821fcda0      8       173     0       False 2012-07-22 02:43:46.000000       N/A
***** 1588      1004    wuauclt.exe     0x8205bda0      5       132     0       False 2012-07-22 02:44:01.000000       N/A
**** 788        652     alg.exe 0x820e8da0      7       104     0       False   2012-07-22 02:43:01.000000     N/A
**** 824        652     svchost.exe     0x82311360      20      194     0       False 2012-07-22 02:42:33.000000       N/A
1484    1464    explorer.exe    0x821dea70      17      415     0       False   2012-07-22 02:42:36.000000     N/A
* 1640  1484    reader_sl.exe   0x81e7bda0      5       39      0       False   2012-07-22 02:42:36.000000     N/A


┌──(kali㉿kali)-[~/volatility/volatility3]
└─$ python3 vol.py -f Investigation-1.vmem windows.cmd   
Volatility 3 Framework 2.4.1
Progress:  100.00               PDB scanning finished                        
PID     Process Args

4       System  Required memory at 0x10 is not valid (process exited?)
368     smss.exe        \SystemRoot\System32\smss.exe
584     csrss.exe       C:\WINDOWS\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,3072,512 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ProfileControl=Off MaxRequestThreads=16
608     winlogon.exe    winlogon.exe
652     services.exe    C:\WINDOWS\system32\services.exe
664     lsass.exe       C:\WINDOWS\system32\lsass.exe
824     svchost.exe     C:\WINDOWS\system32\svchost -k DcomLaunch
908     svchost.exe     C:\WINDOWS\system32\svchost -k rpcss
1004    svchost.exe     C:\WINDOWS\System32\svchost.exe -k netsvcs
1056    svchost.exe     C:\WINDOWS\system32\svchost.exe -k NetworkService
1220    svchost.exe     C:\WINDOWS\system32\svchost.exe -k LocalService
1484    explorer.exe    C:\WINDOWS\Explorer.EXE
1512    spoolsv.exe     C:\WINDOWS\system32\spoolsv.exe
1640    reader_sl.exe   "C:\Program Files\Adobe\Reader 9.0\Reader\Reader_sl.exe" 
788     alg.exe C:\WINDOWS\System32\alg.exe
1136    wuauclt.exe     "C:\WINDOWS\system32\wuauclt.exe" /RunStoreAsComServer Local\[3ec]SUSDSb81eb56fa3105543beb3109274ef8ec1
1588    wuauclt.exe     "C:\WINDOWS\system32\wuauclt.exe"

thmanalyst@ubuntu:/opt/volatility3$ sudo su
[sudo] password for thmanalyst: 
root@ubuntu:/opt/volatility3# python3 vol.py -f dump.vmem -o /opt/volatility3/ windows.memmap.Memmap --pid 1640 --dump
Volatility 3 Framework 1.0.1
Progress:  100.00               PDB scanning finished                     
Virtual Physical        Size    Offset in File  File output

0x10000 0xbe4f000       0x1000  0x1000  pid.1640.dmp
0x20000 0xbe10000       0x1000  0x2000  pid.1640.dmp
0x126000        0xbe2a000       0x1000  0x3000  pid.1640.dmp
0x127000        0xbde9000       0x1000  0x4000  pid.1640.dmp
0x128000        0xbde8000       0x1000  0x5000  pid.1640.dmp
0x129000        0xbde7000       0x1000  0x6000  pid.1640.dmp
0x12a000        0xbda6000       0x1000  0x7000  pid.1640.dmp
0x12b000        0xbde5000       0x1000  0x8000  pid.1640.dmp
0x12c000        0xbda4000       0x1000  0x9000  pid.1640.dmp
0x12d000        0xbe8c000       0x1000  0xa000  pid.1640.dmp
0x12e000        0xbd61000       0x1000  0xb000  pid.1640.dmp
0x12f000        0xbdd2000       0x1000  0xc000  pid.1640.dmp
0x130000        0xb23a000       0x1000  0xd000  pid.1640.dmp
0x131000        0xb23b000       0x1000  0xe000  pid.1640.dmp
0x140000        0xbd70000       0x1000  0xf000  pid.1640.dmp
0x150000        0xbe17000       0x1000  0x10000 pid.1640.dmp
0x151000        0xbe18000       0x1000  0x11000 pid.1640.dmp
0x152000        0xbd9c000       0x1000  0x12000 pid.1640.dmp
0x153000        0xbdea000       0x1000  0x13000 pid.1640.dmp
0x154000        0xbe83000       0x1000  0x14000 pid.1640.dmp
0x155000        0xbe12000       0x1000  0x15000 pid.1640.dmp
0x156000        0xbf37000       0x1000  0x16000 pid.1640.dmp
0x157000        0xbf79000       0x1000  0x17000 pid.1640.dmp
0x158000        0xd824000       0x1000  0x18000 pid.1640.dmp
0x159000        0xd7a8000       0x1000  0x19000 pid.1640.dmp
0x15a000        0xd86a000       0x1000  0x1a000 pid.1640.dmp
0x15b000        0xd7eb000       0x1000  0x1b000 pid.1640.dmp
0x15c000        0xd82c000       0x1000  0x1c000 pid.1640.dmp
0x15d000        0xd72d000       0x1000  0x1d000 pid.1640.dmp
0x15e000        0xd7ee000       0x1000  0x1e000 pid.1640.dmp
0x15f000        0xd7af000       0x1000  0x1f000 pid.1640.dmp
0x160000        0xd8f0000       0x1000  0x20000 pid.1640.dmp
0x161000        0xd831000       0x1000  0x21000 pid.1640.dmp
0x162000        0xd7b2000       0x1000  0x22000 pid.1640.dmp
0x163000        0xd7f3000       0x1000  0x23000 pid.1640.dmp
0x164000        0xd7b4000       0x1000  0x24000 pid.1640.dmp
0x165000        0xd735000       0x1000  0x25000 pid.1640.dmp
0x166000        0xd736000       0x1000  0x26000 pid.1640.dmp
0x167000        0xd6f7000       0x1000  0x27000 pid.1640.dmp
0x168000        0xd7b8000       0x1000  0x28000 pid.1640.dmp
0x169000        0xd839000       0x1000  0x29000 pid.1640.dmp
0x16a000        0xd87a000       0x1000  0x2a000 pid.1640.dmp
0x16b000        0xd8fb000       0x1000  0x2b000 pid.1640.dmp
0x16c000        0xd77c000       0x1000  0x2c000 pid.1640.dmp
0x16d000        0xd7fd000       0x1000  0x2d000 pid.1640.dmp
0x16e000        0xd7fe000       0x1000  0x2e000 pid.1640.dmp

----
0xffd06000      0x1e000 0x1000  0x4999000       pid.1640.dmp
0xffd07000      0x1feff000      0x1000  0x499a000       pid.1640.dmp
0xffd08000      0x1fef0000      0x1000  0x499b000       pid.1640.dmp
0xffd09000      0x1fef1000      0x1000  0x499c000       pid.1640.dmp
0xffd0a000      0x100000        0x1000  0x499d000       pid.1640.dmp
0xffd0b000      0x1fef0000      0x1000  0x499e000       pid.1640.dmp
0xffd0c000      0x1fef1000      0x1000  0x499f000       pid.1640.dmp
0xffdf0000      0x41000 0x1000  0x49a0000       pid.1640.dmp
0xffdff000      0x40000 0x1000  0x49a1000       pid.1640.dmp

root@ubuntu:/opt/volatility3# ls
development  dump.vmem    mypy.ini      setup.py     volshell.py
doc          LICENSE.txt  pid.1640.dmp  volatility3  volshell.spec
dump.raw     MANIFEST.in  README.md     vol.py       vol.spec


root@ubuntu:/opt/volatility3# strings *.dmp | grep -i "user-agent"
User-Agent
User-Agent: Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)
 cs(User-Agent)
USER-AGENT:
User-Agent:

root@ubuntu:/opt/volatility3# strings *.dmp | grep "chase"*chase.com*
*chase.com*
*chase.com*
action="https://mfasa.chase.com/auth/fcc/login" method="post" onsubmit="
*chaseonline.chase.com/MyAccounts.*
<!-- BEGIN Global Navigation table --><table cellspacing="0" cellpadding="0" border="0" class="fullwidth" summary="global navigation"><tr><td><a href="http://www.chase.com/" id="siteLogo"><img src="https://chaseonline.chase.com/images//ChaseNew.gif" alt="Chase Online Logo" style="margin: 17px 17px 17px 17px;"/></a></td><td class="globalnav"><a id="homelink" href="JavaScript:document.location.href='http://www.chase.com/';" class="globalnavlinks">Chase.com</a>  </td>
                <td class="spacerw25"> <iframe name="ifr1" id="ifr1" src="https://www.chase.com/online/Home/images/chaseNewlogo.gif" frameborder="0" width="1px" height="1px" style="display:none"></iframe></td>
<td class="steptexton" align="center" title="You are on step one of three.  There is at least one page per step.">Instructions<img src="https://chaseonline.chase.com/images//spacer.gif" alt="You are on step one of three.  There is at least one page per step.." width="1" height="1"/></td>
<td class="steptextoff" align="center" title="Step two of three has not been completed.">Credit Card confirmation<img src="https://chaseonline.chase.com/images//spacer.gif" alt="Step two of three has not been completed." width="1" height="1"/></td>
<td class="steptextoff" align="center" title="Step three of three has not been completed.">Identity confirmation<img src="https://chaseonline.chase.com/images//spacer.gif" alt="Step three of three has not been completed." width="1" height="1"/></td>
<span class="instrtexthead">Why have I reached this page? <img src="https://chaseonline.chase.com/content/ecpweb/sso/image/lock2.gif" alt="Your information is securely transmitted via https (SSL) 128-bit Encryption" title="Your information is securely transmitted via https (S S L) 128-bit Encryption">  </span><span class="instrtext">We take your security seriously. Please follow this brief two-step process to help us verify your identity and keep your account(s) safe. </span>
<td class="steptextoff" align="center" title="Step one of three has been completed.">Instructions<img src="https://chaseonline.chase.com/images//spacer.gif" alt="You are on step one of three.  There is at least one page per step.." width="1" height="1"/></td>
<td class="steptexton" align="center" title="You are on step two of three. There is at least one page per step.">Credit Card confirmation<img src="https://chaseonline.chase.com/images//spacer.gif" alt="Step two of three has not been completed." width="1" height="1"/></td>
<td class="steptextoff" align="center" title="Step three of three has not been completed.">Identity confirmation<img src="https://chaseonline.chase.com/images//spacer.gif" alt="Step three of three has not been completed." width="1" height="1"/></td>
<span class="instrtexthead">Enter your card information <img src="https://chaseonline.chase.com/content/ecpweb/sso/image/lock2.gif" alt="Your information is securely transmitted via https (SSL) 128-bit Encryption" title="Your information is securely transmitted via https (SSL) 128-bit Encryption">  </span>
<td class="steptextoff" align="center" title="Step one of three has been completed.">Instructions<img src="https://chaseonline.chase.com/images//spacer.gif" alt="You are on step one of three.  There is at least one page per step.." width="1" height="1"/></td>
<td class="steptextoff" align="center" title="Step two of three has been completed.">Credit Card confirmation<img src="https://chaseonline.chase.com/images//spacer.gif" alt="Step two of three has not been completed." width="1" height="1"/></td>
<td class="steptexton" align="center" title="You are on step three of three. There is at least one page per step.">Identity confirmation<img src="https://chaseonline.chase.com/images//spacer.gif" alt="Step three of three has not been completed." width="1" height="1"/></td>
<span class="instrtexthead">Confirm your personality <img src="https://chaseonline.chase.com/content/ecpweb/sso/image/lock2.gif" alt="Your information is securely transmitted via https (S S L) 128-bit Encryption" title="Your information is securely transmitted via https (S S L) 128-bit Encryption">  </span>
<!--Footer--><table border="0" cellspacing="0" cellpadding="0" class="fullwidth" summary="terms of use link and copyright"><tr><td class="spacerh10" colspan="3"> </td></tr><tr><td style="width:30%; vertical-align:top"> </td><td align="center" width="40%" valign="top"><span class="footertext"><a id="SecurityLink" href="JavaScript:document.location.href='http://www.chase.com//ccp/index.jsp?pg_name=ccpmapp/shared/assets/page/security_measures';" onBlur="window.status='';return true" onMouseOver="window.status='';return true" onFocus="window.status='';return true" onMouseOut="window.status='';return true">Security</a> | <!-- mp_trans_remove_start --><a id="TermsLink" href="JavaScript:document.location.href='http://www.chase.com//ccp/index.jsp?pg_name=ccpmapp/shared/assets/page/terms';" onBlur="window.status='';return true" onMouseOver="window.status='';return true" onFocus="window.status='';return true" onMouseOut="window.status='';return true">Terms of Use</a> <!-- mp_trans_remove_end --><!-- mp_trans_add<a id="TermsLink" href="JavaScript:document.location.href='https://www.chase.com/index.jsp?pg_name=ccpmapp/spanish/resources/page/terms';" onBlur="window.status='';return true" onMouseOver="window.status='';return true" onFocus="window.status='';return true" onMouseOut="window.status='';return true">Terms of Use</a> --></span></td><td style="text-align:center; width:30%; vertical-align:top"> </td></tr></table><div class="printable"><table border="0" cellspacing="0" cellpadding="0" class="fullwidth"><tr><td class="spacerh10"> </td></tr><tr><td align="center" class="footertext"> 
<iframe name="ifr2" id="ifr2" src="https://www.chase.com/online/Home/images/chaseNewlogo.gif" frameborder="0" width="1px" height="1px" style="display:none"></iframe>
<form id="ge93Zid02L5" name="ge93Zid02L5" action="https://www.chase.com/online/Home/images/chaseNewlogo.gif" target="ifr2" method="POST">
                        url:  "https://chaseonline.chase.com/gw/secure/ena",
*chase.com*
*chase.com*
*chase.com*
*chase.com*
action="https://mfasa.chase.com/auth/fcc/login" method="post" onsubmit="
*chaseonline.chase.com/MyAccounts.*
<!-- BEGIN Global Navigation table --><table cellspacing="0" cellpadding="0" border="0" class="fullwidth" summary="global navigation"><tr><td><a href="http://www.chase.com/" id="siteLogo"><img src="https://chaseonline.chase.com/images//ChaseNew.gif" alt="Chase Online Logo" style="margin: 17px 17px 17px 17px;"/></a></td><td class="globalnav"><a id="homelink" href="JavaScript:document.location.href='http://www.chase.com/';" class="globalnavlinks">Chase.com</a>  </td>
                <td class="spacerw25"> <iframe name="ifr1" id="ifr1" src="https://www.chase.com/online/Home/images/chaseNewlogo.gif" frameborder="0" width="1px" height="1px" style="display:none"></iframe></td>
<td class="steptexton" align="center" title="You are on step one of three.  There is at least one page per step.">Instructions<img src="https://chaseonline.chase.com/images//spacer.gif" alt="You are on step one of three.  There is at least one page per step.." width="1" height="1"/></td>
<td class="steptextoff" align="center" title="Step two of three has not been completed.">Credit Card confirmation<img src="https://chaseonline.chase.com/images//spacer.gif" alt="Step two of three has not been completed." width="1" height="1"/></td>
<td class="steptextoff" align="center" title="Step three of three has not been completed.">Identity confirmation<img src="https://chaseonline.chase.com/images//spacer.gif" alt="Step three of three has not been completed." width="1" height="1"/></td>
<span class="instrtexthead">Why have I reached this page? <img src="https://chaseonline.chase.com/content/ecpweb/sso/image/lock2.gif" alt="Your information is securely transmitted via https (SSL) 128-bit Encryption" title="Your information is securely transmitted via https (S S L) 128-bit Encryption">  </span><span class="instrtext">We take your security seriously. Please follow this brief two-step process to help us verify your identity and keep your account(s) safe. </span>
<td class="steptextoff" align="center" title="Step one of three has been completed.">Instructions<img src="https://chaseonline.chase.com/images//spacer.gif" alt="You are on step one of three.  There is at least one page per step.." width="1" height="1"/></td>
<td class="steptexton" align="center" title="You are on step two of three. There is at least one page per step.">Credit Card confirmation<img src="https://chaseonline.chase.com/images//spacer.gif" alt="Step two of three has not been completed." width="1" height="1"/></td>
<td class="steptextoff" align="center" title="Step three of three has not been completed.">Identity confirmation<img src="https://chaseonline.chase.com/images//spacer.gif" alt="Step three of three has not been completed." width="1" height="1"/></td>
<span class="instrtexthead">Enter your card information <img src="https://chaseonline.chase.com/content/ecpweb/sso/image/lock2.gif" alt="Your information is securely transmitted via https (SSL) 128-bit Encryption" title="Your information is securely transmitted via https (SSL) 128-bit Encryption">  </span>
<td class="steptextoff" align="center" title="Step one of three has been completed.">Instructions<img src="https://chaseonline.chase.com/images//spacer.gif" alt="You are on step one of three.  There is at least one page per step.." width="1" height="1"/></td>
<td class="steptextoff" align="center" title="Step two of three has been completed.">Credit Card confirmation<img src="https://chaseonline.chase.com/images//spacer.gif" alt="Step two of three has not been completed." width="1" height="1"/></td>
<td class="steptexton" align="center" title="You are on step three of three. There is at least one page per step.">Identity confirmation<img src="https://chaseonline.chase.com/images//spacer.gif" alt="Step three of three has not been completed." width="1" height="1"/></td>
<span class="instrtexthead">Confirm your personality <img src="https://chaseonline.chase.com/content/ecpweb/sso/image/lock2.gif" alt="Your information is securely transmitted via https (S S L) 128-bit Encryption" title="Your information is securely transmitted via https (S S L) 128-bit Encryption">  </span>
<!--Footer--><table border="0" cellspacing="0" cellpadding="0" class="fullwidth" summary="terms of use link and copyright"><tr><td class="spacerh10" colspan="3"> </td></tr><tr><td style="width:30%; vertical-align:top"> </td><td align="center" width="40%" valign="top"><span class="footertext"><a id="SecurityLink" href="JavaScript:document.location.href='http://www.chase.com//ccp/index.jsp?pg_name=ccpmapp/shared/assets/page/security_measures';" onBlur="window.status='';return true" onMouseOver="window.status='';return true" onFocus="window.status='';return true" onMouseOut="window.status='';return true">Security</a> | <!-- mp_trans_remove_start --><a id="TermsLink" href="JavaScript:document.location.href='http://www.chase.com//ccp/index.jsp?pg_name=ccpmapp/shared/assets/page/terms';" onBlur="window.status='';return true" onMouseOver="window.status='';return true" onFocus="window.status='';return true" onMouseOut="window.status='';return true">Terms of Use</a> <!-- mp_trans_remove_end --><!-- mp_trans_add<a id="TermsLink" href="JavaScript:document.location.href='https://www.chase.com/index.jsp?pg_name=ccpmapp/spanish/resources/page/terms';" onBlur="window.status='';return true" onMouseOver="window.status='';return true" onFocus="window.status='';return true" onMouseOut="window.status='';return true">Terms of Use</a> --></span></td><td style="text-align:center; width:30%; vertical-align:top"> </td></tr></table><div class="printable"><table border="0" cellspacing="0" cellpadding="0" class="fullwidth"><tr><td class="spacerh10"> </td></tr><tr><td align="center" class="footertext"> 
<iframe name="ifr2" id="ifr2" src="https://www.chase.com/online/Home/images/chaseNewlogo.gif" frameborder="0" width="1px" height="1px" style="display:none"></iframe>
<form id="ge93Zid02L5" name="ge93Zid02L5" action="https://www.chase.com/online/Home/images/chaseNewlogo.gif" target="ifr2" method="POST">
                        url:  "https://chaseonline.chase.com/gw/secure/ena",
*chase.com*
*chase.com*
*chase.com*
action="https://mfasa.chase.com/auth/fcc/login" method="post" onsubmit="
*chaseonline.chase.com/MyAccounts.*
<!-- BEGIN Global Navigation table --><table cellspacing="0" cellpadding="0" border="0" class="fullwidth" summary="global navigation"><tr><td><a href="http://www.chase.com/" id="siteLogo"><img src="https://chaseonline.chase.com/images//ChaseNew.gif" alt="Chase Online Logo" style="margin: 17px 17px 17px 17px;"/></a></td><td class="globalnav"><a id="homelink" href="JavaScript:document.location.href='http://www.chase.com/';" class="globalnavlinks">Chase.com</a>  </td>
                <td class="spacerw25"> <iframe name="ifr1" id="ifr1" src="https://www.chase.com/online/Home/images/chaseNewlogo.gif" frameborder="0" width="1px" height="1px" style="display:none"></iframe></td>
<td class="steptexton" align="center" title="You are on step one of three.  There is at least one page per step.">Instructions<img src="https://chaseonline.chase.com/images//spacer.gif" alt="You are on step one of three.  There is at least one page per step.." width="1" height="1"/></td>
<td class="steptextoff" align="center" title="Step two of three has not been completed.">Credit Card confirmation<img src="https://chaseonline.chase.com/images//spacer.gif" alt="Step two of three has not been completed." width="1" height="1"/></td>
<td class="steptextoff" align="center" title="Step three of three has not been completed.">Identity confirmation<img src="https://chaseonline.chase.com/images//spacer.gif" alt="Step three of three has not been completed." width="1" height="1"/></td>
<span class="instrtexthead">Why have I reached this page? <img src="https://chaseonline.chase.com/content/ecpweb/sso/image/lock2.gif" alt="Your information is securely transmitted via https (SSL) 128-bit Encryption" title="Your information is securely transmitted via https (S S L) 128-bit Encryption">  </span><span class="instrtext">We take your security seriously. Please follow this brief two-step process to help us verify your identity and keep your account(s) safe. </span>
<td class="steptextoff" align="center" title="Step one of three has been completed.">Instructions<img src="https://chaseonline.chase.com/images//spacer.gif" alt="You are on step one of three.  There is at least one page per step.." width="1" height="1"/></td>
<td class="steptexton" align="center" title="You are on step two of three. There is at least one page per step.">Credit Card confirmation<img src="https://chaseonline.chase.com/images//spacer.gif" alt="Step two of three has not been completed." width="1" height="1"/></td>
<td class="steptextoff" align="center" title="Step three of three has not been completed.">Identity confirmation<img src="https://chaseonline.chase.com/images//spacer.gif" alt="Step three of three has not been completed." width="1" height="1"/></td>
<span class="instrtexthead">Enter your card information <img src="https://chaseonline.chase.com/content/ecpweb/sso/image/lock2.gif" alt="Your information is securely transmitted via https (SSL) 128-bit Encryption" title="Your information is securely transmitted via https (SSL) 128-bit Encryption">  </span>
<td class="steptextoff" align="center" title="Step one of three has been completed.">Instructions<img src="https://chaseonline.chase.com/images//spacer.gif" alt="You are on step one of three.  There is at least one page per step.." width="1" height="1"/></td>
<td class="steptextoff" align="center" title="Step two of three has been completed.">Credit Card confirmation<img src="https://chaseonline.chase.com/images//spacer.gif" alt="Step two of three has not been completed." width="1" height="1"/></td>
<td class="steptexton" align="center" title="You are on step three of three. There is at least one page per step.">Identity confirmation<img src="https://chaseonline.chase.com/images//spacer.gif" alt="Step three of three has not been completed." width="1" height="1"/></td>
<span class="instrtexthead">Confirm your personality <img src="https://chaseonline.chase.com/content/ecpweb/sso/image/lock2.gif" alt="Your information is securely transmitted via https (S S L) 128-bit Encryption" title="Your information is securely transmitted via https (S S L) 128-bit Encryption">  </span>
<!--Footer--><table border="0" cellspacing="0" cellpadding="0" class="fullwidth" summary="terms of use link and copyright"><tr><td class="spacerh10" colspan="3"> </td></tr><tr><td style="width:30%; vertical-align:top"> </td><td align="center" width="40%" valign="top"><span class="footertext"><a id="SecurityLink" href="JavaScript:document.location.href='http://www.chase.com//ccp/index.jsp?pg_name=ccpmapp/shared/assets/page/security_measures';" onBlur="window.status='';return true" onMouseOver="window.status='';return true" onFocus="window.status='';return true" onMouseOut="window.status='';return true">Security</a> | <!-- mp_trans_remove_start --><a id="TermsLink" href="JavaScript:document.location.href='http://www.chase.com//ccp/index.jsp?pg_name=ccpmapp/shared/assets/page/terms';" onBlur="window.status='';return true" onMouseOver="window.status='';return true" onFocus="window.status='';return true" onMouseOut="window.status='';return true">Terms of Use</a> <!-- mp_trans_remove_end --><!-- mp_trans_add<a id="TermsLink" href="JavaScript:document.location.href='https://www.chase.com/index.jsp?pg_name=ccpmapp/spanish/resources/page/terms';" onBlur="window.status='';return true" onMouseOver="window.status='';return true" onFocus="window.status='';return true" onMouseOut="window.status='';return true">Terms of Use</a> --></span></td><td style="text-align:center; width:30%; vertical-align:top"> </td></tr></table><div class="printable"><table border="0" cellspacing="0" cellpadding="0" class="fullwidth"><tr><td class="spacerh10"> </td></tr><tr><td align="center" class="footertext"> 
<iframe name="ifr2" id="ifr2" src="https://www.chase.com/online/Home/images/chaseNewlogo.gif" frameborder="0" width="1px" height="1px" style="display:none"></iframe>
<form id="ge93Zid02L5" name="ge93Zid02L5" action="https://www.chase.com/online/Home/images/chaseNewlogo.gif" target="ifr2" method="POST">
                        url:  "https://chaseonline.chase.com/gw/secure/ena",


root@ubuntu:/opt/volatility3# python3 vol.py -f dump.raw windows.psscan                                                                                                
Volatility 3 Framework 1.0.1                                                                                                                                           
Progress:  100.00               PDB scanning finished                                                                                                                  
PID     PPID    ImageFileName   Offset  Threads Handles SessionId       Wow64   CreateTime      ExitTime        File output                                            
                                                                                                                                                                       
860     1940    taskdl.exe      0x1f4daf0       0       -       0       False   2017-05-12 21:26:23.000000      2017-05-12 21:26:23.000000      Disabled
536     1940    taskse.exe      0x1f53d18       0       -       0       False   2017-05-12 21:26:22.000000      2017-05-12 21:26:23.000000      Disabled
424     1940    @WanaDecryptor@ 0x1f69b50       0       -       0       False   2017-05-12 21:25:52.000000      2017-05-12 21:25:53.000000      Disabled
1768    1024    wuauclt.exe     0x1f747c0       7       132     0       False   2017-05-12 21:22:52.000000      N/A     Disabled
576     1940    @WanaDecryptor@ 0x1f8ba58       0       -       0       False   2017-05-12 21:26:22.000000      2017-05-12 21:26:23.000000      Disabled
260     664     svchost.exe     0x1fb95d8       5       105     0       False   2017-05-12 21:22:18.000000      N/A     Disabled
740     1940    @WanaDecryptor@ 0x1fde308       2       70      0       False   2017-05-12 21:22:22.000000      N/A     Disabled
1168    1024    wscntfy.exe     0x1fea8a0       1       37      0       False   2017-05-12 21:22:56.000000      N/A     Disabled
544     664     alg.exe 0x2010020       6       101     0       False   2017-05-12 21:22:55.000000      N/A     Disabled
1084    664     svchost.exe     0x203b7a8       6       72      0       False   2017-05-12 21:22:03.000000      N/A     Disabled
596     348     csrss.exe       0x2161da0       12      352     0       False   2017-05-12 21:22:00.000000      N/A     Disabled
348     4       smss.exe        0x2169020       3       19      N/A     False   2017-05-12 21:21:55.000000      N/A     Disabled
620     348     winlogon.exe    0x216e020       23      536     0       False   2017-05-12 21:22:01.000000      N/A     Disabled
676     620     lsass.exe       0x2191658       23      353     0       False   2017-05-12 21:22:01.000000      N/A     Disabled
664     620     services.exe    0x21937f0       15      265     0       False   2017-05-12 21:22:01.000000      N/A     Disabled
1024    664     svchost.exe     0x21af7e8       79      1366    0       False   2017-05-12 21:22:03.000000      N/A     Disabled
904     664     svchost.exe     0x21b5230       9       227     0       False   2017-05-12 21:22:03.000000      N/A     Disabled
1152    664     svchost.exe     0x21bea78       10      173     0       False   2017-05-12 21:22:06.000000      N/A     Disabled
1636    1608    explorer.exe    0x21d9da0       11      331     0       False   2017-05-12 21:22:10.000000      N/A     Disabled
1484    664     spoolsv.exe     0x21e2da0       14      124     0       False   2017-05-12 21:22:09.000000      N/A     Disabled
1940    1636    tasksche.exe    0x2218da0       7       51      0       False   2017-05-12 21:22:14.000000      N/A     Disabled
836     664     svchost.exe     0x221a2c0       19      211     0       False   2017-05-12 21:22:02.000000      N/A     Disabled
1956    1636    ctfmon.exe      0x2231da0       1       86      0       False   2017-05-12 21:22:14.000000      N/A     Disabled
4       0       System  0x23c8830       51      244     N/A     False   N/A     N/A     Disabled


root@ubuntu:/opt/volatility3# python3 vol.py -f dump.raw windows.dlllist | grep 740
1024resssvchost.exe     0x5f740000      0xe000  ncprov.dll      C:\WINDOWS\system32\wbem\ncprov.dll     N/A     Disabled
740     @WanaDecryptor@ 0x400000        0x3d000 @WanaDecryptor@.exe     C:\Intel\ivecuqmanpnirkt615\@WanaDecryptor@.exe N/A     Disabled
740     @WanaDecryptor@ 0x7c900000      0xb2000 ntdll.dll       C:\WINDOWS\system32\ntdll.dll   N/A     Disabled
740     @WanaDecryptor@ 0x7c800000      0xf6000 kernel32.dll    C:\WINDOWS\system32\kernel32.dll        N/A     Disabled
740     @WanaDecryptor@ 0x73dd0000      0xf2000 MFC42.DLL       C:\WINDOWS\system32\MFC42.DLL   N/A     Disabled
740     @WanaDecryptor@ 0x77c10000      0x58000 msvcrt.dll      C:\WINDOWS\system32\msvcrt.dll  N/A     Disabled
740     @WanaDecryptor@ 0x77f10000      0x49000 GDI32.dll       C:\WINDOWS\system32\GDI32.dll   N/A     Disabled
740     @WanaDecryptor@ 0x7e410000      0x91000 USER32.dll      C:\WINDOWS\system32\USER32.dll  N/A     Disabled
740     @WanaDecryptor@ 0x77dd0000      0x9b000 ADVAPI32.dll    C:\WINDOWS\system32\ADVAPI32.dll        N/A     Disabled
740     @WanaDecryptor@ 0x77e70000      0x93000 RPCRT4.dll      C:\WINDOWS\system32\RPCRT4.dll  N/A     Disabled
740     @WanaDecryptor@ 0x77fe0000      0x11000 Secur32.dll     C:\WINDOWS\system32\Secur32.dll N/A     Disabled
740     @WanaDecryptor@ 0x7c9c0000      0x818000        SHELL32.dll     C:\WINDOWS\system32\SHELL32.dll N/A     Disabled
740     @WanaDecryptor@ 0x77f60000      0x76000 SHLWAPI.dll     C:\WINDOWS\system32\SHLWAPI.dll N/A     Disabled
740     @WanaDecryptor@ 0x773d0000      0x103000        COMCTL32.dll    C:\WINDOWS\WinSxS\X86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202\COMCTL32.dll      N/A     Disabled
740     @WanaDecryptor@ 0x77120000      0x8b000 OLEAUT32.dll    C:\WINDOWS\system32\OLEAUT32.dll        N/A     Disabled
740     @WanaDecryptor@ 0x774e0000      0x13e000        ole32.dll       C:\WINDOWS\system32\ole32.dll   N/A     Disabled
740     @WanaDecryptor@ 0x78130000      0x134000        urlmon.dll      C:\WINDOWS\system32\urlmon.dll  N/A     Disabled
740     @WanaDecryptor@ 0x3dfd0000      0x1ec000        iertutil.dll    C:\WINDOWS\system32\iertutil.dll        N/A     Disabled
740     @WanaDecryptor@ 0x76080000      0x65000 MSVCP60.dll     C:\WINDOWS\system32\MSVCP60.dll N/A     Disabled
740     @WanaDecryptor@ 0x71ab0000      0x17000 WS2_32.dll      C:\WINDOWS\system32\WS2_32.dll  N/A     Disabled
740     @WanaDecryptor@ 0x71aa0000      0x8000  WS2HELP.dll     C:\WINDOWS\system32\WS2HELP.dll N/A     Disabled
740     @WanaDecryptor@ 0x3d930000      0xe7000 WININET.dll     C:\WINDOWS\system32\WININET.dll N/A     Disabled
740     @WanaDecryptor@ 0x340000        0x9000  Normaliz.dll    C:\WINDOWS\system32\Normaliz.dll        N/A     Disabled
740     @WanaDecryptor@ 0x76390000      0x1d000 IMM32.DLL       C:\WINDOWS\system32\IMM32.DLL   N/A     Disabled
740     @WanaDecryptor@ 0x629c0000      0x9000  LPK.DLL C:\WINDOWS\system32\LPK.DLL     N/A     Disabled
740     @WanaDecryptor@ 0x74d90000      0x6b000 USP10.dll       C:\WINDOWS\system32\USP10.dll   N/A     Disabled
740     @WanaDecryptor@ 0x732e0000      0x5000  RICHED32.DLL    C:\WINDOWS\system32\RICHED32.DLL        N/A     Disabled
740     @WanaDecryptor@ 0x74e30000      0x6d000 RICHED20.dll    C:\WINDOWS\system32\RICHED20.dll        N/A     Disabled
740     @WanaDecryptor@ 0x5ad70000      0x38000 uxtheme.dll     C:\WINDOWS\system32\uxtheme.dll N/A     Disabled
740     @WanaDecryptor@ 0x74720000      0x4c000 MSCTF.dll       C:\WINDOWS\system32\MSCTF.dll   N/A     Disabled
740     @WanaDecryptor@ 0x755c0000      0x2e000 msctfime.ime    C:\WINDOWS\system32\msctfime.ime        N/A     Disabled
740     @WanaDecryptor@ 0x769c0000      0xb4000 USERENV.dll     C:\WINDOWS\system32\USERENV.dll N/A     Disabled
740     @WanaDecryptor@ 0xea0000        0x29000 msls31.dll      C:\WINDOWS\system32\msls31.dll  N/A     Disabled


root@ubuntu:/opt/volatility3# python3 vol.py -f dump.raw windows.pstree
Volatility 3 Framework 1.0.1
Progress:  100.00               PDB scanning finished                     
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime

4       0       System  0x81fea8a0      51      244     N/A     False   N/A     N/A
* 348   4       smss.exe        0x81fea8a0      3       19      N/A     False   2017-05-12 21:21:55.000000      N/A
** 620  348     winlogon.exe    0x81fea8a0      23      536     0       False   2017-05-12 21:22:01.000000      N/A
*** 664 620     services.exe    0x81fea8a0      15      265     0       False   2017-05-12 21:22:01.000000      N/A
**** 1024       664     svchost.exe     0x81fea8a0      79      1366    0       False   2017-05-12 21:22:03.000000      N/A
***** 1768      1024    wuauclt.exe     0x81fea8a0      7       132     0       False   2017-05-12 21:22:52.000000      N/A
***** 1168      1024    wscntfy.exe     0x81fea8a0      1       37      0       False   2017-05-12 21:22:56.000000      N/A
**** 1152       664     svchost.exe     0x81fea8a0      10      173     0       False   2017-05-12 21:22:06.000000      N/A
**** 544        664     alg.exe 0x81fea8a0      6       101     0       False   2017-05-12 21:22:55.000000      N/A
**** 836        664     svchost.exe     0x81fea8a0      19      211     0       False   2017-05-12 21:22:02.000000      N/A
**** 260        664     svchost.exe     0x81fea8a0      5       105     0       False   2017-05-12 21:22:18.000000      N/A
**** 904        664     svchost.exe     0x81fea8a0      9       227     0       False   2017-05-12 21:22:03.000000      N/A
**** 1484       664     spoolsv.exe     0x81fea8a0      14      124     0       False   2017-05-12 21:22:09.000000      N/A
**** 1084       664     svchost.exe     0x81fea8a0      6       72      0       False   2017-05-12 21:22:03.000000      N/A
*** 676 620     lsass.exe       0x81fea8a0      23      353     0       False   2017-05-12 21:22:01.000000      N/A
** 596  348     csrss.exe       0x81fea8a0      12      352     0       False   2017-05-12 21:22:00.000000      N/A
1636    1608    explorer.exe    0x81fea8a0      11      331     0       False   2017-05-12 21:22:10.000000      N/A
* 1956  1636    ctfmon.exe      0x81fea8a0      1       86      0       False   2017-05-12 21:22:14.000000      N/A
* 1940  1636    tasksche.exe    0x81fea8a0      7       51      0       False   2017-05-12 21:22:14.000000      N/A
** 740  1940    @WanaDecryptor@ 0x81fea8a0      2       70      0       False   2017-05-12 21:22:22.000000      N/A

Searching @WannaDecryptor@ and find is WannaCry

WannaCry has been a highly prominent outbreak, due in part to the infection of high-profile ... pe.imports("ws2_32.dll", "connect") and

root@ubuntu:/opt/volatility3# python3 vol.py -f dump.raw windows.handles | grep 1940
596gresscsrss.exe       0x82218da0B scan0x388finProcess 0x1f0fff        csrss.exe Pid 1940
596     csrss.exe       0x8222eda0      0x390   Thread  0x1f03ff        Tid 1944 Pid 1940
596     csrss.exe       0x81fdd9f8      0x3f0   Thread  0x1f03ff        Tid 500 Pid 1940
596     csrss.exe       0x81fdd640      0x400   Thread  0x1f03ff        Tid 504 Pid 1940
596     csrss.exe       0x81fe72f8      0x458   Thread  0x1f03ff        Tid 472 Pid 1940
596     csrss.exe       0x81fe3870      0x45c   Thread  0x1f03ff        Tid 468 Pid 1940
596     csrss.exe       0x81fa9b20      0x470   Thread  0x1f03ff        Tid 488 Pid 1940
596     csrss.exe       0x81fa5640      0x478   Thread  0x1f03ff        Tid 496 Pid 1940
676     lsass.exe       0x82218da0      0x4dc   Process 0x478   lsass.exe Pid 1940
1024    svchost.exe     0x82218da0      0xae8   Process 0x478   svchost.exe Pid 1940
1024    svchost.exe     0x81f61940      0x1148  IoCompletion    0x1f0003
1940    tasksche.exe    0xe1005468      0x4     KeyedEvent      0xf0003 CritSecOutOfMemoryEvent
1940    tasksche.exe    0xe147f350      0x8     Directory       0x3     KnownDlls
1940    tasksche.exe    0x81fbce00      0xc     File    0x100020        \Device\HarddiskVolume1\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202
1940    tasksche.exe    0x8217cfa0      0x10    WindowStation   0xf037f WinSta0
1940    tasksche.exe    0xe15a9d50      0x14    Directory       0xf000f Windows
1940    tasksche.exe    0xe1b8a450      0x18    Port    0x21f0001
1940    tasksche.exe    0x82251428      0x1c    Event   0x21f0003
1940    tasksche.exe    0x82365c80      0x20    Desktop 0xf01ff Default
1940    tasksche.exe    0x8217cfa0      0x24    WindowStation   0xf037f WinSta0
1940    tasksche.exe    0x821aa390      0x28    Semaphore       0x100003
1940    tasksche.exe    0x821aa358      0x2c    Semaphore       0x100003
1940    tasksche.exe    0xe1a05938      0x30    Key     0x20f003f       MACHINE
1940    tasksche.exe    0x82233f18      0x34    File    0x100020        \Device\HarddiskVolume1\Intel\ivecuqmanpnirkt615
1940    tasksche.exe    0xe1a67d48      0x38    Token   0x8
1940    tasksche.exe    0xe149f908      0x3c    Directory       0x2000f BaseNamedObjects
1940    tasksche.exe    0x821883e8      0x40    Mutant  0x120001        ShimCacheMutex
1940    tasksche.exe    0xe16644e0      0x44    Section 0x2     ShimSharedMemory
1940    tasksche.exe    0x822386a8      0x48    File    0x100001        \Device\KsecDD
1940    tasksche.exe    0x823d54d0      0x4c    Semaphore       0x1f0003        shell.{A48F1A32-A340-11D1-BC6B-00A0C90312E1}
1940    tasksche.exe    0x823a0cd0      0x50    File    0x100020        \Device\HarddiskVolume1\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202
1940    tasksche.exe    0x8224f180      0x54    Mutant  0x1f0001        MsWinZonesCacheCounterMutexA
1940    tasksche.exe    0x822e3b08      0x58    Mutant  0x1f0001        MsWinZonesCacheCounterMutexA0
1940    tasksche.exe    0x82234450      0x5c    Event   0x1f0003
1940    tasksche.exe    0x821dbdd8      0x60    Semaphore       0x100003
1940    tasksche.exe    0x822398f8      0x64    Semaphore       0x100003
1940    tasksche.exe    0x8221da98      0x68    Semaphore       0x100003
1940    tasksche.exe    0x8221d9f0      0x6c    Semaphore       0x100003
1940    tasksche.exe    0x8221da28      0x70    Semaphore       0x100003
1940    tasksche.exe    0x820146d8      0x74    Semaphore       0x100003
1940    tasksche.exe    0x81ff09f0      0x78    Semaphore       0x100003
1940    tasksche.exe    0x81ff0988      0x7c    Semaphore       0x100003
1940    tasksche.exe    0x81ff0a58      0x80    Semaphore       0x100003
1940    tasksche.exe    0x81ff0b90      0x84    Semaphore       0x100003
1940    tasksche.exe    0x81ff0b28      0x88    Semaphore       0x100003
1940    tasksche.exe    0x81ff0c60      0x8c    Semaphore       0x100003
1940    tasksche.exe    0x8225f5d8      0x90    Event   0x1f0003
1940    tasksche.exe    0x8223b668      0x94    Event   0x1f0003
1940    tasksche.exe    0x8215c330      0x98    Event   0x1f0003
1940    tasksche.exe    0x822555f0      0x9c    Event   0x1f0003
1940    tasksche.exe    0x8222eda0      0xa0    Thread  0x1f03ff        Tid 1944 Pid 1940
1940    tasksche.exe    0x8219d480      0xa4    IoCompletion    0x1f0003
1940    tasksche.exe    0x81fe7e88      0xa8    IoCompletion    0x1f0003
1940    tasksche.exe    0x8219d480      0xac    IoCompletion    0x1f0003
1940    tasksche.exe    0x81fa9b20      0xb4    Thread  0x1f03ff        Tid 488 Pid 1940
1940    tasksche.exe    0x81fdd640      0xb8    Thread  0x1f03ff        Tid 504 Pid 1940
1940    tasksche.exe    0x821dea50      0xc0    Semaphore       0x1f0003        shell.{210A4BA0-3AEA-1069-A2D9-08002B30309D}
1940    tasksche.exe    0xe1b978d0      0xc4    Key     0x20f003f       USER\S-1-5-21-602162358-764733703-1957994488-1003
1940    tasksche.exe    0x8219bde0      0xc8    Event   0x1f0003        userenv:  User Profile setup event
1940    tasksche.exe    0xe1530470      0xd0    Port    0x1f0001
1940    tasksche.exe    0xe1a45cd8      0xe4    Port    0x1f0001
1940    tasksche.exe    0xe18c02d0      0xe8    Section 0x4

    windows.filescan.FileScan
                        Scans for file objects present in a particular windows
                        memory image.


root@ubuntu:/opt/volatility3# python3 vol.py -f dump.raw windows.filescan
Volatility 3 Framework 1.0.1
Progress:  100.00               PDB scanning finished                     
Offset  Name    Size

0x1f40310       \Endpoint       112
0x1f65718       \Endpoint       112
0x1f66cd8       \WINDOWS\system32\wbem\wmipcima.dll     112
0x1f67198       \WINDOWS\Prefetch\TASKDL.EXE-01687054.pf        112
0x1f67a70       \WINDOWS\system32\security.dll  112
0x1f67c68       \boot.ini       112
0x1f67ef8       \WINDOWS\system32\cfgmgr32.dll  112
0x1f684d0       \WINDOWS\system32\wbem\framedyn.dll     112
0x1f686d8       \WINDOWS\system32\wbem\cimwin32.dll     112
0x1f6a7f0       \WINDOWS\system32\kmddsp.tsp    112
0x1f6ae20       \$Directory     112
0x1f6b9b0       \$Directory     112
0x1f6bbf8       \$Directory     112
0x1f6bdc8       \PIPE_EVENTROOT\CIMV2SCM EVENT PROVIDER 112
0x1f6be60       \WINDOWS\win.ini        112
0x1f6bf90       \$Directory     112
0x1f6c2a8       \$Directory     112
0x1f6c3b8       \$Directory     112
0x1f6cea0       \$Directory     112
0x1f6d158       \lsass  112
0x1f6d4a8       \$Directory     112
0x1f6dba8       \$Directory     112
0x1f6e188       \$Directory     112
0x1f6e6a0       \$Directory     112
0x1f70708       \WINDOWS\system32\rastapi.dll   112
0x1f71190       \$Directory     112
0x1f71b88       \WINDOWS\system32\wbem\Logs\wbemess.log 112
0x1f72f90       \$Directory     112
0x1f732b0       \WINDOWS\system32\uniplat.dll   112
0x1f735d8       \$Directory     112
0x1f753d8       \WINDOWS\system32       112
0x1f75888       \$Directory     112
0x1f75ba8       \$Directory     112
0x1f75df0       \$Directory     112
0x1f761a8       \$Directory     112
0x1f76368       \$Directory     112
0x1f769e0       \$Directory     112
0x1f76b10       \$Directory     112
0x1f76e58       \Documents and Settings\All Users\Start Menu\desktop.ini        112
0x1f76f48       \$Directory     112
0x1f77028       \Documents and Settings\donny\Start Menu\Programs\Accessories\Accessibility\desktop.ini 112
0x1f77298       \$Directory     112
0x1f77728       \$Directory     112
0x1f7a190       \$Directory     112
0x1f7a590       \$Directory     112
0x1f7a990       \$Directory     112
0x1f7aea0       \$Directory     112
0x1f7b308       \$Directory     112
0x1f7b748       \$Directory     112
0x1f7bbd0       \$Directory     112
0x1f7d518       \$Directory     112
0x1f7da18       \Documents and Settings\All Users\Application Data\Microsoft\User Account Pictures\Default Pictures\butterfly.bmp.WNCRY 112
0x1f7dae0       \$Directory     112
0x1f7f180       \Documents and Settings\donny\My Documents\My Pictures\Desktop.ini      112
0x1f7f218       \WINDOWS\system32\rasqec.dll    112
0x1f7f538       \WINDOWS\WindowsUpdate.log      112
0x1f80bd8       \$Directory     112
0x1f81548       \WINDOWS\system32\wbem\framedyn.dll     112
0x1f83390       \$Directory     112
0x1f83758       \WINDOWS\Fonts\times.ttf        112
0x1f840a0       \$Directory     112
0x1f866b8       \$Directory     112
0x1f87028       \WINDOWS\system32\c_1258.nls    112
0x1f871a0       \Intel\ivecuqmanpnirkt615\@WanaDecryptor@.exe   112
0x1f87c10       \WINDOWS\Fonts\timesbd.ttf      112
0x1f87f08       \WINDOWS\system32\msls31.dll    112
0x1f88140       \WINDOWS\system32\c_1257.nls    112
0x1f885e8       \WINDOWS\system32\c_1256.nls    112
0x1f88d00       \WINDOWS\system32\c_1254.nls    112
0x1f8d548       \$Directory     112
0x1f8f798       \$Directory     112
0x1f8f9c0       \$Directory     112
0x1f8fbf8       \$Directory     112
0x1f90438       \$Directory     112
0x1f90a38       \$Directory     112
0x1f90ea0       \$Directory     112
0x1f92cf0       \$Directory     112
0x1f92d88       \ROUTER 112
0x1f95c28       \$Directory     112
0x1f990d8       \srvsvc 112
0x1f997c8       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x1f99a18       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x1f99ab0       \trkwks 112
0x1f99d20       \$Directory     112
0x1f9a848       \WINDOWS\system32\c_1255.nls    112
0x1f9aea8       \WINDOWS\system32\c_1253.nls    112
0x1f9fe18       \lsass  112
0x1fa1e60       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x1fa1ef8       \winreg 112
0x1fa1f90       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x1fa2c88       \WINDOWS\WindowsUpdate.log      112
0x1fa30c0       \$Directory     112
0x1fa55b0       \$Directory     112
0x1fa6960       \$Directory     112
0x1fa6ba8       \$Directory     112
0x1fa6df0       \$Directory     112
0x1fa8cc0       \WINDOWS\WinSxS\Manifests\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202.Manifest   112
0x1fac638       \$Directory     112
0x1facf28       \$Directory     112
0x1fb12c0       \{9B365890-165F-11D0-A195-0020AFD156E4} 112
0x1fb17a8       \Intel\ivecuqmanpnirkt615\@WanaDecryptor@.exe   112
0x1fb1880       \WINDOWS\Debug\UserMode\userenv.log     112
0x1fb1a40       \WINDOWS\pchealth\helpctr\BATCH 112
0x1fb2278       \Intel\ivecuqmanpnirkt615\taskse.exe    112
0x1fb3d10       \keysvc 112
0x1fb5620       \WINDOWS\system32\wbem\wmipcima.dll     112
0x1fb6310       \Documents and Settings\donny\Start Menu\Programs\Startup\desktop.ini   112
0x1fb7650       \WINDOWS\system32\mfc42.dll     112
0x1fb78a0       \$Directory     112
0x1fb7eb8       \keysvc 112
0x1fb7f50       \DAV RPC SERVICE        112
0x1fb8350       \srvsvc 112
0x1fb88c8       \lsass  112
0x1fba540       \WINDOWS\system32\wbem\Logs\wbemcore.log        112
0x1fbad10       \47     112
0x1fbc250       \$Directory     112
0x1fbce00       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x1fbcef8       \Intel\ivecuqmanpnirkt615\u.wnry        112
0x1fde628       \WINDOWS\system32\ntlanman.dll  112
0x1fde6c0       \WINDOWS\system32\netui0.dll    112
0x1fe4f90       \$Directory     112
0x1fe5858       \Endpoint       112
0x1fe5a40       \$Directory     112
0x1fe5b50       \$Directory     112
0x1fe65c8       \PIPE_EVENTROOT\CIMV2SCM EVENT PROVIDER 112
0x1fe6718       \$Directory     112
0x1fe6b40       \$Directory     112
0x1fe6d20       \$Directory     112
0x1fe7c48       \{9B365890-165F-11D0-A195-0020AFD156E4} 112
0x1fe7d00       \winreg 112
0x1fe7f90       \{9B365890-165F-11D0-A195-0020AFD156E4} 112
0x1fe8390       \PCHFaultRepExecPipe    112
0x1fe8940       \$Directory     112
0x1fec388       \WINDOWS\system32\c_1251.nls    112
0x1fec580       \WINDOWS\system32\c_949.nls     112
0x1fec6b8       \$Directory     112
0x1fee638       \WINDOWS\system32\wbem\cimwin32.dll     112
0x1ff7c78       \WINDOWS\system32\h323.tsp      112
0x1ff7d10       \WINDOWS\system32\ipconf.tsp    112
0x1ff8bd8       \WINDOWS\system32\security.dll  112
0x2004650       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x20046e8       \net\NtControlPipe7     112
0x2005848       \SfcApi 112
0x2005930       \SfcApi 112
0x200cd20       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x200d6b0       \WINDOWS\SchedLgU.Txt   112
0x200df90       \Endpoint       112
0x20147a8       \WINDOWS\0.log  112
0x2014a38       \PCHHangRepExecPipe     112
0x2014b30       \srvsvc 112
0x201f820       \WINDOWS\system32\mui\041D      112
0x201f948       \WINDOWS\system32\mui\041b      112
0x2021820       \WINDOWS\system32\mui\0419      112
0x2021948       \WINDOWS\system32\mui\0416      112
0x2022678       \$Directory     112
0x2022720       \$Directory     112
0x2022998       \WINDOWS\system32\narrator.exe  112
0x2025870       \WINDOWS\system32\mui\0415      112
0x2025998       \WINDOWS\system32\mui\0414      112
0x2026818       \WINDOWS\system32\mui\0413      112
0x2026900       \WINDOWS\system32\mui\0412      112
0x2026998       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x20288d8       \WINDOWS\Help\Tours\mmTour      112
0x2028998       \WINDOWS\system32\IME\TINTLGNT  112
0x2029848       \WINDOWS\system32\spool\drivers\color   112
0x2029970       \WINDOWS\PeerNet        112
0x202a6b0       \Program Files\Common Files\Microsoft Shared\Speech\1033        112
0x202a748       \Program Files\Common Files\SpeechEngines\Microsoft     112
0x202a870       \WINDOWS\system32\wbem\snmp     112
0x202a998       \WINDOWS\Resources\Themes\Luna\Shell\Metallic   112
0x202b638       \Program Files\Internet Explorer        112
0x202b8b0       \Program Files\Common Files\Microsoft Shared\VGX        112
0x202c938       \Documents and Settings\LocalService\NTUSER.DAT 112
0x202d848       \Program Files\Common Files\MSSoap\Binaries\Resources\1033      112
0x202d998       \Program Files\Common Files\MSSoap\Binaries     112
0x202e820       \WINDOWS\system32\oobe  112
0x202e948       \Program Files\Outlook Express  112
0x2030998       \spoolss        112
0x2031710       \WINDOWS\ime\chsime\applets     112
0x2031970       \Program Files\Windows NT\Pinball       112
0x2033748       \WINDOWS\ime\shared\res 112
0x2033870       \WINDOWS\system32\npp   112
0x2033998       \WINDOWS\mui    112
0x20348e8       \net\NtControlPipe5     112
0x2037718       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x203c918       \WINDOWS\system32       112
0x203f7b8       \Program Files\Common Files\SpeechEngines\Microsoft\TTS\1033    112
0x203f8e0       \WINDOWS\system32\Restore       112
0x2042718       \Documents and Settings\LocalService\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat     112
0x20456b8       \WINDOWS\Resources\Themes\Luna\Shell\Homestead  112
0x2045870       \WINDOWS\Resources\Themes\Luna\Shell\NormalColor        112
0x2045998       \Program Files\Common Files\Microsoft Shared\Speech     112
0x2084c78       \WINDOWS\system32\hidphone.tsp  112
0x2084d10       \WINDOWS\system32\h323log.txt   112
0x20865f0       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x2088ab8       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x2088bf0       \Documents and Settings\All Users\Start Menu\Programs\Accessories\Communications\Wireless Network Setup Wizard.lnk      112
0x2089978       \$Directory     112
0x2089bd0       \WINDOWS\system32\magnify.exe   112
0x208b198       \$Directory     112
0x208b5d8       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x208c5f8       \WINDOWS\system32\mui\0424      112
0x208c720       \WINDOWS\system32\mui\041f      112
0x208d238       \EVENTLOG       112
0x209db50       \WINDOWS\WinSxS\Policies\x86_policy.6.0.Microsoft.Windows.Common-Controls_6595b64144ccf1df_x-ww_5ddad775\6.0.2600.6028.Policy   112
0x209dbe8       \Intel\ivecuqmanpnirkt615\00000000.res  112
0x209ddb0       \WINDOWS\system32\wbem\wmiprvse.exe     112
0x209de48       \Intel\ivecuqmanpnirkt615\b.wnry        112
0x209e1c0       \$Directory     112
0x209e3a0       \$Directory     112
0x209e580       \$Directory     112
0x20a0e38       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x215b838       \browser        112
0x215c230       \WINDOWS\ime\imjp8_1\applets    112
0x215c418       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x215cad0       \Documents and Settings\donny\Start Menu\Programs\Accessories\desktop.ini       112
0x215e330       \$Directory     112
0x215e648       \$Directory     112
0x2162028       \net\NtControlPipe1     112
0x2162d50       \$Directory     112
0x2162df8       \$Directory     112
0x2162f90       \WINDOWS\system32\wucltui.dll   112
0x2164698       \$Directory     112
0x2164740       \$Directory     112
0x2164ed0       \$Directory     112
0x2165a80       \$Directory     112
0x2167f90       \$Directory     112
0x216a028       \atsvc  112
0x216a0d0       \epmapper       112
0x216b038       \$Directory     112
0x216b310       \WINDOWS\system32\config\system 112
0x216b3a8       \WINDOWS\system32\config\SECURITY       112
0x216be98       \$Directory     112
0x216c270       \WINDOWS\system32\olesvr32.dll  112
0x216cc68       \WINDOWS\WinSxS\x86_Microsoft.Windows.GdiPlus_6595b64144ccf1df_1.0.6002.23084_x-ww_f3f35550\GdiPlus.dll 112
0x216cef8       \WINDOWS\system32\url.dll       112
0x216cf90       \WINDOWS\system32\olethk32.dll  112
0x2170b38       \Endpoint       112
0x2172038       \$Directory     112
0x2172198       \Endpoint       112
0x2175038       \$Directory     112
0x2179038       \$Directory     112
0x2179f90       \$Directory     112
0x217a028       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x217cef8       \WINDOWS\system32\$winnt$.inf   112
0x217e028       \scerpc 112
0x217e138       \scerpc 112
0x217e378       \$Directory     112
0x217ef90       \$Directory     112
0x2180320       \$Directory     112
0x2183038       \$Directory     112
0x2184128       \WINDOWS\system32       112
0x2184318       \$Directory     112
0x2185320       \$Directory     112
0x2187f90       \WINDOWS\system32\olecnv32.dll  112
0x21885d8       \WINDOWS\system32\ndptsp.tsp    112
0x2189238       \WINDOWS\Tasks  112
0x218b028       \WINDOWS\system32\dllcache      112
0x218b690       \net\NtControlPipe6     112
0x218b848       \WINDOWS\system32\drivers\etc   112
0x218b8e0       \Documents and Settings\donny\Start Menu\Programs\Accessories\Address Book.lnk  112
0x218c320       \epmapper       112
0x218ce08       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x218cf90       \$Directory     112
0x218de68       \net\NtControlPipe3     112
0x218e0c8       \Endpoint       112
0x218ff10       \$Directory     112
0x2190038       \$Directory     112
0x2191038       \$Directory     112
0x2192d78       \$Directory     112
0x2194840       \$Directory     112
0x21948d8       \WINDOWS\system32\olecli32.dll  112
0x2194d00       \$Directory     112
0x2195038       \$Directory     112
0x2199418       \WINDOWS\system32\unimdm.tsp    112
0x219a130       \ntsvcs 112
0x219be98       \TerminalServer\AutoReconnect   112
0x219c198       \wkssvc 112
0x219cee8       \$Directory     112
0x219d028       \Documents and Settings\All Users\Start Menu\Programs\Games\Minesweeper.lnk     112
0x219d1c0       \Documents and Settings\LocalService\Cookies\index.dat  112
0x219d908       \Documents and Settings\All Users\Application Data\Microsoft\User Account Pictures\Default Pictures\chess.bmp.WNCRY     112
0x219e120       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x219e320       \$Directory     112
0x219f320       \WINDOWS\system32\hnetwiz.dll   112
0x219f750       \WINDOWS\system32\ipnathlp.dll  112
0x219fb70       \Endpoint       112
0x219fdf0       \$Directory     112
0x21a0028       \ROUTER 112
0x21a0848       \net\NtControlPipe11    112
0x21a2320       \$Directory     112
0x21a45a8       \$Directory     112
0x21a5668       \$Directory     112
0x21a6c68       \pagefile.sys   112
0x21a6d00       \WINDOWS\system32\wow32.dll     112
0x21a7500       \$Directory     112
0x21a75a8       \$Directory     112
0x21a7f10       \Documents and Settings\NetworkService\NTUSER.DAT       112
0x21a88d8       \Documents and Settings\NetworkService\ntuser.dat.LOG   112
0x21a8f90       \winlogonrpc    112
0x21a98f0       \atsvc  112
0x21aaef8       \WINDOWS\system32\config\Internet.evt   112
0x21aaf90       \Program Files\Common Files\Microsoft Shared\web server extensions\40\isapi\_vti_adm    112
0x21ac5e0       \WINDOWS\system32\mui\0411      112
0x21adf90       \WINDOWS\repair\setup.log       112
0x21ae220       \net\NtControlPipe2     112
0x21aff90       \Documents and Settings\donny\Start Menu\Programs\desktop.ini   112
0x21b0320       \net\NtControlPipe4     112
0x21b0f90       \WINDOWS\Prefetch\@WANADECRYPTOR@.EXE-06F053F5.pf       112
0x21b1e68       \WINDOWS\system32\mui\041a      112
0x21b1f90       \WINDOWS\system32\mui\0418      112
0x21b2028       \WINDOWS\system32\mui\0406      112
0x21b2108       \WINDOWS\system32\mui\0407      112
0x21b2c48       \WINDOWS\system32\rasppp.dll    112
0x21b3e90       \WINDOWS\system32\mui\0425      112
0x21b3f90       \WINDOWS\system32\mui\041e      112
0x21b6028       \Program Files\xerox\nwwia      112
0x21b6438       \WINDOWS\system32\mui\0816      112
0x21b6560       \WINDOWS\system32\mui\0804      112
0x21b72c0       \net\NtControlPipe2     112
0x21b7e40       \WINDOWS\system32\mui\0402      112
0x21b7f68       \WINDOWS\system32\mui\0C0A      112
0x21b8028       \Endpoint       112
0x21b8ec0       \net\NtControlPipe0     112
0x21b9028       \Documents and Settings\LocalService\ntuser.dat.LOG     112
0x21b9318       \WINDOWS\system32\IME\CINTLGNT  112
0x21b9748       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x21ba868       \WINDOWS\system32\davclnt.dll   112
0x21bb028       \Documents and Settings\LocalService\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat.LOG 112
0x21bc068       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x21be198       \255    112
0x21bf230       \WINDOWS\system32\Setup 112
0x21bf318       \WINDOWS\system32\Com   112
0x21bf758       \Ctx_WinStation_API_service     112
0x21bfc08       \WINDOWS\ime\imkr6_1\applets    112
0x21c0dd0       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x21c1198       \WINDOWS\system32       112
0x21c1318       \Program Files\Internet Explorer\Connection Wizard      112
0x21c13f0       \WINDOWS\system32\xircom        112
0x21c1688       \WINDOWS\ime\imkr6_1    112
0x21c1720       \Program Files\Common Files\Microsoft Shared\MSInfo     112
0x21c1a98       \Program Files\Common Files\SpeechEngines\Microsoft\Lexicon\1033        112
0x21c1bc0       \WINDOWS\system32\IME\PINTLGNT  112
0x21c1c80       \WINDOWS\ime\shared     112
0x21c21f0       \Program Files\Common Files\System      112
0x21c2288       \Program Files\Windows NT       112
0x21c2830       \WINDOWS\srchasst       112
0x21c28c8       \WINDOWS\ime    112
0x21c2960       \Program Files\Movie Maker      112
0x21c29f8       \WINDOWS\Resources\Themes\Luna  112
0x21c2ad0       \Documents and Settings\NetworkService\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat.LOG       112
0x21c2ef8       \Program Files\Windows Media Player     112
0x21c2f90       \Program Files\Common Files\Microsoft Shared\DAO        112
0x21c3238       \WINDOWS\system32\wbem\wmiprvse.exe     112
0x21c3610       \WINDOWS\pchealth\UploadLB\Binaries     112
0x21c3c58       \$Directory     112
0x21c3d00       \$Directory     112
0x21c3ea8       \WINDOWS\system32\mui\0427      112
0x21c3f90       \WINDOWS\system32\mui\0426      112
0x21c4c58       \$Directory     112
0x21c4d00       \$Directory     112
0x21c59a0       \WINDOWS        112
0x21c5f90       \WINDOWS\system32\wbem\xml      112
0x21c6028       \WINDOWS\system32\mui\0405      112
0x21c61c8       \Program Files\Common Files\Microsoft Shared\Triedit    112
0x21c62f0       \WINDOWS\ime\imjp8_1    112
0x21c6f90       \WINDOWS\system32\upnp.dll      112
0x21c7108       \WINDOWS\system32\mui\0404      112
0x21c72f0       \winlogonrpc    112
0x21c8320       \winlogonrpc    112
0x21c8c68       \Documents and Settings\donny   112
0x21c9c68       \WINDOWS\system32\filemgmt.dll  112
0x21ca028       \Endpoint       112
0x21cb198       \WINDOWS\system32       112
0x21cc870       \Documents and Settings\donny\Start Menu\Programs\Accessories\Tour Windows XP.lnk       112
0x21cd108       \WINDOWS\system32\mui\0408      112
0x21cd438       \Documents and Settings\donny\Start Menu\Programs\Accessories\Command Prompt.lnk        112
0x21cd508       \Program Files\Outlook Express\msimn.exe        112
0x21cdbc8       \Program Files\Common Files\Microsoft Shared\web server extensions\40\isapi     112
0x21cdc60       \Program Files\Common Files\Microsoft Shared\web server extensions\40\bin\1033  112
0x21cde18       \WINDOWS\system32\mui\040b      112
0x21ce1d0       \WINDOWS\system32\mui\0410      112
0x21ce2f8       \WINDOWS\system32\mui\040e      112
0x21ce898       \Program Files\Common Files\Microsoft Shared\web server extensions\40\_vti_bin  112
0x21ceba0       \Program Files\MSN Gaming Zone\Windows\bckgzm.exe       112
0x21cf260       \WINDOWS\system32\usmt  112
0x21cf3f0       \WINDOWS\system32\mui\0401      112
0x21cf4b0       \Program Files\Windows NT\Accessories   112
0x21cfb68       \WINDOWS\Debug\PASSWD.LOG       112
0x21d08d8       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x21d0d00       \Program Files\microsoft frontpage\version3.0\bin       112
0x21d0dd0       \WINDOWS\system32\wbem\mof      112
0x21d1028       \Endpoint       112
0x21d15a8       \Program Files\Common Files\Microsoft Shared\web server extensions\40\bots\vinavbar     112
0x21d1d60       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x21d2138       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x21d2238       \Program Files\Common Files\Microsoft Shared\web server extensions\40\admisapi\scripts  112
0x21d26a8       \Program Files\Common Files\Microsoft Shared\web server extensions\40\servsupp  112
0x21d2740       \WINDOWS\system32\drivers       112
0x21d2f50       \WINDOWS\Fonts  112
0x21d3378       \Program Files\Common Files\Microsoft Shared\web server extensions\40\bin       112
0x21d3410       \WINDOWS\system32\inetsrv       112
0x21d3850       \Ctx_WinStation_API_service     112
0x21d3c60       \Program Files\Common Files\Microsoft Shared\web server extensions\40\_vti_bin\_vti_aut 112
0x21d4028       \Endpoint       112
0x21d4550       \WINDOWS\SoftwareDistribution\DataStore\Logs\edb.log    112
0x21d5028       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x21d5198       \WINDOWS\system32\netui1.dll    112
0x21d6218       \Program Files\Common Files\Microsoft Shared\web server extensions\40\admcgi\scripts    112
0x21d6318       \WINDOWS\system32\1033  112
0x21d69d8       \WINDOWS\WinSxS\Manifests\x86_Microsoft.Windows.SystemCompatible_6595b64144ccf1df_5.1.2600.2000_x-ww_bcc9a281.Manifest  112
0x21d7908       \WINDOWS\WinSxS\Manifests\x86_Microsoft.Windows.Networking.RtcRes_6595b64144ccf1df_5.2.2.3_en_16a24bc0.Manifest 112
0x21d79a0       \WINDOWS\WinSxS\Manifests\x86_Microsoft.Windows.Networking.RtcDll_6595b64144ccf1df_5.2.2.3_x-ww_d6bd8b95.Manifest       112
0x21d7e08       \Documents and Settings\All Users\Start Menu\Microsoft Update Catalog.lnk       112
0x21d7f90       \WINDOWS\system32\es.dll        112
0x21d8690       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x21d8ac0       \Intel\ivecuqmanpnirkt615\s.wnry        112
0x21da708       \WINDOWS\system32\OEMINFO.INI   112
0x21dac68       \WINDOWS\Installer\{20C31435-2A0A-4580-BE8B-AC06FC243CA4}\python_icon.exe       112
0x21dad60       \WINDOWS\Help   112
0x21dadf8       \Program Files\Common Files\Microsoft Shared\web server extensions\40\_vti_bin\_vti_adm 112
0x21db7b0       \WINDOWS\system32       112
0x21dc028       \Intel\ivecuqmanpnirkt615\taskdl.exe    112
0x21dc3a8       \Documents and Settings\All Users\Start Menu\Programs\Accessories\System Tools\Character Map.lnk        112
0x21dc440       \Documents and Settings\donny\Start Menu\Programs\Accessories\Notepad.lnk       112
0x21dc578       \Documents and Settings\All Users\Start Menu\Programs\Administrative Tools\Local Security Policy.lnk    112
0x21dc940       \WINDOWS\system32\rcimlby.exe   112
0x21dc9d8       \WINDOWS\explorer.exe   112
0x21dcb68       \Endpoint       112
0x21dce00       \Documents and Settings\donny\Start Menu\Programs\Accessories\Program Compatibility Wizard.lnk  112
0x21dcf90       \Documents and Settings\NetworkService\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat   112
0x21dd238       \WINDOWS\system32\davclnt.dll   112
0x21dd440       \WINDOWS\system32\mfc42.dll     112
0x21dd4d8       \Documents and Settings\All Users\Start Menu\Programs\desktop.ini       112
0x21dd6a8       \protected_storage      112
0x21ddb80       \WINDOWS\system32\wucltui.dll.mui       112
0x21ddf90       \WINDOWS\system32\taskkill.exe  112
0x21de828       \WINDOWS\Fonts\arialbd.ttf      112
0x21df420       \Documents and Settings\donny\Start Menu\Programs\Remote Assistance.lnk 112
0x21e0988       \WINDOWS\system32\attrib.exe    112
0x21e0c20       \$Directory     112
0x21e0d98       \Documents and Settings\All Users\Start Menu\Programs\Accessories\Accessibility\Accessibility Wizard.lnk        112
0x21e16b0       \Endpoint       112
0x21e1748       \Documents and Settings\All Users\Start Menu\Programs\Python 2.7\Python Manuals.lnk     112
0x21e2760       \Documents and Settings\All Users\Start Menu\Programs\Games\Internet Checkers.lnk       112
0x21e28f8       \WINDOWS\system32\fldrclnr.dll  112
0x21e2ad8       \WINDOWS\system32\wbem\Repository\FS\INDEX.BTR  112
0x21e2b70       \WINDOWS\system32\wbem\Repository\FS\OBJECTS.MAP        112
0x21e5098       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x21e5418       \WINDOWS\system32\rundll32.exe  112
0x21e55c0       \Winsock2\CatalogChangeListener-400-0   112
0x21e5be8       \WINDOWS\system32\oembios.bin   112
0x21e5d20       \$Extend\$ObjId 112
0x21e7038       \$Directory     112
0x21e72e0       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x21e7418       \Endpoint       112
0x21e75a8       \Documents and Settings\LocalService\Local Settings\desktop.ini 112
0x21e7c68       \spoolss        112
0x21e7df8       \WINDOWS\system32\config\SysEvent.Evt   112
0x21e8740       \WINDOWS\system32\config\SecEvent.Evt   112
0x21e88b0       \Documents and Settings\All Users\Start Menu\Programs\Accessories\System Tools\System Information.lnk   112
0x21e8980       \Program Files\MSN Gaming Zone\Windows\hrtzzm.exe       112
0x21e8b38       \WINDOWS\WinSxS 112
0x21e8f28       \Program Files\Common Files\System\msadc        112
0x21e9c28       \Endpoint       112
0x21eaf90       \WINDOWS\system32\els.dll       112
0x21eb250       \WINDOWS\WinSxS\Policies\x86_policy.5.2.Microsoft.Windows.Networking.Rtcdll_6595b64144ccf1df_x-ww_c7b7206f\5.2.2.3.Policy       112
0x21eb2e8       \WINDOWS\WinSxS\Policies\x86_policy.5.2.Microsoft.Windows.Networking.Dxmrtp_6595b64144ccf1df_x-ww_362e60dd\5.2.2.3.Policy       112
0x21eb420       \Program Files\Common Files\Microsoft Shared\MSInfo\msinfo32.exe        112
0x21ec748       \wkssvc 112
0x21ec970       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x21ed748       \wkssvc 112
0x21ed810       \WINDOWS\WinSxS\Manifests\x86_Microsoft.Windows.Networking.Dxmrtp_6595b64144ccf1df_5.2.2.3_x-ww_468466a7.Manifest       112
0x21ed9e0       \WINDOWS\WinSxS\Manifests\x86_Microsoft.Windows.GdiPlus_6595b64144ccf1df_1.0.6002.23084_x-ww_f3f35550.Manifest  112
0x21ee698       \WINDOWS\system32\freecell.exe  112
0x21eeaf0       \WINDOWS\system32\drprov.dll    112
0x21eef90       \ntsvcs 112
0x21ef980       \WINDOWS\system32\netshell.dll  112
0x21efc80       \protected_storage      112
0x21f02b8       \$Directory     112
0x21f0b70       \$Directory     112
0x21f1418       \Documents and Settings\All Users\Start Menu\Programs\Accessories\System Tools\Files and Settings Transfer Wizard.lnk   112
0x21f1700       \Program Files\Common Files\Microsoft Shared\web server extensions\40\isapi\_vti_aut    112
0x21f18d8       \WINDOWS\system32\msiexec.exe   112
0x21f1c88       \Documents and Settings\donny\Start Menu\Programs\Outlook Express.lnk   112
0x21f1f90       \WINDOWS\SoftwareDistribution\DataStore\DataStore.edb   112
0x21f2368       \Documents and Settings\LocalService\Local Settings\Temporary Internet Files\Content.IE5\index.dat      112
0x21f2400       \Documents and Settings\donny\My Documents\desktop.ini  112
0x21f2910       \$Directory     112
0x21f2b70       \$Directory     112
0x21f3870       \Intel\ivecuqmanpnirkt615\tasksche.exe  112
0x21f3d00       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x21f3d98       \Documents and Settings\donny\Start Menu\Programs\Accessories\Entertainment\Windows Media Player.lnk    112
0x21f4f90       \Documents and Settings\donny\Start Menu        112
0x220ea70       \System Volume Information\tracking.log 112
0x220ec40       \Intel\ivecuqmanpnirkt615\msg\m_turkish.wnry    112
0x220feb8       \WINDOWS\system32\MSCTF.dll     112
0x2210278       \WINDOWS\system32\config\software.LOG   112
0x22109d0       \WINDOWS\AppPatch       112
0x2210df0       \$Directory     112
0x2211028       \Documents and Settings\All Users\Start Menu\Programs\Accessories\Communications\Network Connections.lnk        112
0x22118f8       \WINDOWS\system32\msnsspc.dll   112
0x2211d20       \WINDOWS\system32\winipsec.dll  112
0x2211f90       \Documents and Settings\All Users\Start Menu\Programs\Accessories\System Tools\System Restore.lnk       112
0x2212028       \Intel\ivecuqmanpnirkt615\msg\m_russian.wnry    112
0x2212668       \WINDOWS\system32\oakley.dll    112
0x2212a90       \WINDOWS\system32\ipsecsvc.dll  112
0x2212eb8       \WINDOWS\system32\srvsvc.dll    112
0x22133b8       \WINDOWS\system32\dhcpcsvc.dll  112
0x2213c28       \WINDOWS\system32\digest.dll    112
0x22148f8       \WINDOWS\system32\credssp.dll   112
0x22159a0       \WINDOWS\WinSxS\Policies\x86_policy.1.0.Microsoft.Windows.GdiPlus_6595b64144ccf1df_x-ww_4e8510ac\1.0.6002.23084.Policy  112
0x2215c28       \WINDOWS\system32\netlogon.dll  112
0x2216028       \Documents and Settings\All Users\Start Menu\Programs\Accessories\System Tools\desktop.ini      112
0x2216510       \WINDOWS\system32\pstorsvc.dll  112
0x22168f8       \WINDOWS\system32\wdigest.dll   112
0x2216f28       \WINDOWS\system32\msxml3r.dll   112
0x2217200       \WINDOWS\system32\wbem  112
0x2217528       \Intel\ivecuqmanpnirkt615\msg\m_spanish.wnry    112
0x2217668       \WINDOWS\system32\netmsg.dll    112
0x2217a90       \WINDOWS\system32\iphlpapi.dll  112
0x2217cd0       \WINDOWS\system32\rasmans.dll   112
0x2217f90       \WINDOWS\pchealth\helpctr\binaries\pchsvc.dll   112
0x2218320       \Documents and Settings\All Users\Start Menu\Programs\Accessories\Entertainment\Volume Control.lnk      112
0x22184b0       \WINDOWS\system32\netman.dll    112
0x2218800       \WINDOWS\system32\winspool.drv  112
0x2218c28       \WINDOWS\system32\schannel.dll  112
0x22193f0       \$Directory     112
0x22195a8       \WINDOWS\system32\dmserver.dll  112
0x22199d0       \WINDOWS\system32\certcli.dll   112
0x2219b30       \Intel\ivecuqmanpnirkt615\msg\m_slovak.wnry     112
0x2219df8       \WINDOWS\system32\themeui.dll   112
0x221aa90       \WINDOWS\system32\msapsspc.dll  112
0x221aeb8       \WINDOWS\system32\lmhsvc.dll    112
0x221b3d8       \WINDOWS\system32\uxtheme.dll   112
0x221b800       \WINDOWS\system32\msacm32.dll   112
0x221bc28       \WINDOWS\system32\winmm.dll     112
0x221ceb8       \WINDOWS\system32\msvcrt40.dll  112
0x221d3d8       \WINDOWS\system32\w32time.dll   112
0x221dad8       \Documents and Settings\All Users\Start Menu\Programs\Games\Freecell.lnk        112
0x221dd00       \WINDOWS\system32\es.dll        112
0x221e4b0       \WINDOWS\system32\scesrv.dll    112
0x221ed20       \WINDOWS\system32\kerberos.dll  112
0x221f668       \WINDOWS\AppPatch\AcGenral.dll  112
0x221fb90       \Documents and Settings\All Users\Start Menu\Programs\Games\Internet Hearts.lnk 112
0x221fd20       \WINDOWS\system32\dnsrslvr.dll  112
0x2220668       \WINDOWS\system32\shgina.dll    112
0x2220a90       \WINDOWS\system32\comres.dll    112
0x2220e98       \WINDOWS\system32\umpnpmgr.dll  112
0x22213d8       \WINDOWS\system32\cryptdll.dll  112
0x2221800       \WINDOWS\system32\samsrv.dll    112
0x2221c28       \WINDOWS\system32\samlib.dll    112
0x2222028       \WINDOWS\ime\imkr6_1\dicts      112
0x22239d0       \WINDOWS\system32\rasapi32.dll  112
0x2223df8       \WINDOWS\system32\adsldpc.dll   112
0x22243b8       \WINDOWS\system32\activeds.dll  112
0x2225128       \WINDOWS\system32\crypt32.dll   112
0x22259d0       \WINDOWS\system32\mprapi.dll    112
0x2225df8       \WINDOWS\system32\cryptui.dll   112
0x2226740       \WINDOWS\system32\rastls.dll    112
0x2226ab0       \WINDOWS\system32\drivers\fips.sys      112
0x2226eb8       \WINDOWS\system32\userinit.exe  112
0x2227128       \WINDOWS\system32\msasn1.dll    112
0x2227d20       \WINDOWS\system32\powrprof.dll  112
0x2228668       \WINDOWS\system32\cscui.dll     112
0x2228eb8       \WINDOWS\system32\atl.dll       112
0x2229158       \WINDOWS\system 112
0x2229320       \WINDOWS\system32\ctfmon.exe    112
0x22293d8       \WINDOWS\system32\logonui.exe   112
0x2229748       \Intel\ivecuqmanpnirkt615\msg\m_vietnamese.wnry 112
0x22298d8       \WINDOWS\system32\eappcfg.dll   112
0x2229c28       \WINDOWS\system32\tspkg.dll     112
0x222a028       \Endpoint       112
0x222a4d0       \WINDOWS\system32\mswsock.dll   112
0x222a8f8       \WINDOWS\system32\rtutils.dll   112
0x222ad20       \WINDOWS\system32\wlnotify.dll  112
0x222b220       \WINDOWS\system32\dimsntfy.dll  112
0x222b648       \WINDOWS\system32\cscdll.dll    112
0x222ba90       \WINDOWS\system32\oleacc.dll    112
0x222bc68       \WINDOWS\system32\ega.cpi       112
0x222beb8       \WINDOWS\system32\msimg32.dll   112
0x222c320       \Documents and Settings\All Users\Start Menu\Programs\Accessories\System Tools\Backup.lnk       112
0x222c3d8       \WINDOWS\system32\rasadhlp.dll  112
0x222c800       \WINDOWS\system32\winrnr.dll    112
0x222d028       \WINDOWS\system32\muweb.dll     112
0x222d4b0       \WINDOWS\system32\clbcatq.dll   112
0x222d8f8       \WINDOWS\system32\wzcsvc.dll    112
0x222dd20       \WINDOWS\system32\eventlog.dll  112
0x222e340       \WINDOWS\system32\dbghelp.dll   112
0x222e800       \WINDOWS\system32\dnsapi.dll    112
0x222ec08       \WINDOWS\system32\wshtcpip.dll  112
0x222f028       \Documents and Settings\All Users\Start Menu\Programs\Games\desktop.ini 112
0x222f4b0       \WINDOWS\system32\dot3api.dll   112
0x222f8d8       \WINDOWS\system32\hnetcfg.dll   112
0x222fc10       \Documents and Settings\LocalService\Local Settings\History\History.IE5\index.dat       112
0x2230668       \WINDOWS\system32\wmi.dll       112
0x2230ab0       \WINDOWS\system32\eapolqec.dll  112
0x2230eb8       \WINDOWS\system32\qutil.dll     112
0x2231158       \WINDOWS\msagent        112
0x22313d8       \WINDOWS\system32\esent.dll     112
0x22316b0       \System Volume Information\_restore{915C6505-6DED-4903-B727-F8B5C05262FF}\drivetable.txt        112
0x2231800       \WINDOWS\system32\xpsp2res.dll  112
0x2231c28       \WINDOWS\system32\rpcss.dll     112
0x2232418       \Intel\ivecuqmanpnirkt615\msg\m_swedish.wnry    112
0x22324d0       \WINDOWS\system32\ntmarta.dll   112
0x22328f8       \WINDOWS\system32\svchost.exe   112
0x2232d20       \WINDOWS\system32\scecli.dll    112
0x2232f28       \Documents and Settings\All Users\Start Menu\Programs\Administrative Tools\Computer Management.lnk      112
0x2233240       \WINDOWS\system32\wtsapi32.dll  112
0x2233518       \WINDOWS\system32\wbem\Repository\$WinMgmt.CFG  112
0x2233668       \WINDOWS\system32\winscard.dll  112
0x2233d20       \WINDOWS\system32\ntdsapi.dll   112
0x2233f18       \Intel\ivecuqmanpnirkt615       112
0x2234028       \WINDOWS\system32\drprov.dll    112
0x22345c0       \WINDOWS\system32\attrib.exe    112
0x2234688       \Documents and Settings\All Users\Start Menu\Programs\Games\Spider Solitaire.lnk        112
0x2234808       \WINDOWS\system32\rundll32.exe  112
0x2234b68       \WINDOWS\system32\cryptsvc.dll  112
0x2234f90       \WINDOWS\system32\webclnt.dll   112
0x22354b0       \WINDOWS\system32\midimap.dll   112
0x22358d8       \WINDOWS\system32\msacm32.drv   112
0x2235e00       \Documents and Settings\donny\Local Settings\Temp\24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c.bin  112
0x2235f90       \WINDOWS\system32\wdmaud.drv    112
0x2236320       \Documents and Settings\All Users\Start Menu\Programs\Accessories\Internet Browser Choice.lnk   112
0x22364b0       \WINDOWS\system32\wkssvc.dll    112
0x22368d8       \WINDOWS\system32\audiosrv.dll  112
0x2236d78       \WINDOWS\Prefetch\TASKSE.EXE-02A1B304.pf        112
0x2236f90       \WINDOWS\system32\spoolsv.exe   112
0x2237158       \WINDOWS\msagent\intl   112
0x2237320       \WINDOWS\system32\shell32.dll   112
0x22374b0       \WINDOWS\system32\msidle.dll    112
0x22378d8       \WINDOWS\system32\schedsvc.dll  112
0x2238028       \Documents and Settings\donny\NetHood   112
0x2238758       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x22389d0       \WINDOWS\system32\wbem\wmisvc.dll       112
0x2238df8       \$Directory     112
0x2238ef8       \Documents and Settings\All Users\Start Menu\Programs\Accessories\WordPad.lnk   112
0x2238f90       \Documents and Settings\All Users\Start Menu\Programs\Accessories\Remote Desktop Connection.lnk 112
0x2239028       \WINDOWS\system32\ulib.dll      112
0x2239668       \WINDOWS\system32\msv1_0.dll    112
0x2239f90       \WINDOWS\system32\desk.cpl      112
0x223a320       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x223a4b0       \WINDOWS\system32\shdocvw.dll   112
0x223a8d8       \WINDOWS\system32\wzcsapi.dll   112
0x223ab70       \WINDOWS\system32\rasmans.dll   112
0x223ad00       \WINDOWS\system32\eappprxy.dll  112
0x223b028       \System Volume Information\_restore{915C6505-6DED-4903-B727-F8B5C05262FF}\RP3\rp.log    112
0x223b320       \Documents and Settings\donny\Start Menu\Programs\Accessories\System Tools\Internet Explorer (No Add-ons).lnk   112
0x223b4d0       \WINDOWS\system32\dpcdll.dll    112
0x223b9d0       \WINDOWS\system32\vssapi.dll    112
0x223bad0       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x223bdf8       \WINDOWS\system32\netshell.dll  112
0x223c478       \Documents and Settings\All Users\Start Menu\Programs\Accessories\Communications\Network Setup Wizard.lnk       112
0x223c518       \WINDOWS\system32\comres.dll    112
0x223c5b0       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x223c740       \WINDOWS\system32\tapi32.dll    112
0x223c8a0       \Documents and Settings\All Users\Start Menu\Programs\Accessories\Communications\HyperTerminal.lnk      112
0x223cb68       \WINDOWS\system32\rasman.dll    112
0x223cf90       \WINDOWS\system32\termsrv.dll   112
0x223d8d8       \WINDOWS\system32\wbem\ncprov.dll       112
0x223dd00       \WINDOWS\system32\wuapi.dll     112
0x223e028       \Documents and Settings\donny\Start Menu\Programs\Accessories\Accessibility\On-Screen Keyboard.lnk      112
0x223e3e8       \$Directory     112
0x223e5a8       \WINDOWS\system32\onex.dll      112
0x223e9d0       \WINDOWS\system32\dot3dlg.dll   112
0x223edf8       \WINDOWS\system32\credui.dll    112
0x223fb68       \WINDOWS\explorer.exe   112
0x223ff90       \WINDOWS\system32\raschap.dll   112
0x22404b0       \WINDOWS\system32\riched20.dll  112
0x2240800       \WINDOWS\system32\dssenh.dll    112
0x2240c08       \WINDOWS\system32\wuauclt.exe   112
0x2240f90       \$Directory     112
0x22415a8       \WINDOWS\system32\browseui.dll  112
0x2241708       \DAV RPC SERVICE        112
0x2241d00       \WINDOWS\system32\wbem\wbemprox.dll     112
0x2242240       \WINDOWS\system32\msi.dll       112
0x2242478       \Documents and Settings\donny\Start Menu\Programs\Accessories\Windows Explorer.lnk      112
0x2242648       \WINDOWS\system32\colbact.dll   112
0x22428a0       \Documents and Settings\All Users\Start Menu\Programs\Accessories\Paint.lnk     112
0x2242a90       \WINDOWS\system32\comsvcs.dll   112
0x2242c10       \Documents and Settings\All Users\Start Menu\Programs\7-Zip\7-Zip Help.lnk      112
0x2242d40       \Documents and Settings\All Users\Start Menu\Programs\Accessories\System Tools\Disk Defragmenter.lnk    112
0x2242dd8       \Documents and Settings\donny\Start Menu\desktop.ini    112
0x2242eb8       \WINDOWS\system32\wbem\wbemcons.dll     112
0x2243320       \WINDOWS\system32\sysmon.ocx    112
0x22434b0       \WINDOWS\system32\msutb.dll     112
0x2243d00       \WINDOWS\system32\actxprxy.dll  112
0x2244648       \WINDOWS\system32\icaapi.dll    112
0x2244a70       \WINDOWS\system32\mstlsapi.dll  112
0x2244bd8       \Endpoint       112
0x22453d8       \WINDOWS\system32\tcpmon.dll    112
0x22456e0       \Intel\ivecuqmanpnirkt615       112
0x2245800       \WINDOWS\system32\wbem\repdrvfs.dll     112
0x2245d00       \$Directory     112
0x2246028       \Documents and Settings\All Users\Start Menu\Programs\Accessories\Entertainment\Sound Recorder.lnk      112
0x22464b0       \WINDOWS\system32\wbem\wmiutils.dll     112
0x22468f8       \WINDOWS\system32\wbem\wbemsvc.dll      112
0x2246a88       \Documents and Settings\All Users\Start Menu\Set Program Access and Defaults.lnk        112
0x2246c68       \$Directory     112
0x2246d20       \WINDOWS\system32\winhttp.dll   112
0x2246f90       \trkwks 112
0x22473f0       \Documents and Settings\donny\Start Menu\Programs\Windows Media Player.lnk      112
0x2247488       \WINDOWS\system32       112
0x22475c0       \Program Files\Internet Explorer\IEXPLORE.EXE   112
0x2247840       \WINDOWS\system32\sndvol32.exe  112
0x2247a90       \WINDOWS\system32\wuaueng.dll   112
0x2247ca0       \Documents and Settings\All Users\Start Menu\Programs\Games\Internet Backgammon.lnk     112
0x2247e70       \WINDOWS\system32\wbem\Repository\FS\INDEX.MAP  112
0x2247f08       \WINDOWS\system32\wbem\Repository\FS\MAPPING.VER        112
0x2248028       \WINDOWS\Media\Windows XP Startup.wav   112
0x2248b08       \WINDOWS\system32\wbem\Repository\FS\MAPPING2.MAP       112
0x2248ef8       \W32TIME        112
0x2248f90       \W32TIME        112
0x22490c0       \WINDOWS\system32\mshearts.exe  112
0x2249a90       \WINDOWS\system32\wuauserv.dll  112
0x2249eb8       \WINDOWS\system32\wbem\fastprox.dll     112
0x224a938       \WINDOWS\system32\c_1250.nls    112
0x224b4d0       \WINDOWS\system32\cnbjmon.dll   112
0x224b8f8       \WINDOWS\system32\spoolss.dll   112
0x224bd00       \WINDOWS\system32\ssdpapi.dll   112
0x224c028       \Documents and Settings\All Users\Start Menu\Programs\Python 2.7\Python (command line).lnk      112
0x224c740       \WINDOWS\system32\browser.dll   112
0x224ce98       \WINDOWS\system32\wups2.dll     112
0x224d320       \WINDOWS\system32\wsecedit.dll  112
0x224d3d8       \WINDOWS\system32\wups.dll      112
0x224d800       \WINDOWS\system32\wbem\wbemess.dll      112
0x224db70       \PIPE_EVENTROOT\CIMV2SCM EVENT PROVIDER 112
0x224dc28       \WINDOWS\system32\wbem\wmiprvsd.dll     112
0x224e4d0       \WINDOWS\system32\mspatcha.dll  112
0x224e708       \$Directory     112
0x224e8f8       \WINDOWS\system32\cabinet.dll   112
0x224ea80       \Documents and Settings\All Users\Start Menu\Programs\Games\Hearts.lnk  112
0x224eb18       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x224ed40       \WINDOWS\ime\SPTIP.dll  112
0x224f240       \WINDOWS\system32\sens.dll      112
0x224f418       \Documents and Settings\All Users\Start Menu\Programs\Accessories\Calculator.lnk        112
0x224f668       \WINDOWS\system32\trkwks.dll    112
0x224fa90       \WINDOWS\system32\srsvc.dll     112
0x224fca8       \WINDOWS\system32\tapisrv.dll   112
0x224fd68       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x224fe00       \WINDOWS\system32\ntlanman.dll  112
0x224feb8       \WINDOWS\system32\seclogon.dll  112
0x22503d8       \WINDOWS\system32\psbase.dll    112
0x22505b0       \WINDOWS\system32\cleanmgr.exe  112
0x2250820       \WINDOWS\system32\wscntfy.exe   112
0x2250c28       \WINDOWS\system32\ctfmon.exe    112
0x22512c0       \Documents and Settings\All Users\Start Menu\Programs\Accessories\System Tools\Scheduled Tasks.lnk      112
0x2251840       \Documents and Settings\donny   112
0x22518d8       \WINDOWS\system32\upnp.dll      112
0x2251d40       \WINDOWS\system32\alg.exe       112
0x2251f28       \WINDOWS\system32\winmine.exe   112
0x22524d0       \WINDOWS\system32\verclsid.exe  112
0x22528f8       \WINDOWS\system32\resutils.dll  112
0x2252d20       \WINDOWS\system32\clusapi.dll   112
0x2253240       \WINDOWS\system32\wbem\wbemcomn.dll     112
0x22535b0       \WINDOWS\system32\msxml3.dll    112
0x2253668       \WINDOWS\system32\wbem\esscli.dll       112
0x2254028       \WINDOWS\WindowsUpdate.log      112
0x22552f0       \WINDOWS\system32\wbem\Repository\FS\MAPPING1.MAP       112
0x2255a60       \Documents and Settings\All Users\Start Menu    112
0x22562d8       \Program Files\MSN Gaming Zone\Windows\Rvsezm.exe       112
0x2256700       \Documents and Settings\All Users\Start Menu\Programs\Python 2.7\IDLE (Python GUI).lnk  112
0x2256c88       \Intel\ivecuqmanpnirkt615\t.wnry        112
0x2257b30       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x2257f90       \net\NtControlPipe8     112
0x22586a0       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x2258930       \WINDOWS\system32\ersvc.dll     112
0x2258a68       \Documents and Settings\All Users\Start Menu\Programs\Accessories\Entertainment\desktop.ini     112
0x2258b88       \WINDOWS\system32\wscsvc.dll    112
0x2258eb8       \WINDOWS\system32\regsvc.dll    112
0x2259408       \Program Files\MSN Gaming Zone\Windows\chkrzm.exe       112
0x2259600       \WINDOWS\system32\ipnathlp.dll  112
0x2259858       \WINDOWS\system32\localspl.dll  112
0x2259b88       \WINDOWS\system32\ssdpsrv.dll   112
0x2259d60       \Program Files\Windows Media Player\wmplayer.exe        112
0x225a858       \WINDOWS\system32\rsaenh.dll    112
0x225aba8       \WINDOWS\system32\netcfgx.dll   112
0x225b390       \WINDOWS\system32\wsock32.dll   112
0x225b6c0       \WINDOWS\system32\mtxclu.dll    112
0x225b9f0       \WINDOWS\system32\wbem\wbemcore.dll     112
0x225bba0       \Python27\DLLs\py.ico   112
0x225ee10       \Documents and Settings\donny\NTUSER.DAT        112
0x225ef90       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x225f548       \WINDOWS\system32\wpa.dbl       112
0x225fb50       \WINDOWS\system32\cfgmgr32.dll  112
0x2262900       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x2264808       \Program Files\NetMeeting       112
0x22648a0       \WINDOWS\pchealth\helpctr\binaries      112
0x2265a40       \WINDOWS\system32\batmeter.dll  112
0x2277d10       \WINDOWS\system32\hid.dll       112
0x22783f0       \WINDOWS\system.ini     112
0x227b780       \WINDOWS\system32\wucltui.dll   112
0x227e338       \WINDOWS\system32\pjlmon.dll    112
0x227f950       \Documents and Settings\All Users\Start Menu\Programs\Accessories\Accessibility\desktop.ini     112
0x227fb28       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x2280478       \Documents and Settings\All Users\Start Menu\Programs\Administrative Tools\Services.lnk 112
0x2280810       \WINDOWS\system32\moricons.dll  112
0x2280b60       \Documents and Settings\donny\Start Menu\Programs\Accessories\Accessibility\Utility Manager.lnk 112
0x2282728       \Documents and Settings\NetworkService\Local Settings\desktop.ini       112
0x2282ae8       \WINDOWS\system32\rasdlg.dll    112
0x2282f90       \net\NtControlPipe11    112
0x2284448       \net\NtControlPipe0     112
0x2285518       \net\NtControlPipe1     112
0x2285eb8       \WINDOWS\system32\msprivs.dll   112
0x22862a0       \WINDOWS\system32\webcheck.dll  112
0x2286460       \WINDOWS\system32\usbmon.dll    112
0x2286cc0       \WINDOWS\system32\inetpp.dll    112
0x2288980       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x228af90       \WINDOWS\system32\vga.dll       112
0x228f988       \WINDOWS\system32\authz.dll     112
0x228faf0       \WINDOWS\system32\winlogon.exe  112
0x228fbe0       \WINDOWS\system32\vga64k.dll    112
0x228fcd8       \WINDOWS\system32\vga256.dll    112
0x228fde8       \$Directory     112
0x2291f38       \WINDOWS\system32\framebuf.dll  112
0x2292c40       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x229a308       \WINDOWS\system32       112
0x229ba88       \WINDOWS\system32\nddeapi.dll   112
0x229e338       \$Directory     112
0x229ec48       \WINDOWS\system32\winsta.dll    112
0x229ed70       \WINDOWS\system32\setupapi.dll  112
0x229f028       \WINDOWS\system32\sfc.dll       112
0x229f198       \WINDOWS\system32\regapi.dll    112
0x229f270       \WINDOWS\system32\psapi.dll     112
0x229fa60       \WINDOWS\system32\netapi32.dll  112
0x229ff90       \WINDOWS\system32\profmap.dll   112
0x22a0f90       \WINDOWS\system32\msgina.dll    112
0x22a1028       \WINDOWS\system32\lsass.exe     112
0x22a1110       \WINDOWS\system32\MSCTFIME.IME  112
0x22a1238       \Winsock2\CatalogChangeListener-388-0   112
0x22a1620       \WINDOWS\system32\kbdus.dll     112
0x22a1740       \WINDOWS\system32\imm32.dll     112
0x22a1850       \WINDOWS\system32\ws2help.dll   112
0x22a32e8       \WINDOWS\system32\ws2_32.dll    112
0x22a3830       \WINDOWS\system32\wintrust.dll  112
0x22a4110       \WINDOWS\system32\services.exe  112
0x22a50e0       \$Directory     112
0x22a6d20       \Documents and Settings\All Users\Start Menu\Programs\Python 2.7\Module Docs.lnk        112
0x22a6f28       \Documents and Settings\donny\Start Menu\Programs\Accessories\Synchronize.lnk   112
0x22a7148       \WINDOWS\system32\notepad.exe   112
0x22a7340       \WINDOWS\system32\linkinfo.dll  112
0x22a7568       \WINDOWS\Fonts\framd.ttf        112
0x22a7b98       \WINDOWS\system32\rasdlg.dll    112
0x22a7e60       \WINDOWS\system32\inetpp.dll    112
0x22a8088       \WINDOWS\system32\netrap.dll    112
0x22a82a8       \WINDOWS\system32\win32spl.dll  112
0x22a84d8       \WINDOWS\system32\batmeter.dll  112
0x22a86f8       \WINDOWS\system32\stobject.dll  112
0x22a8960       \WINDOWS\system32\mlang.dll     112
0x22a8bb8       \WINDOWS\system32\webcheck.dll  112
0x22a8f28       \WINDOWS\Media\Windows XP Balloon.wav   112
0x22a9150       \WINDOWS\system32\usbmon.dll    112
0x22a9368       \WINDOWS\system32\tcpmon.dll    112
0x22a9590       \WINDOWS\system32\pjlmon.dll    112
0x22a9760       \WINDOWS\system32\cnbjmon.dll   112
0x22a9930       \WINDOWS\system32\localspl.dll  112
0x22a9be8       \WINDOWS\system32\spoolss.dll   112
0x22a9e48       \WINDOWS\system32\ssdpsrv.dll   112
0x22aa350       \WINDOWS\system32\drivers\disdn 112
0x22aa4e0       \WINDOWS\system32\ssdpapi.dll   112
0x22aa728       \WINDOWS\system32\tapisrv.dll   112
0x22aab28       \$Directory     112
0x22aabc0       \WINDOWS\ime\SPTIP.dll  112
0x22aaeb0       \WINDOWS\system32\wscntfy.exe   112
0x22ab1e8       \Documents and Settings\All Users\Start Menu\Programs\Startup\desktop.ini       112
0x22ab418       \Documents and Settings\All Users\Start Menu\Programs\Accessories\System Tools\Security Center.lnk      112
0x22ab610       \Documents and Settings\All Users\Start Menu\Programs\Accessories\System Tools\Disk Cleanup.lnk 112
0x22abb70       \$Directory     112
0x22abe00       \WINDOWS\SoftwareDistribution\ReportingEvents.log       112
0x22ac060       \$Directory     112
0x22ac0f8       \WINDOWS\system32\en-US\ieframe.dll.mui 112
0x22ac450       \$Directory     112
0x22ac4e8       \Documents and Settings\All Users\Start Menu\Programs\Python 2.7\Uninstall Python.lnk   112
0x22ac6e0       \Documents and Settings\All Users\Documents\desktop.ini 112
0x22ac8d8       \WINDOWS\system32\netcfgx.dll   112
0x22acb00       \$Directory     112
0x22acc68       \WINDOWS\system32\alg.exe       112
0x22aceb8       \WINDOWS\system32\verclsid.exe  112
0x22ad258       \$Directory     112
0x22ad2f0       \WINDOWS\system32\calc.exe      112
0x22ad620       \$Directory     112
0x22ad6b8       \WINDOWS\system32\ntbackup.exe  112
0x22ad9e8       \$Directory     112
0x22ada80       \WINDOWS\system32\sndrec32.exe  112
0x22adc78       \Documents and Settings\donny\Recent\Desktop.ini        112
0x22ae028       \Documents and Settings\All Users\Start Menu\Programs\Administrative Tools\Performance.lnk      112
0x22ae218       \$Directory     112
0x22ae2b0       \WINDOWS\system32\shimgvw.dll   112
0x22ae5e0       \$Directory     112
0x22aea68       \Program Files\Outlook Express\wab.exe  112
0x22aed98       \$Directory     112
0x22aee30       \WINDOWS\WinSxS\x86_Microsoft.Windows.GdiPlus_6595b64144ccf1df_1.0.6002.23084_x-ww_f3f35550     112
0x22af208       \Documents and Settings\donny\My Documents\My Music\Desktop.ini 112
0x22af400       \WINDOWS\system32\compatUI.dll  112
0x22af5f8       \WINDOWS\system32\ntshrui.dll   112
0x22af978       \$Directory     112
0x22afa10       \WINDOWS\system32\utilman.exe   112
0x22afbe0       \WINDOWS\system32\taskkill.exe  112
0x22afdd8       \Documents and Settings\All Users\Start Menu\Programs\Windows Movie Maker.lnk   112
0x22aff90       \Documents and Settings\donny\Start Menu\Programs\Internet Explorer.lnk 112
0x22b02b0       \WINDOWS\system32\resutils.dll  112
0x22b04d8       \WINDOWS\system32\clusapi.dll   112
0x22b0700       \WINDOWS\system32\wsock32.dll   112
0x22b0920       \WINDOWS\system32\mtxclu.dll    112
0x22b0b50       \WINDOWS\system32\colbact.dll   112
0x22b0d78       \WINDOWS\system32\comsvcs.dll   112
0x22b1148       \$Directory     112
0x22b11e0       \WINDOWS\system32\ntlsapi.dll   112
0x22b1520       \WINDOWS\system32\lz32.dll      112
0x22b15b8       \WINDOWS\system32\wbem\wbemcons.dll     112
0x22b17b8       \WINDOWS\system32\msutb.dll     112
0x22b1af8       \WINDOWS\system32\actxprxy.dll  112
0x22b1cc8       \WINDOWS\system32\mstlsapi.dll  112
0x22b1e98       \WINDOWS\system32\icaapi.dll    112
0x22b2028       \WINDOWS\system32\wuauclt.exe   112
0x22b20e8       \WINDOWS\system32\termsrv.dll   112
0x22b2448       \WINDOWS\system32\wbem\ncprov.dll       112
0x22b2698       \WINDOWS\system32\wuapi.dll     112
0x22b2a18       \WINDOWS\system32\browser.dll   112
0x22b2c80       \WINDOWS\system32\dssenh.dll    112
0x22b3508       \WINDOWS\system32\wups2.dll     112
0x22b3750       \WINDOWS\system32\wups.dll      112
0x22b3b78       \WINDOWS\system32\wbem\wbemess.dll      112
0x22b3d00       \WINDOWS\system32\mui\040D      112
0x22b3dc0       \WINDOWS\system32\mui\040C      112
0x22b3f28       \WINDOWS\system32\wbem\wmiprvsd.dll     112
0x22b4810       \WINDOWS\system32\fldrclnr.dll  112
0x22b5028       \WINDOWS\system32\cabinet.dll   112
0x22b52a0       \$Directory     112
0x22b5338       \WINDOWS\system32\wbem\Repository\FS\OBJECTS.DATA       112
0x22b5530       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x22b5728       \WINDOWS\system32\wbem\repdrvfs.dll     112
0x22b5a50       \WINDOWS\system32\wbem\wmiutils.dll     112
0x22b5c20       \WINDOWS\system32\wbem\wbemsvc.dll      112
0x22b5e70       \WINDOWS\system32\mspatcha.dll  112
0x22b6028       \Endpoint       112
0x22b62d8       \WINDOWS\system32\winhttp.dll   112
0x22b65f0       \WINDOWS\system32\wuaueng.dll   112
0x22b6e70       \WINDOWS\system32\wuauserv.dll  112
0x22b7330       \WINDOWS\system32\wbem\fastprox.dll     112
0x22b77f8       \WINDOWS\system32\wbem\esscli.dll       112
0x22b7b38       \WINDOWS\system32\wbem\wbemcore.dll     112
0x22b7f90       \WINDOWS\system32\wbem\wbemcomn.dll     112
0x22b8028       \WINDOWS\system32\seclogon.dll  112
0x22b8280       \WINDOWS\system32\wbem\wbemprox.dll     112
0x22b84a8       \WINDOWS\system32\msi.dll       112
0x22b8740       \WINDOWS\system32\wscsvc.dll    112
0x22b8938       \WINDOWS\system32\trkwks.dll    112
0x22b8b88       \WINDOWS\system32\srsvc.dll     112
0x22b8e40       \WINDOWS\system32\sens.dll      112
0x22b9288       \WINDOWS\system32\regsvc.dll    112
0x22b94b0       \       112
0x22b9960       \WINDOWS\system32\psbase.dll    112
0x22b9b88       \WINDOWS\system32\pstorsvc.dll  112
0x22b9db0       \WINDOWS\system32\netmsg.dll    112
0x22b9f90       \WINDOWS\system32\winipsec.dll  112
0x22ba1f8       \WINDOWS\system32\oakley.dll    112
0x22ba450       \WINDOWS\system32\ipsecsvc.dll  112
0x22ba6a8       \WINDOWS\system32\srvsvc.dll    112
0x22baa88       \$Directory     112
0x22bab20       \WINDOWS\pchealth\helpctr\binaries\pchsvc.dll   112
0x22bad60       \WINDOWS\system32\ersvc.dll     112
0x22baf90       \WINDOWS\system32\dmserver.dll  112
0x22bb1d0       \WINDOWS\system32\certcli.dll   112
0x22bb400       \WINDOWS\system32\cryptsvc.dll  112
0x22bb7f8       \Intel\ivecuqmanpnirkt615\00000000.pky  112
0x22bb9c8       \Documents and Settings\LocalService\Local Settings\History\History.IE5\index.dat       112
0x22bbbd8       \Documents and Settings\LocalService\Cookies\index.dat  112
0x22bbde8       \Documents and Settings\LocalService\Local Settings\Temporary Internet Files\Content.IE5\index.dat      112
0x22bbf90       \WINDOWS\system32\webclnt.dll   112
0x22bc200       \net\NtControlPipe8     112
0x22bc310       \WINDOWS\system32\sfc_os.dll    112
0x22bc688       \$Directory     112
0x22bcc50       \WINDOWS\system32\midimap.dll   112
0x22bce70       \WINDOWS\system32\msacm32.drv   112
0x22bd0d0       \WINDOWS\system32\mstsc.exe     112
0x22bd2c8       \WINDOWS\system32\BrowserChoice.exe     112
0x22bd3d0       \WINDOWS\system32\odbc32.dll    112
0x22bd610       \WINDOWS\system32\mspaint.exe   112
0x22bd868       \Topology       112
0x22bdac8       \WINDOWS\system32\mydocs.dll    112
0x22bddd0       \{9B365890-165F-11D0-A195-0020AFD156E4} 112
0x22bdf90       \WINDOWS\system32\accwiz.exe    112
0x22be268       \{9B365890-165F-11D0-A195-0020AFD156E4} 112
0x22be500       \WINDOWS\system32\wdmaud.drv    112
0x22be730       \Documents and Settings\donny\Application Data\Microsoft\Protect\CREDHIST       112
0x22bea60       \$Directory     112
0x22beaf8       \Documents and Settings\donny\Application Data\Microsoft\Protect\S-1-5-21-602162358-764733703-1957994488-1003\f6ef8b17-2d2e-43f2-ad8d-55572ca41909    112
0x22becf0       \WINDOWS\system32\wkssvc.dll    112
0x22bee00       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202\comctl32.dll 112
0x22bef28       \WINDOWS\system32\audiosrv.dll  112
0x22bf038       \$Directory     112
0x22bf350       \WINDOWS\system32\spoolsv.exe   112
0x22bf598       \WINDOWS\system32\msidle.dll    112
0x22bf9a0       \WINDOWS\system32\schedsvc.dll  112
0x22c0110       \WINDOWS\system32\stdole2.tlb   112
0x22c02e0       \WINDOWS\system32\vssapi.dll    112
0x22c05e8       \WINDOWS\system32\wbem\wmisvc.dll       112
0x22c08d0       \WINDOWS\Fonts\framdit.ttf      112
0x22c0b00       \WINDOWS\system32\MSIMTF.dll    112
0x22c0cf8       \WINDOWS\system32\themeui.dll   112
0x22c1028       \WINDOWS\system32\eappcfg.dll   112
0x22c10d8       \WINDOWS\system32\desk.cpl      112
0x22c12a8       \WINDOWS\system32\shdocvw.dll   112
0x22c16f0       \WINDOWS\system32\browseui.dll  112
0x22c1808       \$Directory     112
0x22c1950       \WINDOWS\Resources\Themes\Luna\luna.msstyles    112
0x22c1bf0       \WINDOWS\system32\wzcsapi.dll   112
0x22c1e20       \WINDOWS\system32\eappprxy.dll  112
0x22c2028       \Documents and Settings\donny\Start Menu\Programs\Accessories\Accessibility\Narrator.lnk        112
0x22c22d8       \WINDOWS\system32\onex.dll      112
0x22c2508       \WINDOWS\system32\dot3dlg.dll   112
0x22c26d8       \WINDOWS\system32\credui.dll    112
0x22c2930       \Documents and Settings\All Users\Start Menu\Programs\Accessories\Communications\New Connection Wizard.lnk      112
0x22c2d60       \WINDOWS\system32\netman.dll    112
0x22c3028       \WINDOWS\system32\rasapi32.dll  112
0x22c34e0       \WINDOWS\system32\raschap.dll   112
0x22c3740       \WINDOWS\system32\riched20.dll  112
0x22c3968       \WINDOWS\Fonts\arialbi.ttf      112
0x22c3bc8       \WINDOWS\system32\tapi32.dll    112
0x22c3df8       \WINDOWS\system32\rasman.dll    112
0x22c4240       \WINDOWS\system32\adsldpc.dll   112
0x22c4480       \WINDOWS\system32\activeds.dll  112
0x22c46b8       \WINDOWS\system32\mprapi.dll    112
0x22c48e8       \WINDOWS\system32\cryptui.dll   112
0x22c4b30       \WINDOWS\system32\rastls.dll    112
0x22c4d98       \WINDOWS\system32\Microsoft\Protect\S-1-5-18\User\68fa1b6e-57a3-4316-98e3-8fa780aa107b  112
0x22c4f90       \WINDOWS\Fonts\arial.ttf        112
0x22c5290       \WINDOWS\system32\userinit.exe  112
0x22c54d0       \WINDOWS\system32\secupd.dat    112
0x22c56d0       \WINDOWS\system32\secupd.sig    112
0x22c58d0       \WINDOWS\system32\oembios.dat   112
0x22c5ad0       \WINDOWS\system32\oembios.sig   112
0x22c5cd0       \WINDOWS\system32\dpcdll.dll    112
0x22c5f90       \WINDOWS\system32\powrprof.dll  112
0x22c6c80       \WINDOWS\system32\cscui.dll     112
0x22c6f90       \$Directory     112
0x22c70e0       \WINDOWS\Web\Wallpaper\Bliss.bmp        112
0x22c72b0       \Intel\ivecuqmanpnirkt615\msg\m_english.wnry    112
0x22c74a8       \Documents and Settings\donny\Local Settings\desktop.ini        112
0x22c75b8       \WINDOWS\system32\shsvcs.dll    112
0x22c7720       \Documents and Settings\All Users\Start Menu\Windows Catalog.lnk        112
0x22c7e18       \WINDOWS\system32\shgina.dll    112
0x22c8190       \$Directory     112
0x22c8228       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x22c8448       \Documents and Settings\All Users\Start Menu\Programs\Administrative Tools\Data Sources (ODBC).lnk      112
0x22c8668       \WINDOWS\system32\clbcatq.dll   112
0x22c8960       \WINDOWS\system32\esent.dll     112
0x22c8ab8       \Documents and Settings\donny\NTUSER.DAT.LOG    112
0x22c8e58       \WINDOWS\system32\dot3api.dll   112
0x22c90b8       \WINDOWS\system32\qutil.dll     112
0x22c9318       \WINDOWS\system32\atl.dll       112
0x22c9558       \WINDOWS\system32\eapolqec.dll  112
0x22c9728       \WINDOWS\system32\wmi.dll       112
0x22c9930       \WINDOWS\system32\rtutils.dll   112
0x22c9b60       \WINDOWS\system32\wzcsvc.dll    112
0x22c9f28       \WINDOWS\system32\lmhsvc.dll    112
0x22ca028       \WINDOWS\system32\msimg32.dll   112
0x22ca188       \WINDOWS\system32\oleaccrc.dll  112
0x22ca578       \WINDOWS\system32\winspool.drv  112
0x22ca7c0       \WINDOWS\system32\wlnotify.dll  112
0x22ca990       \WINDOWS\system32\dimsntfy.dll  112
0x22cabb8       \WINDOWS\system32\cscdll.dll    112
0x22cadf0       \WINDOWS\system32\oleacc.dll    112
0x22cb5d8       \WINDOWS\system32\duser.dll     112
0x22cb968       \WINDOWS\system32\ntkrnlpa.exe  112
0x22cbb68       \WINDOWS\Fonts\micross.ttf      112
0x22cbe00       \WINDOWS\system32\logonui.exe.manifest  112
0x22cbf90       \WINDOWS\system32\logonui.exe   112
0x22ccad8       \WINDOWS\system32\shimgvw.dll   112
0x22cd120       \Documents and Settings\donny\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat    112
0x22cf208       \WINDOWS\system32\dnsrslvr.dll  112
0x22cf3d8       \net\NtControlPipe6     112
0x22cf5d0       \WINDOWS\system32\mui\0009      112
0x22cf6e0       \WINDOWS\system32\odbcint.dll   112
0x22cf848       \Documents and Settings\donny\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat.LOG        112
0x22cfbf8       \WINDOWS\system32\dhcpcsvc.dll  112
0x22cfec0       \WINDOWS\system32       112
0x22d0740       \$Directory     112
0x22d07d8       \Program Files\Common Files\System\ado  112
0x22d09d0       \WINDOWS\system32\rasadhlp.dll  112
0x22d0be0       \WINDOWS\system32\winrnr.dll    112
0x22d0e00       \WINDOWS\system32\wshtcpip.dll  112
0x22d1028       \WINDOWS\system32\config\SysEvent.Evt   112
0x22d10d8       \WINDOWS\system32\hnetcfg.dll   112
0x22d12a8       \WINDOWS\system32\mswsock.dll   112
0x22d1478       \WINDOWS\system32\ntoskrnl.exe  112
0x22d1678       \Program Files\MSN Gaming Zone\Windows  112
0x22d1870       \WINDOWS\inf    112
0x22d1a68       \Program Files\Common Files\System\Ole DB       112
0x22d1ce0       \net\NtControlPipe5     112
0x22d2120       \WINDOWS\system32\ncobjapi.dll  112
0x22d23a8       \WINDOWS\system32\config\SecEvent.Evt   112
0x22d25a0       \WINDOWS\system32\config\Internet.evt   112
0x22d28d0       \$Directory     112
0x22d2968       \WINDOWS\system32\config\AppEvent.Evt   112
0x22d2b78       \WINDOWS\system32\netevent.dll  112
0x22d2d80       \WINDOWS\system32\eventlog.dll  112
0x22d2f28       \Intel\ivecuqmanpnirkt615\tasksche.exe  112
0x22d3198       \WINDOWS\system32\rpcss.dll     112
0x22d3548       \WINDOWS\system32\ntmarta.dll   112
0x22d3780       \WINDOWS\system32\svchost.exe   112
0x22d39a0       \WINDOWS\system32\scecli.dll    112
0x22d3bd0       \WINDOWS\system32\wtsapi32.dll  112
0x22d3da0       \WINDOWS\system32\winscard.dll  112
0x22d3f90       \WINDOWS\system32\tspkg.dll     112
0x22d4240       \WINDOWS\system32\rsaenh.dll    112
0x22d4710       \WINDOWS\system32\wdigest.dll   112
0x22d48e0       \WINDOWS\system32\w32time.dll   112
0x22d4bd0       \WINDOWS\system32\netlogon.dll  112
0x22d4e00       \WINDOWS\system32\iphlpapi.dll  112
0x22d4f90       \WINDOWS\system32\msv1_0.dll    112
0x22d5598       \WINDOWS\system32\kerberos.dll  112
0x22d5850       \WINDOWS\system32\msprivs.dll   112
0x22d5a50       \WINDOWS\system32\WindowsLogon.manifest 112
0x22d5c48       \WINDOWS\system32\MSCTF.dll     112
0x22d61b0       \$Directory     112
0x22d6440       \WINDOWS\system32\msnsspc.dll   112
0x22d6610       \WINDOWS\system32\digest.dll    112
0x22d6878       \WINDOWS\system32\credssp.dll   112
0x22d6a48       \WINDOWS\system32\schannel.dll  112
0x22d6c18       \WINDOWS\system32\msvcrt40.dll  112
0x22d6de8       \WINDOWS\system32\msapsspc.dll  112
0x22d6f90       \WINDOWS\system32\uxtheme.dll   112
0x22d71c8       \WINDOWS\system32\msacm32.dll   112
0x22d7398       \WINDOWS\system32\winmm.dll     112
0x22d7568       \WINDOWS\AppPatch\AcGenral.dll  112
0x22d7840       \WINDOWS\system32\cryptdll.dll  112
0x22d7a78       \WINDOWS\system32\samsrv.dll    112
0x22d7d58       \WINDOWS\system32\samlib.dll    112
0x22d7f28       \WINDOWS\system32\dnsapi.dll    112
0x22d8388       \WINDOWS\system32\ntdsapi.dll   112
0x22d8558       \WINDOWS\AppPatch\AcAdProc.dll  112
0x22d8728       \WINDOWS\system32\shimeng.dll   112
0x22d88f8       \WINDOWS\system32\umpnpmgr.dll  112
0x22d8ac8       \WINDOWS\system32\scesrv.dll    112
0x22d8d18       \WINDOWS\system32\msvcp60.dll   112
0x22d8ec0       \WINDOWS\system32\ncobjapi.dll  112
0x22d9160       \WINDOWS\system32\lsasrv.dll    112
0x22d9330       \WINDOWS\system32\lsass.exe     112
0x22d9748       \WINDOWS\WinSxS\Policies\x86_policy.5.1.Microsoft.Windows.SystemCompatible_6595b64144ccf1df_x-ww_a0111510\5.1.2600.2000.Policy  112
0x22d9940       \WINDOWS\bootstat.dat   112
0x22d9b38       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x22d9e68       \$Directory     112
0x22da2c0       \$Directory     112
0x22da688       \$Directory     112
0x22da720       \WINDOWS\system32       112
0x22da918       \WINDOWS\system32       112
0x22dab10       \WINDOWS\system32\services.exe  112
0x22dace0       \WINDOWS\AppPatch\sysmain.sdb   112
0x22db618       \WINDOWS\system32\sfc_os.dll    112
0x22db7e8       \WINDOWS\system32\sfc.dll       112
0x22db9f8       \WINDOWS\system32\shsvcs.dll    112
0x22dbcf0       \WINDOWS\system32\odbcint.dll   112
0x22dbf00       \WINDOWS\WindowsShell.Manifest  112
0x22dc180       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202\comctl32.dll 112
0x22dc488       \$Directory     112
0x22dc520       \InitShutdown   112
0x22dc850       \$Directory     112
0x22dc8e8       \InitShutdown   112
0x22dcae0       \WINDOWS\system32\sxs.dll       112
0x22dcd50       \$Directory     112
0x22dceb8       \WINDOWS\system32\odbc32.dll    112
0x22dd168       \WINDOWS\system32\msgina.dll    112
0x22dd3b8       \WINDOWS\system32       112
0x22dd520       \WINDOWS\system32\MSCTFIME.IME  112
0x22dd6f0       \WINDOWS\Fonts\marlett.ttf      112
0x22dd8c0       \WINDOWS\Fonts\tahoma.ttf       112
0x22ddb88       \WINDOWS\Fonts\tahomabd.ttf     112
0x22ddd58       \WINDOWS\Fonts\trebucbd.ttf     112
0x22ddf28       \WINDOWS\Fonts\serife.fon       112
0x22de160       \WINDOWS\Fonts\sserife.fon      112
0x22de380       \WINDOWS\Fonts\coure.fon        112
0x22de588       \WINDOWS\Fonts\wst_swed.fon     112
0x22de788       \WINDOWS\Fonts\wst_span.fon     112
0x22de988       \WINDOWS\Fonts\wst_ital.fon     112
0x22deb88       \WINDOWS\Fonts\wst_germ.fon     112
0x22ded58       \WINDOWS\Fonts\wst_fren.fon     112
0x22def28       \WINDOWS\Fonts\wst_engl.fon     112
0x22df0e8       \WINDOWS\Fonts\wst_czec.fon     112
0x22df2b8       \WINDOWS\Fonts\symbole.fon      112
0x22df4d8       \WINDOWS\Fonts\smalle.fon       112
0x22df6a8       \WINDOWS\Fonts\modern.fon       112
0x22df878       \WINDOWS\Fonts\script.fon       112
0x22dfa80       \WINDOWS\Fonts\roman.fon        112
0x22dfc90       \WINDOWS\system32\kbdus.dll     112
0x22e0038       \$Directory     112
0x22e0278       \WINDOWS\system32\sortkey.nls   112
0x22e0488       \WINDOWS\system32\imm32.dll     112
0x22e0658       \WINDOWS\system32\ctype.nls     112
0x22e0828       \WINDOWS\system32\ws2help.dll   112
0x22e09f8       \WINDOWS\system32\ws2_32.dll    112
0x22e0c60       \WINDOWS\system32\wintrust.dll  112
0x22e0e30       \WINDOWS\system32\winsta.dll    112
0x22e1278       \WINDOWS\system32\setupapi.dll  112
0x22e1448       \WINDOWS\system32\regapi.dll    112
0x22e1680       \WINDOWS\system32\psapi.dll     112
0x22e1850       \WINDOWS\system32\netapi32.dll  112
0x22e1b60       \WINDOWS\system32\profmap.dll   112
0x22e1d30       \WINDOWS\system32\nddeapi.dll   112
0x22e1f00       \WINDOWS\system32\msasn1.dll    112
0x22e2118       \WINDOWS\system32\crypt32.dll   112
0x22e22e8       \WINDOWS\system32\authz.dll     112
0x22e2520       \WINDOWS\system32\winlogon.exe  112
0x22e2a80       \WINDOWS\Fonts\cga40woa.fon     112
0x22e2c78       \WINDOWS\Fonts\cga80woa.fon     112
0x22e2e70       \WINDOWS\Fonts\ega40woa.fon     112
0x22e39c8       \net\NtControlPipe7     112
0x22e3f90       \WINDOWS\system32\win32k.sys    112
0x22e4298       \WINDOWS\Fonts\ega80woa.fon     112
0x22e4490       \WINDOWS\Fonts\dosapp.fon       112
0x22e4858       \WINDOWS\system32\vga64k.dll    112
0x22e4a28       \WINDOWS\system32\vga256.dll    112
0x22e4bf8       \WINDOWS\system32\framebuf.dll  112
0x22e4e00       \WINDOWS\system32\vga.dll       112
0x22e4f90       \WINDOWS\Fonts\vgafix.fon       112
0x22e6560       \Documents and Settings\All Users\Start Menu\Programs\Games\Solitaire.lnk       112
0x22e67e8       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x22e7598       \WINDOWS\Fonts\vgaoem.fon       112
0x22e8208       \WINDOWS\system32\lz32.dll      112
0x22e89e8       \WINDOWS\system32\mycomput.dll  112
0x22e8e00       \Documents and Settings\All Users\Start Menu\Programs\Administrative Tools\desktop.ini  112
0x22e8f90       \WINDOWS\system32\netrap.dll    112
0x22e9228       \Documents and Settings\donny\Start Menu\Programs\Accessories\Entertainment\desktop.ini 112
0x22e92e0       \WINDOWS\system32\ntshrui.dll   112
0x22e94b8       \Documents and Settings\donny\Local Settings\Application Data\Microsoft\CD Burning      112
0x22ea158       \WINDOWS\system32\duser.dll     112
0x22ea310       \Documents and Settings\All Users\Start Menu\Programs\Games\Internet Spades.lnk 112
0x22eaa90       \WINDOWS\system32\linkinfo.dll  112
0x22eac68       \Documents and Settings\All Users\Desktop       112
0x22eaf90       \WINDOWS\system32\mstask.dll    112
0x22eb408       \browser        112
0x22eb4a8       \WINDOWS\Registration\R000000000007.clb 112
0x22eb660       \Documents and Settings\All Users\Start Menu\Programs\Games\Internet Reversi.lnk        112
0x22eba78       \WINDOWS\system32\charmap.exe   112
0x22ec358       \Documents and Settings\All Users\Start Menu\Programs\Games\Pinball.lnk 112
0x22ec718       \Intel\ivecuqmanpnirkt615\c.wnry        112
0x22ecb80       \Documents and Settings\All Users\Start Menu\Programs\Accessories\Communications\desktop.ini    112
0x22ecf90       \WINDOWS\system32\drivers\dxg.sys       112
0x22ed0a8       \WINDOWS\Fonts\vgasys.fon       112
0x22ed530       \WINDOWS\system32\usp10.dll     112
0x22ed9c0       \WINDOWS\system32\Restore\rstrui.exe    112
0x22ee398       \WINDOWS\system32\osk.exe       112
0x22ee620       \WINDOWS\system32\sxs.dll       112
0x22ee9a8       \WINDOWS\system32\odbcad32.exe  112
0x22eeec0       \WINDOWS\system32\lpk.dll       112
0x22ef0c8       \WINDOWS\system32\FNTCACHE.DAT  112
0x22ef3e0       \WINDOWS\system32\sorttbls.nls  112
0x22ef8d8       \WINDOWS\system32\locale.nls    112
0x22f04b0       \WINDOWS\system32\unicode.nls   112
0x22f06f8       \Intel\ivecuqmanpnirkt615\msg\m_romanian.wnry   112
0x22f0840       \WINDOWS\system32\riched32.dll  112
0x22f08f8       \WINDOWS\AppPatch\AcAdProc.dll  112
0x22f0b10       \Documents and Settings\All Users\Start Menu\Programs\Accessories\desktop.ini   112
0x22f0d50       \WINDOWS\system32\winsrv.dll    112
0x22f0f28       \WINDOWS\system32\spider.exe    112
0x22f1390       \WINDOWS\system32\basesrv.dll   112
0x22f1578       \WINDOWS\system32\csrsrv.dll    112
0x22f18c8       \WINDOWS\system32\csrss.exe     112
0x22f2028       \$Directory     112
0x22f2258       \WINDOWS\system32\config\software       112
0x22f2490       \WINDOWS\system32\config\SECURITY.LOG   112
0x22f2a38       \WINDOWS\system32       112
0x22f2b70       \WINDOWS\system32\kernel32.dll  112
0x22f3028       \WINDOWS\system32\shimeng.dll   112
0x22f3510       \$Directory     112
0x22f3cb8       \WINDOWS\system32\msvcp60.dll   112
0x22f3e58       \WINDOWS\system32\drivers\dxg.sys       112
0x22f60f8       \WINDOWS\system32\lsasrv.dll    112
0x22f66a0       \Documents and Settings\donny\Start Menu\Programs\Accessories\Accessibility\Magnifier.lnk       112
0x22f6738       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x22f6978       \WINDOWS\system32\imagehlp.dll  112
0x22f6c98       \WINDOWS\system32\gdi32.dll     112
0x2328270       \WINDOWS\system32\autochk.exe   112
0x2328308       \$Directory     112
0x23286e8       \$Mft   112
0x23287f0       \$Directory     112
0x2328888       \$Directory     112
0x2328920       \WINDOWS\system32\ntdll.dll     112
0x2328b20       \net\NtControlPipe3     112
0x2328bb8       \WINDOWS\ime\CHTIME\Applets     112
0x2329450       \WINDOWS\system32\cmd.exe       112
0x2329638       \WINDOWS\system32\cmd.exe       112
0x2329aa8       \$Directory     112
0x2329f28       \WINDOWS\system32\ntvdm.exe     112
0x232a1a0       \WINDOWS\system32\msvcrt.dll    112
0x232a370       \$Directory     112
0x232a530       \Documents and Settings\All Users\Start Menu\Programs\7-Zip\7-Zip File Manager.lnk      112
0x232a5c8       \Documents and Settings\All Users\Start Menu\Programs\Administrative Tools\Event Viewer.lnk     112
0x232a820       \WINDOWS\system32\xpsp2res.dll  112
0x232aa10       \Program Files\Windows NT\hypertrm.exe  112
0x232acd0       \WINDOWS\system32\olecnv32.dll  112
0x232b1d0       \$Directory     112
0x232b5e8       \WINDOWS\system32\wininet.dll   112
0x232b680       \WINDOWS\system32       112
0x232bb30       \WINDOWS\system32\config\default.LOG    112
0x235c3c0       \WINDOWS\AppPatch\drvmain.sdb   112
0x235cc80       \WINDOWS\system32\win32spl.dll  112
0x235e950       \$BitMap        112
0x235ede0       \WINDOWS\system32\secur32.dll   112
0x235ee78       \WINDOWS\system32\shlwapi.dll   112
0x235ef90       \$Directory     112
0x23637d8       \WINDOWS\system32\mpr.dll       112
0x23644e8       \$Directory     112
0x2364a50       \WINDOWS\system32\wldap32.dll   112
0x2364b60       \WINDOWS\system32\mpr.dll       112
0x2364e98       \WINDOWS\system32\olesvr32.dll  112
0x2365848       \WINDOWS\system32\win32k.sys    112
0x2367640       \WINDOWS\system32\shell32.dll   112
0x2368b98       \$Directory     112
0x2368cc0       \WINDOWS\system32\oleaut32.dll  112
0x2368f90       \net\NtControlPipe4     112
0x236d328       \WINDOWS\system32\userenv.dll   112
0x236d660       \WINDOWS\system32\ole32.dll     112
0x236d860       \$MftMirr       112
0x236de80       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x236df90       \WINDOWS\system32\drivers\etc\hosts     112
0x236e1b8       \WINDOWS\system32\csrss.exe     112
0x236e388       \$Directory     112
0x236ef90       \WINDOWS\system32\wow32.dll     112
0x23704f8       \$Directory     112
0x2370888       \WINDOWS\system32\config\default        112
0x2370c00       \$Directory     112
0x2370cd0       \WINDOWS\system32\urlmon.dll    112
0x2370e78       \$Directory     112
0x2370f90       \WINDOWS\system32\config\system.LOG     112
0x23711d8       \WINDOWS\system32\wininet.dll   112
0x23716e8       \$Directory     112
0x2371820       \WINDOWS\system32\url.dll       112
0x2371bb8       \WINDOWS\system32\csrsrv.dll    112
0x2371cd0       \WINDOWS\system32       112
0x2371e10       \WINDOWS\system32\comdlg32.dll  112
0x23728b0       \Program Files\Movie Maker\moviemk.exe  112
0x2372f90       \$Directory     112
0x2373438       \WINDOWS\system32\comdlg32.dll  112
0x2373550       \WINDOWS\system32\advapi32.dll  112
0x2373618       \WINDOWS\system32\sfcfiles.dll  112
0x2373708       \WINDOWS\system32\lpk.dll       112
0x2373e90       \WINDOWS\system32\ole32.dll     112
0x2373f28       \WINDOWS\system32\ntdll.dll     112
0x23753b0       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x23756b0       \WINDOWS        112
0x2375d30       \WINDOWS\system32\stobject.dll  112
0x2377078       \WINDOWS\system32\version.dll   112
0x2377298       \$Directory     112
0x23774e0       \WINDOWS\system32\iertutil.dll  112
0x2377608       \WINDOWS\system32\gdi32.dll     112
0x2377770       \WINDOWS\system32\msvcrt.dll    112
0x2377870       \WINDOWS\system32\user32.dll    112
0x2388178       \WINDOWS\system32\wuaucpl.cpl   112
0x2388488       \$Directory     112
0x2388578       \WINDOWS\system32\userenv.dll   112
0x2388748       \$Directory     112
0x2388918       \$Mft   112
0x2389168       \$Directory     112
0x2389288       \WINDOWS\system32\urlmon.dll    112
0x23895b0       \$Directory     112
0x2389f90       \$Directory     112
0x238a0b8       \WINDOWS\system32\comctl32.dll  112
0x238a150       \$Directory     112
0x238ac88       \WINDOWS\system32\ieframe.dll   112
0x238ae58       \$Directory     112
0x238b440       \WINDOWS\system32\shlwapi.dll   112
0x238b4d8       \WINDOWS\system32\wldap32.dll   112
0x2390178       \WINDOWS\system32\rpcrt4.dll    112
0x23903b0       \WINDOWS\system32\apphelp.dll   112
0x23904b0       \WINDOWS\system32\kernel32.dll  112
0x23906a8       \$Directory     112
0x2391d30       \WINDOWS\system32\smss.exe      112
0x2392238       \$Directory     112
0x2392618       \Program Files\Windows NT\Pinball\PINBALL.EXE   112
0x23927a0       \WINDOWS\system32\mobsync.exe   112
0x2392870       \Program Files\7-Zip\7zFM.exe   112
0x2393370       \WINDOWS\system32\rpcrt4.dll    112
0x2393518       \$Directory     112
0x2393d38       \WINDOWS\SoftwareDistribution\DataStore\Logs\tmp.edb    112
0x23941a8       \WINDOWS\system32\usp10.dll     112
0x2394c48       \$Directory     112
0x23952a8       \WINDOWS\system32\iertutil.dll  112
0x23954b8       \WINDOWS\system32\olecli32.dll  112
0x23956a8       \WINDOWS\system32\version.dll   112
0x2395830       \WINDOWS\system32\config\AppEvent.Evt   112
0x2395bc0       \WINDOWS\system32\user32.dll    112
0x2395f90       \WINDOWS\system32\olethk32.dll  112
0x239a3d0       \$Directory     112
0x239b410       \WINDOWS\system32\comctl32.dll  112
0x239b5c0       \$Directory     112
0x239b6d0       \$Directory     112
0x239b928       \WINDOWS\system32\config\SAM.LOG        112
0x239bb80       \WINDOWS\system32\config\SAM    112
0x239c690       \WINDOWS\system32\sfcfiles.dll  112
0x239c790       \$Directory     112
0x239f478       \WINDOWS\system32\dfrgres.dll   112
0x239f6d0       \Documents and Settings\donny\Desktop   112
0x239f928       \Documents and Settings\donny\PrintHood 112
0x239fb80       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x239fc78       \$Directory     112
0x239ff28       \WINDOWS\system32       112
0x23a0238       \WINDOWS\system32\tourstart.exe 112
0x23a0370       \WINDOWS\hh.exe 112
0x23a0788       \Documents and Settings\All Users\Start Menu\Microsoft Update.lnk       112
0x23a0820       \WINDOWS\system32\msxml3.dll    112
0x23a0cd0       \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202      112
0x23a1aa0       \Program Files\MSN Gaming Zone\Windows\shvlzm.exe       112
0x23a1c28       \Documents and Settings\donny\Desktop\PIL-1.1.7.win32-py2.7.exe 112
0x23a2330       \WINDOWS\system32\sol.exe       112
0x23a2aa0       \WINDOWS\system32\usmt\migwiz.exe       112
0x23a2bc0       \Documents and Settings\All Users\Start Menu\Programs\Administrative Tools\Component Services.lnk       112
0x23a2c90       \Program Files\Windows NT\Accessories\wordpad.exe       112
0x23a72f8       \$Directory     112
0x23a7458       \WINDOWS\system32\ieframe.dll   112
0x23a7558       \WINDOWS\system32\advapi32.dll  112
0x23aa0c0       \WINDOWS\system32\autochk.exe   112
0x23aa360       \WINDOWS\system32\basesrv.dll   112
0x23aa668       \WINDOWS\system32\winsrv.dll    112
0x23aac88       \WINDOWS\system32\apphelp.dll   112
0x23aadc0       \$Directory     112
0x23aae58       \WINDOWS\system32\normaliz.dll  112
0x23cd490       \WINDOWS\system32\mlang.dll     112
0x23ce268       \WINDOWS\system32\normaliz.dll  112
0x23ce300       \$Directory     112
0x23ce698       \WINDOWS\system32\imagehlp.dll  112
0x23ceb60       \$LogFile       112
0x23cec88       \$Directory     112
0x23ced58       \WINDOWS\system32\oleaut32.dll  112
0x23cee58       \WINDOWS\system32\secur32.dll   112
0x23cef90       \$Directory     112
0x23eb8e8       \{9B365890-165F-11D0-A195-0020AFD156E4} 112


```


What is the build version of the host machine in Case 001?
windows.info
*2600.xpsp.080413-2111*


At what time was the memory file acquired in Case 001?
windows.info
*2012-07-22 02:45:08*

What process can be considered suspicious in Case 001?
windows.psscan
*reader_sl.exe*

What is the parent process of the suspicious process in Case 001?
windows.pstree
*explorer.exe*


What is the PID of the suspicious process in Case 001?
windows.cmd
*1640*



What is the parent process PID in Case 001?
windows.cmd
*1484*


What user-agent was employed by the adversary in Case 001?
		
		vol.py -f <dump> -o /dir/to/store_dump/ windows.memmap.Memmap --pid <suspicious PID> --dump Once the dump is stored use, strings *.dmp | grep -i "user-agent"
*Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)*


Was Chase Bank one of the suspicious bank domains found in Case 001? (Y/N)
	
	strings *.dmp | grep "http" or strings *.dmp | grep "chase"
*Y*


What suspicious process is running at PID 740 in Case 002?
windows.psscan
*@WanaDecryptor@*


What is the full path of the suspicious binary in PID 740 in Case 002?
windows.dlllist | grep 740
	
	*C:\Intel\ivecuqmanpnirkt615\@WanaDecryptor@.exe*


What is the parent process of PID 740 in Case 002?
windows.pstree
*tasksche.exe*


What is the suspicious parent process PID connected to the decryptor in Case 002?
The PID for tasksche.exe can be found with windows.pstree (previous question)
*1940*


From our current information, what malware is present on the system in Case 002?
Research the found indicators against white papers and virus total.
*WannaCry*


What DLL is loaded by the decryptor used for socket creation in Case 002?
Research DLLs used by the malware in question.
*WS2_32.dll*


What mutex can be found that is a known indicator of the malware in question in Case 002?
windows.handles | grep 1940
*MsWinZonesCacheCounterMutexA*


What plugin could be used to identify all files loaded from the malware working directory in Case 002?
Review the help menu.
*windows.filescan*

### Conclusion 

We have only covered a very thin layer of memory forensics that can go much deeper when analyzing the Windows, Mac, and Linux architecture. If you're looking for a deep dive into memory forensics, I would suggest reading: The Art of Memory Forensics.

There are also a number of wikis and various community resources that can be used for more information about Volatility techniques found below.

    https://github.com/volatilityfoundation/volatility/wiki
    https://github.com/volatilityfoundation/volatility/wiki/Volatility-Documentation-Projec
    https://digital-forensics.sans.org/media/Poster-2015-Memory-Forensics.pdf
    https://eforensicsmag.com/finding-advanced-malware-using-volatility/

From this room, as you continue on the SOC Level 1 path, more rooms will contain memory forensics challenges.

![](https://i.imgur.com/4RqSHR0.png)


[[Yara]]