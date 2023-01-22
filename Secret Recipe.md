---
Perform Registry Forensics to Investigate a case.
---

![](https://tryhackme-images.s3.amazonaws.com/room-icons/08870f82d4ce4374cdc6fe1ad922d0e3.png)

###  Introduction

 Start Machine

Storyline

Jasmine owns a famous New York coffee shop **Coffely** which is famous city-wide for its unique taste. Only Jasmine keeps the original copy of the recipe, and she only keeps it on her work laptop. Last week, James from the IT department was consulted to fix Jasmine's laptop. But it is suspected he may have copied the secret recipes from Jasmine's machine and is keeping them on his machine.![Image showing a Laptop with a magnifying glass](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/e5df5e314ace15620057d1a6dd83f5a4.png)

His machine has been confiscated and examined, but no traces could be found. The security department has pulled some important **registry artifacts** from his device and has tasked you to examine these artifacts and determine the presence of secret files on his machine.

Room Machine

Before moving forward, let's deploy the machine. The machine will start in a split-screen view. In case the VM is not visible, use the blue Show Split View button at the top-right of the page. You may also access it via the AttackBox or RDP using the credentials below. It will take up to 3-5 minutes to start.

On the Desktop, there is a folder named `Artifacts`, which contains the registry Hives to examine and another folder named `EZ tools`, which includes all the required tools to analyze the artifacts.

**Credentials**

**Username**: `Administrator`

**Password:** `thm_4n6`

**Note:** If you are using Registry Explorer to parse the hives, expect some delay in loading as it takes time to parse the hives.  

Answer the questions below

Connect with the Lab  

 Completed

How many Files are available in the Artifacts folder on the Desktop?

![[Pasted image 20230121145600.png]]

*6*


### Windows Registry Forensics

 Download Task Files

Registry Recap  

Windows Registry is like a database that contains a lot of juicy information about the system, user, user activities, processes executed, the files accessed or deleted, etc.![Image showing Registry icon](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/102a9b75468cf27947949d403c91456a.png)

Following Registry Hives have been pulled from the suspect Host and placed in the `C:\Users\Administrator\Desktop\Artifacts` folder. All required tools are also placed on the path. `C:\Users\Administrator\Desktop\EZ Tools`.

Your challenge is to examine the registry hives using the tools provided, observe the user's activities and answer the questions.  

Registry Hives  

-   SYSTEM
-   SECURITY  
    
-   SOFTWARE
-   SAM
-   NTUSER.DAT
-   UsrClass.dat

**Note:** The `Download Task Files` button has a cheat sheet, which can be used as a reference to answer the questions.

Answer the questions below

```
Los archivos mencionados (SYSTEM, SECURITY, SOFTWARE, SAM, NTUSER.DAT, UsrClass.dat) son todos archivos de sistema de Windows conocidos como "tableros" o "colmenas" del Registro. Cada uno de estos archivos contiene una serie de claves y valores que se utilizan para almacenar la configuración del sistema y los programas instalados.

-   SYSTEM: Contiene información sobre los controladores de dispositivos y el hardware del sistema.
-   SECURITY: Contiene información sobre la seguridad del sistema, incluyendo cuentas de usuario y grupos, políticas de seguridad y registros de auditoría.
-   SOFTWARE: Contiene información sobre los programas instalados en el sistema, incluyendo configuraciones de programas y claves de registro de aplicaciones.
-   SAM: Contiene información sobre las cuentas de usuario del sistema, incluyendo nombres de usuario y contraseñas cifradas.
-   NTUSER.DAT: Contiene información sobre la configuración de usuario individual, incluyendo preferencias de escritorio, configuraciones de programas y historial de navegación.
-   UsrClass.dat: Contiene información sobre la configuración de clases de usuario, que se utiliza para personalizar la experiencia de usuario en el sistema.

Un "tablero" o "colmena" del Registro es un archivo que almacena un conjunto de claves y valores que se utilizan para almacenar la configuración del sistema y los programas instalados en el sistema operativo Windows. El registro es una base de datos jerárquica que contiene información sobre hardware, software, configuraciones de usuario y aplicaciones. Los tableros son los archivos donde se guarda esa información.

Shellbags is a term used to describe information that is stored in the Windows Registry related to the configuration of folders and the way they are displayed in Windows Explorer. This information includes the size and position of the window, the sort order of the files, and the folder's expanded or collapsed state.

For example, if a user opens a folder and resizes the window, this new size is stored in the Shellbags key of the Windows Registry. Next time the user opens that folder, the folder will automatically open with the same size and position that the user last used.

Another example is if a user opens a folder and sorts the files by the date modified, this new sort order is also stored in the Shellbags key of the Windows Registry. Next time the user opens that folder, the files will automatically be sorted by the date modified, this way the user doesn't have to sort the files again.

In summary, Shellbags is a feature of Windows that automatically saves and restores the settings of the folders and files, like the position, size, sorting, expanded and collapsed state, etc.

-   Current Control Set: This is a key in the Windows Registry that contains settings and configuration information for the current version of Windows. This key is used to store system-wide settings, including device driver settings, services and device settings, and other system-wide configurations.
    
-   MRUs (Most Recently Used): These are keys in the Windows Registry that store a list of the most recently used files, folders, and other resources by the user. For example, the MRU key for the Run dialog box stores a list of the most recent commands typed in the Run dialog box.
    
-   UserAssist: This is a key in the Windows Registry that stores information about the programs and files that a user has used on the system. It keeps track of the number of times the user has opened a program or file, the last time it was opened, and other related information.
    
-   ShimCache: This is a cache of shims, which are small programs that are used to fix compatibility issues with older programs. ShimCache stores information about the shims that have been used on the system, including the name of the shim, the date and time it was used, and other related information.
    
-   Amcache: This is a key in the Windows Registry that stores information about applications that have been installed on the system. It keeps track of the name, publisher, version, and other information about the application, and the date and time it was installed.
    
-   BAM/DAM (Boot Execution and Application Execution): These are keys in the Windows Registry that store information about the programs and files that have been run on the system during the boot process and after the system has started up. This information includes the name of the program or file, the date and time it was run, and other related information.
    

For example, when a user runs a program, ShimCache will store information about the program and when it was run. This information can be useful for forensic analysis, as it can provide insight into what programs were run on a system and when. Another example is when an user install an application, Amcache will store information about the application name, publisher, version, and the date and time it was installed. This information can be used to identify what programs were installed on a system and when.

Regenerate response

Using Registry explorer v1.6.0.0

1)
Load Hive/SYSTEM/

SYSTEM\ControlSet001\Control\ComputerName\ComputerName ---> JAMES

2) Load Hive/SAM/

SAM\Domains\Account\Users\Name\Administrator ---> 2021-03-17 14:58:48 (copy last write time)

3)

RegUnknown (0x1F4, 500 decimal)

The RID (Relative Identifier) associated with the Administrator account is typically 500. RID is a unique number that is assigned to each account in Windows and is used to differentiate between different accounts on the system. The RID is part of the security identifier (SID) of an account, which is used to identify the account and its permissions on the system. The SID is composed of a domain SID, which is unique to the domain or system, and a RID, which is unique to the account within the domain or system.

In Windows, the RID for the built-in Administrator account is 500. This is a well-known RID and is used by the system to identify the Administrator account, regardless of the name that is assigned to it. Other built-in accounts such as Guest, also have well-known RIDs.

It is important to note that RID can be changed, but it is not recommend as it can cause issues on the system.

Un ejemplo de cómo se ve un SID con un RID es: S-1-5-21-34233434-123456789-12345678-500, en donde el último número, 500 es el RID que identifica a la cuenta Administrador.

Otro ejemplo es, un usuario llamado "Juan" tiene una cuenta en el sistema operativo Windows, el sistema le asigna un RID, por ejemplo 1000, este RID es único para esa cuenta y no se repite en otras cuentas.

4)

7 users: Administrator, art-test, bdoor, DefaultAccount, Guest, J. Andreson and WDAGUtilityAccount.

5)

bdoor  -> RegUnknown (0x3F5, 1013 decimal)

6)

Load Hive/Software

Software/Microsoft/Windows NT/CurrentVersion/NetworkList ---> ProtonVPN

7)

First Connect LOCAL

2022-10-12 19:52:36

8)

Load Hive/SYSTEM

search shares

SYSTEM/ControlSet001/Services/LanmanServer/Shares -- Path=C:\RESTRICTED FILES (Value Name RESTRICTED)

8)

DHCP (Dynamic Host Configuration Protocol) is a network protocol that is used to automatically assign IP addresses, subnet masks, default gateways, and other network configuration settings to devices on a network. This eliminates the need for manual configuration of these settings on each device.

For example, when a device such as a laptop or smartphone is connected to a network, it sends a broadcast message requesting an IP address. The DHCP server on the network receives this request and assigns an available IP address to the device along with the necessary network configuration settings. The device can then communicate on the network using the assigned IP address.

Another example, in a company, when a new employee joins the company, he/she is given a laptop. The employee connects the laptop to the company's network via a wired or wireless connection. The laptop sends a request for an IP address to the DHCP server. The DHCP server assigns an available IP address to the laptop, and also assigns the necessary network configurations such as the subnet mask and the default gateway. This way, the new employee can start working on his/her laptop and access the company's network resources.

In short, DHCP is a protocol that helps automate the process of assigning IP addresses and other network configurations to devices on a network, making it easier for network administrators to manage and maintain the network.

Load Hive/SYSTEM

SYSTEM\ControlSet001\Services\Tcpip \Parameters\Interfaces (DHCPIP Address 172.31.2.197)

9)

Load Hive/NTUSER.DAT

NTUSER.DAT\Software\Microsoft\Windows \CurrentVersion\Explorer\RecentDocs\pdf (secret-recipe.pdf)

10)

RunMRU (Run Most Recently Used) is a key in the Windows Registry that stores a list of the most recently used commands that were typed into the Run dialog box. The Run dialog box is a feature in Windows that allows users to quickly open programs, files, and folders by typing the name or path of the item into the Run box and pressing Enter.

Each entry in the RunMRU key corresponds to a command that was typed into the Run dialog box, and it is stored in the form of a string value. The values are named with a numerical suffix, starting with "0" for the most recent command, and increasing for each older command. The value contains the command that was typed, as well as other metadata such as the time the command was executed.

For example, when a user opens the Run dialog box and types "cmd" and press Enter, the command "cmd" is stored in the RunMRU key in the Windows Registry. If the user opens the Run dialog box again and types "notepad" and press Enter, the command "notepad" is stored in the RunMRU key, replacing the previous command "cmd" as the most recent command.

RunMRU is useful for forensic analysis, as it can provide insight into what commands were typed into the Run dialog box, and when they were executed. It can help investigators to understand the actions that were taken on a system and identify potential malicious activity.

Load Hive/NTUSER.DAT

NTUSER.DAT\Software\Microsoft\Windows \CurrentVersion\Explorer\RunMRU

commands:  ncpa.cpl, pnputil /enum-interfaces , pnputil /enum-devices, resmon, msconfig, wmic, regedit, ipconfig, cmd \n

ncpa.cpl is a command that is used to open the Network Connections control panel in Windows. It allows you to view and manage the network connections on your computer, including wired and wireless connections.

You can use this command by typing "ncpa.cpl" into the Run dialog box (Windows+R), or by searching for it in the Start menu. Once you open the Network Connections control panel, you can view a list of all the available connections, including the status of each connection, the type of connection, and the speed. You can also perform actions such as disabling and enabling connections, troubleshoot problems, and configure advanced settings.

For example, if you're experiencing problems connecting to a wireless network, you can open the Network Connections control panel by typing "ncpa.cpl" in the Run dialog box, then you can check the status of your wireless connection and troubleshoot any issues. Or if you want to connect to a new wireless network you can open the Network Connections control panel, then you can configure the settings for the new network and connect to it.

In summary, ncpa.cpl is a command that allows you to access the Network Connections control panel, where you can view and manage the network connections on your computer, troubleshoot problems and configure advanced settings.

pnputil is a command-line tool that is included with Windows operating system, it allows you to manage Plug and Play devices on a system. It can be used to add, delete, and enumerate devices, drivers and their associated files.

-   pnputil /enum-interfaces: This command is used to enumerate the Plug and Play interfaces on the system. It lists the interfaces and their associated device instances, along with the status of the interfaces. It provides information such as the class, the device instance ID and the device's friendly name.
    
-   pnputil /enum-devices: This command is used to enumerate the Plug and Play devices on the system. It lists the devices and their associated drivers, along with the status of the devices. It provides information such as the class, the device instance ID, the device's friendly name and the location information.
    

For example, if you want to view a list of all the Plug and Play devices that are currently connected to your computer, you can open the command prompt and type "pnputil /enum-devices" and press enter. This will show you a list of all the devices along with their class, device instance ID, friendly name and location information.

Another example, you want to view a list of all the Plug and Play interfaces that are currently connected to your computer, you can open the command prompt and type "pnputil /enum-interfaces" and press enter. This will show you a list of all the interfaces along with their class, device instance ID and friendly name.

-   resmon: Resource Monitor (resmon.exe) is a built-in Windows tool that provides real-time information about the usage of the computer's hardware and software resources. It allows you to view information about CPU usage, memory usage, disk usage, network usage, and other performance metrics.
    
-   msconfig: The System Configuration (msconfig.exe) is a built-in Windows tool that allows you to configure settings related to startup programs, services, and system components. It allows you to disable or enable startup programs, change the startup type of services, and troubleshoot problems related to the system configuration.
    
-   wmic: Windows Management Instrumentation Command-line (WMIC) is a command-line interface that allows you to interact with the Windows Management Instrumentation (WMI) infrastructure. It allows you to query and manage system information such as hardware, software, and system settings.
    
-   regedit: Registry Editor (regedit.exe) is a built-in Windows tool that allows you to view and edit the Windows Registry. The Registry is a central database that stores settings and configurations for the Windows operating system and installed software.
    
-   ipconfig: IP Configuration (ipconfig.exe) is a command-line tool that allows you to view and manage the IP configuration of a computer. It allows you to view the IP address, subnet mask, default gateway, and other network settings of a computer.

Command Prompt (cmd.exe) is a command-line interface that is built-in to Windows operating systems. It allows you to execute commands and run programs by typing them into the command prompt. It also allows you to navigate the file system, manage files and folders, and perform other system-level tasks. It is a powerful tool for advanced users and system administrators, as it allows them to perform tasks that may not be possible through the graphical user interface.

pnputil /enum-interfaces

11)

Load Hive/NTUSER.DAT

NTUSER.DAT\Software\Microsoft\Windows \CurrentVersion\Explorer\WordWheelQuery (netcat)

WordWheelQuery is a term used to describe a feature in Windows that allows users to quickly search for files and programs on their computer by typing a few letters of the desired item's name. It is also known as the "Run As" function. The feature works by matching the letters that are typed in with the names of files and programs on the computer, and displaying a list of potential matches. As the user types more letters, the list of matches becomes more specific. This feature is available in Windows 7 and later versions.

For example, when a user presses the Windows key + R, the Run box will open. If the user starts typing the name of a program or file they are looking for, Windows will begin to search for matches and display them in a list as the user types. If the user sees the file or program they were looking for in the list, they can select it and press Enter to open it.

WordWheelQuery is a useful feature that can save time and make it easier for users to find and open files and programs on their computer. It is especially useful for users who have a large number of files and programs installed on their computer and want to find a specific one quickly.

12)

Load Hive/NTUSER.DAT

NTUSER.DAT\Software\Microsoft\Windows \CurrentVersion\Explorer\RecentDocs\

secret-code.txt

13)

Load Hive/NTUSER.DAT

NTUSER.DAT\Software\Microsoft\Windows \Currentversion\Explorer\UserAssist\{GUID}\Count (Run Counter Powershell 3)

14)

Load Hive/NTUSER.DAT

NTUSER.DAT\Software\Microsoft\Windows \Currentversion\Explorer\UserAssist\{GUID}\Count

wireshark

15)

Load Hive/NTUSER.DAT

NTUSER.DAT\Software\Microsoft\Windows \Currentversion\Explorer\UserAssist\{GUID}\Count

(Focus Time 05m, 43s so 343 seconds)

16)

Everything.exe is a third-party search tool for Windows that allows you to quickly search for files and folders on your computer. It is an alternative to the built-in Windows search feature and it is faster and more efficient than the default search function.

The program works by indexing all the files and folders on your computer, which allows it to search through them very quickly. Once the indexing is done, you can search for a file or folder by typing a few letters of the name into the search bar, and it will display a list of matches as you type. The results are displayed in real time and are organized by folder, making it easy to find the file you are looking for.

For example, if you need to find a specific document you can open the Everything.exe and type the name or part of the name of the document, it will instantly show you the files that match that name, regardless of the location where the document is stored, it will also show you the path of the file.

Everything.exe is a convenient tool for users who frequently need to search for files and folders on their computer, it's faster than the built-in search and it allows you to find the files you need quickly.

Load Hive/NTUSER.DAT

NTUSER.DAT\Software\Microsoft\Windows \Currentversion\Explorer\UserAssist\{GUID}\Count

C:\Users\Administrator\Downloads\tools\Everything\Everything.exe

```

What is the Computer Name of the Machine found in the registry?

![[Pasted image 20230121152512.png]]

*JAMES*

When was the **Administrator** account created on this machine? (Format: yyyy-mm-dd hh:mm:ss)  

*2021-03-17 14:58:48*

What is the RID associated with the Administrator account?

![[Pasted image 20230121154835.png]]

*500*

How many User accounts were observed on this machine?

![[Pasted image 20230121155759.png]]

*7*

There seems to be a suspicious account created as a backdoor with RID 1013. What is the Account Name?

*bdoor*

What is the VPN connection this host connected to?

Look for NetworkList in Software Hive

![[Pasted image 20230121200839.png]]

*ProtonVPN*


When was the first VPN connection observed? (Format: YYYY-MM-DD HH:MM:SS)  

*2022-10-12 19:52:36*

There were three shared folders observed on his machine. What is the path of the third share?

![[Pasted image 20230121202133.png]]

	*C:\RESTRICTED FILES*

What is the Last DHCP IP assigned to this host?

Look for NetworkList in Software Hive

![[Pasted image 20230121203452.png]]

*172.31.2.197*


The suspect seems to have accessed a file containing the secret coffee recipe. What is the name of the file?

*secret-recipe.pdf*

The suspect ran multiple commands in the run windows. What command was run to enumerate the network interfaces?

![[Pasted image 20230121205959.png]]

*pnputil /enum-interfaces*

In the file explorer, the user searched for a network utility to transfer files. What is the name of that tool?

*netcat*

What is the recent text file opened by the suspect?

*secret-code.txt*

How many times was Powershell executed on this host?

![[Pasted image 20230121211230.png]]

*3*

The suspect also executed a network monitoring tool. What is the name of the tool?

*wireshark*

Registry Hives also notes the amount of time a process is in focus. Examine the Hives. For how many seconds was ProtonVPN executed?

*343*

Everything.exe is a utility used to search for files in a Windows machine. What is the full path from which everything.exe was executed?

![[Pasted image 20230121212431.png]]

	*C:\Users\Administrator\Downloads\tools\Everything\Everything.exe*


[[NoNameCTF]]