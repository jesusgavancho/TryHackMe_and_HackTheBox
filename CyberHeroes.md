---
Want to be a part of the elite club of CyberHeroes? Prove your merit by finding a way to log in!
---

![|333](https://tryhackme-images.s3.amazonaws.com/room-icons/e8874c2d58c8ff0df78b5183fb828c81.png)


```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -T4 -A 10.10.144.202     
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-25 13:48 EDT
Nmap scan report for 10.10.144.202
Host is up (0.20s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 38:66:7e:8f:62:41:e9:5c:8e:00:81:91:9f:3d:9a:32 (RSA)
|   256 eb:03:8d:bf:8b:73:39:90:70:0c:71:7f:ca:0b:4a:27 (ECDSA)
|_  256 96:df:2a:20:7b:36:f6:be:43:6f:c8:dc:9d:52:3a:15 (ED25519)
80/tcp open  http    Apache httpd 2.4.48 ((Ubuntu))
|_http-server-header: Apache/2.4.48 (Ubuntu)
|_http-title: CyberHeros : Index
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=9/25%OT=22%CT=1%CU=41503%PV=Y%DS=2%DC=T%G=Y%TM=6330948
OS:9%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M506ST11NW7%O2=M506ST11NW7%O3=M506NNT11NW7%O4=M506ST11NW7%O5=M506ST1
OS:1NW7%O6=M506ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN
OS:(R=Y%DF=Y%T=40%W=F507%O=M506NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1723/tcp)
HOP RTT       ADDRESS
1   197.26 ms 10.18.0.1
2   198.06 ms 10.10.144.202

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 42.02 seconds
zsh: segmentation fault  sudo nmap -sC -sV -T4 -A 10.10.144.202


view-source:http://10.10.144.202/login.html

 <script>
    function authenticate() {
      a = document.getElementById('uname')
      b = document.getElementById('pass')
      const RevereString = str => [...str].reverse().join('');
      if (a.value=="h3ck3rBoi" & b.value==RevereString("54321@terceSrepuS")) { 
        var xhttp = new XMLHttpRequest();
        xhttp.onreadystatechange = function() {
          if (this.readyState == 4 && this.status == 200) {
            document.getElementById("flag").innerHTML = this.responseText ;
            document.getElementById("todel").innerHTML = "";
            document.getElementById("rm").remove() ;
          }
        };
        xhttp.open("GET", "RandomLo0o0o0o0o0o0o0o0o0o0gpath12345_Flag_"+a.value+"_"+b.value+".txt", true);
        xhttp.send();
      }
      else {
        alert("Incorrect Password, try again.. you got this hacker !")
      }
    }
  </script>

reverse it cyberchef (54321@terceSrepuS) -> SuperSecret@12345

login
so h3ck3rBoi:SuperSecret@12345

Congrats Hacker, you made it !! Go ahead and nail other challenges as well :D flag{edb0be532c540b1a150c3a7e85d2466e} 



```

![[Pasted image 20220925125528.png]]

Uncover the flag!
*flag{edb0be532c540b1a150c3a7e85d2466e}*




[[Archangel]]