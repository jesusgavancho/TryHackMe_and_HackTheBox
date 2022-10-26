---
Learn basic scripting by solving some challenges!
---

![](https://miro.medium.com/max/2560/1*enCF61GFzLovMNXzAJmVNQ.png)

![](https://tryhackme-images.s3.amazonaws.com/room-icons/b404cfcdf14054b6dabf2a94a48f0ba0.png)

### [Easy] Base64 

This file has been base64 encoded 50 times - write a script to retrieve the flag. Here is the general process to do this:

    read input from the file
    use function to decode the file
    do process in a loop

Try do this in both Bash and Python!

```
download the task 30 mb b64 encoded 50 times

with cyberchef takes a lot time ... so create a python script


┌──(kali㉿kali)-[~/scripting]
└─$ nano b64.py   
                                                                                     
┌──(kali㉿kali)-[~/scripting]
└─$ cat b64.py
import base64

#Open file
with open('b64.txt') as f:
        msg = f.read()

#Decode 50 times
for _ in range(50):
        msg = base64.b64decode(msg)

print(f"Th flag is: {msg.decode('utf8')}")
                                                                                     
┌──(kali㉿kali)-[~/scripting]
└─$ python3 b64.py
Th flag is: HackBack2019=



```

![[Pasted image 20221026121914.png]]

What is the final string?
*HackBack2019=*


###  [Medium] Gotta Catch em All 

You need to write a script that connects to this webserver on the correct port, do an operation on a number and then move onto the next port. Start your original number at 0.

The format is: operation, number, next port.

For example the website might display, add 900 3212 which would be: add 900 and move onto port 3212.

Then if it was minus 212 3499, you'd minus 212 (from the previous number which was 900) and move onto the next port 3499

Do this until you the page response is STOP (or you hit port 9765).

Each port is also only live for 4 seconds. After that it goes to the next port. You might have to wait until port 1337 becomes live again...

Go to: http://<machines_ip>:3010 to start...

General Approach(it's best to do this using the sockets library in Python):

    Create a socket in Python using the sockets library https://docs.python.org/3/howto/sockets.html
    Connect to the port 
    Send an operation
    View response and continue


![[Pasted image 20221026123721.png]]

```
┌──(kali㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.174.84 --ulimit 5500 -b 65535 -- -A
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.174.84:22
Open 10.10.174.84:3010
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-26 13:35 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:35
Completed NSE at 13:35, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:35
Completed NSE at 13:35, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:35
Completed NSE at 13:35, 0.00s elapsed
Initiating Ping Scan at 13:35
Scanning 10.10.174.84 [2 ports]
Completed Ping Scan at 13:35, 0.31s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 13:35
Completed Parallel DNS resolution of 1 host. at 13:35, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 13:35
Scanning 10.10.174.84 [2 ports]
Discovered open port 22/tcp on 10.10.174.84
Discovered open port 3010/tcp on 10.10.174.84
Completed Connect Scan at 13:35, 0.31s elapsed (2 total ports)
Initiating Service scan at 13:35
Scanning 2 services on 10.10.174.84
Completed Service scan at 13:35, 7.58s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.174.84.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:35
Completed NSE at 13:35, 9.37s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:35
Completed NSE at 13:35, 1.41s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:35
Completed NSE at 13:35, 0.00s elapsed
Nmap scan report for 10.10.174.84
Host is up, received conn-refused (0.31s latency).
Scanned at 2022-10-26 13:35:21 EDT for 19s

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c8cc25b7cbd585c3d8b1a2b81bf99ee3 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCXsmODtOWVYR+ZZRJmgrnoJY4Gvlvbrj+g+rpi1n9J9XACL1Wp10tdAc+vtcLEBQ+Oc7IUs9CUnL/NY/q2rATFxhZ0MBy+AmZ29Exf9ywCdSHX41NyLQ3FbNOjS3P0gyyNhsrfK8YbXKBMr8xqjeZYM9Ypn0NT3WJq+QmzlF2lTnMVqatBHQTbCAGmMo5pd91wekaE5oqBppOpUKoVCPsPUatGKg4dOVW3dOrkn2hwWwCVkmFw3+RQzyVvWKMMgNaNOH66h1NDAB6INOvjYvW+brxxrGGHns2WeZpFU9cxQVhF0l1R0tWNCJnkSTvR1Qi6aYZQMrdPcHiE92C+d4KV
|   256 d83c67cd1d400835ca018091ec37515c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMzxLhIw6LzXpIjMMlPy6RMV72TqZgCwHgEW0xCAx5eLKJhyg9QSkJdDco4sd0hw/PYgCN50HmylNrCkT1cah3g=
|   256 8a89d6a62f3bf0628814a05cd16f5358 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFGEKu05jt0N6KtTD9SHIrBmdeNJv2wHYWGu09PqYnNH
3010/tcp open  http    syn-ack Werkzeug httpd 0.14.1 (Python 3.5.2)
|_http-server-header: Werkzeug/0.14.1 Python/3.5.2
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:35
Completed NSE at 13:35, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:35
Completed NSE at 13:35, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:35
Completed NSE at 13:35, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.30 seconds


go to ip:3010 to see currently port

┌──(kali㉿kali)-[~/scripting]
└─$ cat webClient.py
import socket
import time
import re
import sys

def Main():
        serverIP = sys.argv[1] #Get ip from user input
        serverPort = 1337
        oldNum = 0 # Start as 0 per instructions

        while serverPort != 9765:
                try: #try until port 1337 is available
                        if serverPort == 1337:
                                print(f"Connecting to {serverIP} waiting for Port {serverPort} to become available...")

                        #Creating socket and connect to server
                        s = socket.socket()
                        s.connect((serverIP,serverPort))

                        #Send get request to server
                        gRequest = f"GET / HTTP/1.0\r\nHost: {serverIP}:{serverPort}\r\n\r\n"

                        s.send(gRequest.encode('utf8'))

                        #Retrieve data from get request
                        while True:
                                response = s.recv(1024)
                                if (len(response) < 1):
                                        break
                                data = response.decode("utf8")

                        #Format and assign the data into usable vars
                        op, newNum, nextPort = assignData(data)
                        #perform given calcs
                        oldNum = doMath(op, oldNum, newNum)
                        #Display output and move on
                        print(f"Current number is {oldNum}, moving onto port {nextPort}")
                        serverPort = nextPort

                        s.close()

                except:
                        s.close()
                        time.sleep(3) #Ports update every 4 sec
                        pass

        print(f"The final answer is {round(oldNum,2)}")

def doMath(op, oldNum, newNum):
        if op == 'add':
                return oldNum + newNum
        elif op == 'minus':
                return oldNum - newNum
        elif op == 'divide':
                return oldNum / newNum
        elif op == 'multiply':
                return oldNum * newNum
        else:
                return None

def assignData(data):
        dataArr = re.split(' |\*|\n' , data) #Split data with multi delim
        dataArr = list(filter(None, dataArr)) #Filter null strings
        #Assign the last 3 values of data
        op = dataArr[-3]
        newNum = float(dataArr[-2])
        nextPort = int(dataArr[-1])

        return op, newNum, nextPort

if __name__ == '__main__':
        Main()



                                                                  
┌──(kali㉿kali)-[~/scripting]
└─$ python3 webClient.py 10.10.174.84
Connecting to 10.10.174.84 waiting for Port 1337 to become available...
Connecting to 10.10.174.84 waiting for Port 1337 to become available...
Connecting to 10.10.174.84 waiting for Port 1337 to become available...
Connecting to 10.10.174.84 waiting for Port 1337 to become available...
Connecting to 10.10.174.84 waiting for Port 1337 to become available...
Connecting to 10.10.174.84 waiting for Port 1337 to become available...
Connecting to 10.10.174.84 waiting for Port 1337 to become available...
Connecting to 10.10.174.84 waiting for Port 1337 to become available...
Connecting to 10.10.174.84 waiting for Port 1337 to become available...
Connecting to 10.10.174.84 waiting for Port 1337 to become available...
Connecting to 10.10.174.84 waiting for Port 1337 to become available...
Connecting to 10.10.174.84 waiting for Port 1337 to become available...
Connecting to 10.10.174.84 waiting for Port 1337 to become available...
Connecting to 10.10.174.84 waiting for Port 1337 to become available...
Connecting to 10.10.174.84 waiting for Port 1337 to become available...
Connecting to 10.10.174.84 waiting for Port 1337 to become available...
Connecting to 10.10.174.84 waiting for Port 1337 to become available...
Connecting to 10.10.174.84 waiting for Port 1337 to become available...
Connecting to 10.10.174.84 waiting for Port 1337 to become available...
Connecting to 10.10.174.84 waiting for Port 1337 to become available...
Connecting to 10.10.174.84 waiting for Port 1337 to become available...
Connecting to 10.10.174.84 waiting for Port 1337 to become available...
Connecting to 10.10.174.84 waiting for Port 1337 to become available...
Connecting to 10.10.174.84 waiting for Port 1337 to become available...
Connecting to 10.10.174.84 waiting for Port 1337 to become available...
Connecting to 10.10.174.84 waiting for Port 1337 to become available...
Connecting to 10.10.174.84 waiting for Port 1337 to become available...
Connecting to 10.10.174.84 waiting for Port 1337 to become available...
Connecting to 10.10.174.84 waiting for Port 1337 to become available...
Connecting to 10.10.174.84 waiting for Port 1337 to become available...
Connecting to 10.10.174.84 waiting for Port 1337 to become available...
Connecting to 10.10.174.84 waiting for Port 1337 to become available...
Connecting to 10.10.174.84 waiting for Port 1337 to become available...
Current number is 900.0, moving onto port 23456
Current number is 898.0, moving onto port 8888
Current number is 3592.0, moving onto port 9823
Current number is 1796.0, moving onto port 9887
Current number is 2252.0, moving onto port 7823
Current number is 2209.0, moving onto port 10456
Current number is 4418.0, moving onto port 10457
Current number is 5295.0, moving onto port 40000
Current number is 5304.0, moving onto port 40200
Current number is 180336.0, moving onto port 8743
Current number is 180331.0, moving onto port 63890
Current number is 180331.0, moving onto port 38721
Current number is 180374.0, moving onto port 6632
Current number is 180352.0, moving onto port 29932
Current number is 60117.333333333336, moving onto port 29132
Current number is 541056.0, moving onto port 8773
Current number is 539856.0, moving onto port 1338
Current number is 539868.0, moving onto port 1876
Current number is 539868.0, moving onto port 34232
Current number is 539868.0, moving onto port 6783
Current number is 539768.0, moving onto port 4040
Current number is -1079536.0, moving onto port 5050
Current number is -1079236.0, moving onto port 9898
Current number is -107923.6, moving onto port 3232
Current number is -107933.6, moving onto port 10321
Current number is -107803.6, moving onto port 7709
Current number is -431214.4, moving onto port 9872
Current number is 5174572.800000001, moving onto port 32424
Current number is 1724857.6000000003, moving onto port 65513
Current number is 1723857.6000000003, moving onto port 3459
Current number is 1723880.6000000003, moving onto port 7832
Current number is 344776.12000000005, moving onto port 1111
Current number is 344768.12000000005, moving onto port 2222
Current number is 344769.12000000005, moving onto port 9765
The final answer is 344769.12
                                      



```

Once you have done all operations, what number do you get (rounded to 2 decimal places at the end of your calculation)?
*344769.12*

### [Hard] Encrypted Server Chit Chat 

The VM you have to connect to has a UDP server running on port 4000. Once connected to this UDP server, send a UDP message with the payload "hello" to receive more information. You will find some sort of encryption(using the AES-GCM cipher). Using the information from the server, write a script to retrieve the flag. Here are some useful thingsto keep in mind:

    sending and receiving data over a network is done in bytes
    the PyCA encryption library and functions takes its inputs as bytes
    AES GCM sends both encrypted plaintext and tag, and the server sends these values sequentially in the form of the encrypted plaintext followed by the tag

This machine may take up to 5 minutes to configure once deployed. Please be patient. 

Use this general approach(use Python3 here as well):

    Use the Python sockets library to create a UDP socket and send the aforementioned packets to the server
    use the PyCA encyption library and follow the instructions from the server



What is the flag?
Are some of the tags intentionally corrupted.

*THM{eW-sCrIpTiNg-AnD-cRyPtO}*

```

┌──(kali㉿kali)-[~/Downloads]
└─$ ping 10.10.166.103
PING 10.10.166.103 (10.10.166.103) 56(84) bytes of data.
64 bytes from 10.10.166.103: icmp_seq=1 ttl=252 time=469 ms
64 bytes from 10.10.166.103: icmp_seq=2 ttl=252 time=354 ms
64 bytes from 10.10.166.103: icmp_seq=3 ttl=252 time=318 ms
64 bytes from 10.10.166.103: icmp_seq=4 ttl=252 time=323 ms
^C
--- 10.10.166.103 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3010ms
rtt min/avg/max/mdev = 318.219/365.927/468.784/60.923 ms

prolly a windows machine

┌──(kali㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.166.103 --ulimit 5500 -b 65535 -- -A
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

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.166.103:22
Open 10.10.166.103:111
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-26 14:45 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:45
Completed NSE at 14:45, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:45
Completed NSE at 14:45, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:45
Completed NSE at 14:45, 0.00s elapsed
Initiating Ping Scan at 14:45
Scanning 10.10.166.103 [2 ports]
Completed Ping Scan at 14:45, 0.31s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 14:45
Completed Parallel DNS resolution of 1 host. at 14:45, 0.01s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 14:45
Scanning 10.10.166.103 [2 ports]
Discovered open port 111/tcp on 10.10.166.103
Discovered open port 22/tcp on 10.10.166.103
Completed Connect Scan at 14:45, 0.31s elapsed (2 total ports)
Initiating Service scan at 14:45
Scanning 2 services on 10.10.166.103
Completed Service scan at 14:45, 6.63s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.166.103.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:45
Completed NSE at 14:46, 8.53s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:46
Completed NSE at 14:46, 0.93s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:46
Completed NSE at 14:46, 0.00s elapsed
Nmap scan report for 10.10.166.103
Host is up, received conn-refused (0.31s latency).
Scanned at 2022-10-26 14:45:45 EDT for 17s

PORT    STATE SERVICE REASON  VERSION
22/tcp  open  ssh     syn-ack OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 1a929761d90375a7dd0d7c27dc1667ef (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCcPrLC019PWd4gNNv+cp+qeyVtx0IGBI6pRzLOG8f3IdtUZeqsMFz3UcCa1rvm9imJsxkhJ5HBVjIrmmYQAwBMNk/IKXolOfiaWwMQmwBxmq8v5GDbaQXP+Qg+ccJsQXRW94RWVAFL6u7TSishYNh2isZgVs39mpGA3Ag+m+Uu1VoZkkVD0kahtRnfLgLo2x+DWp3UZFc1w1bvVlJjFEKLx5Ba2eibj74uTbpiN82bB8WOUzmJtn8eCTB0OsOerNTG/rZ/gZXed/wpQEQ/U9+NJrMn6uOTnEetF00JcOTHKuK99IiI29a8gq/k1v9MW2M5jQ9THwz9e3tHYmoWeJzR
|   256 420352f27397ff8f01c1960bf96e06f4 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJrMurRdbu2mSQVmV0lR6LVQQVXjNs53ao5hqtoVc+r77jrpmz7YzjB4Fbz0C3VCjlHRO27FUfc9qi5TOpHPdGA=
|   256 3fef6fb4092b677f11806a7e8bc4b0e0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA95LYGDMeyYs3Dmsb4qgWJZHKdpOlkxo7puh1iJYFsZ
111/tcp open  rpcbind syn-ack 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:46
Completed NSE at 14:46, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:46
Completed NSE at 14:46, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:46
Completed NSE at 14:46, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.76 seconds



┌──(kali㉿kali)-[~/Downloads]
└─$ cat server_chit_chat.py 
import socket
import hashlib
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

def Main():
    host = sys.argv[1] #Get ip from user input
    port = 4000
    server = (host, port)
    iv = b'secureivl337' #Hardcoded for ease
    key = b'thisisaverysecretkeyl337'

    #Create socket *No need to connect as using UDP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    #Get initial message
    s.sendto(b"hello", server)
    print(recv(s))
    #Get the rest of the information
    s.sendto(b"ready", server)
    data = recv(s)
    print(data)
    checksum = data[104:136].hex() #Convert to hex to make comparison easier

    #Loop flags until checksums match
    while True:
        #Get the cipher text
        s.sendto(b"final", server)
        cText = bytes(recv(s))
        #Get the tag
        s.sendto(b"final", server)
        tag = bytes(recv(s))
        #Decrypt
        pText = decrypt(key, iv, cText, tag)
        #Compare
        if hashlib.sha256(pText).hexdigest() != checksum:
            continue
        else:
            print(f"The flag is: {pText}")
            break

def recv(s):
    try:
        data = s.recv(1024)
        return data
    except Exception as e:
        print(str(e))

def decrypt(key, iv, cText, tag):
    #Create AES GCM decryptor object
    decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag),
    backend = default_backend()).decryptor()
    #Return decrypted text
    return decryptor.update(cText) + decryptor.finalize()

if __name__ == '__main__':
    Main()


┌──(kali㉿kali)-[~/Downloads]
└─$ python3 server_chit_chat.py 10.10.166.103
b"You've connected to the super secret server, send a packet with the payload ready to receive more information"
b"key:thisisaverysecretkeyl337 iv:secureivl337 to decrypt and find the flag that has a SHA256 checksum of ]w\xf0\x18\xd2\xbfwx`T\x86U\xd8Ms\x82\xdc'\xd6\xce\x81n\xdeh\xf6]rb\x14c\xd9\xda send final in the next payload to receive all the encrypted flags"
The flag is: b'THM{eW-sCrIpTiNg-AnD-cRyPtO}'


```



[[The Docker Rodeo]]