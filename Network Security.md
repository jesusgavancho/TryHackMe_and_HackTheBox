---
Learn about network security, understand attack methodology, and practice hacking into a target server.
---

###  Introduction

A computer network is a group of computers and devices connected with each other. Network security focuses on protecting the security of these devices and the links connecting them. (In more precise terms, network security refers to the devices, technologies, and processes to protect the confidentiality, integrity, and availability of a computer network and the data on it.)

Network security consists of different hardware and software solutions to achieve the set security goals. Hardware solutions refer to the devices you set up in your network to protect your network security. They are hardware, so you can literally hold them. A hardware appliance might look something like the image below.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5a7527aeef27ad74320defaf1bae8d6d.png)

Examples of hardware appliances include:

-   Firewall appliance: The firewall allows and blocks connections based on a predefined set of rules. It restricts what can enter and what can leave a network.
-   Intrusion Detection System (IDS) appliance: An IDS detects system and network intrusions and intrusion attempts. It tries to detect attackers’ attempts to break into your network.
-   Intrusion Prevention System (IPS) appliance: An IPS blocks detected intrusions and intrusion attempts. It aims to prevent attackers from breaking into your network.
-   Virtual Private Network (VPN) concentrator appliance: A VPN ensures that the network traffic cannot be read nor altered by a third party. It protects the confidentiality (secrecy) and integrity of the sent data.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/ab8ec75d3343f5d49c616f6b31840e49.png) 
On the other hand, we have software security solutions. Common examples are:

-   Antivirus software: You install an antivirus on your computer or smartphone to detect malicious files and block them from executing.
-   Host firewall: Unlike the firewall appliance, a hardware device, a host firewall is a program that ships as part of your system, or it is a program that you install on your system. For instance, MS Windows includes Windows Defender Firewall, and Apple macOS includes an application firewall; both are host firewalls.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/e2ecef770b63d3af285688bb5e141bbc.png)

According to the [Cost of a Data Breach Report 2021](https://newsroom.ibm.com/2021-07-28-IBM-Report-Cost-of-a-Data-Breach-Hits-Record-High-During-Pandemic) by IBM Security, a data breach in 2021 cost a company $4.24 million per incident on average, in comparison with $3.86 million in 2020. The average cost changes with the sector and the country. For example, the average total cost for a data breach was $9.23 million for the healthcare sector, while $3.79 million for the education sector.

  
What type of firewall is Windows Defender Firewall? *Host firewall*

### Methodology

Every “operation” requires some form of planning to achieve success. If you are interested in wildlife photography, you cannot just grab a camera and head to the jungle unless you don’t care about the outcome. For a safe and successful wildlife photography tour, you would need to learn more about the animals you want to shoot with your camera. This includes the habits of the animals and the dangers to avoid. The same would apply to a military operation against a target or breaking into a target network.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/9cba92802ccc445a7690301b3ea49283.png)
Breaking into a target network usually includes a number of steps. According to [Lockheed Martin](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html), the Cyber Kill Chain has seven steps:

1.  Recon: Recon, short for reconnaissance, refers to the step where the attacker tries to learn as much as possible about the target. Information such as the types of servers, operating system, IP addresses, names of users, and email addresses, can help the attack’s success.
2.  Weaponization: This step refers to preparing a file with a malicious component, for example, to provide the attacker with remote access.
3.  Delivery: Delivery means delivering the “weaponized” file to the target via any feasible method, such as email or USB flash memory.
4.  Exploitation: When the user opens the malicious file, their system executes the malicious component.
5.  Installation: The previous step should install the malware on the target system.
6.  Command & Control (C2): The successful installation of the malware provides the attacker with a command and control ability over the target system.
7.  Actions on Objectives: After gaining control over one target system, the attacker has achieved their objectives. One example objective is Data Exfiltration (stealing target’s data).

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/a8e61f1f9a2ea3612d3bf84f9a11f41c.png)

Another analogy would be a thief interested in a target house. The thief will spend some time learning about the target house, who lives there, when they leave, and when they return home. The thief will determine whether they have security cameras and alarm systems. Once enough information has been gathered, the thief will plan the best entrance strategy. Physical theft planning and execution resemble, in a way, the malicious attack that aims to break into a network and steal data.

In the next task, we will carry out a practical example of the Cyber Kill Chain.

  
During which step of the Cyber Kill Chain does the attacker gather information about the target? *recon*

### Practical Example of Network Security

We will try to hack into a target Linux system in this task. We assume that you have never used a Linux system before, and we will explain accordingly.

Start the AttackBox by clicking on the blue “Start AttackBox” button at the top right of the room. Start the attached machine by clicking on the green “Start Machine” button at the top right of this task. It usually takes a minute or two to load fully. Once they are both ready, you should use the AttackBox, which uses the right half of your screen by default.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/e23ead9afc25ba400e51fa0b13d16fe2.png)

On the AttackBox, start the terminal by clicking on the terminal icon shown in the image above. You will be writing all the commands you need on the terminal shown below.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/46a993d315974a57dceeb933c561849b.png)

The first step of our attack is **Recon**; we can speed up our reconnaissance activities using different tools that gather information about the various aspects related to the target. For simplicity, we will use a single tool in this task, Nmap, short for _Network Mapper_. Nmap is a network scanner that helps us discover running machines and any programs running on them that are visible to the outside world. The IP address of the target is `10.10.176.167`. We can scan it by running `nmap 10.10.176.167` at the terminal prompt.

AttackBox Terminal

```shell-session
root@AttackBox# nmap 10.10.176.167
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-06 17:38 EEST
Nmap scan report for 10.20.30.130
Host is up (0.00024s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 0.33 seconds
```

We just discovered three services running:

1.  FTP server: FTP stands for File Transfer Protocol and is used to transfer files between machines.
2.  SSH server: SSH stands for Secure Shell and is used for secure remote login. In other words, it allows you to execute commands on a remote system securely.
3.  HTTP server: HTTP stands for Hypertext Transfer Protocol and is used for the web. Whenever you are browsing the web, you are using HTTP or HTTPS. HTTPS is the secure (encrypted) version of HTTP.

You can also notice that Nmap reports on whether the host is up based on whether it receives any response from it. This is useful to know when no ports are open or accessible.

Let’s try to gather more information about the FTP server.

1.  We will connect to the target FTP server by typing on the AttackBox’s terminal `ftp 10.10.176.167`.
2.  Next, we will try to log in using the login `anonymous` to see if this FTP server supports anonymous logins. To our luck, it worked.
3.  We try to see the files available using the command `ls`, short for _list_. We get a list of the filenames along with their details.
4.  If you are curious about any file, you can download it using `get filename`. I wonder what the file `secret.txt` contains, so let’s download it using `get secret.txt`.
5.  Once you download the files, type `exit` or `bye` to quit the FTP client.

The above interaction with the FTP server is shown in the terminal output below.

AttackBox Terminal

```shell-session
root@AttackBox# ftp 10.10.176.167
Connected to 10.10.176.167 (MACHINE_IP).
220 (vsFTPd 3.0.3)
Name (MACHINE_IP:root): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
227 Entering Passive Mode (10,20,30,130,181,190).
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp        425351 Apr 06 11:22 2680-0.txt
-rw-r--r--    1 ftp      ftp           356 Apr 06 11:22 2680.epub
-rw-r--r--    1 ftp      ftp        251857 Apr 06 11:22 55317-0.txt
-rw-r--r--    1 ftp      ftp           358 Apr 06 11:22 55317.epub
-rwxr-xr-x    1 ftp      ftp           214 Apr 06 11:22 backup.sh
-rw-r--r--    1 ftp      ftp            23 Apr 06 11:22 secret.txt
226 Directory send OK.
ftp> get secret.txt 
local: secret.txt remote: secret.txt
227 Entering Passive Mode (10,20,30,130,159,46).
150 Opening BINARY mode data connection for secret.txt (23 bytes).
226 Transfer complete.
23 bytes received in 0.00107 secs (21.48 Kbytes/sec)
ftp> exit
221 Goodbye.
```

Looking at the files, we notice six files: three `txt` files, two `epub` files, and one `sh` file. The first two extensions are for text files and ebooks, while the `sh` extension indicates that the file is a shell script. A shell script usually contains a group of commands that needs to be performed repetitively.

After we downloaded the file `secret.txt` with the FTP command `get secret.txt` and exited the FTP client using `exit`, we returned to the terminal. Let’s display the contents of the file `secret.txt` using `cat secret.txt`.

AttackBox Terminal

```shell-session
root@AttackBox# cat secret.txt 
password: ABC789xyz123
```

We have kept the password hidden so you can try it for yourself. Repeat the above steps till you can display the contents of `secret.txt` and use it to answer the first question in this task.

It must be the password of one of the accounts unintentionally copied to a public FTP server. Let’s try it to see if it works with the root account. The root account has full privileges on a Linux system, meaning that it can read and write any file and install and remove any program. At the terminal, we type `ssh root@10.10.176.167`. We will be asked for the password, so let’s try the password we discovered in the FTP server.

AttackBox Terminal

```shell-session
root@AttackBox# ssh root@10.10.176.167
root@10.10.176.167's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-107-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu  7 Apr 08:16:42 UTC 2022

  System load:  0.15              Processes:              225
  Usage of /:   64.6% of 6.53GB   Users logged in:        0
  Memory usage: 19%               IPv4 address for ens33: MACHINE_IP
  Swap usage:   0%

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

0 updates can be applied immediately.


Last login: Thu Apr  7 07:53:28 2022 from 10.10.10.1
```

Congratulations! You now have complete control over the target server. Let’s collect a couple of flags. After logging in as `root`, we used the following Linux commands:

1.  `pwd`, short for _print working directory_, to see where we are in the system. We are in the `/root` directory.
2.  `ls` to list the files. We notice a `flag.txt`.
3.  Use `cat flag.txt` to answer the second question in this task.

AttackBox Terminal

```shell-session
root@AttackBox# pwd
/root
root@AttackBox# ls
flag.txt  snap
root@AttackBox# cat flag.txt 
THM{FTP_SERVER_OWNED}
```

Because we are logged in as root, we have full access to all files, including other users’ files. Let’s try this out. We executed the following Linux commands:

1.  `cd /home` to go to the directory containing all the users’ home directories. `cd` is short for _change directory_.
2.  We run `ls` while in `/home`. We notice `librarian` is one of the users on the system. However, we have system administrator (`root`) privileges to check the contents of his home folder.
3.  `cd librarian` to go to the user’s directory.
4.  `pwd` to confirm that we are at `/home/librarian`.
5.  `ls` shows that `librarian` has a single file `flag.txt`.
6.  We can print the text file contents using `cat flag.txt`. Use this to answer the third question in this task.

AttackBox Terminal

```shell-session
root@AttackBox# cd /home
root@AttackBox# ls
ftpsecure  librarian  strategos
root@AttackBox# cd librarian/
root@AttackBox# pwd
/home/librarian
root@AttackBox# ls
flag.txt
root@AttackBox# cat flag.txt 
THM{LIBRARIAN_ACCOUNT_COMPROMISED}
```

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/a708c20aa1243c8e2be30bb9e74bd663.png)

Let’s summarize what we have done in this task to get `root` access on the target system of IP address `10.10.176.167`:

1.  We used `nmap` to learn about the running services.
2.  We connected to the FTP server to learn more about its configuration.
3.  We discovered a file containing the root password mistakenly copied to a public folder.
4.  We used the password we found, allowing us to log in successfully.
5.  We gained access to all the users’ files.

  
What is the password in the `secret.txt` file?
*ABC789xyz123*
  
What is the content of the `flag.txt` in the `/root` directory?
*THM{FTP_SERVER_OWNED}*
  
What is the content of the `flag.txt` in the `/home/librarian` directory?

*THM{LIBRARIAN_ACCOUNT_COMPROMISED}*

[[Operating System Security]]
