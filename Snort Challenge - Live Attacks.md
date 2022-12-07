---
Put your snort skills into practice and defend against a live attack
---

### Scenario 1 | Brute-Force 

Use the attached VM to finish this task.

[+] THE NARRATOR


J&Y Enterprise is one of the top coffee retails in the world. They are known as tech-coffee shops and serve millions of coffee lover tech geeks and IT specialists every day. 


They are famous for specific coffee recipes for the IT community and unique names for these products. Their top five recipe names are;

![222](https://tryhackme-images.s3.amazonaws.com/user-uploads/6131132af49360005df01ae3/room-content/ad1f7bcbf706c98d82e3892763c280fa.png)

WannaWhite, ZeroSleep, MacDown, BerryKeep and CryptoY.


J&Y's latest recipe, "Shot4J", attracted great attention at the global coffee festival. J&Y officials promised that the product will hit the stores in the coming months. 


The super-secret of this recipe is hidden in a digital safe. Attackers are after this recipe, and J&Y enterprises are having difficulties protecting their digital assets.


Last week, they received multiple attacks and decided to work with you to help them improve their security level and protect their recipe secrets.  


This is your assistant J.A.V.A. (Just Another Virtual Assistant). She is an AI-driven virtual assistant and will help you notice possible anomalies. Hey, wait, something is happening...


[+] J.A.V.A.

Welcome, sir. I am sorry for the interruption. It is an emergency. Somebody is knocking on the door!

[+] YOU

Knocking on the door? What do you mean by "knocking on the door"?

[+] J.A.V.A.

We have a brute-force attack, sir.

[+] THE NARRATOR

This is not a comic book! Would you mind going and checking what's going on! Please... 

[+] J.A.V.A.

Sir, you need to observe the traffic with Snort and identify the anomaly first. Then you can create a rule to stop the brute-force attack. GOOD LUCK!
Answer the questions below
First of all, start Snort in sniffer mode and try to figure out the attack source, service and port.

Then, write an IPS rule and run Snort in IPS mode to stop the brute-force attack. Once you stop the attack properly, you will have the flag on the desktop!

Here are a few points to remember:

    Create the rule and test it with "-A console" mode. 
    Use "-A full" mode and the default log path to stop the attack.
    Write the correct rule and run the Snort in IPS "-A full" mode.
    Block the traffic at least for a minute and then the flag file will appear on your desktop.

Stop the attack and get the flag (which will appear on your Desktop)

 "IPS mode and Dropping Packets" is covered in the main Snort room TASK-7. https://tryhackme.com/room/snort

```
ubuntu@ip-10-10-72-206:~$ sudo su
root@ip-10-10-72-206:/home/ubuntu# ls
Desktop  Documents  Downloads  Music  Pictures  Public  Templates  Videos
root@ip-10-10-72-206:/home/ubuntu# cd Desktop/
root@ip-10-10-72-206:/home/ubuntu/Desktop# ls
root@ip-10-10-72-206:/home/ubuntu/Desktop# ls -lah
total 8.0K
drwxr-xr-x  2 ubuntu ubuntu 4.0K Feb  2  2022 .
drwxr-xr-x 22 ubuntu ubuntu 4.0K Dec  7 16:23 ..
root@ip-10-10-72-206:/home/ubuntu/Desktop# cd ..
root@ip-10-10-72-206:/home/ubuntu# ls
Desktop  Documents  Downloads  Music  Pictures  Public  Templates  Videos
root@ip-10-10-72-206:/home/ubuntu# cd /etc/snort/rules/
root@ip-10-10-72-206:/etc/snort/rules# ls
attack-responses.rules         community-web-dos.rules   policy.rules
backdoor.rules                 community-web-iis.rules   pop2.rules
bad-traffic.rules              community-web-misc.rules  pop3.rules
chat.rules                     community-web-php.rules   porn.rules
community-bot.rules            ddos.rules                rpc.rules
community-deleted.rules        deleted.rules             rservices.rules
community-dos.rules            dns.rules                 scan.rules
community-exploit.rules        dos.rules                 shellcode.rules
community-ftp.rules            experimental.rules        smtp.rules
community-game.rules           exploit.rules             snmp.rules
community-icmp.rules           finger.rules              sql.rules
community-imap.rules           ftp.rules                 telnet.rules
community-inappropriate.rules  icmp-info.rules           tftp.rules
community-mail-client.rules    icmp.rules                virus.rules
community-misc.rules           imap.rules                web-attacks.rules
community-nntp.rules           info.rules                web-cgi.rules
community-oracle.rules         local.rules               web-client.rules
community-policy.rules         misc.rules                web-coldfusion.rules
community-sip.rules            multimedia.rules          web-frontpage.rules
community-smtp.rules           mysql.rules               web-iis.rules
community-sql-injection.rules  netbios.rules             web-misc.rules
community-virus.rules          nntp.rules                web-php.rules
community-web-attacks.rules    oracle.rules              x11.rules
community-web-cgi.rules        other-ids.rules
community-web-client.rules     p2p.rules
root@ip-10-10-72-206:/etc/snort/rules# cat local.rules
# $Id: local.rules,v 1.11 2004/07/23 20:15:44 bmc Exp $
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.

root@ip-10-10-72-206:/etc/snort/rules# nano local.rules 
root@ip-10-10-72-206:/etc/snort/rules# cat local.rules 
# $Id: local.rules,v 1.11 2004/07/23 20:15:44 bmc Exp $
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
drop tcp any any -> any any (msg:"Drop traffic";sid:100001;rev:1;)


root@ip-10-10-72-206:/etc/snort# cat snort.conf | grep "local.rules"
include $RULE_PATH/local.rules

root@ip-10-10-72-206:/etc/snort/rules# sudo snort -c /etc/snort/snort.conf -q -Q --daq afpacket -i eth0:eth1 -A full

works but thm based seems disconnected

now adding my pass to user ubuntu to use ssh

┌──(kali㉿kali)-[~]
└─$ mkpasswd -m sha-512 Password1234
$6$k8T7DhT1SA37vAlT$KLkbHcBicXx26F.f3/c1KYKdJb1WrFGe/7U6d5ZfZMwvNotaLi5UUmuVOFpvYPGts2EDHqtLzyoPLIAU18DXB.

root@ip-10-10-252-13:/home/ubuntu# nano /etc/shadow

┌──(kali㉿kali)-[~]
└─$ ssh ubuntu@10.10.252.13
The authenticity of host '10.10.252.13 (10.10.252.13)' can't be established.
ED25519 key fingerprint is SHA256:e6IKCdjCEQ6wEQpUb7A3ZGGbJLGSADMQ4M3GMxQRAY4.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.252.13' (ED25519) to the list of known hosts.
ubuntu@10.10.252.13's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.8.0-1038-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Dec  7 16:54:53 UTC 2022

  System load:  1.29               Processes:             222
  Usage of /:   15.5% of 43.56GB   Users logged in:       0
  Memory usage: 18%                IPv4 address for eth0: 10.10.252.13
  Swap usage:   0%                 IPv4 address for eth1: 10.234.0.1


214 updates can be applied immediately.
107 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

/usr/bin/xhost:  unable to open display ""


yep works, i was disconnected because need to stop :)

now in desktop

THM{81b7fef657f8aaa6e4e200d616738254}

root@ip-10-10-252-13:/home/ubuntu# sudo snort -c /etc/snort/snort.conf -q -Q --daq afpacket -i eth0:eth1 -A console

12/07-17:12:01.751941  [Drop] [**] [1:100001:1] Drop traffic [**] [Priority: 0] {TCP} 10.10.245.36:46686 -> 10.10.140.29:22
12/07-17:12:01.937416  [Drop] [**] [1:100001:1] Drop traffic [**] [Priority: 0] {TCP} 10.8.19.103:50570 -> 10.10.252.13:22
12/07-17:12:02.165726  [Drop] [**] [1:100001:1] Drop traffic [**] [Priority: 0] {TCP} 10.10.245.36:46688 -> 10.10.140.29:22
12/07-17:12:02.818343  [Drop] [**] [1:100001:1] Drop traffic [**] [Priority: 0] {TCP} 10.10.140.29:22 -> 10.10.245.36:46674
12/07-17:12:02.838699  [Drop] [**] [1:100001:1] Drop traffic [**] [Priority: 0] {TCP} 10.10.245.36:46690 -> 10.10.140.29:22
12/07-17:12:03.555909  [Drop] [**] [1:100001:1] Drop traffic [**] [Priority: 0] {TCP} 10.10.245.36:46678 -> 10.10.140.29:22
12/07-17:12:03.559298  [Drop] [**] [1:100001:1] Drop traffic [**] [Priority: 0] {TCP} 10.10.245.36:46692 -> 10.10.140.29:22
12/07-17:12:03.581693  [Drop] [**] [1:100001:1] Drop traffic [**] [Priority: 0] {TCP} 10.10.140.29:22 -> 10.10.245.36:46838
12/07-17:12:03.624598  [Drop] [**] [1:100001:1] Drop traffic [**] [Priority: 0] {TCP} 10.10.245.36:46836 -> 10.10.140.29:22
12/07-17:12:03.730228  [Drop] [**] [1:100001:1] Drop traffic [**] [Priority: 0] {TCP} 10.10.245.36:46822 -> 10.10.140.29:22
12/07-17:12:03.750497  [Drop] [**] [1:100001:1] Drop traffic [**] [Priority: 0] {TCP} 10.10.245.36:46842 -> 10.10.140.29:22
12/07-17:12:04.458028  [Drop] [**] [1:100001:1] Drop traffic [**] [Priority: 0] {TCP} 10.10.245.36:46826 -> 10.10.140.29:22
12/07-17:12:04.471911  [Drop] [**] [1:100001:1] Drop traffic [**] [Priority: 0] {TCP} 10.10.245.36:46824 -> 10.10.140.29:22
12/07-17:12:04.488151  [Drop] [**] [1:100001:1] Drop traffic [**] [Priority: 0] {TCP} 10.10.245.36:46846 -> 10.10.140.29:22
12/07-17:12:04.500340  [Drop] [**] [1:100001:1] Drop traffic [**] [Priority: 0] {TCP} 10.10.245.36:46844 -> 10.10.140.29:22

```


 *THM{81b7fef657f8aaa6e4e200d616738254}*


What is the name of the service under attack?
*ssh*


What is the used protocol/port in the attack?
*tcp/22*

###  Scenario 2 | Reverse-Shell 

Use the attached VM to finish this task.


[+] THE NARRATOR

Good Job! Glad to have you in the team!


[+] J.A.V.A.

Congratulations sir. It is inspiring watching you work.


[+] You

Thanks team. J.A.V.A. can you do a quick scan for me? We haven't investigated the outbound traffic yet. 


[+] J.A.V.A.

Yes, sir. Outbound traffic investigation has begun. 


[+] THE NARRATOR

The outbound traffic? Why?


[+] YOU

We have stopped some inbound access attempts, so we didn't let the bad guys get in. How about the bad guys who are already inside? Also, no need to mention the insider risks, huh? The dwell time is still around 1-3 months, and I am quite new here, so it is worth checking the outgoing traffic as well.


[+] J.A.V.A.

Sir, persistent outbound traffic is detected. Possibly a reverse shell...


[+] YOU

You got it!


[+] J.A.V.A.

Sir, you need to observe the traffic with Snort and identify the anomaly first. Then you can create a rule to stop the reverse shell. GOOD LUCK!
Answer the questions below
First of all, start Snort in sniffer mode and try to figure out the attack source, service and port.

Then, write an IPS rule and run Snort in IPS mode to stop the brute-force attack. Once you stop the attack properly, you will have the flag on the desktop!

Here are a few points to remember:

    Create the rule and test it with "-A console" mode. 
    Use "-A full" mode and the default log path to stop the attack.
    Write the correct rule and run the Snort in IPS "-A full" mode.
    Block the traffic at least for a minute and then the flag file will appear on your desktop.

Stop the attack and get the flag (which will appear on your Desktop)

You can easily drop all the traffic coming to a specific port as a rapid response.

```
again replacing

┌──(kali㉿kali)-[~]
└─$ mkpasswd -m sha-512 Password1234
$6$WzIYjkxUA0Q6QYCL$A1EcSuJVv4UMmlTaM4w/NMG8.uLZ02a7wJwVpUamQxfxnkfgYEVcLSpYy/bC42hrZnQ8vDcAqXATWLod58/ot0
                                                                                             
┌──(kali㉿kali)-[~]
└─$ ssh ubuntu@10.10.89.155
The authenticity of host '10.10.89.155 (10.10.89.155)' can't be established.
ED25519 key fingerprint is SHA256:GHvuqyCyMreJYZjBh6SdD7miBXbe9oviCxIMlOmn47Q.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.89.155' (ED25519) to the list of known hosts.
ubuntu@10.10.89.155's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.8.0-1038-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Dec  7 17:19:29 UTC 2022

  System load:  1.51               Processes:             219
  Usage of /:   15.6% of 43.56GB   Users logged in:       0
  Memory usage: 18%                IPv4 address for eth0: 10.10.89.155
  Swap usage:   0%                 IPv4 address for eth1: 10.234.0.1


214 updates can be applied immediately.
107 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

/usr/bin/xhost:  unable to open display ""
ubuntu@ip-10-10-89-155:~$ sudo su

root@ip-10-10-89-155:/home/ubuntu# nano /etc/snort/rules/local.rules 
root@ip-10-10-89-155:/home/ubuntu# cat /etc/snort/rules/local.rules 
# $Id: local.rules,v 1.11 2004/07/23 20:15:44 bmc Exp $
# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.
drop tcp any any -> any any (msg:"Drop traffic";sid:100001;rev:1;)

root@ip-10-10-89-155:/home/ubuntu# sudo snort -c /etc/snort/snort.conf -q -Q --daq afpacket -i eth0:eth1 -A full
^C*** Caught Int-Signal

when see disconnected so get the flag

root@ip-10-10-89-155:/home/ubuntu# cd Desktop/
root@ip-10-10-89-155:/home/ubuntu/Desktop# ls
flag.txt
root@ip-10-10-89-155:/home/ubuntu/Desktop# cat flag.txt 
THM{0ead8c494861079b1b74ec2380d2cd24}

root@ip-10-10-89-155:/home/ubuntu/Desktop# sudo snort -c /etc/snort/snort.conf -q -Q --daq afpacket -i eth0:eth1 -A console

12/07-17:25:50.626132  [Drop] [**] [1:100001:1] Drop traffic [**] [Priority: 0] {TCP} 10.10.144.156:4444 -> 10.10.196.55:54142
12/07-17:25:50.692051  [Drop] [**] [1:100001:1] Drop traffic [**] [Priority: 0] {TCP} 10.10.144.156:4444 -> 10.10.196.55:54138
12/07-17:25:50.736850  [Drop] [**] [1:100001:1] Drop traffic [**] [Priority: 0] {TCP} 10.10.144.156:4444 -> 10.10.196.55:54144
12/07-17:25:50.819481  [Drop] [**] [1:100001:1] Drop traffic [**] [Priority: 0] {TCP} 10.8.19.103:33836 -> 10.10.89.155:22
12/07-17:25:50.847577  [Drop] [**] [1:100001:1] Drop traffic [**] [Priority: 0] {TCP} 10.10.144.156:4444 -> 10.10.196.55:54146
12/07-17:25:50.935890  [Drop] [**] [1:100001:1] Drop traffic [**] [Priority: 0] {TCP} 10.10.196.55:54148 -> 10.10.144.156:4444
12/07-17:25:51.253335  [Drop] [**] [1:100001:1] Drop traffic [**] [Priority: 0] {TCP} 10.10.144.156:4444 -> 10.10.196.55:54150
12/07-17:25:51.277003  [Drop] [**] [1:100001:1] Drop traffic [**] [Priority: 0] {TCP} 10.10.144.156:4444 -> 10.10.196.55:54152
12/07-17:25:51.377170  [Drop] [**] [1:100001:1] Drop traffic [**] [Priority: 0] {TCP} 10.10.144.156:4444 -> 10.10.196.55:54154
12/07-17:25:51.495410  [Drop] [**] [1:100001:1] Drop traffic [**] [Priority: 0] {TCP} 10.10.144.156:4444 -> 10.10.196.55:54156
12/07-17:25:52.337351  [Drop] [**] [1:100001:1] Drop traffic [**] [Priority: 0] {TCP} 10.10.144.156:4444 -> 10.10.196.55:54172
12/07-17:25:52.471892  [Drop] [**] [1:100001:1] Drop traffic [**] [Priority: 0] {TCP} 10.10.144.156:4444 -> 10.10.196.55:54242
12/07-17:25:52.702459  [Drop] [**] [1:100001:1] Drop traffic [**] [Priority: 0] {TCP} 10.10.144.156:4444 -> 10.10.196.55:54306
12/07-17:25:52.929806  [Drop] [**] [1:100001:1] Drop traffic [**] [Priority: 0] {TCP} 10.10.144.156:4444 -> 10.10.196.55:54328
12/07-17:25:52.953497  [Drop] [**] [1:100001:1] Drop traffic [**] [Priority: 0] {TCP} 10.10.144.156:4444 -> 10.10.196.55:54332
12/07-17:25:53.071735  [Drop] [**] [1:100001:1] Drop traffic [**] [Priority: 0] {TCP} 10.10.144.156:4444 -> 10.10.196.55:54366
12/07-17:25:53.178174  [Drop] [**] [1:100001:1] Drop traffic [**] [Priority: 0] {TCP} 10.10.196.55:54114 -> 10.10.144.156:4444
^C*** Caught Int-Signal

https://www.speedguide.net/port.php?port=4444#:~:text=4444%20(TCP%2FUDP)%20is,proxy%20also%20uses%20this%20port.
4444 (TCP/UDP) is the default listener port for Metasploit.
I2P HTTP/S proxy also uses this port.
```


*THM{0ead8c494861079b1b74ec2380d2cd24}*


What is the used protocol/port in the attack?
*tcp/4444*



Which tool is highly associated with this specific port number?
*Metasploit*



[[Snort Challenge - The Basics]]