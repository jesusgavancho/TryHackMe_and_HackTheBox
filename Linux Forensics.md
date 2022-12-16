---
Learn about the common forensic artifacts found in the file system of Linux Operating System
---
![](https://assets.tryhackme.com/additional/linuxforensics/room-banner.png)


###  Introduction

In the previous few rooms, we learned about performing forensics on Windows machines. While Windows is still the most common Desktop Operating System, especially in enterprise environments, Linux also constitutes a significant portion of the pie. Especially, Linux is very common in servers that host different services for enterprises. 

In an Enterprise environment, the two most common entry points for an external attacker are either through public-facing servers or through endpoints used by individuals. Since Linux can be found in any of these two endpoints, it is useful to know how to find forensic information on a Linux machine, which is the focus of this room.

## Learning Objectives:

After completing this room, we will have learned:

-   An introduction to Linux and its different flavors.
-   Finding OS, account, and system information on a Linux machine
-   Finding information about running processes, executed processes, and processes that are scheduled to run
-   Finding system log files and identifying information from them
-   Common third-party applications used in Linux and their logs

### Linux Forensics

The Linux Operating System can be found in a lot of places. While it might not be as easy to use as Windows or macOS, it has its own set of advantages that make its use widespread. It is found in the Web servers you interact with, in your smartphone, and maybe, even in the entertainment unit of your car. One of the reasons for this versatility is that Linux is an open-source Operating System with many different flavors. It is also very lightweight and can run on very low resources. It can be considered modular in nature and can be customized as per requirements, meaning that only those components can be installed which are required. All of these reasons make Linux an important part of our lives.

For learning more about Linux, it is highly recommended that you go through the [Linux Fundamentals 1](https://tryhackme.com/room/linuxfundamentalspart1), [Linux Fundamentals 2](https://tryhackme.com/room/linuxfundamentalspart2), and [Linux Fundamentals 3](https://tryhackme.com/room/linuxfundamentalspart3) rooms on TryHackMe.

## Linux Distributions:![Different Linux Distributions](https://tryhackme-images.s3.amazonaws.com/user-uploads/61306d87a330ed00419e22e7/room-content/a75df704781c9f5e5fb3a63851e26f9e.png)

Linux comes in many different flavors, also called distributions. There are minor differences between these distributions. Sometimes the differences are mostly cosmetic, while sometimes the differences are a little more pronounced. Some of the common Linux distributions include:

-   Ubuntu
-   Redhat
-   ArchLinux
-   Open SUSE
-   Linux Mint
-   CentOS
-   Debian

For the purpose of this room, we will be working on the Ubuntu distribution. So let's move on to the next task to learn to perform forensics on Linux.

### OS and account information

As we did in the Windows Forensics rooms, we will start by identifying the system and finding basic information about the system. In the case of Windows, we identified that the Windows Registry contains information about the Windows machine. For a Linux system, everything is stored in a file. Therefore, to identify forensic artifacts, we will need to know the locations of these files and how to read them. Below, we will start by identifying System information on a Linux host.

## Access the attached machine

Let's start by accessing the machine attached to the room. To access the machine, press the "Start Machine" icon, which will open the machine in the split view.![Press the button in the top right corner of the task to start the machine](https://tryhackme-images.s3.amazonaws.com/user-uploads/61306d87a330ed00419e22e7/room-content/820faae29e0698495f229bdf0d591230.png)

Alternatively, you can access the machine using the following credentials:

**Username**: Ubuntu

**Password**: 123456

## OS release information

To find the OS release information, we can use the `cat` utility to read the file located at `/etc/os-release`.To know more about the `cat` utility, you can read its man page.

`man cat`

The below terminal shows the OS release information.

OS release

```shell-session
user@machine$ cat /etc/os-release 
NAME="Ubuntu"
VERSION="20.04.1 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.1 LTS"
VERSION_ID="20.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=focal
UBUNTU_CODENAME=focal
```

## User accounts

The `/etc/passwd` file contains information about the user accounts that exist on a Linux system. We can use the `cat` utility to read this file. The output contains 7 colon-separated fields, describing username, password information, user id (uid), group id (gid), description, home directory information, and the default shell that executes when the user logs in. It can be noticed that just like Windows, the user-created user accounts have uids 1000 or above. You can use the following command to make it more readable:

`cat /etc/passwd| column -t -s :`  

User accounts

```shell-session
user@machine$cat /etc/passwd| column -t -s :
root                  x  0      0      root                                /root                    /bin/bash
daemon                x  1      1      daemon                              /usr/sbin                /usr/sbin/nologin
bin                   x  2      2      bin                                 /bin                     /usr/sbin/nologin
sys                   x  3      3      sys                                 /dev                     /usr/sbin/nologin
sync                  x  4      65534  sync                                /bin                     /bin/sync
games                 x  5      60     games                               /usr/games               /usr/sbin/nologin
.
.
.
.
.
ubuntu                x  1000   1000   Ubuntu                              /home/ubuntu             /bin/bash
pulse                 x  123    130    PulseAudio daemon,,,                /var/run/pulse           /usr/sbin/nologin
tryhackme             x  1001   1001   tryhackme,,,                        /home/tryhackme          /bin/bash
```

In the above command, we can see the information for the user ubuntu. The username is ubuntu, its password information field shows `x`, which signifies that the password information is stored in the `/etc/shadow` file. The uid of the user is 1000. The gid is also 1000. The description, which often contains the full name or contact information, mentions the name Ubuntu. The home directory is set to `/home/ubuntu`, and the default shell is set to `/bin/bash`. We can see similar information about other users from the file as well.

## Group Information

The `/etc/group` file contains information about the different user groups present on the host. It can be read using the cat utility.

Group information

```shell-session
user@machine$ cat /etc/group
root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog,ubuntu
tty:x:5:syslog
```

We can see that the user `ubuntu` belongs to the `adm` group, which has a password stored in the `/etc/shadow` file, signified by the `x` character. The gid is 4, and the group contains 2 users, Syslog, and ubuntu.

## Sudoers List

A Linux host allows only those users to elevate privileges to `sudo`, which are present in the Sudoers list. This list is stored in the file `/etc/sudoers` and can be read using the `cat` utility. You will need to elevate privileges to access this file.

Sudoers list

```shell-session
user@machine$ sudo cat /etc/sudoers
#
# This file MUST be edited with the 'visudo' command as root.
#
# Please consider adding local content in /etc/sudoers.d/ instead of
# directly modifying this file.
#
# See the man page for details on how to write a sudoers file.
#
Defaults	env_reset
Defaults	mail_badpass
Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"

# Host alias specification

# User alias specification

# Cmnd alias specification

# User privilege specification
root	ALL=(ALL:ALL) ALL

# Members of the admin group may gain root privileges
%admin ALL=(ALL) ALL

# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# See sudoers(5) for more information on "#include" directives:

#includedir /etc/sudoers.d
```

## Login information

In the /var/log directory, we can find log files of all kinds including `wtmp` and `btmp`. The `btmp` file saves information about failed logins, while the `wtmp` keeps historical data of logins. These files are not regular text files that can be read using `cat`, `less` or `vim`; instead, they are binary files, which have to be read using the `last` utility. You can learn more about the `last` utility by reading its man page.

`man last`

The following terminal shows the contents of `wtmp` being read using the `last` utility.

Login information

```shell-session
user@machine$ sudo last -f /var/log/wtmp
reboot   system boot  5.4.0-1029-aws   Tue Mar 29 17:28   still running
reboot   system boot  5.4.0-1029-aws   Tue Mar 29 04:46 - 15:52  (11:05)
reboot   system boot  5.4.0-1029-aws   Mon Mar 28 01:35 - 01:51 (1+00:16)

wtmp begins Mon Mar 28 01:35:10 2022
```

## Authentication logs

Every user that authenticates on a Linux host is logged in the auth log. The auth log is a file placed in the location `/var/log/auth.log`. It can be read using the `cat` utility, however, given the size of the file, we can use `tail`, `head`, `more` or `less` utilities to make it easier to read.

Auth logs

```shell-session
user@machine$ cat /var/log/auth.log |tail
Mar 29 17:28:48 tryhackme gnome-keyring-daemon[989]: The PKCS#11 component was already initialized
Mar 29 17:28:48 tryhackme gnome-keyring-daemon[989]: The SSH agent was already initialized
Mar 29 17:28:49 tryhackme polkitd(authority=local): Registered Authentication Agent for unix-session:2 (system bus name :1.73 [/usr/lib/x86_64-linux-gnu/polkit-mate/polkit-mate-authentication-agent-1], object path /org/mate/PolicyKit1/AuthenticationAgent, locale en_US.UTF-8)
Mar 29 17:28:58 tryhackme pkexec[1618]: ubuntu: Error executing command as another user: Not authorized [USER=root] [TTY=unknown] [CWD=/home/ubuntu] [COMMAND=/usr/lib/update-notifier/package-system-locked]
Mar 29 17:29:09 tryhackme dbus-daemon[548]: [system] Failed to activate service 'org.bluez': timed out (service_start_timeout=25000ms)
Mar 29 17:30:01 tryhackme CRON[1679]: pam_unix(cron:session): session opened for user root by (uid=0)
Mar 29 17:30:01 tryhackme CRON[1679]: pam_unix(cron:session): session closed for user root
Mar 29 17:49:52 tryhackme sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/cat /etc/sudoers
Mar 29 17:49:52 tryhackme sudo: pam_unix(sudo:session): session opened for user root by (uid=0)
Mar 29 17:49:52 tryhackme sudo: pam_unix(sudo:session): session closed for user root
```

In the above log file, we can see that the user ubuntu elevated privileges on `Mar 29 17:49:52` using `sudo` to run the command `cat /etc/sudoers`. We can see the subsequent session opened and closed events for the root user, which were a result of the above-mentioned privilege escalation.

Answer the questions below

In the attached VM, there is a user account named tryhackme. What is the uid of this account?

See the /etc/passwd file

```
ubuntu@Linux4n6:~$ tail /etc/passwd | column -t -s :
cups-pk-helper     x  121   127   user for cups-pk-helper service,,,  /home/cups-pk-helper     /usr/sbin/nologin
geoclue            x  122   128   /var/lib/geoclue                    /usr/sbin/nologin
pulse              x  123   130   PulseAudio daemon,,,                /var/run/pulse           /usr/sbin/nologin
speech-dispatcher  x  124   29    Speech Dispatcher,,,                /run/speech-dispatcher   /bin/false
saned              x  125   132   /var/lib/saned                      /usr/sbin/nologin
nm-openvpn         x  126   133   NetworkManager OpenVPN,,,           /var/lib/openvpn/chroot  /usr/sbin/nologin
colord             x  127   134   colord colour management daemon,,,  /var/lib/colord          /usr/sbin/nologin
hplip              x  128   7     HPLIP system user,,,                /run/hplip               /bin/false
gdm                x  129   135   Gnome Display Manager               /var/lib/gdm3            /bin/false
tryhackme          x  1001  1001  tryhackme,,,                        /home/tryhackme          /bin/bash
```

*1001*

Which two users are the members of the group `audio`?

See group information

```
ubuntu@Linux4n6:~$ cat /etc/group | grep audio
audio:x:29:ubuntu,pulse

```

*ubuntu,pulse*

A session was started on this machine on Sat Apr 16 20:10. How long did this session last?

Get this info from wtmp

```
ubuntu@Linux4n6:~$ sudo last -f /var/log/wtmp
reboot   system boot  5.4.0-1029-aws   Fri Dec 16 21:51   still running
reboot   system boot  5.4.0-1029-aws   Sun Apr 17 21:00   still running
reboot   system boot  5.4.0-1029-aws   Sun Apr 17 20:50 - 21:00  (00:10)
reboot   system boot  5.4.0-1029-aws   Sun Apr 17 09:40 - 09:43  (00:03)
reboot   system boot  5.4.0-1029-aws   Sun Apr 17 05:01 - 09:23  (04:22)
reboot   system boot  5.4.0-1029-aws   Sat Apr 16 22:51 - 23:10  (00:18)
reboot   system boot  5.4.0-1029-aws   Sat Apr 16 20:10 - 21:43  (01:32)

wtmp begins Sat Apr 16 20:10:29 2022
```

*01:32*

### System Configuration

Once we have identified the OS and account information, we can start looking into the system configuration of the host.

## Hostname

The hostname is stored in the `/etc/hostname` file on a Linux Host. It can be accessed using the `cat` utility.

Hostname

```shell-session
user@machine$ cat /etc/hostname 
tryhackme
```

## Timezone

Timezone information is a significant piece of information that gives an indicator of the general location of the device or the time window it might be used in. Timezone information can be found at the location`/etc/timezone` and it can be read using the `cat` utility.

Timezone

```shell-session
user@machine$ cat /etc/timezone
Etc/UTC
```

## Network Configuration

To find information about the network interfaces, we can `cat` the `/etc/network/interfaces` file. The output on your machine might be different from the one shown here, depending on your configuration.

Network interfaces

```shell-session
user@machine$ cat /etc/network/interfaces
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
```

Similarly, to find information about the MAC and IP addresses of the different interfaces, we can use the `ip` utility. To learn more about the `ip` utility, we can see its `man` page.

`man ip`

The below terminal shows the usage of the `ip` utility. Note that this will only be helpful on a live system.

IP information

```shell-session
user@machine$ ip address show 
1: lo:  mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0:  mtu 9001 qdisc mq state UP group default qlen 1000
    link/ether 02:20:61:f1:3c:e9 brd ff:ff:ff:ff:ff:ff
    inet 10.10.95.252/16 brd 10.10.255.255 scope global dynamic eth0
       valid_lft 2522sec preferred_lft 2522sec
    inet6 fe80::20:61ff:fef1:3ce9/64 scope link 
       valid_lft forever preferred_lft forever
```

## Active network connections

On a live system, knowing the active network connections provides additional context to the investigation. We can use the `netstat` utility to find active network connections on a Linux host. We can learn more about the `netstat` utility by reading its `man` page.

`man netstat`

The below terminal shows the usage of the `netstat` utility.

Active network connections

```shell-session
user@machine$ netstat -natp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:5901          0.0.0.0:*               LISTEN      829/Xtigervnc       
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:60602         127.0.0.1:5901          ESTABLISHED -                   
tcp        0      0 10.10.95.252:57432      18.66.171.77:443        ESTABLISHED -                   
tcp        0      0 10.10.95.252:80         10.100.1.33:51934       ESTABLISHED -                   
tcp        0      0 127.0.0.1:5901          127.0.0.1:60602         ESTABLISHED 829/Xtigervnc       
tcp6       0      0 ::1:5901                :::*                    LISTEN      829/Xtigervnc       
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 ::1:631                 :::*                    LISTEN      -               
```

## Running processes

If performing forensics on a live system, it is helpful to check the running processes. The `ps` utility shows details about the running processes. To find out about the `ps` utility, we can use the `man` page.

`man ps`

The below terminal shows the usage of the `ps` utility.

Running processes

```shell-session
user@machine$ ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         729  0.0  0.0   7352  2212 ttyS0    Ss+  17:28   0:00 /sbin/agetty -o -p -- \u --keep-baud 115200,38400,9600 ttyS0 vt220
root         738  0.0  0.0   5828  1844 tty1     Ss+  17:28   0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
root         755  0.0  1.5 272084 63736 tty7     Ssl+ 17:28   0:00 /usr/lib/xorg/Xorg -core :0 -seat seat0 -auth /var/run/lightdm/root/:0 -nolisten tcp vt7 -novtswitch
ubuntu      1672  0.0  0.1   5264  4588 pts/0    Ss   17:29   0:00 bash
ubuntu      1985  0.0  0.0   5892  2872 pts/0    R+   17:40   0:00 ps au
```

## DNS information

The file `/etc/hosts` contains the configuration for the DNS name assignment. We can use the `cat` utility to read the hosts file. To learn more about the hosts file, we can use the `man`page.

`man hosts`

The below terminal shows a sample output of the hosts file.

hosts file

```shell-session
user@machine$ cat /etc/hosts
127.0.0.1 localhost

# The following lines are desirable for IPv6 capable hosts
::1 ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts
```

The information about DNS servers that a Linux host talks to for DNS resolution is stored in the resolv.conf file. Its location is `/etc/resolv.conf`. We can use the `cat` utility to read this file.

Resolv.conf

```shell-session
user@machine$ cat /etc/resolv.conf 
# This file is managed by man:systemd-resolved(8). Do not edit.
#
# This is a dynamic resolv.conf file for connecting local clients to the
# internal DNS stub resolver of systemd-resolved. This file lists all
# configured search domains.
#
# Run "resolvectl status" to see details about the uplink DNS servers
# currently in use.
#
# Third party programs must not access this file directly, but only through the
# symlink at /etc/resolv.conf. To manage man:resolv.conf(5) in a different way,
# replace this symlink by a static file or a different symlink.
#
# See man:systemd-resolved.service(8) for details about the supported modes of
# operation for /etc/resolv.conf.

nameserver 127.0.0.53
options edns0 trust-ad
search eu-west-1.compute.internal
```

Answer the questions below

What is the hostname of the attached VM?

```
ubuntu@Linux4n6:~$ cat /etc/hostname
Linux4n6

```

*Linux4n6*

What is the timezone of the attached VM?

```
ubuntu@Linux4n6:~$ cat /etc/timezone
Asia/Karachi
```

*Asia/Karachi*

What program is listening on the address 127.0.0.1:5901?

Use netstat to see open connections, find the mentioned address and the associated program name

```
ubuntu@Linux4n6:~$ netstat -natp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:5901          0.0.0.0:*               LISTEN      919/Xtigervnc       
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      -                   
tcp        0      0 10.10.12.178:80         10.100.1.202:37888      ESTABLISHED -                   
tcp        0      0 127.0.0.1:5901          127.0.0.1:51586         ESTABLISHED 919/Xtigervnc       
tcp        0      0 127.0.0.1:51586         127.0.0.1:5901          ESTABLISHED -                   
tcp6       0      0 ::1:5901                :::*                    LISTEN      919/Xtigervnc       
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 ::1:631                 :::*                    LISTEN      -  
```

*Xtigervnc*

What is the full path of this program?

Use ps aux command to view running processes. You can grep the required process name. Please note that process names are case-sensitive.

```
ubuntu@Linux4n6:~$ ps aux | grep -i "Xtigervnc"
ubuntu       919  0.3  3.0 350720 123564 ?       S    21:51   0:22 /usr/bin/Xtigervnc :1 -desktop Linux4n6:1 (ubuntu) -auth /home/ubuntu/.Xauthority -geometry 1900x1200 -depth 24 -rfbwait 30000 -rfbauth /home/ubuntu/.vnc/passwd -rfbport 5901 -pn -localhost -SecurityTypes VncAuth
ubuntu      2732  0.0  0.0   3436   656 pts/0    S+   23:25   0:00 grep --color=auto -i Xtigervnc

```

*/usr/bin/Xtigervnc*

Read about the flags used above with the netstat and ps commands in their respective man pages.

 Completed


###  Persistence mechanisms

Knowing the environment we are investigating, we can then move on to finding out what persistence mechanisms exist on the Linux host under investigation. Persistence mechanisms are ways a program can survive after a system reboot. This helps malware authors retain their access to a system even if the system is rebooted. Let's see how we can identify persistence mechanisms in a Linux host.

## Cron jobs

Cron jobs are commands that run periodically after a set amount of time. A Linux host maintains a list of Cron jobs in a file located at `/etc/crontab`. We can read the file using the `cat` utility.

Cron jobs

```shell-session
user@machine$ cat /etc/crontab 
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
```

The above terminal output shows the contents of a sample `/etc/crontab` file. As can be seen, the file contains information about the time interval after which the command has to run, the username that runs the command, and the command itself. It can also contain scripts to run, where the script that needs to be run will be placed on the disk, and the command to run it will be added to this file.

## Service startup

Like Windows, services can be set up in Linux that will start and run in the background after every system boot. A list of services can be found in the `/etc/init.d` directory. We can check the contents of the directory by using the `ls` utility.

Service startup

```shell-session
user@machine$ ls /etc/init.d/
acpid       avahi-daemon      cups          hibagent           kmod             networking     pppd-dns                     screen-cleanup     unattended-upgrades
alsa-utils  bluetooth         cups-browsed  hwclock.sh         lightdm          open-iscsi     procps                       speech-dispatcher  uuidd
anacron     console-setup.sh  dbus          irqbalance         lvm2             open-vm-tools  pulseaudio-enable-autospawn  spice-vdagent      whoopsie
apparmor    cron              gdm3          iscsid             lvm2-lvmpolld    openvpn        rsync                        ssh                x11-common
apport      cryptdisks        grub-common   kerneloops         multipath-tools  plymouth       rsyslog                      udev
atd         cryptdisks-early  hddtemp       keyboard-setup.sh  network-manager  plymouth-log   saned                        ufw
```

## .Bashrc

When a bash shell is spawned, it runs the commands stored in the `.bashrc` file. This file can be considered as a startup list of actions to be performed. Hence it can prove to be a good place to look for persistence. 

The following terminal shows an example .bashrc file.

Bashrc

```shell-session
user@machine$ cat ~/.bashrc
# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

# set variable identifying the chroot you work in (used in the prompt below)
if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

# set a fancy prompt (non-color, unless we know we "want" color)
case "$TERM" in
    xterm-color|*-256color) color_prompt=yes;;
esac

# If this is an xterm set the title to user@host:dir
case "$TERM" in
xterm*|rxvt*)
    PS1="\[\e]0;${debian_chroot:+($debian_chroot)}\u@\h: \w\a\]$PS1"
    ;;
*)
    ;;
esac

# Add an "alert" alias for long running commands.  Use like so:
#   sleep 10; alert
alias alert='notify-send --urgency=low -i "$([ $? = 0 ] && echo terminal || echo error)" "$(history|tail -n1|sed -e '\''s/^\s*[0-9]\+\s*//;s/[;&|]\s*alert$//'\'')"'

# Alias definitions.
# You may want to put all your additions into a separate file like
# ~/.bash_aliases, instead of adding them here directly.
# See /usr/share/doc/bash-doc/examples in the bash-doc package.

if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi

# enable programmable completion features (you don't need to enable
# this, if it's already enabled in /etc/bash.bashrc and /etc/profile
# sources /etc/bash.bashrc).
if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi
```

System-wide settings are stored in `/etc/bash.bashrc` and `/etc/profile` files, so it is often a good idea to take a look at these files as well.

Answer the questions below

In the bashrc file, the size of the history file is defined. What is the size of the history file that is set for the user Ubuntu in the attached machine?

Check .bashrc for the user ubuntu and look for HISTFILESIZE

```
ubuntu@Linux4n6:~$ more .bashrc
# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

# don't put duplicate lines or lines starting with space in the history.
# See bash(1) for more options
HISTCONTROL=ignoreboth

# append to the history file, don't overwrite it
shopt -s histappend

# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
HISTSIZE=1000
HISTFILESIZE=2000
```

*2000*

### Evidence of Execution

Knowing what programs have been executed on a host is one of the main purposes of performing forensic analysis. On a Linux host, we can find the evidence of execution from the following sources.

## Sudo execution history

All the commands that are run on a Linux host using `sudo` are stored in the auth log. We already learned about the auth log in Task 3. We can use the `grep` utility to filter out only the required information from the auth log.

Auth logs

```shell-session
user@machine$ cat /var/log/auth.log* |grep -i COMMAND|tail
Mar 29 17:28:58 tryhackme pkexec[1618]: ubuntu: Error executing command as another user: Not authorized [USER=root] [TTY=unknown] [CWD=/home/ubuntu] [COMMAND=/usr/lib/update-notifier/package-system-locked]
Mar 29 17:49:52 tryhackme sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/cat /etc/sudoers
Mar 29 17:55:22 tryhackme sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/cat /var/log/btmp
Mar 29 17:55:39 tryhackme sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/cat /var/log/wtmp
Mar 29 18:00:54 tryhackme sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/tail -f /var/log/btmp
Mar 29 18:01:24 tryhackme sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/last -f /var/log/btmp
Mar 29 18:03:58 tryhackme sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/last -f /var/log/wtmp
Mar 29 18:05:41 tryhackme sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/last -f /var/log/btmp
Mar 29 18:07:51 tryhackme sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/last -f /var/log/utmp
Mar 29 18:08:13 tryhackme sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/last -f /var/run/utmp
```

The above terminal shows commands run by the user ubuntu using `sudo`.

## Bash history

Any commands other than the ones run using `sudo` are stored in the bash history. Every user's bash history is stored separately in that user's home folder. Therefore, when examining bash history, we need to get the bash_history file from each user's home directory. It is important to examine the bash history from the root user as well, to make note of all the commands run using the root user as well.

Bash history

```shell-session
user@machine$ cat ~/.bash_history 
cd Downloads/
ls
unzip PracticalMalwareAnalysis-Labs-master.zip 
cd PracticalMalwareAnalysis-Labs-master/
ls
cd ..
ls
rm -rf sality/
ls
mkdir wannacry
mv Ransomware.WannaCry.zip wannacry/
cd wannacry/
unzip Ransomware.WannaCry.zip 
cd ..
rm -rf wannacry/
ls
mkdir exmatter
mv 325ecd90ce19dd8d184ffe7dfb01b0dd02a77e9eabcb587f3738bcfbd3f832a1.7z exmatter/
cd exmatter/
strings -d 325ecd90ce19dd8d184ffe7dfb01b0dd02a77e9eabcb587f3738bcfbd3f832a1|sort|uniq>str-sorted
cd ..
ls
```

## Files accessed using vim

The `Vim` text editor stores logs for opened files in `Vim` in the file named `.viminfo` in the home directory. This file contains command line history, search string history, etc. for the opened files. We can use the `cat` utility to open `.viminfo`.

Viminfo

```shell-session
user@machine$ cat ~/.viminfo
# This viminfo file was generated by Vim 8.1.
# You may edit it if you're careful!

# Viminfo version
|1,4

# Value of 'encoding' when this file was written
*encoding=utf-8


# hlsearch on (H) or off (h):
~h
# Command Line History (newest to oldest):
:q
|2,0,1636562413,,"q"

# Search String History (newest to oldest):

# Expression History (newest to oldest):

# Input Line History (newest to oldest):

# Debug Line History (newest to oldest):

# Registers:

# File marks:
'0  1139  0  ~/Downloads/str
|4,48,1139,0,1636562413,"~/Downloads/str"

# Jumplist (newest first):
-'  1139  0  ~/Downloads/str
|4,39,1139,0,1636562413,"~/Downloads/str"
-'  1  0  ~/Downloads/str
|4,39,1,0,1636562322,"~/Downloads/str"

# History of marks within files (newest to oldest):

> ~/Downloads/str
	*	1636562410	0
	"	1139	0
```

Answer the questions below

The user tryhackme used apt-get to install a package. What was the command that was issued?

Check bash history for user tryhackme

```
ubuntu@Linux4n6:/home$ ls
tryhackme  ubuntu
ubuntu@Linux4n6:/home$ cd tryhackme/
ubuntu@Linux4n6:/home/tryhackme$ ls
ubuntu@Linux4n6:/home/tryhackme$ cat .bash_history 
cat: .bash_history: Permission denied
ubuntu@Linux4n6:/home/tryhackme$ sudo cat .bash_history 
ls -a /home/tryhackme/
cd ../tryhackme/
rm -rf .bash_logout 
history -w
ls -a /home/tryhackme/
cd ../tryhackme/
rm -rf .bash_logout 
history -w
cat .bash_history
sudo apt-get install apache2
```

*sudo apt-get install apache2*

What was the current working directory when the command to install net-tools was issued?

Check the auth log, you can grep COMMAND and net-tools. The working directory is denoted by PWD.

```
ubuntu@Linux4n6:/home/tryhackme$ sudo cat /var/log/auth.log* | grep -i "net-tools"
Apr 17 15:54:52 tryhackme sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/apt-get install net-tools
```

*/home/ubuntu*

### Log files

One of the most important sources of information on the activity on a Linux host is the log files. These log files maintain a history of activity performed on the host and the amount of logging depends on the logging level defined on the system. Let's take a look at some of the important log sources. Logs are generally found in the `/var/log` directory.

## Syslog

The Syslog contains messages that are recorded by the host about system activity. The detail which is recorded in these messages is configurable through the logging level. We can use the `cat` utility to view the Syslog, which can be found in the file `/var/log/syslog`. Since the Syslog is a huge file, it is easier to use `tail`, `head`, `more` or `less` utilities to help make it more readable.

Syslog

```shell-session
user@machine$ cat /var/log/syslog* | head
Mar 29 00:00:37 tryhackme systemd-resolved[519]: Server returned error NXDOMAIN, mitigating potential DNS violation DVE-2018-0001, retrying transaction with reduced feature level UDP.
Mar 29 00:00:37 tryhackme rsyslogd: [origin software="rsyslogd" swVersion="8.2001.0" x-pid="635" x-info="https://www.rsyslog.com"] rsyslogd was HUPed
Mar 29 00:00:37 tryhackme systemd[1]: man-db.service: Succeeded.
Mar 29 00:00:37 tryhackme systemd[1]: Finished Daily man-db regeneration.
Mar 29 00:09:01 tryhackme CRON[7713]: (root) CMD (   test -x /etc/cron.daily/popularity-contest && /etc/cron.daily/popularity-contest --crond)
Mar 29 00:17:01 tryhackme CRON[7726]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)
Mar 29 00:30:45 tryhackme snapd[2930]: storehelpers.go:721: cannot refresh: snap has no updates available: "amazon-ssm-agent", "core", "core18", "core20", "lxd"
Mar 29 00:30:45 tryhackme snapd[2930]: autorefresh.go:536: auto-refresh: all snaps are up-to-date
Mar 29 01:17:01 tryhackme CRON[7817]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)
Mar 29 01:50:37 tryhackme systemd[1]: Starting Cleanup of Temporary Directories...
```

The above terminal shows the system time, system name, the process that sent the log [the process id], and the details of the log. We can see a couple of cron jobs being run here in the logs above, apart from some other activity. We can see an asterisk(*) after the syslog. This is to include rotated logs as well. With the passage of time, the Linux machine rotates older logs into files such as syslog.1, syslog.2 etc, so that the syslog file doesn't become too big. In order to search through all of the syslogs, we use the asterisk(*) wildcard.

## Auth logs

We have already discussed the auth logs in the previous tasks. The auth logs contain information about users and authentication-related logs. The below terminal shows a sample of the auth logs.

Auth logs

```shell-session
user@machine$ cat /var/log/auth.log* |head
Feb 27 13:52:33 ip-10-10-238-44 useradd[392]: new group: name=ubuntu, GID=1000
Feb 27 13:52:33 ip-10-10-238-44 useradd[392]: new user: name=ubuntu, UID=1000, GID=1000, home=/home/ubuntu, shell=/bin/bash, from=none
Feb 27 13:52:33 ip-10-10-238-44 useradd[392]: add 'ubuntu' to group 'adm'
Feb 27 13:52:33 ip-10-10-238-44 useradd[392]: add 'ubuntu' to group 'dialout'
Feb 27 13:52:33 ip-10-10-238-44 useradd[392]: add 'ubuntu' to group 'cdrom'
Feb 27 13:52:33 ip-10-10-238-44 useradd[392]: add 'ubuntu' to group 'floppy'
Feb 27 13:52:33 ip-10-10-238-44 useradd[392]: add 'ubuntu' to group 'sudo'
Feb 27 13:52:33 ip-10-10-238-44 useradd[392]: add 'ubuntu' to group 'audio'
Feb 27 13:52:33 ip-10-10-238-44 useradd[392]: add 'ubuntu' to group 'dip'
Feb 27 13:52:33 ip-10-10-238-44 useradd[392]: add 'ubuntu' to group 'video'
```

We can see above that the log stored information about the creation of a new group, a new user, and the addition of the user into different groups.

### Third-party logs

Similar to the syslog and authentication logs, the `/var/log/` directory contains logs for third-party applications such as webserver, database, or file share server logs. We can investigate these by looking at the`/var/log/` directory.

Third-party logs

```shell-session
user@machine$ ls /var/log
Xorg.0.log          apt                    cloud-init.log  dmesg.2.gz      gdm3                    kern.log.1         prime-supported.log  syslog.2.gz
Xorg.0.log.old      auth.log               cups            dmesg.3.gz      gpu-manager-switch.log  landscape          private              syslog.3.gz
alternatives.log    auth.log.1             dist-upgrade    dmesg.4.gz      gpu-manager.log         lastlog            samba                syslog.4.gz
alternatives.log.1  btmp                   dmesg           dpkg.log        hp                      lightdm            speech-dispatcher    syslog.5.gz
amazon              btmp.1                 dmesg.0         dpkg.log.1      journal                 openvpn            syslog               unattended-upgrades
apache2             cloud-init-output.log  dmesg.1.gz      fontconfig.log  kern.log                prime-offload.log  syslog.1             wtmp
```

As is obvious, we can find the apache logs in the apache2 directory and samba logs in the samba directory.

Apache logs

```shell-session
user@machine$  ls /var/log/apache2/
access.log  error.log  other_vhosts_access.log
```

Similarly, if any database server like MySQL is installed on the system, we can find the logs in this directory.

Answer the questions below

Though the machine's current hostname is the one we identified in Task 4. The machine earlier had a different hostname. What was the previous hostname of the machine?

Check syslog. You can use grep hostname to shortlist the logs of your interest. Check what other hostname was present in the syslogs apart from the current one. You can use syslog* to include syslogs that have been rotated into your search.

```
ubuntu@Linux4n6:/home/tryhackme$ cat /var/log/syslog* | grep -i hostname | head
Dec 16 21:52:28 Linux4n6 systemd[1]: systemd-hostnamed.service: Succeeded.
Apr 17 00:01:30 tryhackme dbus-daemon[539]: [system] Successfully activated service 'org.freedesktop.hostname1'
Apr 17 00:01:30 tryhackme systemd[1]: Started Hostname Service.
Apr 17 00:01:30 tryhackme NetworkManager[540]: <info>  [1650153690.6203] hostname: hostname: using hostnamed
Apr 17 00:01:30 tryhackme NetworkManager[540]: <info>  [1650153690.6204] hostname: hostname changed from (none) to "tryhackme"

```

*tryhackme*

### Conclusion

Well, that's a wrap for this room. That was interesting!!

If you found it difficult to remember all the forensic artifacts, here is a cheatsheet that you can reference. 

You can stick around and find out what other exciting artifacts you found in the VM. You can let us know what you found interesting in this room using our [Discord channel](https://discord.gg/tryhackme) or [Twitter account](http://twitter.com/realtryhackme).


[[DFIR An Introduction]]