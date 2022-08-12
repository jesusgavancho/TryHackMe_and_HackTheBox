---
CVE-2021-4034 (colloquially dubbed "Pwnkit") is a terrifying Local Privilege Escalation (LPE) vulnerability, located in the "Polkit" package installed by default on almost every major distribution of the Linux operating system (as well as many other *nix operating systems).
---

> In other words, it affects virtually every mainstream Linux system on the planet.
This room will provide an overview of the vulnerability, as well as recommendations to patch affected systems. A vulnerable machine has also been attached to allow you to try the vulnerability for yourself!

*Without further ado, let's begin.*

### Background 

#### Overview

> CVE-2021-4034 (aka "pwnkit") was discovered by researchers at Qualys and announced in January 2022; the technical security advisory for this vulnerability can be found here. The vulnerability has existed in every version of the "Policy Toolkit" (or, Polkit) package since it was first released in 2009 and allows any unprivileged attacker to easily obtain full administrative access over any Linux machine with the Polkit package installed. Unfortunately, Polkit is installed by default on most distributions of Linux, making this vulnerability extremely widespread.

`The ease of exploitation and ubiquitous nature of Polkit make this an absolutely devastating vulnerability; however, fortunately it is not exploitable remotely, making Pwnkit purely a local privilege escalation (LPE) vulnerability.`

#### What is Polkit?

> lkit can be used to determine whether you have the requisite permissions. It is integrated with systemd and is much more configurable than the traditional sudo system. Indeed, it is sometimes referred to as the "sudo of systemd", providing a granular system with which to assign permissions to users.
When interacting with polkit we can use the pkexec utility — it is this program that contains the Pwnkit vulnerability. As an example of using the utility, attempting to run the useradd command through pkexec in a GUI session results in a pop-up asking for credentials:

```
pkexec useradd test1234
```

> To summarise, the policy toolkit can be thought of as a fine-grained alternative to the simpler sudo system that you may already be familiar with.

> The short version is this: versions of pkexec released prior to the patch don't handle command-line arguments safely, which leads to an "out-of-bounds write" vulnerability, allowing an attacker to manipulate the environment with which pkexec is run. This is all you really need to know, but for a slightly more technical explanation, read on!

---
#### theorie

> We format these permissions like this: rwx, for read, write and execute respectively.
If we were missing the permission to write to the file then it would look like this: r-x

> rw-r--r--
Here, the owner can read and write, the group can read, and everyone else (i.e. world) can also read.

> With the octal format, each of the permissions is assigned a value:
r = 4
w = 2
x = 1
rwx
421
To specify a permission, we add these numbers together; so rwx would be 4 + 2 + 1 = 7, and r-x would be 4 + 1 = 5

> rw- r-- r--
420 400 400
644

#### special bits

> For example, what happens when you need to execute a file, but as the admin user (root)? A good example of this is the passwd command in Linux. As a low privileged user, you don’t have permission to access the system files which contain the passwords, but you can still change your password with the passwdcommand, so how does this work?

*The answer is something called the “SUID” bit. *

#### SUID

> Up until now we’ve seen the read (r), write (w) and execute (x) bits. Now we’re seeing the SUID (s) bit. When this bit is set, it replaces the x in the owner permissions, like so: rws------. What the SUID bit does is allow the file to be executed as the owner of the file, so, in other words, if the command is owned by root, when you execute it then you will be using the root (i.e. admin) permissions. This means that you can use passwd to edit the system password file, without actually having permission to edit it manually!

> Notice that the passwd command is owned by root (i.e. the admin). We have permissions to read and execute it as our own user (r-x) — we need these in order to use the SUID bit. Additionally, we also have the SUID bit set (rws) which allows us to execute the command as the owner — in this case root — thus temporarily giving us the permissions of the admin.

#### SGID

>The SGID bit works almost identically to the SUID bit; however, rather than giving you the permissions of the user that owns the file it gives you the permissions of the group that owns the file. We’re going to discuss groups in detail in the next section, but for now all you need to understand is that the SGID does for groups what the SUID does for the owner of a file. It allows you to execute the program in question with the same permissions as if you were a member of the group that owns the file.
A good example of this is the wall command, which allows you to send messages to all logged in users:
File permissions for the /usr/bin/wall command
Notice that in this case the (s) bit is in the second block of permissions, indicating that it’s an SGID, rather than an SUID bit. The command is owned by the user root, but it’s also owned by the group tty, thus when you execute the wall command, you’re executing it with the same permissions as a user who is a member of the tty group.

#### Sticky Bit

> The final special permission that we’re going to look at is the sticky bit. Whereas SUID and SGID allow you to temporarily obtain greater permissions when executing a single program, the sticky bit acts as a protection mechanism. A file that has the sticky bit enabled can only be renamed or deleted by its owner, or by the root user. In all other respects, normal permissions apply; i.e. if the file is world readable and world write-able (rw-) then any user can read or write to it — they just can’t delete it, or rename it. A good example of the sticky bit is the /tmp directory, which is used to store temporary files. Any user can read and write to the /tmp directory, but they can’t delete any files belonging to another user.
File permissions for the /tmp directory.File permissions for /tmp directory
Notice the t bit at the end of the permissions list. This signifies that the sticky bit is active. You’ll also see that the d bit at the start of the permissions list is active — this just means that we’re looking at a directory, not a file.

> To reference SUID, we use the number 4. To reference SGID we use the number 2, and to reference sticky bit, we use the number 1. When adding these to a permission definition, we just add them on at the start of the three numbers we used previously.

*In other words, full permissions plus the sticky bit would look like this: 1777. Adding SUID to a file that the owner can read and write to, and everyone else can read, would look like this: 4644. Adding the SGID bit to a file that can be read by everyone, and modified/executed by no one, would look like this: 2444.*

*As with the other octal sets, these can be added together to add more than one special permission. If you wanted to set both SUID and SGID in a file with full permissions (for example), you could use 6777. To add SUID, SGID and sticky bit to a file that is readable by everyone, but writeable and executable by no one, you could use 7444.*

> Say we want to give everyone full permissions, the octal for this is 777. We would edit the file like so: chmod 777 filename

#### Changing File Ownership

> As mentioned previously, all files have a group owner, as well as a user owner. The command to alter these is called chown. We use it like this:
chown user:group filename

 If you just want to change the user then you could do:
chown user filename

Similarly, if you just want to change the group then you could use:
chown :group filename

> Worked Example
You now know how to work with file permissions in Unix. Let’s do one worked example, starting from a completely new file and locking it down appropriately.
Lets say that we’ve got a file called Diary.txt. We want to share it with Bob, but not with anyone else on the system. Bob should be able to read it, but not write to it. The root user (i.e. us) should be able to read and write to the Diary.
Let’s get started!
First we’re going to create the file. It’s got the default permissions of 644:

*touch Diary.txt
ls -al Diary.txt
default permissions 644
We don’t want this to be world readable, so let’s start by removing the r bit from world:
chmod o-r Diary.txt && ls -al Diary.txt
The permissions look to be set up nicely, but how are we going to let Bob read the diary? Let’s make a new secondary group called Diary, then add Bob into it:
groupadd Diary
usermod -aG Diary bob
Now all that we need to do is change the group ownership of Diary.txt so that it’s group owned by our new Diary group:
chown :Diary Diary.txt
ls -al Diary.txt
Et Viola! We have a diary that root can read and write to, members of the Diary group (of which our specified user — bob — is a member) can read the diary, and world is completely shut out. *


---

### Continuing

- Is Pwnkit exploitable remotely (Aye/Nay)? *Nay*
- In which Polkit utility does the Pwnkit vulnerability reside?*pkexec*

###  Exploitation 

#### ssh

==tryhackme:TryHackMe123!==

```
gcc cve-2021-4034-poc.c -o exploit
```

```
./exploit
```

```
cd /root/flag.txt
```

==THM{CONGRATULATIONS-YOU-EXPLOITED-PWNKIT}==

###  Remediations 

> The patched version can be installed with a simple apt upgrade — e.g. 
> `sudo apt update && sudo apt upgrade.`

>In distributions which have not yet released patched versions of the package, the recommended hotfix is to simply remove the SUID bit from the pkexec binary. This can be done with a command such as the following:

`sudo chmod 0755 `which pkexec``

> You can check to ensure that a system is patched by attempting to run a copy of the exploit against it. If the exploit returns the pkexec help menu then the system is patched:

[[Spring4Shell]]





