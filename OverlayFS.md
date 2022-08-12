---
OverlayFS is a Linux kernel module that allows the system to combine several mount points into one, so that you can access all the files from each within one directory structure.
---

> It's often used by live USBs, or some other specialist applications. One use is having a read only root file system, and another partition "overlayed" with that to allow applications to write to a temporary file system.

> This vulnerability is particularly serious, as overlayfs is a kernel module that is installed by default on Ubuntu 1804 Server.
If the system is vulnerable, you can very easily escalate from any user to root, as long as you can run a binary.
If there isn't a C compiler installed on the machine, you can compile the binary statically elsewhere and copy just the binary over.

### ssh

==overlya:tryhackme123==

[SSD-Disclosure](https://ssd-disclosure.com/ssd-advisory-overlayfs-pe/)
```
uname -a
```

```cp from link above
nano exploit.c
```

```
gcc exploit.c -o exploit
```

```
./exploit
```

```root
id
```

```
cat /root/flag.txt
```

==thm{27aaa5865a52dcd4cb04c0e0a2d39404}==


