---
We got our hands on a confidential case file from some self-declared "black hat hackers"... it looks like they have a secret invite code.
---

![|333](https://tryhackme-images.s3.amazonaws.com/room-icons/6c9609e592b4ac47833804790222c091.png)

### Confidential 

We got our hands on a confidential case file from some self-declared "black hat hackers"... it looks like they have a secret invite code available within a QR code, but it's covered by some image in this PDF! If we want to thwart whatever it is they are planning, we need your help to uncover what that QR code says!


Access this challenge by deploying the machine attached to this task by pressing the green "Start Machine" button. This machine shows in Split View in your browser, if it doesn't automatically display you may need to click "Show Split View" in the top right.

The file you need is located in /home/ubuntu/confidential on the VM.

```
split view to see the pdf then download

ubuntu@thm-confidential:~$ ls
Desktop  Pictures  confidential
ubuntu@thm-confidential:~$ cd confidential/
ubuntu@thm-confidential:~/confidential$ ls
Repdf.pdf
ubuntu@thm-confidential:~/confidential$ nc 10.18.1.77 4444 < Repdf.pdf 
ls
ubuntu@thm-confidential:~/confidential$ ls -lah
total 112K
drwxrwxr-x  2 ubuntu ubuntu 4.0K Mar 11  2022 .
drwxr-xr-x 15 ubuntu ubuntu 4.0K Sep 19 17:02 ..
-rw-rw-r--  1 ubuntu ubuntu 101K Mar 11  2022 Repdf.pdf


┌──(kali㉿kali)-[~/confidential]
└─$ ls
sus.pdf
                                                                                          
┌──(kali㉿kali)-[~/confidential]
└─$ ls -lha sus.pdf 
-rw-r--r-- 1 kali kali 101K Sep 19 13:11 sus.pdf

┌──(kali㉿kali)-[~/confidential]
└─$ sudo apt-get update
Get:2 https://dl.google.com/linux/chrome/deb stable InRelease [1,811 B]      
Get:1 http://kali.download/kali kali-rolling InRelease [30.6 kB]                         
Get:3 https://dl.google.com/linux/chrome/deb stable/main amd64 Packages [1,093 B]
Get:4 https://packages.microsoft.com/debian/10/prod buster InRelease [29.8 kB]
Get:5 http://kali.download/kali kali-rolling/main amd64 Packages [18.3 MB]
Get:6 https://packages.microsoft.com/debian/10/prod buster/main armhf Packages [30.2 kB]
Get:7 http://kali.download/kali kali-rolling/main amd64 Contents (deb) [42.7 MB] 
Get:8 https://packages.microsoft.com/debian/10/prod buster/main amd64 Packages [194 kB]
Get:9 https://packages.microsoft.com/debian/10/prod buster/main arm64 Packages [30.5 kB] 
Get:10 https://packages.microsoft.com/debian/10/prod buster/main amd64 Contents (deb) [2,046 kB]
Get:11 http://kali.download/kali kali-rolling/contrib amd64 Packages [110 kB]            
Get:12 http://kali.download/kali kali-rolling/contrib amd64 Contents (deb) [160 kB]
Get:13 http://kali.download/kali kali-rolling/non-free amd64 Packages [221 kB]
Get:14 http://kali.download/kali kali-rolling/non-free amd64 Contents (deb) [897 kB]
Fetched 64.8 MB in 18s (3,687 kB/s)                                                      
Reading package lists... Done
                                                                                          
┌──(kali㉿kali)-[~/confidential]
└─$ pdfimages              
Command 'pdfimages' not found, but can be installed with:
sudo apt install poppler-utils
Do you want to install it? (N/y)y
sudo apt install poppler-utils
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following additional packages will be installed:
  libpoppler123
The following NEW packages will be installed:
  libpoppler123 poppler-utils
0 upgraded, 2 newly installed, 0 to remove and 824 not upgraded.
Need to get 2,076 kB of archives.
After this operation, 5,429 kB of additional disk space will be used.
Do you want to continue? [Y/n] Y
Get:1 http://kali.download/kali kali-rolling/main amd64 libpoppler123 amd64 22.08.0-2.1 [1,867 kB]
Get:2 http://kali.download/kali kali-rolling/main amd64 poppler-utils amd64 22.08.0-2.1 [209 kB]
Fetched 2,076 kB in 3s (774 kB/s)       
debconf: unable to initialize frontend: Dialog
debconf: (Dialog frontend requires a screen at least 13 lines tall and 31 columns wide.)
debconf: falling back to frontend: Readline
Selecting previously unselected package libpoppler123:amd64.
(Reading database ... 315708 files and directories currently installed.)
Preparing to unpack .../libpoppler123_22.08.0-2.1_amd64.deb ...
Unpacking libpoppler123:amd64 (22.08.0-2.1) ...
Selecting previously unselected package poppler-utils.
Preparing to unpack .../poppler-utils_22.08.0-2.1_amd64.deb ...
Unpacking poppler-utils (22.08.0-2.1) ...
Setting up libpoppler123:amd64 (22.08.0-2.1) ...
Setting up poppler-utils (22.08.0-2.1) ...
Processing triggers for libc-bin (2.34-4) ...
Processing triggers for man-db (2.10.2-1) ...
Processing triggers for kali-menu (2022.3.1) ...
debconf: unable to initialize frontend: Dialog
debconf: (Dialog frontend requires a screen at least 13 lines tall and 31 columns wide.)
debconf: falling back to frontend: Readline
Scanning processes...                                                                     
Scanning processor microcode...                                                           
Scanning linux images...                                                                  

Running kernel seems to be up-to-date.

The processor microcode seems to be up-to-date.

No services need to be restarted.

No containers need to be restarted.

No user sessions are running outdated binaries.

No VM guests are running outdated hypervisor (qemu) binaries on this host.
                                                                                          
┌──(kali㉿kali)-[~/confidential]
└─$ pdfimages -all sus.pdf ext
                                                                                          
┌──(kali㉿kali)-[~/confidential]
└─$ ls             
ext-000.png  ext-001.png  ext-002.png  sus.pdf


now qr




```

![[Pasted image 20220919122720.png]]

![[Pasted image 20220919122803.png]]

Uncover and scan the QR code to retrieve the flag!
*flag{e08e6ce2f077a1b420cfd4a5d1a57a8d}*  (now just scan the qr)


[[Chill Hack]]