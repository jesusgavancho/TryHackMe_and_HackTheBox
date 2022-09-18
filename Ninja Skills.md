![](https://i.imgur.com/HNs4Vov.png)

![|333](https://i.imgur.com/JbCoSfv.png)

(If you prefer to SSH into the machine, use the credentials new-user as the username and password)

Answer the questions about the following files:

    8V2L
    bny0
    c4ZX
    D8B3
    FHl1
    oiMO
    PFbD
    rmfX
    SRSq
    uqyw
    v2Vb
    X1Uy

The aim is to answer the questions as efficiently as possible.

```
┌──(kali㉿kali)-[~/Downloads]
└─$ ssh new-user@10.10.223.25
new-user@10.10.223.25's password: 
Last failed login: Sun Sep 18 17:36:05 UTC 2022 from ip-10-18-1-77.eu-west-1.compute.internal on ssh:notty
There were 2 failed login attempts since the last successful login.
Last login: Wed Oct 23 22:13:05 2019 from ip-10-10-231-194.eu-west-1.compute.internal
████████╗██████╗ ██╗   ██╗██╗  ██╗ █████╗  ██████╗██╗  ██╗███╗   ███╗███████╗
╚══██╔══╝██╔══██╗╚██╗ ██╔╝██║  ██║██╔══██╗██╔════╝██║ ██╔╝████╗ ████║██╔════╝
   ██║   ██████╔╝ ╚████╔╝ ███████║███████║██║     █████╔╝ ██╔████╔██║█████╗  
   ██║   ██╔══██╗  ╚██╔╝  ██╔══██║██╔══██║██║     ██╔═██╗ ██║╚██╔╝██║██╔══╝  
   ██║   ██║  ██║   ██║   ██║  ██║██║  ██║╚██████╗██║  ██╗██║ ╚═╝ ██║███████╗
   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝
        Let the games begin!
[new-user@ip-10-10-223-25 ~]$ ls -lah
total 32K
drwx------ 3 new-user new-user 4.0K Oct 23  2019 .
drwxr-xr-x 5 root     root     4.0K Oct 23  2019 ..
-rw------- 1 new-user new-user  242 Oct 23  2019 .bash_history
-rw-r--r-- 1 new-user new-user   18 Aug 30  2017 .bash_logout
-rw-r--r-- 1 new-user new-user  193 Aug 30  2017 .bash_profile
-rw-r--r-- 1 new-user new-user  124 Aug 30  2017 .bashrc
drwxrwxr-x 2 new-user new-user 4.0K Oct 23  2019 files
-rw------- 1 new-user new-user 1.0K Oct 23  2019 .rnd


[new-user@ip-10-10-223-25 /]$ find -name 8V2L 2>/dev/null
./etc/8V2L
[new-user@ip-10-10-223-25 /]$ find -name bny0 2>/dev/null
[new-user@ip-10-10-223-25 /]$ find . -name bny0 2>/dev/null
[new-user@ip-10-10-223-25 /]$ find . -name c4ZX 2>/dev/null
./mnt/c4ZX
[new-user@ip-10-10-223-25 /]$ find . -name D8B3 2>/dev/null
./mnt/D8B3
[new-user@ip-10-10-223-25 /]$ find . -name FHl1 2>/dev/null
./var/FHl1
[new-user@ip-10-10-223-25 /]$ find . -name oiMO 2>/dev/null
./opt/oiMO
[new-user@ip-10-10-223-25 /]$ find . -name PFbD 2>/dev/null
./opt/PFbD
[new-user@ip-10-10-223-25 /]$ find . -name rmfX 2>/dev/null
./media/rmfX
[new-user@ip-10-10-223-25 /]$ find . -name SRSq 2>/dev/null
./etc/ssh/SRSq
[new-user@ip-10-10-223-25 /]$ find . -name uqyw 2>/dev/null
./var/log/uqyw
[new-user@ip-10-10-223-25 /]$ find . -name v2Vb 2>/dev/null
./home/v2Vb
[new-user@ip-10-10-223-25 /]$ find . -name X1Uy 2>/dev/null
./X1Uy

or just 

[new-user@ip-10-10-223-25 /]$ find / -type f \( -name 8V2L -o -name bny0 -o -name c4ZX -o -name D8B3 -o -name FHl1 -o -name oiM0 -o -name PFbD -o -name rmfX -o -name SRSq -o -name uqyw -o -name v2Vb -o -name X1Uy \) 2>/dev/null
/mnt/D8B3
/mnt/c4ZX
/var/FHl1
/var/log/uqyw
/opt/PFbD
/media/rmfX
/etc/8V2L
/etc/ssh/SRSq
/home/v2Vb
/X1Uy

    / means the Root directory
    -type option is used to specify the file type and here, we are searching for regular files as represented by f
    -name option is used to specify a search pattern in this case, the file extensions
    -o means “OR”


```

Which of the above files are owned by the best-group group(enter the answer separated by spaces in alphabetical order)
```
[new-user@ip-10-10-223-25 /]$ ls -lah /etc/8V2L
-rwxrwxr-x 1 new-user new-user 14K Oct 23  2019 /etc/8V2L
[new-user@ip-10-10-223-25 /]$ ls -lah /mnt/c4ZX
-rw-rw-r-- 1 new-user new-user 14K Oct 23  2019 /mnt/c4ZX
[new-user@ip-10-10-223-25 /]$ ls -lah /mnt/D8B2
ls: cannot access /mnt/D8B2: No such file or directory
[new-user@ip-10-10-223-25 /]$ ls -lah /mnt/D8B3
-rw-rw-r-- 1 new-user best-group 14K Oct 23  2019 /mnt/D8B3
[new-user@ip-10-10-223-25 /]$ ls -lah /var/FHl1
-rw-rw-r-- 1 new-user new-user 14K Oct 23  2019 /var/FHl1
[new-user@ip-10-10-223-25 /]$ ls -lah /opt/oiMO
-rw-rw-r-- 1 new-user new-user 14K Oct 23  2019 /opt/oiMO
[new-user@ip-10-10-223-25 /]$ ls -lah /opt/PFbD
-rw-rw-r-- 1 new-user new-user 14K Oct 23  2019 /opt/PFbD
[new-user@ip-10-10-223-25 /]$ ls -lah /media/rmfX
-rw-rw-r-- 1 new-user new-user 14K Oct 23  2019 /media/rmfX
[new-user@ip-10-10-223-25 /]$ ls -lah /etc/ssh/SRSq
-rw-rw-r-- 1 new-user new-user 14K Oct 23  2019 /etc/ssh/SRSq
[new-user@ip-10-10-223-25 /]$ ls -lah /var/log/uqyw
-rw-rw-r-- 1 new-user new-user 14K Oct 23  2019 /var/log/uqyw
[new-user@ip-10-10-223-25 /]$ ls -lah /home/v2Vb
-rw-rw-r-- 1 new-user best-group 14K Oct 23  2019 /home/v2Vb

or

[new-user@ip-10-10-223-25 /]$ find / -type f \( -name 8V2L -o -name bny0 -o -name c4ZX -o -name D8B3 -o -name FHl1 -o -name oiM0 -o -name PFbD -o -name rmfX -o -name SRSq -o -name uqyw -o -name v2Vb -o -name X1Uy \) -exec ls -l {} \; 2>/dev/null
-rw-rw-r-- 1 new-user best-group 13545 Oct 23  2019 /mnt/D8B3
-rw-rw-r-- 1 new-user new-user 13545 Oct 23  2019 /mnt/c4ZX
-rw-rw-r-- 1 new-user new-user 13545 Oct 23  2019 /var/FHl1
-rw-rw-r-- 1 new-user new-user 13545 Oct 23  2019 /var/log/uqyw
-rw-rw-r-- 1 new-user new-user 13545 Oct 23  2019 /opt/PFbD
-rw-rw-r-- 1 new-user new-user 13545 Oct 23  2019 /media/rmfX
-rwxrwxr-x 1 new-user new-user 13545 Oct 23  2019 /etc/8V2L
-rw-rw-r-- 1 new-user new-user 13545 Oct 23  2019 /etc/ssh/SRSq
-rw-rw-r-- 1 new-user best-group 13545 Oct 23  2019 /home/v2Vb
-rw-rw-r-- 1 newer-user new-user 13545 Oct 23  2019 /X1Uy


```

*D8B3 v2Vb*

Which of these files contain an IP address?

[regex](https://www.shellhacks.com/regex-find-ip-addresses-file-grep/)

```
[new-user@ip-10-10-223-25 /]$ find / -type f \( -name 8V2L -o -name bny0 -o -name c4ZX -o -name D8B3 -o -name FHl1 -o -name oiMO -o -name PFbD -o -name rmfX -o -name SRSq -o -name uqyw -o -name v2Vb -o -name X1Uy \) -exec grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" * {} \; 2>/dev/null
/opt/oiMO:1.1.1.1
```

*oiMO*

Which file has the SHA1 hash of 9d54da7584015647ba052173b84d45e8007eba94

```
[new-user@ip-10-10-223-25 /]$ find / -type f \( -name 8V2L -o -name bny0 -o -name c4ZX -o -name D8B3 -o -name FHl1 -o -name oiMO -o -name PFbD -o -name rmfX -o -name SRSq -o -name uqyw -o -name v2Vb -o -name X1Uy \) -exec sha1sum {} \; 2>/dev/null2c8de970ff0701c8fd6c55db8a5315e5615a9575  /mnt/D8B3
9d54da7584015647ba052173b84d45e8007eba94  /mnt/c4ZX
d5a35473a856ea30bfec5bf67b8b6e1fe96475b3  /var/FHl1
57226b5f4f1d5ca128f606581d7ca9bd6c45ca13  /var/log/uqyw
256933c34f1b42522298282ce5df3642be9a2dc9  /opt/PFbD
5b34294b3caa59c1006854fa0901352bf6476a8c  /opt/oiMO
4ef4c2df08bc60139c29e222f537b6bea7e4d6fa  /media/rmfX
0323e62f06b29ddbbe18f30a89cc123ae479a346  /etc/8V2L
acbbbce6c56feb7e351f866b806427403b7b103d  /etc/ssh/SRSq
7324353e3cd047b8150e0c95edf12e28be7c55d3  /home/v2Vb
59840c46fb64a4faeabb37da0744a46967d87e57  /X1Uy

```

*c4ZX*

Which file contains 230 lines?

```
[new-user@ip-10-10-223-25 /]$ find / -type f \( -name 8V2L -o -name bny0 -o -name c4ZX -o -name D8B3 -o -name FHl1 -o -name oiMO -o -name PFbD -o -name rmfX -o -name SRSq -o -name uqyw -o -name v2Vb -o -name X1Uy \) -exec wc -l {} \; 2>/dev/null
209 /mnt/D8B3
209 /mnt/c4ZX
209 /var/FHl1
209 /var/log/uqyw
209 /opt/PFbD
209 /opt/oiMO
209 /media/rmfX
209 /etc/8V2L
209 /etc/ssh/SRSq
209 /home/v2Vb
209 /X1Uy
```
*bny0*  (maybe this because )

```
[new-user@ip-10-10-223-25 /]$ find / -type f \( -name 8V2L -o -name bny0 -o -name c4ZX -o -name D8B3 -o -name FHl1 -o -name oiMO -o -name PFbD -o -name rmfX -o -name SRSq -o -name uqyw -o -name v2Vb -o -name X1Uy \) -exec ls -l {} \; 2>/dev/null
-rw-rw-r-- 1 new-user best-group 13545 Oct 23  2019 /mnt/D8B3
-rw-rw-r-- 1 new-user new-user 13545 Oct 23  2019 /mnt/c4ZX
-rw-rw-r-- 1 new-user new-user 13545 Oct 23  2019 /var/FHl1
-rw-rw-r-- 1 new-user new-user 13545 Oct 23  2019 /var/log/uqyw
-rw-rw-r-- 1 new-user new-user 13545 Oct 23  2019 /opt/PFbD
-rw-rw-r-- 1 new-user new-user 13545 Oct 23  2019 /opt/oiMO
-rw-rw-r-- 1 new-user new-user 13545 Oct 23  2019 /media/rmfX
-rwxrwxr-x 1 new-user new-user 13545 Oct 23  2019 /etc/8V2L
-rw-rw-r-- 1 new-user new-user 13545 Oct 23  2019 /etc/ssh/SRSq
-rw-rw-r-- 1 new-user best-group 13545 Oct 23  2019 /home/v2Vb
-rw-rw-r-- 1 newer-user new-user 13545 Oct 23  2019 /X1Uy

or

[new-user@ip-10-10-223-25 /]$ find / -user newer-user -name "*" 2>/dev/null
/var/spool/mail/newer-user
/home/newer-user
/X1Uy

```

Which file's owner has an ID of 502?
*X1Uy*

Which file is executable by everyone?
*8V2L*  -rwxrwxr-x

[[LazyAdmin]]