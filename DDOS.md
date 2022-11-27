```
https://tryhackme.com/room/blockchainvkkgjrphsh
┌──(kali㉿kali)-[~/Downloads/DDOS]
└─$ ftp 10.10.161.202
Connected to 10.10.161.202.
220 (vsFTPd 3.0.3)
Name (10.10.161.202:kali): bouncer
331 Please specify the password.
Password: (cyberbouncer) 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||10602|)
150 Here comes the directory listing.
-rw-rw-r--    1 1001     1001       242207 Jul 04 20:27 blockchain-demo-master.zip
drwxr-xr-x    2 1001     1001         4096 Jul 04 21:28 test
-rw-rw-r--    1 1001     1001     15803548 Jul 04 20:27 ufonet-master.zip
226 Directory send OK.
ftp> get ufonet-master.zip
local: ufonet-master.zip remote: ufonet-master.zip
229 Entering Extended Passive Mode (|||10591|)
150 Opening BINARY mode data connection for ufonet-master.zip (15803548 bytes).
100% |****************************************| 15433 KiB   84.07 KiB/s    00:00 ETA
226 Transfer complete.
15803548 bytes received in 03:07 (82.48 KiB/s)
sudo python3 setup.py build && sudo python3 setup.py install && sudo apt install python3-scapy; 
sudo python3 ufonet --gui;
sudo python3 ufonet --gui


```

[[CVE-2021-41773]]