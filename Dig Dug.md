---
Turns out this machine is a DNS server - it's time to get your shovels out!
---

![|222](https://tryhackme-images.s3.amazonaws.com/room-icons/c583f9d6cc8a7f2a749fad911eb81eb3.png)

Oooh, turns out, this 10.10.94.219 machine is also a DNS server! If we could dig into it, I am sure we could find some interesting records! But... it seems weird, this only responds to a special type of request for a givemetheflag.com domain?

```
└─$ dig givemetheflag.com @10.10.94.219 


; <<>> DiG 9.18.4-2-Debian <<>> givemetheflag.com @10.10.94.219
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 40653
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;givemetheflag.com.             IN      A

;; ANSWER SECTION:
givemetheflag.com.      0       IN      TXT     "flag{0767ccd06e79853318f25aeb08ff83e2}"

;; Query time: 191 msec
;; SERVER: 10.10.94.219#53(10.10.94.219) (UDP)
;; WHEN: Wed Sep 21 12:59:59 EDT 2022
;; MSG SIZE  rcvd: 86
```


Retrieve the flag from the DNS server!
*flag{0767ccd06e79853318f25aeb08ff83e2}*


[[IDE]]