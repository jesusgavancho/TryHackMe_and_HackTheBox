---
Can you escape the Corridor?
---

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/04afd126bf7a729eec5ff41e5b9b1212.png)

### Escape the Corridor

You have found yourself in a strange corridor. Can you find your way back to where you came?  

In this challenge, you will explore potential IDOR vulnerabilities. Examine the URL endpoints you access as you navigate the website and note the hexadecimal values you find (they look an awful lot like a _hash_, don't they?). This could help you uncover website locations you were not expected to access.

  
What is the flag?
Where do those doors take you? The numbers and letters seem to follow a pattern...

![[Pasted image 20221223124602.png]]

```
using crackstation md5 is not hex

c9f0f895fb98ab9159f51fd0297e236d (8)

45c48cce2e2d7fbdea1afc51c7c6ad26 (9)

d3d9446802a44259755d38e6d163e820 (10)

6512bd43d9caa6e02c990b0a82652dca (11)

uhmm

c20ad4d76fe97759aa27a0c99bff6710 (12)

c51ce410c124a10e0db5e4b97fc2af39 (13)

8f14e45fceea167a5a36dedd4bea2543 (7) center 🚪

c4ca4238a0b923820dcc509a6f75849b (1)

c81e728d9d4c2f636f067f89cc14862c (2)

eccbc87e4b5ce2fe28308fd9f2a7baf3 (3)

a87ff679a2f3e71d9181a67b7542122c (4)

e4da3b7fbbce2345d7772b0674a318d5 (5)

1679091c5a880faf6fb5e6087eb1b2dc (6)

let's see number 0 or 14

┌──(kali㉿kali)-[~]
└─$ echo -n "0" | md5sum
cfcd208495d565ef66e7dff9f98764da  -

yea it works!

http://10.10.201.112/cfcd208495d565ef66e7dff9f98764da

flag{2477ef02448ad9156661ac40a6b8862e}
```

![[Pasted image 20221223124946.png]]

![[Pasted image 20221223125132.png]]
![[Pasted image 20221223125224.png]]


*flag{2477ef02448ad9156661ac40a6b8862e}*

[[Team]]