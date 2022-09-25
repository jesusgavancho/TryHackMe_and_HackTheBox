---
One of our developers accidentally committed some sensitive code to our GitHub repository. Well, at least, that is what they told us...
---

![|333](https://tryhackme-images.s3.amazonaws.com/room-icons/ef784093d79afdb312c67643b7eb4bbe.png)


Oh no, not again! One of our developers accidentally committed some sensitive code to our GitHub repository. Well, at least, that is what they told us... the problem is, we don't remember what or where! Can you track down what we accidentally committed?


Access this challenge by deploying the machine attached to this task by pressing the green "Start Machine" button. You will need to use the in-browser view to complete this room. Don't see anything? Press the "Show Split Screen" button at the top of the page.

The files you need are located in /home/ubuntu/commited on the VM attached to this task.


```
┌──(kali㉿kali)-[~/mrphisher]
└─$ nc -nvlp 1337 > commited.zip
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.33.21.
Ncat: Connection from 10.10.33.21:51352.
^C
                                                                                                         
ubuntu@thm-comitted:~$ cd commited
ubuntu@thm-comitted:~/commited$ ls
commited.zip
ubuntu@thm-comitted:~/commited$ nc 10.18.1.77 1337 < commited.zip


┌──(kali㉿kali)-[~/mrphisher]
└─$ ls
commited.zip  MrPhisher.docm
                                                                                                         
┌──(kali㉿kali)-[~/mrphisher]
└─$ file commited.zip 
commited.zip: Zip archive data, at least v1.0 to extract, compression method=store


┌──(kali㉿kali)-[~/mrphisher/commited]
└─$ git log --all                                                       
commit 28c36211be8187d4be04530e340206b856198a84 (HEAD -> master)
Author: fumenoid <fumenoid@gmail.com>
Date:   Sun Feb 13 00:49:32 2022 -0800

    Finished

commit 4e16af9349ed8eaa4a29decd82a7f1f9886a32db (dbint)
Author: fumenoid <fumenoid@gmail.com>
Date:   Sun Feb 13 00:48:08 2022 -0800

    Reminder Added.

commit c56c470a2a9dfb5cfbd54cd614a9fdb1644412b5
Author: fumenoid <fumenoid@gmail.com>
Date:   Sun Feb 13 00:46:39 2022 -0800

    Oops

commit 3a8cc16f919b8ac43651d68dceacbb28ebb9b625
Author: fumenoid <fumenoid@gmail.com>
Date:   Sun Feb 13 00:45:14 2022 -0800

    DB check

commit 6e1ea88319ae84175bfe953b7791ec695e1ca004
Author: fumenoid <fumenoid@gmail.com>
Date:   Sun Feb 13 00:43:34 2022 -0800

    Note added

commit 9ecdc566de145f5c13da74673fa3432773692502
Author: fumenoid <fumenoid@gmail.com>
Date:   Sun Feb 13 00:40:19 2022 -0800

    Database management features added.

commit 26bcf1aa99094bf2fb4c9685b528a55838698fbe
Author: fumenoid <fumenoid@gmail.com>
Date:   Sun Feb 13 00:32:49 2022 -0800

    Create database logic added

commit b0eda7db60a1cb0aea86f053816a1bfb7e2d6c67
Author: fumenoid <fumenoid@gmail.com>
Date:   Sun Feb 13 00:30:43 2022 -0800

    Connecting to db logic added

commit 441daaaa600aef8021f273c8c66404d5283ed83e
Author: fumenoid <fumenoid@gmail.com>
Date:   Sun Feb 13 00:28:16 2022 -0800

    Initial Project.
(END)

Oops looks really interesting, we should check it out with


┌──(kali㉿kali)-[~/mrphisher/commited]
└─$ git checkout c56c470a2a9dfb5cfbd54cd614a9fdb1644412b5               
Note: switching to 'c56c470a2a9dfb5cfbd54cd614a9fdb1644412b5'.

You are in 'detached HEAD' state. You can look around, make experimental
changes and commit them, and you can discard any commits you make in this
state without impacting any branches by switching back to a branch.

If you want to create a new branch to retain commits you create, you may
do so (now or later) by using -c with the switch command. Example:

  git switch -c <new-branch-name>

Or undo this operation with:

  git switch -

Turn off this advice by setting config variable advice.detachedHead to false

HEAD is now at c56c470 Oops



If we read main.py now, we see there is a username in the code:


┌──(kali㉿kali)-[~/mrphisher/commited]
└─$ cat main.py
import mysql.connector

def create_db():
    mydb = mysql.connector.connect(
    host="localhost",
    user="root", # Username Goes Here
    password="" # Password Goes Here
    )

    mycursor = mydb.cursor()

    mycursor.execute("CREATE DATABASE commited")


def create_tables():
    mydb = mysql.connector.connect(
    host="localhost",
    user="root", #username Goes here
    password="", #password Goes here
    database="commited"
    )

    mycursor = mydb.cursor()

    mycursor.execute("CREATE TABLE customers (name VARCHAR(255), address VARCHAR(255))")
    

def populate_tables():
    mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="commited"
    )

    mycursor = mydb.cursor()

    sql = "INSERT INTO customers (name, address) VALUES (%s, %s)"
    val = ("John", "Highway 21")
    mycursor.execute(sql, val)

    mydb.commit()

    print(mycursor.rowcount, "record inserted.")


create_db()
create_tables()
populate_tables()

So maybe if we view one commit earlier there is a password to…


┌──(kali㉿kali)-[~/mrphisher/commited]
└─$ git checkout 3a8cc16f919b8ac43651d68dceacbb28ebb9b625
Previous HEAD position was c56c470 Oops
HEAD is now at 3a8cc16 DB check
                                                                                                         
┌──(kali㉿kali)-[~/mrphisher/commited]
└─$ cat main.py
import mysql.connector

def create_db():
    mydb = mysql.connector.connect(
    host="localhost",
    user="root", # Username Goes Here
    password="flag{a489a9dbf8eb9d37c6e0cc1a92cda17b}" # Password Goes Here
    )

    mycursor = mydb.cursor()

    mycursor.execute("CREATE DATABASE commited")


def create_tables():
    mydb = mysql.connector.connect(
    host="localhost",
    user="root", #username Goes here
    password="flag{a489a9dbf8eb9d37c6e0cc1a92cda17b}", #password Goes here
    database="commited"
    )

    mycursor = mydb.cursor()

    mycursor.execute("CREATE TABLE customers (name VARCHAR(255), address VARCHAR(255))")
    

def populate_tables():
    mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    password="flag{a489a9dbf8eb9d37c6e0cc1a92cda17b}",
    database="commited"
    )

    mycursor = mydb.cursor()

    sql = "INSERT INTO customers (name, address) VALUES (%s, %s)"
    val = ("John", "Highway 21")
    mycursor.execute(sql, val)

    mydb.commit()

    print(mycursor.rowcount, "record inserted.")


create_db()
create_tables()
populate_tables()


```


Discover the flag in the repository!
*flag{a489a9dbf8eb9d37c6e0cc1a92cda17b}*




[[Mr. Phisher]]