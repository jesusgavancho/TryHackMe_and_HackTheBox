---
Enhance your Linux knowledge with this beginner friendly room!
---

![|222](https://tryhackme-images.s3.amazonaws.com/room-icons/a60460f94562420191b875ba8e7ddf5b.png)

In this task, we will be looking back at Linux Fundamentals and a few other topics that seem to cause some trouble around beginners. A requirement for this room is to finish the Linux Fundamentals rooms.

As it covers all the basic requirements and this is just a follow up to it in order to strengthen the understanding you gained throughout the room. In order to do so.
Below I will be asking a few questions related to that room, so please, make sure to complete it first :). If you didn't feel free to go through the tasks and come back to this once you finished the room.

The commands you are allowed to use in this room are:

    cat
    tac
    head
    tail
    xxd
    base64
    find
    grep
    echo
    xargs
    hexeditor
    tar
    gzip
    7zip
    binwalk

Bear in mind, commands such as cd are not allowed. 


***     The SSH credentials are chad:Infinity121       ***



What is the user you are logged in to in the first room of Linux Fundamentals Part 1?
*TryHackMe*


What badge do you receive when you complete all the Linux Fundamentals rooms?
*cat linux.txt*

###  ls 

This task should give you a better understanding of the command ls and a few of the switches that the command can take and what are some of the more efficient ones. Below is a screenshot of the help menu, however, feel free to use the man.

![](https://i.imgur.com/wtqmO0Y.png)

Hopefully, the above screenshot should help you go through a few of the tasks below, however further research is required. A good thing to know is that ls supports multiple ways of chaining switches. Such as:

    ls -x -y -z
    ls -xyz 

In some cases, you would need to keep evidence of your findings. Below we will start with some basic commands you should be familiar with.



How do you run the ls command?
*ls*



 How do you run the ls command to show all the files inside the folder?
 *ls -a*
 
How do you run the ls command to not show the current directory and the previous directory in the output? (almost everything)
*ls -A*



How do you show the information in a long listing format using ls?
*ls -l*



How do you show the size in readable format? e.g. k, Mb, etc
*ls -h*



How do you do a recursive ls?
*ls --recursive*


```
┌──(kali㉿kali)-[~/Downloads]
└─$ ssh chad@10.10.149.220
The authenticity of host '10.10.149.220 (10.10.149.220)' can't be established.
ED25519 key fingerprint is SHA256:uROxrJRt+adg6DuvXJOOtIMDLbXwhBdDlqZ49uxWfuw.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.149.220' (ED25519) to the list of known hosts.
chad@10.10.149.220's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Sep 26 21:59:40 UTC 2022

  System load:  0.0                Processes:           84
  Usage of /:   33.0% of 19.56GB   Users logged in:     0
  Memory usage: 13%                IP address for eth0: 10.10.149.220
  Swap usage:   0%


0 packages can be updated.
0 updates are security updates.


Last login: Tue Nov 10 22:36:51 2020 from 10.10.215.254
chad@flamenco:~$ 

chad@flamenco:~$ ls
base64.txt  binwalk.png  grep1.txt  gzip.txt.gz  tac.txt   tarball.tar  zip.7z
bin         cat.txt      grep.txt   head.txt     tail.txt  xxd.txt
chad@flamenco:~$ pwd
/home/chad


```

How many files did you locate in the home folder of the user?(non-hidden and not inside other folders)
*13*

### cat 

The cat command is one of the most common Linux commands that people use, however, in some instances, the cat command cannot be used as it's removed.

Below is a screenshot of the cat command's help menu.

![](https://i.imgur.com/lOqBTdk.png)

But, as we are professionals we know about a few alternatives of going around it:

The first command we are going to learn about is tac. Yes, cat spelt backwards. It is similar to the command, with the downside of less functionality.

![](https://i.imgur.com/uy57zbm.png)

Thus being a good tool to add to your toolbelt when you are limited by your reverse shell.


Another tool that can be used is head. This is usually used to get the beginning part of a file, however, you can use it to your heart's content and grab as many lines as you want.

![](https://i.imgur.com/Z0PisaW.png)

One more tool that can be used to grab the content of a file is tail. This is similar to the head command, however, as the name implies it will grab the last part of a file.

![](https://i.imgur.com/1v44ORA.png)

Another useful command is xxd. this can be used to generate a hex dump of the content of a file. Then, if you want you can either just read the text from the right-hand side or convert from hex to ASCII.

![](https://i.imgur.com/m0Mi60o.png)

Similar to the above you can use the base64 command to convert the text to base64 and then convert it back to ASCII.

![](https://i.imgur.com/Qq7UkLg.png)


```
                                                                                                         
┌──(kali㉿kali)-[~]
└─$ tac ftp_flag.txt 
THM{321452667098}
                                                                                                         
┌──(kali㉿kali)-[~]
└─$ head ftp_flag.txt 
THM{321452667098}
                                                                                                         
┌──(kali㉿kali)-[~]
└─$ tail ftp_flag.txt          
THM{321452667098}
                                                                                                         
┌──(kali㉿kali)-[~]
└─$ xxd ftp_flag.txt 
00000000: 5448 4d7b 3332 3134 3532 3636 3730 3938  THM{321452667098
00000010: 7d0a                                     }.
                                                                                                         
┌──(kali㉿kali)-[~]
└─$ base64 ftp_flag.txt| base64 --decode
THM{321452667098}
                   
```


```
chad@flamenco:~$ tac cat.txt
THM{11adbee391acdffee901}
chad@flamenco:~$ cat cat.txt
THM{11adbee391acdffee901}

chad@flamenco:~$ tac tac.txt
THM{acab0111aaa687912139}

chad@flamenco:~$ head head.txt
THM{894abac55f7962abc166}

chad@flamenco:~$ tail tail.txt
THM{1689acafdd20751acff6}

chad@flamenco:~$ xxd xxd.txt
00000000: 5448 4d7b 6661 6331 6161 6232 3130 6436  THM{fac1aab210d6
00000010: 6534 3431 3061 6364 7d0a                 e4410acd}.

chad@flamenco:~$ base64 base64.txt | base64 --decode
THM{aa462c1b2d44801c0a31}
```


What is the content of cat.txt?
*THM{11adbee391acdffee901}*



What is the content of tac.txt?
*THM{acab0111aaa687912139}*



What is the content of head.txt?
*THM{894abac55f7962abc166}*

What is the content of tail.txt?
*THM{1689acafdd20751acff6}*



What is the content of the xxd.txt?
*THM{fac1aab210d6e4410acd}*



What is the content of base64.txt?
*THM{aa462c1b2d44801c0a31}*

### find 

The find command is one of the most useful commands on a Linux operating system.

![](https://i.imgur.com/c763tFd.png)

This command can help us find specific files that match a pattern like:
find . -name *.txt
Or we can use it to find files that have a specific extension:
find / -type f -name "*.bak"

This simple command will start browsing the machine directory, finding all the files with extension .bak (backup).

![](https://i.imgur.com/TEw03hT.png)

But we can also use it to find files that have the SUID or SGID bit set like so:

	find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \;

This command combines permissions 4000 (SUID) and 2000 (SGID)

![](https://i.imgur.com/XmVTUyN.png)


```
chad@flamenco:~$ find . -type f -name "*.txt"
./head.txt
./grep.txt
./base64.txt
./tac.txt
./tail.txt
./cat.txt
./grep1.txt
./xxd.txt


chad@flamenco:~$ find . -type f \( -perm -4000 \) -exec ls -l {} \;

chad@flamenco:~$ find . -perm -4000 


```



How many .txt files did you find in the current folder?
*8*



How many SUID files have you found inside the home folder?
*0*

###  grep 

grep is a really useful command to grab text from files.

![](https://i.imgur.com/1WjzMSy.png)

Let's read through a few examples of grep commands and see how we can use them for our own benefit in a scenario.

grep "word" file

![](https://i.imgur.com/gfLmRxB.png)
Grep not only allows us to check if a certain word exists in the file but also outputs us the context in which the word had appeared. As you can see on the screenshot above, we were able to find an exact match to the word 'if' in the file script.py.

We can also compare two files with similar names using.

grep "word" file*

![](https://i.imgur.com/FLSIDGF.png)

```
chad@flamenco:~$ grep "hacker" grep* -o 
grep1.txt:hacker
grep1.txt:hacker
grep1.txt:hacker
grep1.txt:hacker
grep1.txt:hacker
grep1.txt:hacker
grep1.txt:hacker
grep1.txt:hacker
grep1.txt:hacker
grep1.txt:hacker
grep.txt:hacker
grep.txt:hacker
grep.txt:hacker
grep.txt:hacker
grep.txt:hacker
```

How many times does the word "hacker" appear in the grep files? (including variations)
*15*

### sudo 

sudo command allows certain users to execute a command as another user, according to settings in the /etc/sudoers file. By default, sudo requires that users authenticate themselves with a password of another user.

In the real-life scenario, sudo is mostly used to switch to root account and gain an ability to fully interact with the system.

![](https://i.imgur.com/CN0ckiJ.png)

sudo -l appears to be the most commonly used switch. It can always tell you which commands are you allowed to run as another user on the following system, and in some cases, can give you a clue to root access.

```
chad@flamenco:~$ sudo -l
-rbash: /usr/lib/command-not-found: restricted: cannot specify `/' in command names

```

Is the user allowed to run the above command? (Yay/Nay)
*Nay*


### chmod 

 The chmod command sets the permissions of files or directories.

![](https://i.imgur.com/Ghyg1lm.png)

Those permissions are divided between three main characters:

    User
    Group
    Other

All of them can rather read, write or execute a file. Permission to do so can be granted using chmod.

It can be done rather using letter notation or numerical values.

Let's take a look at the following command:

chmod u=rwx,g=rx,o=rw myfile


    u = user is being giver read, write and execute permission
    g = group can now read and execute
    o = other can read and write

This long notion can be eliminated by numerical values for permission. There are exactly four of them:

0 stands for "no permission."

1 stands for "execute";

2 stands for "write";

4 stands for "read".

Those values can be easily combined by adding them up.

For example, permission to read, write and execute would be 7 (1 + 2 + 4).

chmod 777 file

The following command will grant full file access to everyone on the system. (Those numerical values can be easily calculated using an interactive chmod-calculator).

chmod command comes in handy with ssh key files (id_rsa). By editing their permissions to 'user read-write only' we can use other people's id_rsa files to connect via ssh.

chmod 600 id_rsa

https://chmod-calculator.com/

###  echo 

echo is the most fundamental command found in most operating systems. It used to prints text to standard output, for example, terminal. It is mostly used in bash scripts in order to display output directly to user's console.

![](https://i.imgur.com/coZ6KbD.png)

echo can also be used to interact with other system commands and pass some value to them.

![](https://i.imgur.com/g8qlJV0.png)
echo also has a small trick which allows to print out any command output to console.

	echo "$( [command] )"

```
chad@flamenco:~$ echo "Hackerman"
Hackerman
```

What command would you use to echo the word "Hackerman" ?
*echo "Hackerman"*


###  xargs 

xargs command builds and executes command lines from standard input. It allows you to run the same command on a large number of files.

![](https://i.imgur.com/aeF8ODy.png)

xargs is often used with the find command, in order to easily interact with its input.

Let's take a look at the given command:

find /tmp -name test -type f -print | xargs /bin/rm -f
On the left side, we can see a command which should technically display all files under a name 'test'. xargs command on the left allows us to execute rm (remove) on those files and easily delete all of them.
Same can be done with reading all the files under the name 'test'.

```
find / -name *.bak -type f -print | xargs /bin/cat

```

How would you read all files with extension .bak using xargs?
*find / -name *.bak -type f print | xargs /bin/cat*

###  hexeditor 

Hexeditor is an awesome tool designed to read and modify hex of a file, this comes in handy especially when it comes to troubleshooting magic numbers for files such as JPG, WAV and any other types of files. This tool is also helpful when it comes to CTFs and text is hidden inside a file or when the magic number of a file was altered.

Another tool that is good for this kind of scenarios is called strings but we won't be talking about it in this part of our course.

![](https://i.imgur.com/qMRgTHV.png)

For this task, I will be providing you with resources to help you along your journey around challenges you might be facing in which you need the hexeditor tool.

A few resources I use for tasks that involve analysing files and fixing the magic number I use the following resources:

https://en.wikipedia.org/wiki/List_of_file_signatures

https://gist.github.com/leommoore/f9e57ba2aa4bf197ebc5

https://www.garykessler.net/library/file_sigs.html

###  curl 

The curl command transfers data to or from a network server, using one of the supported protocols (HTTP, HTTPS, FTP, FTPS, SCP, SFTP, TFTP, DICT, TELNET, LDAP or FILE). It is designed to work without any user interaction, so could be ideally used in a shell script.

curl is a huge tool with a lot of switches and possibilities. Let's take a look at some of the most important ones.

curl http://www.ismycomputeron.com/

![](https://i.imgur.com/57RQsie.png)

The most basic command. Fetches data from the website using the HTTP protocol, and display it using standard HTML code. This is essentially the same as "viewing the source" of the webpage.

The following command will limit the connection speed to 1,234 bytes/second:

curl --limit-rate 1234B http://www.ismycomputeron.com/
Another example is saving the output to a file using either:

-o to save the file under a different name
curl -o loginpage.html https://tryhackme.com/login

-O to save the file under the same name:
curl -O https://tryhackme.com/login

Or, you might be interested in fetching the headers silently?
curl -I -s https://tryhackme.com

```
┌──(kali㉿kali)-[~/Downloads/share]
└─$ curl -I -s https://tryhackme.com                             
HTTP/2 200 
date: Tue, 27 Sep 2022 01:16:34 GMT
content-type: text/html; charset=utf-8
set-cookie: AWSALB=WSWfgs7HxXokOt/PntZwQSjgAFWLM4io984Vl5hnUc5q3iAGc+HW/ElKdtC/dITJ5JxAIed8pWQwKMwHiEHsNOu8AxICrE07ShU4nh3UOxbOz9XD8OwW2cN3pU5i; Expires=Tue, 04 Oct 2022 01:16:34 GMT; Path=/
set-cookie: AWSALBCORS=WSWfgs7HxXokOt/PntZwQSjgAFWLM4io984Vl5hnUc5q3iAGc+HW/ElKdtC/dITJ5JxAIed8pWQwKMwHiEHsNOu8AxICrE07ShU4nh3UOxbOz9XD8OwW2cN3pU5i; Expires=Tue, 04 Oct 2022 01:16:34 GMT; Path=/; SameSite=None
set-cookie: _csrf=hhhahdada; Path=/
set-cookie: connect.sid=s%3A5pqisyi7sIeY1tsaQtjc_u08oCXdpxbr.APIb755O7Ttk6S5CCrICIgCuF90FykqLsZzfpeFrw%2BU; Path=/; Expires=Tue, 04 Oct 2022 01:16:34 GMT; HttpOnly
x-powered-by: Express
cf-cache-status: DYNAMIC
server: cloudflare
cf-ray: 7510650a2f1c56b2-LIM

┌──(kali㉿kali)-[~/Downloads/share]
└─$ curl -I -s https://tryhackme.com | grep HTTP
HTTP/2 200 


```

How would you grab the headers silently of https://tryhackme.com but grepping only the HTTP status code?
*curl -I -s https://tryhackme.com | grep HTTP*

### wget 

The wget command downloads files from HTTP, HTTPS, or FTP connection a network.

![](https://i.imgur.com/dp9xFVk.png)

wget http://somewebsite.com/files/images.zip

![](https://i.imgur.com/hDflpWK.png)

Adding a -b switch will allow us to run wget in the background and return the terminal to its initial state.

wget -b http://www.example.org/files/images.zip



What command would you run to get the flag.txt from https://tryhackme.com/ ?
*wget https://tryhackme.com/flag.txt*


```
┌──(kali㉿kali)-[~/Downloads/share]
└─$ wget -r -l =5 https://tryhackme.com
--2022-09-26 21:23:28--  https://tryhackme.com/
Resolving tryhackme.com (tryhackme.com)... 172.67.27.10, 104.22.55.228, 104.22.54.228, ...
Connecting to tryhackme.com (tryhackme.com)|172.67.27.10|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/index.html’

tryhackme.com/index.html       [ <=>                                  ]  35.34K   202KB/s    in 0.2s    

2022-09-26 21:23:29 (202 KB/s) - ‘tryhackme.com/index.html’ saved [36190]

Loading robots.txt; please ignore errors.
--2022-09-26 21:23:29--  https://tryhackme.com/robots.txt
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 69 [text/plain]
Saving to: ‘tryhackme.com/robots.txt’

tryhackme.com/robots.txt   100%[=====================================>]      69  --.-KB/s    in 0s      

2022-09-26 21:23:29 (50.2 MB/s) - ‘tryhackme.com/robots.txt’ saved [69/69]

--2022-09-26 21:23:29--  https://tryhackme.com/assets/pace/pace.js
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 27730 (27K) [application/javascript]
Saving to: ‘tryhackme.com/assets/pace/pace.js’

tryhackme.com/assets/pace/ 100%[=====================================>]  27.08K  --.-KB/s    in 0.001s  

2022-09-26 21:23:30 (51.7 MB/s) - ‘tryhackme.com/assets/pace/pace.js’ saved [27730/27730]

--2022-09-26 21:23:30--  https://tryhackme.com/assets/pace/themes/green/pace-theme-flash.css
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 2289 (2.2K) [text/css]
Saving to: ‘tryhackme.com/assets/pace/themes/green/pace-theme-flash.css’

tryhackme.com/assets/pace/ 100%[=====================================>]   2.24K  --.-KB/s    in 0s      

2022-09-26 21:23:30 (57.0 MB/s) - ‘tryhackme.com/assets/pace/themes/green/pace-theme-flash.css’ saved [2289/2289]

--2022-09-26 21:23:30--  https://tryhackme.com/hacktivities
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/hacktivities’

tryhackme.com/hacktivities     [ <=>                                  ]  31.95K  --.-KB/s    in 0.008s  

2022-09-26 21:23:30 (4.13 MB/s) - ‘tryhackme.com/hacktivities’ saved [32720]

--2022-09-26 21:23:30--  https://tryhackme.com/games/koth
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/games/koth’

tryhackme.com/games/koth       [ <=>                                  ]  42.42K   246KB/s    in 0.2s    

2022-09-26 21:23:31 (246 KB/s) - ‘tryhackme.com/games/koth’ saved [43438]

--2022-09-26 21:23:31--  https://tryhackme.com/leaderboards
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/leaderboards’

tryhackme.com/leaderboards     [ <=>                                  ]  33.78K  --.-KB/s    in 0.001s  

2022-09-26 21:23:31 (60.8 MB/s) - ‘tryhackme.com/leaderboards’ saved [34590]

--2022-09-26 21:23:31--  https://tryhackme.com/network/throwback
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/network/throwback’

tryhackme.com/network/thro     [ <=>                                  ]  35.52K  --.-KB/s    in 0s      

2022-09-26 21:23:31 (80.3 MB/s) - ‘tryhackme.com/network/throwback’ saved [36372]

--2022-09-26 21:23:31--  https://tryhackme.com/room/wreath
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/room/wreath’

tryhackme.com/room/wreath      [ <=>                                  ]  53.71K  --.-KB/s    in 0.001s  

2022-09-26 21:23:31 (54.5 MB/s) - ‘tryhackme.com/room/wreath’ saved [55001]

--2022-09-26 21:23:31--  https://tryhackme.com/classrooms
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/classrooms’

tryhackme.com/classrooms       [ <=>                                  ]  51.39K  --.-KB/s    in 0.004s  

2022-09-26 21:23:32 (12.4 MB/s) - ‘tryhackme.com/classrooms’ saved [52623]

--2022-09-26 21:23:32--  https://tryhackme.com/develop-rooms
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/develop-rooms’

tryhackme.com/develop-room     [ <=>                                  ]  21.50K  --.-KB/s    in 0.001s  

2022-09-26 21:23:32 (20.8 MB/s) - ‘tryhackme.com/develop-rooms’ saved [22020]

--2022-09-26 21:23:32--  https://tryhackme.com/business
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/business’

tryhackme.com/business         [ <=>                                  ]  42.90K  --.-KB/s    in 0s      

2022-09-26 21:23:32 (130 MB/s) - ‘tryhackme.com/business’ saved [43927]

--2022-09-26 21:23:32--  https://tryhackme.com/login
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/login’

tryhackme.com/login            [ <=>                                  ]  18.92K  --.-KB/s    in 0s      

2022-09-26 21:23:32 (68.2 MB/s) - ‘tryhackme.com/login’ saved [19377]

--2022-09-26 21:23:32--  https://tryhackme.com/signup
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/signup’

tryhackme.com/signup           [ <=>                                  ]  19.58K  --.-KB/s    in 0s      

2022-09-26 21:23:32 (221 MB/s) - ‘tryhackme.com/signup’ saved [20048]

--2022-09-26 21:23:32--  https://tryhackme.com/img/getting-started/rocketman.png
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 675773 (660K) [image/png]
Saving to: ‘tryhackme.com/img/getting-started/rocketman.png’

tryhackme.com/img/getting- 100%[=====================================>] 659.93K   917KB/s    in 0.7s    

2022-09-26 21:23:34 (917 KB/s) - ‘tryhackme.com/img/getting-started/rocketman.png’ saved [675773/675773]

--2022-09-26 21:23:34--  https://tryhackme.com/img/illustrations/waves.svg
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 129295 (126K) [image/svg+xml]
Saving to: ‘tryhackme.com/img/illustrations/waves.svg’

tryhackme.com/img/illustra 100%[=====================================>] 126.26K   364KB/s    in 0.3s    

2022-09-26 21:23:34 (364 KB/s) - ‘tryhackme.com/img/illustrations/waves.svg’ saved [129295/129295]

--2022-09-26 21:23:34--  https://tryhackme.com/img/general/networks.png
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 218874 (214K) [image/png]
Saving to: ‘tryhackme.com/img/general/networks.png’

tryhackme.com/img/general/ 100%[=====================================>] 213.74K   399KB/s    in 0.5s    

2022-09-26 21:23:36 (399 KB/s) - ‘tryhackme.com/img/general/networks.png’ saved [218874/218874]

--2022-09-26 21:23:36--  https://tryhackme.com/img/why_subscribe/testimonial_tweets2.png
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 704520 (688K) [image/png]
Saving to: ‘tryhackme.com/img/why_subscribe/testimonial_tweets2.png’

tryhackme.com/img/why_subs 100%[=====================================>] 688.01K   900KB/s    in 0.8s    

2022-09-26 21:23:37 (900 KB/s) - ‘tryhackme.com/img/why_subscribe/testimonial_tweets2.png’ saved [704520/704520]

--2022-09-26 21:23:37--  https://tryhackme.com/img/pix.png?ex1=text-1
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 150 [image/png]
Saving to: ‘tryhackme.com/img/pix.png?ex1=text-1’

tryhackme.com/img/pix.png? 100%[=====================================>]     150  --.-KB/s    in 0s      

2022-09-26 21:23:37 (85.5 MB/s) - ‘tryhackme.com/img/pix.png?ex1=text-1’ saved [150/150]

--2022-09-26 21:23:37--  https://tryhackme.com/resources/newsroom
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/resources/newsroom’

tryhackme.com/resources/ne     [ <=>                                  ]  23.87K  --.-KB/s    in 0s      

2022-09-26 21:23:37 (131 MB/s) - ‘tryhackme.com/resources/newsroom’ saved [24445]

--2022-09-26 21:23:37--  https://tryhackme.com/about
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/about’

tryhackme.com/about            [ <=>                                  ]  26.94K  --.-KB/s    in 0s      

2022-09-26 21:23:38 (144 MB/s) - ‘tryhackme.com/about’ saved [27582]

--2022-09-26 21:23:38--  https://tryhackme.com/resources/blog
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/resources/blog’

tryhackme.com/resources/bl     [ <=>                                  ]  23.87K  --.-KB/s    in 0s      

2022-09-26 21:23:38 (103 MB/s) - ‘tryhackme.com/resources/blog’ saved [24441]

--2022-09-26 21:23:38--  https://tryhackme.com/subscriptions
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/subscriptions’

tryhackme.com/subscription     [ <=>                                  ]  31.06K  --.-KB/s    in 0.006s  

2022-09-26 21:23:38 (5.33 MB/s) - ‘tryhackme.com/subscriptions’ saved [31802]

--2022-09-26 21:23:38--  https://tryhackme.com/cdn-cgi/l/email-protection
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/cdn-cgi/l/email-protection’

tryhackme.com/cdn-cgi/l/em     [ <=>                                  ]   4.58K  --.-KB/s    in 0.001s  

2022-09-26 21:23:38 (8.52 MB/s) - ‘tryhackme.com/cdn-cgi/l/email-protection’ saved [4690]

nofollow attribute found in tryhackme.com/cdn-cgi/l/email-protection. Will not follow any links on this page
--2022-09-26 21:23:38--  https://tryhackme.com/forum
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 301 Moved Permanently
Location: /forum/ [following]
--2022-09-26 21:23:38--  https://tryhackme.com/forum/
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/forum’

tryhackme.com/forum            [ <=>                                  ]  23.56K  --.-KB/s    in 0.002s  

2022-09-26 21:23:39 (15.2 MB/s) - ‘tryhackme.com/forum’ saved [24128]

--2022-09-26 21:23:39--  https://tryhackme.com/legal/terms-of-use
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/legal/terms-of-use’

tryhackme.com/legal/terms-     [ <=>                                  ]  28.11K  --.-KB/s    in 0.01s   

2022-09-26 21:23:39 (2.76 MB/s) - ‘tryhackme.com/legal/terms-of-use’ saved [28786]

pathconf: Not a directory
--2022-09-26 21:23:39--  https://tryhackme.com/login/google
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 302 Found
Location: https://accounts.google.com/o/oauth2/v2/auth?response_type=code&redirect_uri=https%3A%2F%2Ftryhackme.com%2Flogin%2Foauth2%2Fredirect%2Fgoogle&scope=email%20profile&client_id=51725810533-m41mtcp9pg3pac6ijemqd64ut7e579ki.apps.googleusercontent.com [following]
pathconf: Not a directory
--2022-09-26 21:23:39--  https://accounts.google.com/o/oauth2/v2/auth?response_type=code&redirect_uri=https%3A%2F%2Ftryhackme.com%2Flogin%2Foauth2%2Fredirect%2Fgoogle&scope=email%20profile&client_id=51725810533-m41mtcp9pg3pac6ijemqd64ut7e579ki.apps.googleusercontent.com
Resolving accounts.google.com (accounts.google.com)... 142.250.0.84, 2800:3f0:4003:c02::54
Connecting to accounts.google.com (accounts.google.com)|142.250.0.84|:443... connected.
HTTP request sent, awaiting response... 302 Moved Temporarily
Location: https://accounts.google.com/AccountChooser?oauth=1&continue=https%3A%2F%2Faccounts.google.com%2Fsignin%2Foauth%2Flegacy%2Fconsent%3Fauthuser%3Dunknown%26part%3DAJi8hAMuhUGlyhKnQHW96HTdaRNCFjnpBppUBBISSYTPMkWJ-7pjOe1MWyllj3Fu3V8ovL7pqVYFrM7WQz-DYJZVjtE_K9g1QTw2XCCWjqJT5xEaQGVxZzPpjSoaZ93WDvSxax8jPtCT8VkZ72AozUMeuMgVegTBEwBsOiV0vL7EbDhLf9YFS4ig7gnEIVJLLn7j2QmqXOGM2aMflwhkzQQefVmCy-n0k1N5DhYUzKYiBZbjnQ5DzaFqss5RX8yD0Di0GAGUpb50gbAjivAs5tO8MOR1pCXb8RJtvHfJadskZQltajlSN7eOQYhZurF70lM7qajvIYXfSGCO9UU1HVuFXWLnYDEX-84l7booq0tPPQvhmdgG8-5dy7cJEoTcvzcySUJ5IC1Wx-420BNDzIJhYFlBYeqwMi5-7x5g5s1H3Wmzkv1gJ6DLSlwNuMz_5ij79GwRcw2VblArQ6RxwEmU2B7-sWlhig%26as%3DS1241947396%253A1664241820104027%26client_id%3D51725810533-m41mtcp9pg3pac6ijemqd64ut7e579ki.apps.googleusercontent.com%23 [following]
pathconf: Not a directory
--2022-09-26 21:23:40--  https://accounts.google.com/AccountChooser?oauth=1&continue=https%3A%2F%2Faccounts.google.com%2Fsignin%2Foauth%2Flegacy%2Fconsent%3Fauthuser%3Dunknown%26part%3DAJi8hAMuhUGlyhKnQHW96HTdaRNCFjnpBppUBBISSYTPMkWJ-7pjOe1MWyllj3Fu3V8ovL7pqVYFrM7WQz-DYJZVjtE_K9g1QTw2XCCWjqJT5xEaQGVxZzPpjSoaZ93WDvSxax8jPtCT8VkZ72AozUMeuMgVegTBEwBsOiV0vL7EbDhLf9YFS4ig7gnEIVJLLn7j2QmqXOGM2aMflwhkzQQefVmCy-n0k1N5DhYUzKYiBZbjnQ5DzaFqss5RX8yD0Di0GAGUpb50gbAjivAs5tO8MOR1pCXb8RJtvHfJadskZQltajlSN7eOQYhZurF70lM7qajvIYXfSGCO9UU1HVuFXWLnYDEX-84l7booq0tPPQvhmdgG8-5dy7cJEoTcvzcySUJ5IC1Wx-420BNDzIJhYFlBYeqwMi5-7x5g5s1H3Wmzkv1gJ6DLSlwNuMz_5ij79GwRcw2VblArQ6RxwEmU2B7-sWlhig%26as%3DS1241947396%253A1664241820104027%26client_id%3D51725810533-m41mtcp9pg3pac6ijemqd64ut7e579ki.apps.googleusercontent.com%23
Reusing existing connection to accounts.google.com:443.
HTTP request sent, awaiting response... 302 Moved Temporarily
Location: https://accounts.google.com/ServiceLogin?continue=https%3A%2F%2Faccounts.google.com%2Fsignin%2Foauth%2Flegacy%2Fconsent%3Fauthuser%3Dunknown%26part%3DAJi8hAMuhUGlyhKnQHW96HTdaRNCFjnpBppUBBISSYTPMkWJ-7pjOe1MWyllj3Fu3V8ovL7pqVYFrM7WQz-DYJZVjtE_K9g1QTw2XCCWjqJT5xEaQGVxZzPpjSoaZ93WDvSxax8jPtCT8VkZ72AozUMeuMgVegTBEwBsOiV0vL7EbDhLf9YFS4ig7gnEIVJLLn7j2QmqXOGM2aMflwhkzQQefVmCy-n0k1N5DhYUzKYiBZbjnQ5DzaFqss5RX8yD0Di0GAGUpb50gbAjivAs5tO8MOR1pCXb8RJtvHfJadskZQltajlSN7eOQYhZurF70lM7qajvIYXfSGCO9UU1HVuFXWLnYDEX-84l7booq0tPPQvhmdgG8-5dy7cJEoTcvzcySUJ5IC1Wx-420BNDzIJhYFlBYeqwMi5-7x5g5s1H3Wmzkv1gJ6DLSlwNuMz_5ij79GwRcw2VblArQ6RxwEmU2B7-sWlhig%26as%3DS1241947396%253A1664241820104027%26client_id%3D51725810533-m41mtcp9pg3pac6ijemqd64ut7e579ki.apps.googleusercontent.com%23&sacu=1&oauth=1&rip=1 [following]
pathconf: Not a directory
--2022-09-26 21:23:40--  https://accounts.google.com/ServiceLogin?continue=https%3A%2F%2Faccounts.google.com%2Fsignin%2Foauth%2Flegacy%2Fconsent%3Fauthuser%3Dunknown%26part%3DAJi8hAMuhUGlyhKnQHW96HTdaRNCFjnpBppUBBISSYTPMkWJ-7pjOe1MWyllj3Fu3V8ovL7pqVYFrM7WQz-DYJZVjtE_K9g1QTw2XCCWjqJT5xEaQGVxZzPpjSoaZ93WDvSxax8jPtCT8VkZ72AozUMeuMgVegTBEwBsOiV0vL7EbDhLf9YFS4ig7gnEIVJLLn7j2QmqXOGM2aMflwhkzQQefVmCy-n0k1N5DhYUzKYiBZbjnQ5DzaFqss5RX8yD0Di0GAGUpb50gbAjivAs5tO8MOR1pCXb8RJtvHfJadskZQltajlSN7eOQYhZurF70lM7qajvIYXfSGCO9UU1HVuFXWLnYDEX-84l7booq0tPPQvhmdgG8-5dy7cJEoTcvzcySUJ5IC1Wx-420BNDzIJhYFlBYeqwMi5-7x5g5s1H3Wmzkv1gJ6DLSlwNuMz_5ij79GwRcw2VblArQ6RxwEmU2B7-sWlhig%26as%3DS1241947396%253A1664241820104027%26client_id%3D51725810533-m41mtcp9pg3pac6ijemqd64ut7e579ki.apps.googleusercontent.com%23&sacu=1&oauth=1&rip=1
Reusing existing connection to accounts.google.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/login/google’

tryhackme.com/login/google     [  <=>                                 ]  92.16K   249KB/s    in 0.4s    

2022-09-26 21:23:41 (249 KB/s) - ‘tryhackme.com/login/google’ saved [94370]

--2022-09-26 21:23:41--  https://tryhackme.com/img/google-logo.png
Connecting to tryhackme.com (tryhackme.com)|172.67.27.10|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 592 [image/png]
Saving to: ‘tryhackme.com/img/google-logo.png’

tryhackme.com/img/google-l 100%[=====================================>]     592  --.-KB/s    in 0s      

2022-09-26 21:23:41 (2.86 MB/s) - ‘tryhackme.com/img/google-logo.png’ saved [592/592]

--2022-09-26 21:23:41--  https://tryhackme.com/cdn-cgi/scripts/5c5dd728/cloudflare-static/email-decode.min.js
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 1239 (1.2K) [application/javascript]
Saving to: ‘tryhackme.com/cdn-cgi/scripts/5c5dd728/cloudflare-static/email-decode.min.js’

tryhackme.com/cdn-cgi/scri 100%[=====================================>]   1.21K  --.-KB/s    in 0s      

2022-09-26 21:23:41 (14.9 MB/s) - ‘tryhackme.com/cdn-cgi/scripts/5c5dd728/cloudflare-static/email-decode.min.js’ saved [1239/1239]

--2022-09-26 21:23:41--  https://tryhackme.com/img/lifecycle/learn.svg
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 8071 (7.9K) [image/svg+xml]
Saving to: ‘tryhackme.com/img/lifecycle/learn.svg’

tryhackme.com/img/lifecycl 100%[=====================================>]   7.88K  --.-KB/s    in 0.001s  

2022-09-26 21:23:42 (13.8 MB/s) - ‘tryhackme.com/img/lifecycle/learn.svg’ saved [8071/8071]

--2022-09-26 21:23:42--  https://tryhackme.com/img/lifecycle/practice.svg
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 8071 (7.9K) [image/svg+xml]
Saving to: ‘tryhackme.com/img/lifecycle/practice.svg’

tryhackme.com/img/lifecycl 100%[=====================================>]   7.88K  --.-KB/s    in 0s      

2022-09-26 21:23:42 (28.2 MB/s) - ‘tryhackme.com/img/lifecycle/practice.svg’ saved [8071/8071]

--2022-09-26 21:23:42--  https://tryhackme.com/img/lifecycle/none.svg
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 7915 (7.7K) [image/svg+xml]
Saving to: ‘tryhackme.com/img/lifecycle/none.svg’

tryhackme.com/img/lifecycl 100%[=====================================>]   7.73K  --.-KB/s    in 0s      

2022-09-26 21:23:42 (58.0 MB/s) - ‘tryhackme.com/img/lifecycle/none.svg’ saved [7915/7915]

--2022-09-26 21:23:42--  https://tryhackme.com/profile
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 302 Found
Location: /login [following]
--2022-09-26 21:23:43--  https://tryhackme.com/login
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/profile’

tryhackme.com/profile          [ <=>                                  ]  18.92K  --.-KB/s    in 0s      

2022-09-26 21:23:43 (49.1 MB/s) - ‘tryhackme.com/profile’ saved [19377]

--2022-09-26 21:23:43--  https://tryhackme.com/feedback
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 302 Found
Location: /login [following]
--2022-09-26 21:23:43--  https://tryhackme.com/login
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/feedback’

tryhackme.com/feedback         [ <=>                                  ]  18.92K  --.-KB/s    in 0s      

2022-09-26 21:23:43 (49.6 MB/s) - ‘tryhackme.com/feedback’ saved [19377]

--2022-09-26 21:23:43--  https://tryhackme.com/why-subscribe
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/why-subscribe’

tryhackme.com/why-subscrib     [ <=>                                  ]  22.80K  --.-KB/s    in 0s      

2022-09-26 21:23:44 (68.3 MB/s) - ‘tryhackme.com/why-subscribe’ saved [23347]

--2022-09-26 21:23:44--  https://tryhackme.com/paths
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/paths’

tryhackme.com/paths            [ <=>                                  ]  20.46K  --.-KB/s    in 0s      

2022-09-26 21:23:44 (105 MB/s) - ‘tryhackme.com/paths’ saved [20951]

--2022-09-26 21:23:44--  https://tryhackme.com/games/$%7BgetOSImage(koth.box.os)%7D
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 302 Found
Location: /404 [following]
--2022-09-26 21:23:44--  https://tryhackme.com/404
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 404 Not Found
2022-09-26 21:23:44 ERROR 404: Not Found.

Warning: wildcards not supported in HTTP.
--2022-09-26 21:23:44--  https://tryhackme.com/games/$%7BtableData[0].avatar%7D
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 302 Found
Location: /404 [following]
--2022-09-26 21:23:44--  https://tryhackme.com/404
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 404 Not Found
2022-09-26 21:23:45 ERROR 404: Not Found.

Warning: wildcards not supported in HTTP.
--2022-09-26 21:23:45--  https://tryhackme.com/p/$%7BtableData[0].username%7D
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 302 Found
Location: /404 [following]
--2022-09-26 21:23:45--  https://tryhackme.com/404
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 404 Not Found
2022-09-26 21:23:45 ERROR 404: Not Found.

--2022-09-26 21:23:45--  https://tryhackme.com/games/$%7BgetOSImage(machine.os)%7D
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 302 Found
Location: /404 [following]
--2022-09-26 21:23:45--  https://tryhackme.com/404
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 404 Not Found
2022-09-26 21:23:46 ERROR 404: Not Found.

--2022-09-26 21:23:46--  https://tryhackme.com/img/banners/throwback_clean.png
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 408970 (399K) [image/png]
Saving to: ‘tryhackme.com/img/banners/throwback_clean.png’

tryhackme.com/img/banners/ 100%[=====================================>] 399.38K   565KB/s    in 0.7s    

2022-09-26 21:23:47 (565 KB/s) - ‘tryhackme.com/img/banners/throwback_clean.png’ saved [408970/408970]

--2022-09-26 21:23:47--  https://tryhackme.com/img/throwback/throwback.svg
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 47506 (46K) [image/svg+xml]
Saving to: ‘tryhackme.com/img/throwback/throwback.svg’

tryhackme.com/img/throwbac 100%[=====================================>]  46.39K   266KB/s    in 0.2s    

2022-09-26 21:23:48 (266 KB/s) - ‘tryhackme.com/img/throwback/throwback.svg’ saved [47506/47506]

--2022-09-26 21:23:48--  https://tryhackme.com/img/users/timtaylor.jpg
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 11813 (12K) [image/jpeg]
Saving to: ‘tryhackme.com/img/users/timtaylor.jpg’

tryhackme.com/img/users/ti 100%[=====================================>]  11.54K  --.-KB/s    in 0s      

2022-09-26 21:23:48 (59.6 MB/s) - ‘tryhackme.com/img/users/timtaylor.jpg’ saved [11813/11813]

--2022-09-26 21:23:48--  https://tryhackme.com/img/users/Davew.jpg
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 15867 (15K) [image/jpeg]
Saving to: ‘tryhackme.com/img/users/Davew.jpg’

tryhackme.com/img/users/Da 100%[=====================================>]  15.50K  --.-KB/s    in 0s      

2022-09-26 21:23:48 (61.3 MB/s) - ‘tryhackme.com/img/users/Davew.jpg’ saved [15867/15867]

--2022-09-26 21:23:48--  https://tryhackme.com/img/users/themayor.png
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 64047 (63K) [image/png]
Saving to: ‘tryhackme.com/img/users/themayor.png’

tryhackme.com/img/users/th 100%[=====================================>]  62.55K   352KB/s    in 0.2s    

2022-09-26 21:23:49 (352 KB/s) - ‘tryhackme.com/img/users/themayor.png’ saved [64047/64047]

--2022-09-26 21:23:49--  https://tryhackme.com/img/users/IamDuco.png
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 366418 (358K) [image/png]
Saving to: ‘tryhackme.com/img/users/IamDuco.png’

tryhackme.com/img/users/Ia 100%[=====================================>] 357.83K   700KB/s    in 0.5s    

2022-09-26 21:23:50 (700 KB/s) - ‘tryhackme.com/img/users/IamDuco.png’ saved [366418/366418]

--2022-09-26 21:23:50--  https://tryhackme.com/img/users/ninjajc01.jpg
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 62110 (61K) [image/jpeg]
Saving to: ‘tryhackme.com/img/users/ninjajc01.jpg’

tryhackme.com/img/users/ni 100%[=====================================>]  60.65K   359KB/s    in 0.2s    

2022-09-26 21:23:51 (359 KB/s) - ‘tryhackme.com/img/users/ninjajc01.jpg’ saved [62110/62110]

--2022-09-26 21:23:51--  https://tryhackme.com/img/throwback/throwback_shield.svg
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 24838 (24K) [image/svg+xml]
Saving to: ‘tryhackme.com/img/throwback/throwback_shield.svg’

tryhackme.com/img/throwbac 100%[=====================================>]  24.26K  --.-KB/s    in 0s      

2022-09-26 21:23:51 (98.5 MB/s) - ‘tryhackme.com/img/throwback/throwback_shield.svg’ saved [24838/24838]

--2022-09-26 21:23:51--  https://tryhackme.com/network/$%7Bcreator.avatar%7D
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 302 Found
Location: /404 [following]
--2022-09-26 21:23:51--  https://tryhackme.com/404
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 404 Not Found
2022-09-26 21:23:52 ERROR 404: Not Found.

--2022-09-26 21:23:52--  https://tryhackme.com/p/$%7Bcreator.username%7D
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 302 Found
Location: /404 [following]
--2022-09-26 21:23:52--  https://tryhackme.com/404
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 404 Not Found
2022-09-26 21:23:52 ERROR 404: Not Found.

--2022-09-26 21:23:52--  https://tryhackme.com/socket.io/socket.io.js
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [application/javascript]
Saving to: ‘tryhackme.com/socket.io/socket.io.js’

tryhackme.com/socket.io/so     [ <=>                                  ] 105.00K   590KB/s    in 0.2s    

2022-09-26 21:23:53 (590 KB/s) - ‘tryhackme.com/socket.io/socket.io.js’ saved [107516]

--2022-09-26 21:23:53--  https://tryhackme.com/css/utils/network.css
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 832 [text/css]
Saving to: ‘tryhackme.com/css/utils/network.css’

tryhackme.com/css/utils/ne 100%[=====================================>]     832  --.-KB/s    in 0s      

2022-09-26 21:23:53 (16.8 MB/s) - ‘tryhackme.com/css/utils/network.css’ saved [832/832]

--2022-09-26 21:23:53--  https://tryhackme.com/api/room/manage/clone/wreath
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 302 Found
Location: /login [following]
--2022-09-26 21:23:53--  https://tryhackme.com/login
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/api/room/manage/clone/wreath’

tryhackme.com/api/room/man     [ <=>                                  ]  18.92K  --.-KB/s    in 0s      

2022-09-26 21:23:53 (132 MB/s) - ‘tryhackme.com/api/room/manage/clone/wreath’ saved [19377]

--2022-09-26 21:23:53--  https://tryhackme.com/img/tutorials/clipboard.gif
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 58786 (57K) [image/gif]
Saving to: ‘tryhackme.com/img/tutorials/clipboard.gif’

tryhackme.com/img/tutorial 100%[=====================================>]  57.41K  --.-KB/s    in 0.004s  

2022-09-26 21:23:54 (14.4 MB/s) - ‘tryhackme.com/img/tutorials/clipboard.gif’ saved [58786/58786]

--2022-09-26 21:23:54--  https://tryhackme.com/access
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 302 Found
Location: /login [following]
--2022-09-26 21:23:54--  https://tryhackme.com/login
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/access’

tryhackme.com/access           [ <=>                                  ]  18.92K  --.-KB/s    in 0s      

2022-09-26 21:23:54 (102 MB/s) - ‘tryhackme.com/access’ saved [19377]

--2022-09-26 21:23:54--  https://tryhackme.com/img/connect/connect_openvpn_short.png
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 12609 (12K) [image/png]
Saving to: ‘tryhackme.com/img/connect/connect_openvpn_short.png’

tryhackme.com/img/connect/ 100%[=====================================>]  12.31K  --.-KB/s    in 0s      

2022-09-26 21:23:54 (25.2 MB/s) - ‘tryhackme.com/img/connect/connect_openvpn_short.png’ saved [12609/12609]

--2022-09-26 21:23:54--  https://tryhackme.com/img/connect/connect_kali_short.png
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 12303 (12K) [image/png]
Saving to: ‘tryhackme.com/img/connect/connect_kali_short.png’

tryhackme.com/img/connect/ 100%[=====================================>]  12.01K  --.-KB/s    in 0s      

2022-09-26 21:23:55 (132 MB/s) - ‘tryhackme.com/img/connect/connect_kali_short.png’ saved [12303/12303]

--2022-09-26 21:23:55--  https://tryhackme.com/img/illustrations/tryhackme_connect.png
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 48823 (48K) [image/png]
Saving to: ‘tryhackme.com/img/illustrations/tryhackme_connect.png’

tryhackme.com/img/illustra 100%[=====================================>]  47.68K   274KB/s    in 0.2s    

2022-09-26 21:23:55 (274 KB/s) - ‘tryhackme.com/img/illustrations/tryhackme_connect.png’ saved [48823/48823]

--2022-09-26 21:23:55--  https://tryhackme.com/vpn/get-config
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 302 Found
Location: /login [following]
--2022-09-26 21:23:56--  https://tryhackme.com/login
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/vpn/get-config’

tryhackme.com/vpn/get-conf     [ <=>                                  ]  18.92K  --.-KB/s    in 0s      

2022-09-26 21:23:56 (41.6 MB/s) - ‘tryhackme.com/vpn/get-config’ saved [19377]

--2022-09-26 21:23:56--  https://tryhackme.com/my-machine
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 302 Found
Location: /login [following]
--2022-09-26 21:23:56--  https://tryhackme.com/login
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/my-machine’

tryhackme.com/my-machine       [ <=>                                  ]  18.92K  --.-KB/s    in 0s      

2022-09-26 21:23:56 (55.5 MB/s) - ‘tryhackme.com/my-machine’ saved [19377]

--2022-09-26 21:23:56--  https://tryhackme.com/img/logo/tryhackme_logo.svg
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 6313 (6.2K) [image/svg+xml]
Saving to: ‘tryhackme.com/img/logo/tryhackme_logo.svg’

tryhackme.com/img/logo/try 100%[=====================================>]   6.17K  --.-KB/s    in 0s      

2022-09-26 21:23:56 (178 MB/s) - ‘tryhackme.com/img/logo/tryhackme_logo.svg’ saved [6313/6313]

--2022-09-26 21:23:56--  https://tryhackme.com/room/linux1
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/room/linux1’

tryhackme.com/room/linux1      [ <=>                                  ]  52.50K  --.-KB/s    in 0.001s  

2022-09-26 21:23:57 (59.5 MB/s) - ‘tryhackme.com/room/linux1’ saved [53759]

--2022-09-26 21:23:57--  https://tryhackme.com/module/linux-fundamentals
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/module/linux-fundamentals’

tryhackme.com/module/linux     [ <=>                                  ]  22.93K  --.-KB/s    in 0.001s  

2022-09-26 21:23:57 (35.8 MB/s) - ‘tryhackme.com/module/linux-fundamentals’ saved [23476]

--2022-09-26 21:23:57--  https://tryhackme.com/room/webfundamentals
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 301 Moved Permanently
Location: https://tryhackme.com/room/httpindetail [following]
--2022-09-26 21:23:57--  https://tryhackme.com/room/httpindetail
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/room/webfundamentals’

tryhackme.com/room/webfund     [ <=>                                  ]  52.22K  --.-KB/s    in 0s      

2022-09-26 21:23:57 (132 MB/s) - ‘tryhackme.com/room/webfundamentals’ saved [53477]

--2022-09-26 21:23:57--  https://tryhackme.com/module/web-hacking-1
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/module/web-hacking-1’

tryhackme.com/module/web-h     [ <=>                                  ]  23.49K  --.-KB/s    in 0s      

2022-09-26 21:23:57 (86.6 MB/s) - ‘tryhackme.com/module/web-hacking-1’ saved [24058]

--2022-09-26 21:23:57--  https://tryhackme.com/room/owasptop10
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/room/owasptop10’

tryhackme.com/room/owaspto     [ <=>                                  ]  51.76K  --.-KB/s    in 0.001s  

2022-09-26 21:23:57 (52.0 MB/s) - ‘tryhackme.com/room/owasptop10’ saved [52999]

--2022-09-26 21:23:57--  https://tryhackme.com/room/introtonetworking
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/room/introtonetworking’

tryhackme.com/room/introto     [ <=>                                  ]  51.68K  --.-KB/s    in 0.002s  

2022-09-26 21:23:58 (29.4 MB/s) - ‘tryhackme.com/room/introtonetworking’ saved [52919]

--2022-09-26 21:23:58--  https://tryhackme.com/room/furthernmap
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/room/furthernmap’

tryhackme.com/room/further     [ <=>                                  ]  51.67K  --.-KB/s    in 0.001s  

2022-09-26 21:23:58 (38.5 MB/s) - ‘tryhackme.com/room/furthernmap’ saved [52906]

--2022-09-26 21:23:58--  https://tryhackme.com/module/intro-to-networking
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/module/intro-to-networking’

tryhackme.com/module/intro     [ <=>                                  ]  22.84K  --.-KB/s    in 0s      

2022-09-26 21:23:58 (129 MB/s) - ‘tryhackme.com/module/intro-to-networking’ saved [23384]

--2022-09-26 21:23:58--  https://tryhackme.com/room/rpmetasploit
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 301 Moved Permanently
Location: https://tryhackme.com/room/metasploitintro [following]
--2022-09-26 21:23:58--  https://tryhackme.com/room/metasploitintro
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/room/rpmetasploit’

tryhackme.com/room/rpmetas     [ <=>                                  ]  51.71K  --.-KB/s    in 0s      

2022-09-26 21:23:58 (110 MB/s) - ‘tryhackme.com/room/rpmetasploit’ saved [52955]

--2022-09-26 21:23:58--  https://tryhackme.com/room/vulnversity
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/room/vulnversity’

tryhackme.com/room/vulnver     [ <=>                                  ]  53.91K  --.-KB/s    in 0.008s  

2022-09-26 21:23:59 (6.39 MB/s) - ‘tryhackme.com/room/vulnversity’ saved [55202]

--2022-09-26 21:23:59--  https://tryhackme.com/room/basicpentestingjt
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/room/basicpentestingjt’

tryhackme.com/room/basicpe     [ <=>                                  ]  52.24K  --.-KB/s    in 0.001s  

2022-09-26 21:23:59 (35.2 MB/s) - ‘tryhackme.com/room/basicpentestingjt’ saved [53494]

--2022-09-26 21:23:59--  https://tryhackme.com/module/basic-computer-exploitation
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/module/basic-computer-exploitation’

tryhackme.com/module/basic     [ <=>                                  ]  22.90K  --.-KB/s    in 0s      

2022-09-26 21:23:59 (136 MB/s) - ‘tryhackme.com/module/basic-computer-exploitation’ saved [23452]

--2022-09-26 21:23:59--  https://tryhackme.com/module/threat-and-vulnerability-management
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/module/threat-and-vulnerability-management’

tryhackme.com/module/threa     [ <=>                                  ]  23.24K  --.-KB/s    in 0s      

2022-09-26 21:23:59 (60.9 MB/s) - ‘tryhackme.com/module/threat-and-vulnerability-management’ saved [23793]

--2022-09-26 21:23:59--  https://tryhackme.com/module/malware-analysis
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/module/malware-analysis’

tryhackme.com/module/malwa     [ <=>                                  ]  23.08K  --.-KB/s    in 0s      

2022-09-26 21:23:59 (162 MB/s) - ‘tryhackme.com/module/malware-analysis’ saved [23633]

--2022-09-26 21:23:59--  https://tryhackme.com/module/security-operations-and-monitoring
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/module/security-operations-and-monitoring’

tryhackme.com/module/secur     [ <=>                                  ]  23.37K  --.-KB/s    in 0s      

2022-09-26 21:24:00 (46.4 MB/s) - ‘tryhackme.com/module/security-operations-and-monitoring’ saved [23934]

--2022-09-26 21:24:00--  https://tryhackme.com/module/incident-response-and-forensics
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/module/incident-response-and-forensics’

tryhackme.com/module/incid     [ <=>                                  ]  22.89K  --.-KB/s    in 0s      

2022-09-26 21:24:00 (86.3 MB/s) - ‘tryhackme.com/module/incident-response-and-forensics’ saved [23444]

--2022-09-26 21:24:00--  https://tryhackme.com/module/threat-emulation
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/module/threat-emulation’

tryhackme.com/module/threa     [ <=>                                  ]  22.56K  --.-KB/s    in 0s      

2022-09-26 21:24:00 (124 MB/s) - ‘tryhackme.com/module/threat-emulation’ saved [23097]

--2022-09-26 21:24:00--  https://tryhackme.com/img/classrooms/tshirt.png
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 153549 (150K) [image/png]
Saving to: ‘tryhackme.com/img/classrooms/tshirt.png’

tryhackme.com/img/classroo 100%[=====================================>] 149.95K   816KB/s    in 0.2s    

2022-09-26 21:24:00 (816 KB/s) - ‘tryhackme.com/img/classrooms/tshirt.png’ saved [153549/153549]

--2022-09-26 21:24:00--  https://tryhackme.com/img/illustrations/tryhackme_book.svg
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 14909 (15K) [image/svg+xml]
Saving to: ‘tryhackme.com/img/illustrations/tryhackme_book.svg’

tryhackme.com/img/illustra 100%[=====================================>]  14.56K  --.-KB/s    in 0s      

2022-09-26 21:24:01 (129 MB/s) - ‘tryhackme.com/img/illustrations/tryhackme_book.svg’ saved [14909/14909]

--2022-09-26 21:24:01--  https://tryhackme.com/img/illustrations/tryhackme_teaching.png
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 1632953 (1.6M) [image/png]
Saving to: ‘tryhackme.com/img/illustrations/tryhackme_teaching.png’

tryhackme.com/img/illustra 100%[=====================================>]   1.56M  2.89MB/s    in 0.5s    

2022-09-26 21:24:02 (2.89 MB/s) - ‘tryhackme.com/img/illustrations/tryhackme_teaching.png’ saved [1632953/1632953]

--2022-09-26 21:24:02--  https://tryhackme.com/img/business/business-header.png
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 28333 (28K) [image/png]
Saving to: ‘tryhackme.com/img/business/business-header.png’

tryhackme.com/img/business 100%[=====================================>]  27.67K  --.-KB/s    in 0s      

2022-09-26 21:24:02 (181 MB/s) - ‘tryhackme.com/img/business/business-header.png’ saved [28333/28333]

--2022-09-26 21:24:02--  https://tryhackme.com/img/business/comptia.png
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 38325 (37K) [image/png]
Saving to: ‘tryhackme.com/img/business/comptia.png’

tryhackme.com/img/business 100%[=====================================>]  37.43K  --.-KB/s    in 0s      

2022-09-26 21:24:03 (158 MB/s) - ‘tryhackme.com/img/business/comptia.png’ saved [38325/38325]

--2022-09-26 21:24:03--  https://tryhackme.com/img/business/kpmg.png
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 26920 (26K) [image/png]
Saving to: ‘tryhackme.com/img/business/kpmg.png’

tryhackme.com/img/business 100%[=====================================>]  26.29K  --.-KB/s    in 0s      

2022-09-26 21:24:03 (136 MB/s) - ‘tryhackme.com/img/business/kpmg.png’ saved [26920/26920]

--2022-09-26 21:24:03--  https://tryhackme.com/img/business/olx.png
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 11512 (11K) [image/png]
Saving to: ‘tryhackme.com/img/business/olx.png’

tryhackme.com/img/business 100%[=====================================>]  11.24K  --.-KB/s    in 0s      

2022-09-26 21:24:04 (126 MB/s) - ‘tryhackme.com/img/business/olx.png’ saved [11512/11512]

--2022-09-26 21:24:04--  https://tryhackme.com/img/business/travelperk.png
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 9840 (9.6K) [image/png]
Saving to: ‘tryhackme.com/img/business/travelperk.png’

tryhackme.com/img/business 100%[=====================================>]   9.61K  --.-KB/s    in 0s      

2022-09-26 21:24:04 (52.8 MB/s) - ‘tryhackme.com/img/business/travelperk.png’ saved [9840/9840]

--2022-09-26 21:24:04--  https://tryhackme.com/img/business/cyberconvoy.png
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 14583 (14K) [image/png]
Saving to: ‘tryhackme.com/img/business/cyberconvoy.png’

tryhackme.com/img/business 100%[=====================================>]  14.24K  --.-KB/s    in 0s      

2022-09-26 21:24:04 (118 MB/s) - ‘tryhackme.com/img/business/cyberconvoy.png’ saved [14583/14583]

--2022-09-26 21:24:04--  https://tryhackme.com/img/illustrations/curve.svg
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 587 [image/svg+xml]
Saving to: ‘tryhackme.com/img/illustrations/curve.svg’

tryhackme.com/img/illustra 100%[=====================================>]     587  --.-KB/s    in 0s      

2022-09-26 21:24:05 (6.63 MB/s) - ‘tryhackme.com/img/illustrations/curve.svg’ saved [587/587]

--2022-09-26 21:24:05--  https://tryhackme.com/img/business/koth.png
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 298348 (291K) [image/png]
Saving to: ‘tryhackme.com/img/business/koth.png’

tryhackme.com/img/business 100%[=====================================>] 291.36K   511KB/s    in 0.6s    

2022-09-26 21:24:06 (511 KB/s) - ‘tryhackme.com/img/business/koth.png’ saved [298348/298348]

pathconf: Not a directory
--2022-09-26 21:24:06--  https://tryhackme.com/resources/blog/log4j-threat-mitigation
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/resources/blog/log4j-threat-mitigation’

tryhackme.com/resources/bl     [ <=>                                  ]  33.94K  --.-KB/s    in 0s      

2022-09-26 21:24:06 (80.8 MB/s) - ‘tryhackme.com/resources/blog/log4j-threat-mitigation’ saved [34750]

--2022-09-26 21:24:06--  https://tryhackme.com/resources/blog/how-to-build-a-cyber-culture-in-your-workforce
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/resources/blog/how-to-build-a-cyber-culture-in-your-workforce’

tryhackme.com/resources/bl     [ <=>                                  ]  37.75K  --.-KB/s    in 0s      

2022-09-26 21:24:06 (74.4 MB/s) - ‘tryhackme.com/resources/blog/how-to-build-a-cyber-culture-in-your-workforce’ saved [38655]

--2022-09-26 21:24:06--  https://tryhackme.com/resources/blog/cyber-security-needs-to-be-a-business-priority
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/resources/blog/cyber-security-needs-to-be-a-business-priority’

tryhackme.com/resources/bl     [ <=>                                  ]  33.71K  --.-KB/s    in 0s      

2022-09-26 21:24:07 (101 MB/s) - ‘tryhackme.com/resources/blog/cyber-security-needs-to-be-a-business-priority’ saved [34518]

--2022-09-26 21:24:07--  https://tryhackme.com/forgot
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/forgot’

tryhackme.com/forgot           [ <=>                                  ]  19.86K  --.-KB/s    in 0s      

2022-09-26 21:24:07 (103 MB/s) - ‘tryhackme.com/forgot’ saved [20341]

--2022-09-26 21:24:07--  https://tryhackme.com/img/illustrations/ben-ashu-banner-lq.png
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 475177 (464K) [image/png]
Saving to: ‘tryhackme.com/img/illustrations/ben-ashu-banner-lq.png’

tryhackme.com/img/illustra 100%[=====================================>] 464.04K   673KB/s    in 0.7s    

2022-09-26 21:24:08 (673 KB/s) - ‘tryhackme.com/img/illustrations/ben-ashu-banner-lq.png’ saved [475177/475177]

--2022-09-26 21:24:08--  https://tryhackme.com/img/events/generic/cyberready2.jpg
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 418083 (408K) [image/jpeg]
Saving to: ‘tryhackme.com/img/events/generic/cyberready2.jpg’

tryhackme.com/img/events/g 100%[=====================================>] 408.28K  2.27MB/s    in 0.2s    

2022-09-26 21:24:09 (2.27 MB/s) - ‘tryhackme.com/img/events/generic/cyberready2.jpg’ saved [418083/418083]

--2022-09-26 21:24:09--  https://tryhackme.com/img/events/generic/cyberready.jpeg
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 484063 (473K) [image/jpeg]
Saving to: ‘tryhackme.com/img/events/generic/cyberready.jpeg’

tryhackme.com/img/events/g 100%[=====================================>] 472.72K   662KB/s    in 0.7s    

2022-09-26 21:24:10 (662 KB/s) - ‘tryhackme.com/img/events/generic/cyberready.jpeg’ saved [484063/484063]

--2022-09-26 21:24:10--  https://tryhackme.com/img/users/DarkStar7471.png
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 3079 (3.0K) [image/png]
Saving to: ‘tryhackme.com/img/users/DarkStar7471.png’

tryhackme.com/img/users/Da 100%[=====================================>]   3.01K  --.-KB/s    in 0s      

2022-09-26 21:24:10 (23.5 MB/s) - ‘tryhackme.com/img/users/DarkStar7471.png’ saved [3079/3079]

--2022-09-26 21:24:10--  https://tryhackme.com/img/users/0day.png
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 31037 (30K) [image/png]
Saving to: ‘tryhackme.com/img/users/0day.png’

tryhackme.com/img/users/0d 100%[=====================================>]  30.31K  --.-KB/s    in 0s      

2022-09-26 21:24:10 (148 MB/s) - ‘tryhackme.com/img/users/0day.png’ saved [31037/31037]

--2022-09-26 21:24:10--  https://tryhackme.com/img/users/cmnatic.jpg
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 8773 (8.6K) [image/jpeg]
Saving to: ‘tryhackme.com/img/users/cmnatic.jpg’

tryhackme.com/img/users/cm 100%[=====================================>]   8.57K  --.-KB/s    in 0s      

2022-09-26 21:24:10 (51.4 MB/s) - ‘tryhackme.com/img/users/cmnatic.jpg’ saved [8773/8773]

--2022-09-26 21:24:10--  https://tryhackme.com/img/users/MuirlandOracle.png
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 338539 (331K) [image/png]
Saving to: ‘tryhackme.com/img/users/MuirlandOracle.png’

tryhackme.com/img/users/Mu 100%[=====================================>] 330.60K   585KB/s    in 0.6s    

2022-09-26 21:24:12 (585 KB/s) - ‘tryhackme.com/img/users/MuirlandOracle.png’ saved [338539/338539]

--2022-09-26 21:24:12--  https://tryhackme.com/img/users/4ndr34zz.png
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 21101 (21K) [image/png]
Saving to: ‘tryhackme.com/img/users/4ndr34zz.png’

tryhackme.com/img/users/4n 100%[=====================================>]  20.61K  --.-KB/s    in 0s      

2022-09-26 21:24:12 (168 MB/s) - ‘tryhackme.com/img/users/4ndr34zz.png’ saved [21101/21101]

--2022-09-26 21:24:12--  https://tryhackme.com/img/users/spooks.jpg
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 45073 (44K) [image/jpeg]
Saving to: ‘tryhackme.com/img/users/spooks.jpg’

tryhackme.com/img/users/sp 100%[=====================================>]  44.02K   257KB/s    in 0.2s    

2022-09-26 21:24:12 (257 KB/s) - ‘tryhackme.com/img/users/spooks.jpg’ saved [45073/45073]

--2022-09-26 21:24:12--  https://tryhackme.com/img/users/Cryillic.png
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 10523 (10K) [image/png]
Saving to: ‘tryhackme.com/img/users/Cryillic.png’

tryhackme.com/img/users/Cr 100%[=====================================>]  10.28K  --.-KB/s    in 0s      

2022-09-26 21:24:13 (201 MB/s) - ‘tryhackme.com/img/users/Cryillic.png’ saved [10523/10523]

--2022-09-26 21:24:13--  https://tryhackme.com/img/users/bee.jpeg
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 20430 (20K) [image/jpeg]
Saving to: ‘tryhackme.com/img/users/bee.jpeg’

tryhackme.com/img/users/be 100%[=====================================>]  19.95K  --.-KB/s    in 0s      

2022-09-26 21:24:13 (116 MB/s) - ‘tryhackme.com/img/users/bee.jpeg’ saved [20430/20430]

--2022-09-26 21:24:13--  https://tryhackme.com/img/users/Chevalier.png
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 87055 (85K) [image/png]
Saving to: ‘tryhackme.com/img/users/Chevalier.png’

tryhackme.com/img/users/Ch 100%[=====================================>]  85.01K   495KB/s    in 0.2s    

2022-09-26 21:24:14 (495 KB/s) - ‘tryhackme.com/img/users/Chevalier.png’ saved [87055/87055]

--2022-09-26 21:24:14--  https://tryhackme.com/img/users/zayotic.jpg
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 16667 (16K) [image/jpeg]
Saving to: ‘tryhackme.com/img/users/zayotic.jpg’

tryhackme.com/img/users/za 100%[=====================================>]  16.28K  --.-KB/s    in 0s      

2022-09-26 21:24:14 (137 MB/s) - ‘tryhackme.com/img/users/zayotic.jpg’ saved [16667/16667]

--2022-09-26 21:24:14--  https://tryhackme.com/img/users/bobloblaw.png
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 203627 (199K) [image/png]
Saving to: ‘tryhackme.com/img/users/bobloblaw.png’

tryhackme.com/img/users/bo 100%[=====================================>] 198.85K  1.08MB/s    in 0.2s    

2022-09-26 21:24:15 (1.08 MB/s) - ‘tryhackme.com/img/users/bobloblaw.png’ saved [203627/203627]

--2022-09-26 21:24:15--  https://tryhackme.com/img/users/ma1ware.png
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 9733 (9.5K) [image/png]
Saving to: ‘tryhackme.com/img/users/ma1ware.png’

tryhackme.com/img/users/ma 100%[=====================================>]   9.50K  --.-KB/s    in 0s      

2022-09-26 21:24:15 (139 MB/s) - ‘tryhackme.com/img/users/ma1ware.png’ saved [9733/9733]

--2022-09-26 21:24:15--  https://tryhackme.com/img/users/Swafox.jpg
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 36658 (36K) [image/jpeg]
Saving to: ‘tryhackme.com/img/users/Swafox.jpg’

tryhackme.com/img/users/Sw 100%[=====================================>]  35.80K  --.-KB/s    in 0s      

2022-09-26 21:24:15 (112 MB/s) - ‘tryhackme.com/img/users/Swafox.jpg’ saved [36658/36658]

--2022-09-26 21:24:15--  https://tryhackme.com/img/users/szymex73.png
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 15811 (15K) [image/png]
Saving to: ‘tryhackme.com/img/users/szymex73.png’

tryhackme.com/img/users/sz 100%[=====================================>]  15.44K  --.-KB/s    in 0s      

2022-09-26 21:24:16 (99.6 MB/s) - ‘tryhackme.com/img/users/szymex73.png’ saved [15811/15811]

--2022-09-26 21:24:16--  https://tryhackme.com/img/users/holmes.png
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 38795 (38K) [image/png]
Saving to: ‘tryhackme.com/img/users/holmes.png’

tryhackme.com/img/users/ho 100%[=====================================>]  37.89K  --.-KB/s    in 0s      

2022-09-26 21:24:16 (85.5 MB/s) - ‘tryhackme.com/img/users/holmes.png’ saved [38795/38795]

--2022-09-26 21:24:16--  https://tryhackme.com/img/users/Naughty.jpg
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 20149 (20K) [image/jpeg]
Saving to: ‘tryhackme.com/img/users/Naughty.jpg’

tryhackme.com/img/users/Na 100%[=====================================>]  19.68K  --.-KB/s    in 0.001s  

2022-09-26 21:24:16 (21.4 MB/s) - ‘tryhackme.com/img/users/Naughty.jpg’ saved [20149/20149]

--2022-09-26 21:24:16--  https://tryhackme.com/img/users/Magna.jpg
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 20607 (20K) [image/jpeg]
Saving to: ‘tryhackme.com/img/users/Magna.jpg’

tryhackme.com/img/users/Ma 100%[=====================================>]  20.12K  --.-KB/s    in 0s      

2022-09-26 21:24:17 (85.0 MB/s) - ‘tryhackme.com/img/users/Magna.jpg’ saved [20607/20607]

--2022-09-26 21:24:17--  https://tryhackme.com/img/users/paradox.jpg
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 14055 (14K) [image/jpeg]
Saving to: ‘tryhackme.com/img/users/paradox.jpg’

tryhackme.com/img/users/pa 100%[=====================================>]  13.73K  --.-KB/s    in 0s      

2022-09-26 21:24:17 (91.3 MB/s) - ‘tryhackme.com/img/users/paradox.jpg’ saved [14055/14055]

--2022-09-26 21:24:17--  https://tryhackme.com/img/svgs/swirl.svg
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 13860 (14K) [image/svg+xml]
Saving to: ‘tryhackme.com/img/svgs/swirl.svg’

tryhackme.com/img/svgs/swi 100%[=====================================>]  13.54K  --.-KB/s    in 0s      

2022-09-26 21:24:18 (92.7 MB/s) - ‘tryhackme.com/img/svgs/swirl.svg’ saved [13860/13860]

pathconf: Not a directory
pathconf: Not a directory
--2022-09-26 21:24:18--  https://tryhackme.com/forum/thread/'+url+'
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 302 Found
Location: /404 [following]
pathconf: Not a directory
pathconf: Not a directory
--2022-09-26 21:24:18--  https://tryhackme.com/404
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 404 Not Found
2022-09-26 21:24:18 ERROR 404: Not Found.

--2022-09-26 21:24:18--  https://tryhackme.com/legal/acceptable-use-policy
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/legal/acceptable-use-policy’

tryhackme.com/legal/accept     [ <=>                                  ]  26.11K  --.-KB/s    in 0.03s   

2022-09-26 21:24:18 (757 KB/s) - ‘tryhackme.com/legal/acceptable-use-policy’ saved [26735]

--2022-09-26 21:24:18--  https://tryhackme.com/css/pages/why-subscribe.css?v=1.1
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 3096 (3.0K) [text/css]
Saving to: ‘tryhackme.com/css/pages/why-subscribe.css?v=1.1’

tryhackme.com/css/pages/wh 100%[=====================================>]   3.02K  --.-KB/s    in 0s      

2022-09-26 21:24:19 (90.5 MB/s) - ‘tryhackme.com/css/pages/why-subscribe.css?v=1.1’ saved [3096/3096]

--2022-09-26 21:24:19--  https://tryhackme.com/img/why_subscribe/testimonial_tweets.png
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 402315 (393K) [image/png]
Saving to: ‘tryhackme.com/img/why_subscribe/testimonial_tweets.png’

tryhackme.com/img/why_subs 100%[=====================================>] 392.89K   711KB/s    in 0.6s    

2022-09-26 21:24:20 (711 KB/s) - ‘tryhackme.com/img/why_subscribe/testimonial_tweets.png’ saved [402315/402315]

--2022-09-26 21:24:20--  https://tryhackme.com/img/svgs/stardots_gray.svg
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 14834 (14K) [image/svg+xml]
Saving to: ‘tryhackme.com/img/svgs/stardots_gray.svg’

tryhackme.com/img/svgs/sta 100%[=====================================>]  14.49K  --.-KB/s    in 0s      

2022-09-26 21:24:20 (295 MB/s) - ‘tryhackme.com/img/svgs/stardots_gray.svg’ saved [14834/14834]

--2022-09-26 21:24:20--  https://tryhackme.com/api/room/manage/clone/linux1
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 302 Found
Location: /login [following]
--2022-09-26 21:24:20--  https://tryhackme.com/login
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/api/room/manage/clone/linux1’

tryhackme.com/api/room/man     [ <=>                                  ]  18.92K  --.-KB/s    in 0s      

2022-09-26 21:24:20 (68.5 MB/s) - ‘tryhackme.com/api/room/manage/clone/linux1’ saved [19377]

--2022-09-26 21:24:20--  https://tryhackme.com/img/modules/structure.png
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: 7938 (7.8K) [image/png]
Saving to: ‘tryhackme.com/img/modules/structure.png’

tryhackme.com/img/modules/ 100%[=====================================>]   7.75K  --.-KB/s    in 0s      

2022-09-26 21:24:21 (201 MB/s) - ‘tryhackme.com/img/modules/structure.png’ saved [7938/7938]

--2022-09-26 21:24:21--  https://tryhackme.com/module/$%7Blink%7D
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 302 Found
Location: /404 [following]
--2022-09-26 21:24:21--  https://tryhackme.com/404
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 404 Not Found
2022-09-26 21:24:21 ERROR 404: Not Found.

--2022-09-26 21:24:21--  https://tryhackme.com/module/$%7Bimg%7D
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 302 Found
Location: /404 [following]
--2022-09-26 21:24:21--  https://tryhackme.com/404
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 404 Not Found
2022-09-26 21:24:21 ERROR 404: Not Found.

--2022-09-26 21:24:21--  https://tryhackme.com/api/room/manage/clone/httpindetail
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 302 Found
Location: /login [following]
--2022-09-26 21:24:22--  https://tryhackme.com/login
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/api/room/manage/clone/httpindetail’

tryhackme.com/api/room/man     [ <=>                                  ]  18.92K  --.-KB/s    in 0.003s  

2022-09-26 21:24:22 (6.07 MB/s) - ‘tryhackme.com/api/room/manage/clone/httpindetail’ saved [19377]

--2022-09-26 21:24:22--  https://tryhackme.com/api/room/manage/clone/owasptop10
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 302 Found
Location: /login [following]
--2022-09-26 21:24:22--  https://tryhackme.com/login
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/api/room/manage/clone/owasptop10’

tryhackme.com/api/room/man     [ <=>                                  ]  18.92K  --.-KB/s    in 0.003s  

2022-09-26 21:24:22 (6.42 MB/s) - ‘tryhackme.com/api/room/manage/clone/owasptop10’ saved [19377]

--2022-09-26 21:24:22--  https://tryhackme.com/api/room/manage/clone/introtonetworking
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 302 Found
Location: /login [following]
--2022-09-26 21:24:22--  https://tryhackme.com/login
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/api/room/manage/clone/introtonetworking’

tryhackme.com/api/room/man     [ <=>                                  ]  18.92K  --.-KB/s    in 0s      

2022-09-26 21:24:23 (159 MB/s) - ‘tryhackme.com/api/room/manage/clone/introtonetworking’ saved [19377]

--2022-09-26 21:24:23--  https://tryhackme.com/api/room/manage/clone/furthernmap
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 302 Found
Location: /login [following]
--2022-09-26 21:24:23--  https://tryhackme.com/login
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/api/room/manage/clone/furthernmap’

tryhackme.com/api/room/man     [ <=>                                  ]  18.92K  --.-KB/s    in 0s      

2022-09-26 21:24:23 (168 MB/s) - ‘tryhackme.com/api/room/manage/clone/furthernmap’ saved [19377]

--2022-09-26 21:24:23--  https://tryhackme.com/api/room/manage/clone/metasploitintro
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 302 Found
Location: /login [following]
--2022-09-26 21:24:23--  https://tryhackme.com/login
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/api/room/manage/clone/metasploitintro’

tryhackme.com/api/room/man     [ <=>                                  ]  18.92K  --.-KB/s    in 0.002s  

2022-09-26 21:24:23 (8.39 MB/s) - ‘tryhackme.com/api/room/manage/clone/metasploitintro’ saved [19377]

--2022-09-26 21:24:23--  https://tryhackme.com/api/room/manage/clone/vulnversity
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 302 Found
Location: /login [following]
--2022-09-26 21:24:24--  https://tryhackme.com/login
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/api/room/manage/clone/vulnversity’

tryhackme.com/api/room/man     [ <=>                                  ]  18.92K  --.-KB/s    in 0.001s  

2022-09-26 21:24:24 (18.4 MB/s) - ‘tryhackme.com/api/room/manage/clone/vulnversity’ saved [19377]

--2022-09-26 21:24:24--  https://tryhackme.com/room/kali
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 302 Found
Location: /why-subscribe [following]
--2022-09-26 21:24:24--  https://tryhackme.com/why-subscribe
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/room/kali’

tryhackme.com/room/kali        [ <=>                                  ]  22.88K  --.-KB/s    in 0s      

2022-09-26 21:24:24 (89.2 MB/s) - ‘tryhackme.com/room/kali’ saved [23430]

--2022-09-26 21:24:24--  https://tryhackme.com/api/room/manage/clone/basicpentestingjt
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 302 Found
Location: /login [following]
--2022-09-26 21:24:25--  https://tryhackme.com/login
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 429 Too Many Requests
2022-09-26 21:24:25 ERROR 429: Too Many Requests.

--2022-09-26 21:24:25--  https://tryhackme.com/room/solar
Connecting to tryhackme.com (tryhackme.com)|172.67.27.10|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/room/solar’

tryhackme.com/room/solar       [ <=>                                  ]  51.75K  --.-KB/s    in 0.002s  

2022-09-26 21:24:25 (24.6 MB/s) - ‘tryhackme.com/room/solar’ saved [52988]

--2022-09-26 21:24:25--  https://tryhackme.com/resources/blog/cyber-security-the-cost-of-human-error
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/resources/blog/cyber-security-the-cost-of-human-error’

tryhackme.com/resources/bl     [ <=>                                  ]  34.21K  --.-KB/s    in 0s      

2022-09-26 21:24:25 (124 MB/s) - ‘tryhackme.com/resources/blog/cyber-security-the-cost-of-human-error’ saved [35036]

pathconf: Not a directory
--2022-09-26 21:24:25--  https://tryhackme.com/business/?utm_source=blog&utm_medium=onsite&utm_campaign=cyberculture
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/business/index.html?utm_source=blog&utm_medium=onsite&utm_campaign=cyberculture’

tryhackme.com/business/ind     [ <=>                                  ]  42.90K  --.-KB/s    in 0.001s  

2022-09-26 21:24:25 (73.7 MB/s) - ‘tryhackme.com/business/index.html?utm_source=blog&utm_medium=onsite&utm_campaign=cyberculture’ saved [43927]

--2022-09-26 21:24:25--  https://tryhackme.com/business/?utm_source=blog&utm_medium=onsite&utm_campaign=cyber-security-2022
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/business/index.html?utm_source=blog&utm_medium=onsite&utm_campaign=cyber-security-2022’

tryhackme.com/business/ind     [ <=>                                  ]  42.90K  --.-KB/s    in 0.001s  

2022-09-26 21:24:26 (55.9 MB/s) - ‘tryhackme.com/business/index.html?utm_source=blog&utm_medium=onsite&utm_campaign=cyber-security-2022’ saved [43927]

--2022-09-26 21:24:26--  https://tryhackme.com/resources/blog/businesses-investing-in-cyber-security
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/resources/blog/businesses-investing-in-cyber-security’

tryhackme.com/resources/bl     [ <=>                                  ]  35.73K  --.-KB/s    in 0s      

2022-09-26 21:24:26 (151 MB/s) - ‘tryhackme.com/resources/blog/businesses-investing-in-cyber-security’ saved [36591]

--2022-09-26 21:24:26--  https://tryhackme.com/api/room/manage/clone/solar
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 302 Found
Location: /login [following]
--2022-09-26 21:24:26--  https://tryhackme.com/login
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 429 Too Many Requests
2022-09-26 21:24:26 ERROR 429: Too Many Requests.

--2022-09-26 21:24:26--  https://tryhackme.com/business/?utm_source=blog&utm_medium=onsite&utm_campaign=cost-of-human-error
Connecting to tryhackme.com (tryhackme.com)|172.67.27.10|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/business/index.html?utm_source=blog&utm_medium=onsite&utm_campaign=cost-of-human-error’

tryhackme.com/business/ind     [ <=>                                  ]  42.90K  --.-KB/s    in 0.001s  

2022-09-26 21:24:27 (30.2 MB/s) - ‘tryhackme.com/business/index.html?utm_source=blog&utm_medium=onsite&utm_campaign=cost-of-human-error’ saved [43927]

--2022-09-26 21:24:27--  https://tryhackme.com/path/outline/presecurity
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/path/outline/presecurity’

tryhackme.com/path/outline     [ <=>                                  ]  21.02K  --.-KB/s    in 0.001s  

2022-09-26 21:24:27 (16.9 MB/s) - ‘tryhackme.com/path/outline/presecurity’ saved [21529]

--2022-09-26 21:24:27--  https://tryhackme.com/path/outline/pentesting
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/path/outline/pentesting’

tryhackme.com/path/outline     [ <=>                                  ]  21.34K  --.-KB/s    in 0.001s  

2022-09-26 21:24:27 (14.8 MB/s) - ‘tryhackme.com/path/outline/pentesting’ saved [21856]

--2022-09-26 21:24:27--  https://tryhackme.com/path/outline/blueteam
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/path/outline/blueteam’

tryhackme.com/path/outline     [ <=>                                  ]  21.46K  --.-KB/s    in 0s      

2022-09-26 21:24:27 (104 MB/s) - ‘tryhackme.com/path/outline/blueteam’ saved [21979]

pathconf: Not a directory
--2022-09-26 21:24:27--  https://tryhackme.com/games/koth/?utm_source=blog&utm_medium=onsite&utm_campaign=blog
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/games/koth/index.html?utm_source=blog&utm_medium=onsite&utm_campaign=blog’

tryhackme.com/games/koth/i     [ <=>                                  ]  42.42K  --.-KB/s    in 0.001s  

2022-09-26 21:24:28 (47.3 MB/s) - ‘tryhackme.com/games/koth/index.html?utm_source=blog&utm_medium=onsite&utm_campaign=blog’ saved [43438]

--2022-09-26 21:24:28--  https://tryhackme.com/business/?utm_source=blog&utm_medium=onsite&utm_campaign=why-businesses-are-investing-in-cyber
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘tryhackme.com/business/index.html?utm_source=blog&utm_medium=onsite&utm_campaign=why-businesses-are-investing-in-cyber’

tryhackme.com/business/ind     [ <=>                                  ]  42.90K  --.-KB/s    in 0s      

2022-09-26 21:24:28 (159 MB/s) - ‘tryhackme.com/business/index.html?utm_source=blog&utm_medium=onsite&utm_campaign=why-businesses-are-investing-in-cyber’ saved [43927]

--2022-09-26 21:24:28--  https://tryhackme.com/path-action/presecurity/join
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 302 Found
Location: /login [following]
--2022-09-26 21:24:28--  https://tryhackme.com/login
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 429 Too Many Requests
2022-09-26 21:24:28 ERROR 429: Too Many Requests.

--2022-09-26 21:24:28--  https://tryhackme.com/img/general/learningpathcert.png
Connecting to tryhackme.com (tryhackme.com)|172.67.27.10|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 47157 (46K) [image/png]
Saving to: ‘tryhackme.com/img/general/learningpathcert.png’

tryhackme.com/img/general/ 100%[=====================================>]  46.05K   257KB/s    in 0.2s    

2022-09-26 21:24:29 (257 KB/s) - ‘tryhackme.com/img/general/learningpathcert.png’ saved [47157/47157]

--2022-09-26 21:24:29--  https://tryhackme.com/path-action/pentesting/join
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 302 Found
Location: /login [following]
--2022-09-26 21:24:29--  https://tryhackme.com/login
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 429 Too Many Requests
2022-09-26 21:24:29 ERROR 429: Too Many Requests.

--2022-09-26 21:24:29--  https://tryhackme.com/path-action/blueteam/join
Connecting to tryhackme.com (tryhackme.com)|172.67.27.10|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: /login [following]
--2022-09-26 21:24:29--  https://tryhackme.com/login
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 429 Too Many Requests
2022-09-26 21:24:29 ERROR 429: Too Many Requests.

--2022-09-26 21:24:29--  https://tryhackme.com/games/koth/$%7BgetOSImage(koth.box.os)%7D
Connecting to tryhackme.com (tryhackme.com)|172.67.27.10|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: /404 [following]
--2022-09-26 21:24:30--  https://tryhackme.com/404
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 404 Not Found
2022-09-26 21:24:30 ERROR 404: Not Found.

Warning: wildcards not supported in HTTP.
--2022-09-26 21:24:30--  https://tryhackme.com/games/koth/$%7BtableData[0].avatar%7D
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 302 Found
Location: /404 [following]
--2022-09-26 21:24:30--  https://tryhackme.com/404
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 404 Not Found
2022-09-26 21:24:30 ERROR 404: Not Found.

--2022-09-26 21:24:30--  https://tryhackme.com/games/koth/$%7BgetOSImage(machine.os)%7D
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 302 Found
Location: /404 [following]
--2022-09-26 21:24:30--  https://tryhackme.com/404
Reusing existing connection to tryhackme.com:443.
HTTP request sent, awaiting response... 404 Not Found
2022-09-26 21:24:31 ERROR 404: Not Found.

FINISHED --2022-09-26 21:24:31--
Total wall clock time: 1m 3s
Downloaded: 134 files, 9.8M in 10s (1002 KB/s)

```

What command would you run to download recursively up to level 5 from https://tryhackme.com ?
*wget -r -l =5 https://tryhackme.com*


### tar 

tar is a command that allows creating, maintain, modify, and extracts files that are archived in the tar format.

![](https://i.imgur.com/2S09djq.png)

The most common example for tar extraction would be:

tar -xf archive.tar


-x tells tar to extract files from an archive.

-f tells tar that the next argument will be the name of the archive to operate on.

```
chad@flamenco:~$ ls
base64.txt  binwalk.png  grep1.txt  gzip.txt.gz  tac.txt   tarball.tar  zip.7z
bin         cat.txt      grep.txt   head.txt     tail.txt  xxd.txt
chad@flamenco:~$ tar -xf tarball.tar
chad@flamenco:~$ ls
base64.txt   cat.txt    grep.txt     nothing1.txt  tac.txt      xxd.txt
bin          flag.txt   gzip.txt.gz  nothing2.txt  tail.txt     zip.7z
binwalk.png  grep1.txt  head.txt     nothing3.txt  tarball.tar
chad@flamenco:~$ cat flag.txt
THM{C0FFE1337101}

```


What is the flag from the tar file?

*THM{C0FFE1337101}*

### gzip 

gzip - a file format and a software application used for file compression and decompression. gzip-compressed files have .gz extension.

![](https://i.imgur.com/SefVKtG.png)
A gzip file can be decompressed using a simple gzip -d file.gz command, where -d stands for decompress.

```
chad@flamenco:~$ gzip -d gzip.txt.gz
chad@flamenco:~$ ls
base64.txt  binwalk.png  flag.txt   grep.txt  head.txt      nothing2.txt  tac.txt   tarball.tar  zip.7z
bin         cat.txt      grep1.txt  gzip.txt  nothing1.txt  nothing3.txt  tail.txt  xxd.txt
chad@flamenco:~$ cat gzip.txt
THM{0AFDECC951A}

```

What is the content of gzip.txt?
*THM{0AFDECC951A}*

### 7zip 

7-Zip is a free and open-source file archiver, a utility used to place groups of files within compressed containers known as "archives".

![](https://i.imgur.com/jDHu1Zr.png)


7z is as simple as the gzip or tar and you can use the following command:

7z x file.zip to extract the file

This tool comes in handy as it works with a lot more file extensions than other tools. You name the archive extension and 7z should be the tool for you.

```
chad@flamenco:~$ 7z x zip.7z

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,1 CPU Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz (306F2),ASM,AES-NI)

Scanning the drive for archives:
1 file, 142 bytes (1 KiB)

Extracting archive: zip.7z
--
Path = zip.7z
Type = 7z
Physical Size = 142
Headers Size = 122
Method = LZMA2:12
Solid = -
Blocks = 1

Everything is Ok

Size:       16
Compressed: 142
chad@flamenco:~$ ls
7zip.txt    bin          cat.txt   grep1.txt  gzip.txt  nothing1.txt  nothing3.txt  tail.txt     xxd.txt
base64.txt  binwalk.png  flag.txt  grep.txt   head.txt  nothing2.txt  tac.txt       tarball.tar  zip.7z
chad@flamenco:~$ cat 7zip.txt
THM{526accdf94}

```

What is the flag inside the 7zip file?
*THM{526accdf94}*


### binwalk 

binwalk allows users to analyze and extract firmware images and helps in identifying code, files, and other information embedded in those, or inside another file, taking as an example steganography.

![](https://i.imgur.com/V8OySd8.png)

A simple command such as binwalk file allows us to perform a simple file scan and identify code information.

binwalk -e file allows us to extract files from firmware. This method is usually used in CTFs, where some important information can be hidden within the file.

binwalk -Me file does the same as-e, but recursively.

![](https://i.imgur.com/uZn3i9j.png)

```
chad@flamenco:~$ binwalk -e binwalk.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 824 x 461, 8-bit/color RGBA, non-interlaced
78            0x4E            Zlib compressed data, best compression
20066         0x4E62          gzip compressed data, fastest compression, has original file name: "binwalk.txt", from Unix, last modified: 2020-08-01 18:54:33

chad@flamenco:~$ ls
7zip.txt    binwalk.png             flag.txt   gzip.txt      nothing2.txt  tail.txt     zip.7z
base64.txt  _binwalk.png.extracted  grep1.txt  head.txt      nothing3.txt  tarball.tar
bin         cat.txt                 grep.txt   nothing1.txt  tac.txt       xxd.txt
chad@flamenco:~$ cd _binwalk.png.extracted
-rbash: cd: restricted
chad@flamenco:~$ ls _binwalk.png.extracted
4E  4E.zlib  binwalk.txt
chad@flamenco:~$ cat _binwalk.png.extracted/binwalk.txt
THM{af5548a12bc2de}

```

What is the content of binwalk.txt?
*THM{af5548a12bc2de}*


[[Bebop]]
