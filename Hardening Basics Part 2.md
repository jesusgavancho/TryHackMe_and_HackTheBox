---
Continue learning about hardening
---

![](https://tryhackme-images.s3.amazonaws.com/room-icons/81525b4555b637e5ca3b742357fc4b5b.jpeg)

### Introduction 

Introduction

Welcome to Part 2 of Hardening Basics! While this room can be enjoyed on its own, it is meant to be done in conjunction with Part 1. If you have not done Part 1 yet, I highly recommend you do so.

In this room, we will cover the following:

    SSH and Encryption (Chapter 3)
    Mandatory Access Control (Chapter 4)

This was mentioned in Part 1 but in case you did not do that room:

There are no questions related to performing tasks on a virtual machine. However, I have provided a semi-configured Ubuntu 18.04 environment for you to play around with while you go through the different tasks. Things that have been configured at a basic level will be:

    Users
    PAM
    Permissions
    Passwords

And that's it! I'll leave you to play around as you wish. You may access the machine with the following credentials (if you're coming from Part 1, you do not need to deploy the VM):

spooky:tryhackme

These will be global credentials that should give you access to do everything you need to.  I will provide other credentials for tasks where I feel it's possible to lock yourself out from a mistake. You can find some optional challenges in Task 15. 

The hope is that by the end of this room, you'll be able to clearly explain and understand the above topics and apply them to your daily life, or life at work. Whether you're a senior systems administrator or just starting out as a junior, these topics will help you understand what it takes to harden a Linux system.

Topics have been chosen from this book. I looked through the table of contents and picked out the ones that would be the most important and allow the room to have the best content while still keeping it within the proper limits. I think the above 4 topics are the best and will give you the most knowledge on how to harden a system. If you have a subscription to O'Reilly through work or school, I suggest checking the book out.

Disclaimer

All tasks for this room were completed using Ubuntu 18.04 LTS. That being said, pretty much everything that applies to 18.04 can apply to 20.04 as well. If you take what you learn out of this room and try to apply it in the real world for practice and fun and something does not work, be sure to check the documentation for what you are trying to do. 

### ~~~~~ Chapter 3 Quiz ~~~~~ 



Summary

I hope you're continuing to learn something new with each chapter. Even if some of this is re-hashing old concepts, maybe there has been some things you've forgotten. We've gone through GPG and encryption, creating SSH keys, and some methods to harden SSH further.

Now it's time to complete a little skills check and see how well you understand the material.



Which SSH Protocol version is the most secure?
*2*



This is a random, arbitrary number, used as the session key, that is used to encrypt GPG.
*nonce*

Yey/Ney - GPG is based off of the OpenGPG standard
*Yey*
What is the command to generate your GPG keys?
*gpg --gen-key*
```
┌──(kali㉿kali)-[~]
└─$ gpg --gen-key                                     
gpg (GnuPG) 2.2.39; Copyright (C) 2022 g10 Code GmbH
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Note: Use "gpg --full-generate-key" for a full featured key generation dialog.

GnuPG needs to construct a user ID to identify your key.

Real name: 
```
What is the command to symmetrically encrypt a file with GPG?
*gpg -c*

```
┌──(kali㉿kali)-[~]
└─$ gpg -h                                                      
gpg (GnuPG) 2.2.39
libgcrypt 1.10.1
Copyright (C) 2022 g10 Code GmbH
License GNU GPL-3.0-or-later <https://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Home: /home/kali/.gnupg
Supported algorithms:
Pubkey: RSA, ELG, DSA, ECDH, ECDSA, EDDSA
Cipher: IDEA, 3DES, CAST5, BLOWFISH, AES, AES192, AES256, TWOFISH,
        CAMELLIA128, CAMELLIA192, CAMELLIA256
Hash: SHA1, RIPEMD160, SHA256, SHA384, SHA512, SHA224
Compression: Uncompressed, ZIP, ZLIB, BZIP2

Syntax: gpg [options] [files]
Sign, check, encrypt or decrypt
Default operation depends on the input data

Commands:
 
 -s, --sign                         make a signature
     --clear-sign                   make a clear text signature
 -b, --detach-sign                  make a detached signature
 -e, --encrypt                      encrypt data
 -c, --symmetric                    encryption only with symmetric cipher
 -d, --decrypt                      decrypt data (default)
     --verify                       verify a signature
 -k, --list-keys                    list keys
     --list-signatures              list keys and signatures
     --check-signatures             list and check key signatures
     --fingerprint                  list keys and fingerprints
 -K, --list-secret-keys             list secret keys
     --generate-key                 generate a new key pair
     --quick-generate-key           quickly generate a new key pair
     --quick-add-uid                quickly add a new user-id
     --quick-revoke-uid             quickly revoke a user-id
     --quick-set-expire             quickly set a new expiration date
     --full-generate-key            full featured key pair generation
     --generate-revocation          generate a revocation certificate
     --delete-keys                  remove keys from the public keyring
     --delete-secret-keys           remove keys from the secret keyring
     --quick-sign-key               quickly sign a key
     --quick-lsign-key              quickly sign a key locally
     --quick-revoke-sig             quickly revoke a key signature
     --sign-key                     sign a key
     --lsign-key                    sign a key locally
     --edit-key                     sign or edit a key
     --change-passphrase            change a passphrase
     --export                       export keys
     --send-keys                    export keys to a keyserver
     --receive-keys                 import keys from a keyserver
     --search-keys                  search for keys on a keyserver
     --refresh-keys                 update all keys from a keyserver
     --import                       import/merge keys
     --card-status                  print the card status
     --edit-card                    change data on a card
     --change-pin                   change a card's PIN
     --update-trustdb               update the trust database
     --print-md                     print message digests
     --server                       run in server mode
     --tofu-policy VALUE            set the TOFU policy for a key

Options controlling the diagnostic output:
 -v, --verbose                      verbose
 -q, --quiet                        be somewhat more quiet
     --options FILE                 read options from FILE
     --log-file FILE                write server mode logs to FILE

Options controlling the configuration:
     --default-key NAME             use NAME as default secret key
     --encrypt-to NAME              encrypt to user ID NAME as well
     --group SPEC                   set up email aliases
     --openpgp                      use strict OpenPGP behavior
 -n, --dry-run                      do not make any changes
 -i, --interactive                  prompt before overwriting

Options controlling the output:
 -a, --armor                        create ascii armored output
 -o, --output FILE                  write output to FILE
     --textmode                     use canonical text mode
 -z N                               set compress level to N (0 disables)

Options controlling key import and export:
     --auto-key-locate MECHANISMS   use MECHANISMS to locate keys by mail address
     --auto-key-import              import missing key from a signature
     --include-key-block            include the public key in signatures
     --disable-dirmngr              disable all access to the dirmngr

Options to specify keys:
 -r, --recipient USER-ID            encrypt for USER-ID
 -u, --local-user USER-ID           use USER-ID to sign or decrypt

(See the man page for a complete listing of all commands and options)

Examples:

 -se -r Bob [file]          sign and encrypt for user Bob
 --clear-sign [file]        make a clear text signature
 --detach-sign [file]       make a detached signature
 --list-keys [names]        show keys
 --fingerprint [names]      show fingerprints

Please report bugs to <https://bugs.gnupg.org>.
```
What is the command to asymmetrically encrypt a file with GPG?
*gpg -e*
```
┌──(kali㉿kali)-[~]
└─$ ssh-keygen -t rsa       
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kali/.ssh/id_rsa)
```
What is the command to create SSH keys?
*ssh-keygen*
Where are ssh keys stored in a user's home directory?
 The directory name
*.ssh*

What option needs to be set to select the type of key to generate for SSH?
*-t*
The SSH configuration options presented in this chapter were found in what file (full path)?
*/etc/ssh/sshd_config*


### GNU Privacy Guard 

GNU Privacy Guard

![](https://upload.wikimedia.org/wikipedia/commons/thumb/6/61/Gnupg_logo.svg/636px-Gnupg_logo.svg.png)

To understand what GNU Privacy Guard (GPG) is and does, we need to start with the original encryption system it's based off of; Pretty Good Privacy.

Overview of Pretty Good Privacy

Pretty Good Privacy (PGP) is used widely to encrypt and decrypt email by using asymmetrical and symmetrical systems. When you first send your email, it is encrypted with your own public key, as well as a session key, which is a one-time use random number called a nonce. The session key is then encrypted into the public key and sent with the cipher text. To decrypt your email, the receiving end must use their private key in order to discover the session key. The session key combined with the private key are then used to decrypt the cipher text back into the original document.

This is where GPG comes in. GPG is actually directly based off of the OpenPGP standard. GPG comes pre-installed on Ubuntu and comes with several advantages:

    Easy encryption for email and files
    Even the NSA can't crack PGP https://twitter.com/Snowden/status/878686842631139334?s=20
    Asymmetric encryption removes the need to provide a password for decrypting or unlocking files thus improving security overall

Using GPG

﻿Creating GPG Keys

When you first want to use GPG, it requires you to create your own keys. To do that we use gpg --gen-key.

This process is extremely simple. Once you press Enter after inputting the above command, it will create some files and directories as well as ask for some information:

![](https://i.imgur.com/4dw6YWA.png)

I've just entered fake information for this user (the key generation process will still work).

Following that, the program will proceed to generate random bytes for the key. It informs the user that 

![](https://i.imgur.com/4eClzUl.png)

So go ahead and move your mouse, type some stuff out or engage the disks. I just moved the mouse around...a lot. After quite some time, the process will complete and create another directory in your home directory called .gnugpg.

![](https://i.imgur.com/R0o9dGF.png)

You can verify the keys were created with gpg --list-keys.

```
                                                                                     
┌──(kali㉿kali)-[~]
└─$ gpg --gen-key
gpg (GnuPG) 2.2.39; Copyright (C) 2022 g10 Code GmbH
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Note: Use "gpg --full-generate-key" for a full featured key generation dialog.

GnuPG needs to construct a user ID to identify your key.

Real name: witty
Email address: witty@email.com
You selected this USER-ID:
    "witty <witty@email.com>"

Change (N)ame, (E)mail, or (O)kay/(Q)uit? O
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
gpg: directory '/home/kali/.gnupg/openpgp-revocs.d' created
gpg: revocation certificate stored as '/home/kali/.gnupg/openpgp-revocs.d/CD881F54294C394D1DACAF9515EA3A624E2D604E.rev'
public and secret key created and signed.

pub   rsa3072 2022-10-23 [SC] [expires: 2024-10-22]
      [REDACTED]
uid                      witty <witty@email.com>
sub   rsa3072 2022-10-23 [E] [expires: 2024-10-22]

┌──(kali㉿kali)-[~]
└─$ gpg --list-keys
gpg: checking the trustdb
gpg: marginals needed: 3  completes needed: 1  trust model: pgp
gpg: depth: 0  valid:   1  signed:   0  trust: 0-, 0q, 0n, 0m, 0f, 1u
gpg: next trustdb check due at 2024-10-22
/home/kali/.gnupg/pubring.kbx
-----------------------------
pub   dsa3072 2020-03-11 [SCA]
      [REDACTED]
uid           [ unknown] tryhackme <stuxnet@tryhackme.com>
sub   elg1024 2020-03-11 [E]

pub   rsa2048 2020-11-08 [SC] [expires: 2022-11-08]
      [REDACTED]
uid           [ unknown] Paradox <paradox@overpass.thm>
sub   rsa2048 2020-11-08 [E] [expires: 2022-11-08]

pub   dsa2048 2019-08-12 [SCA]
      [REDACTED]
uid           [ unknown] anonforce <melodias@anonforce.nsa>
sub   elg512 2019-08-12 [E]

pub   rsa3072 2022-10-23 [SC] [expires: 2024-10-22]
      [REDACTED]
uid           [ultimate] witty <witty@email.com>
sub   rsa3072 2022-10-23 [E] [expires: 2024-10-22]

```
### Encrypting Your Files 

Encrypting Your Files with GPG

Symmetric

Symmetric encryption works by using only one key to encrypt and decrypt. In our case here, you'll see that we encrypt a text file with a passphrase and then anyone that wants to decrypt and read that file must know the passphrase.

What if we have a secret file that we don't want anyone with prying eyes to just be able to read? We can encrypt it! We do so with gpg -c <our_file> .

![](https://i.imgur.com/AKlotyu.png)

![[Pasted image 20221022195701.png]]
This will prompt the user to enter a passphrase to protect the file.

*Note* This is not the passphrase you used to create your keys

Oddly enough, symmetrically encrypting your file leaves a backup copy that's unencrypted. You can remove it with shred or rm. Then let's decrypt our file and see what's inside!

![](https://i.imgur.com/YYCKsH5.png)

```
┌──(kali㉿kali)-[~]
└─$ gpg -d top.txt.gpg
gpg: AES256.CFB encrypted data
gpg: encrypted with 1 passphrase
gpg top :)
```

As you can see, we can decrypt our file with the -d option while targeting our gpg file that was encrypted. This will print out the contents of the file after prompting for the secret passphrase.  Let's move on to encrypting using asymmetric encryption.

Asymmetric

Asymmetric encryption works by using two keys - one to encrypt, and one to decrypt. The public key is used to encrypt the data while the private key is used to decrypt the data. So using the typical Bob and Alice example, let's say Bob wants to send Alice an encrypted file.

He would first encrypt the file using Alice's public key and then send the file away. Once Alice receives the file, she can decrypt it with her private key. The big takeaway here is that public keys can be shared, private keys should be kept private and held onto for dear life. NEVER SHARE YOUR PRIVATE KEY!

We'll need two users here. For this example, we'll use Nick and Spooky. Nick has a really super, secret file he wants to share but he doesn't want to have to share a passphrase. In order to do this, both parties need to have generated keys using the method from the previous task.

	Since the public key is used to encrypt the data, both Nick and Spooky need to extract their public keys and send them to each other. We do that by navigating to the .gnupg folder and then gpg --export -a -o <filename>.  This will export the user's public key as ASCII armored output as the filename specified. In order to import the file, you need to be in that user's .gnupg directory or know the path.

![](https://i.imgur.com/faW6bw6.png)

```
┌──(kali㉿kali)-[~/.gnupg]
└─$ gpg --export -a -o witty_public_key.txt                  
                                                                                     
┌──(kali㉿kali)-[~/.gnupg]
└─$ ls
openpgp-revocs.d   pubring.kbx   random_seed  witty_public_key.txt
private-keys-v1.d  pubring.kbx~  trustdb.gpg
                                                                                     
┌──(kali㉿kali)-[~/.gnupg]
└─$ gpg --import witty_public_key.txt                        
gpg: key[REDACTED]: "tryhackme <stuxnet@tryhackme.com>" not changed
gpg: key [REDACTED]: "Paradox <paradox@overpass.thm>" not changed
gpg: key [REDACTED]: "anonforce <melodias@anonforce.nsa>" not changed
gpg: key [REDACTED]: "witty <witty@email.com>" not changed
gpg: Total number processed: 4
gpg:              unchanged: 4

```

As easy as that, we can import Spooky's key and he can import Nick's public key using the same command but changing the file name.

	Now, let's say Nick wants to send Spooky an encrypted file. He has some really important document he needs to send. He will encrypt his document asymmetrically with gpg -e <document>.

![](https://i.imgur.com/cI5eSD3.png)

Now, normally, Nick would send this file to Spooky through Email, IRC, Discord, or some other secure method (carrier pigeon lol).  In this case we'll just place it in /tmp. When Spooky goes to decrypt it, he will be prompted for his passphrase for his private key. After entering that he is greeted with the text from the file!

![](https://i.imgur.com/GRc6iAl.png)

So, not really anything super important here...but it could be!

```
┌──(kali㉿kali)-[~]
└─$ gpg -e anonymous.txt 
You did not specify a user ID. (you may use "-r")

Current recipients:

Enter the user ID.  End with an empty line: witty

Current recipients:
rsa3072/466E734D80B976F9 2022-10-23 "witty <witty@email.com>"

Enter the user ID.  End with an empty line: stuxnet
gpg: 61E104A66184FBCC: There is no assurance this key belongs to the named user

sub  elg1024/61E104A66184FBCC 2020-03-11 tryhackme <stuxnet@tryhackme.com>
 Primary key fingerprint: 14B3 794D 5554 349A 715C  DBA0 8F3D A3DE C670 7170
      Subkey fingerprint: 8801 18AB 8F71 8E51 95BC  AD41 61E1 04A6 6184 FBCC

It is NOT certain that the key belongs to the person named
in the user ID.  If you *really* know what you are doing,
you may answer the next question with yes.

Use this key anyway? (y/N) y

Current recipients:
elg1024/61E104A66184FBCC 2020-03-11 "tryhackme <stuxnet@tryhackme.com>"
rsa3072/466E734D80B976F9 2022-10-23 "witty <witty@email.com>"

Enter the user ID.  End with an empty line: 
                                                                                     
┌──(kali㉿kali)-[~]
└─$ ls -la 
total 67108
drwxr-xr-x 55 kali kali     4096 Oct 22 21:20 .
drwxr-xr-x  3 root root     4096 May 12 11:52 ..
-rw-r--r--  1 kali kali       34 Oct 21 00:46 1_hash
-rw-r--r--  1 kali kali       33 Oct 21 16:36 2_hash
-rw-r--r--  1 kali kali     1458 Sep 25 15:49 47799.txt
-rw-r--r--  1 kali kali       65 Sep 27 19:01 agent.hash
drwxr-xr-x  2 kali kali     4096 Sep 27 12:09 alfred
-rw-r--r--  1 kali kali        6 Oct 22 21:18 anonymous.txt
-rw-r--r--  1 kali kali      738 Oct 22 21:20 anonymous.txt.gpg

┌──(kali㉿kali)-[~]
└─$ gpg -d anonymous.txt.gpg 
wgpg: encrypted with 1024-bit ELG key, ID 61E104A66184FBCC, created 2020-03-11
      "tryhackme <stuxnet@tryhackme.com>"
gpg: public key decryption failed: Timeout
gpg: encrypted with 3072-bit RSA key, ID 466E734D80B976F9, created 2022-10-23
      "witty <witty@email.com>"
u r 9


```
![[Pasted image 20221022202335.png]]

```
┌──(kali㉿kali)-[~]
└─$ gpg --gen-key                    
gpg (GnuPG) 2.2.39; Copyright (C) 2022 g10 Code GmbH
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Note: Use "gpg --full-generate-key" for a full featured key generation dialog.

GnuPG needs to construct a user ID to identify your key.

Real name: jesus
Email address: wittyale@mailfence.com
You selected this USER-ID:
    "jesus <wittyale@mailfence.com>"

Change (N)ame, (E)mail, or (O)kay/(Q)uit? E
Email address: wittyale@mailfence.com
You selected this USER-ID:
    "jesus <wittyale@mailfence.com>"

Change (N)ame, (E)mail, or (O)kay/(Q)uit? O
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
gpg: revocation certificate stored as '/home/kali/.gnupg/openpgp-revocs.d/C3E184FC5B3A439C70EC6C294603CAD422451D2E.rev'
public and secret key created and signed.

pub   rsa3072 2022-10-23 [SC] [expires: 2024-10-22]
      [REDACTED]
uid                      jesus <wittyale@mailfence.com>
sub   rsa3072 2022-10-23 [E] [expires: 2024-10-22]


┌──(kali㉿kali)-[~]
└─$ gpg --list-keys
gpg: checking the trustdb
gpg: marginals needed: 3  completes needed: 1  trust model: pgp
gpg: depth: 0  valid:   2  signed:   0  trust: 0-, 0q, 0n, 0m, 0f, 2u
gpg: next trustdb check due at 2024-10-22
/home/kali/.gnupg/pubring.kbx
-----------------------------
pub   dsa3072 2020-03-11 [SCA]
       [REDACTED]
uid           [ unknown] tryhackme <stuxnet@tryhackme.com>
sub   elg1024 2020-03-11 [E]

pub   rsa2048 2020-11-08 [SC] [expires: 2022-11-08]
      [REDACTED]
uid           [ unknown] Paradox <paradox@overpass.thm>
sub   rsa2048 2020-11-08 [E] [expires: 2022-11-08]

pub   dsa2048 2019-08-12 [SCA]
       [REDACTED]C2
uid           [ unknown] anonforce <melodias@anonforce.nsa>
sub   elg512 2019-08-12 [E]

pub   rsa3072 2022-10-23 [SC] [expires: 2024-10-22]
       [REDACTED]
uid           [ultimate] witty <witty@email.com>
sub   rsa3072 2022-10-23 [E] [expires: 2024-10-22]

pub   rsa3072 2022-10-23 [SC] [expires: 2024-10-22]
       [REDACTED]
uid           [ultimate] jesus <wittyale@mailfence.com>
sub   rsa3072 2022-10-23 [E] [expires: 2024-10-22]


┌──(kali㉿kali)-[~]
└─$ cd .gnupg 
                                                                                     
┌──(kali㉿kali)-[~/.gnupg]
└─$ gpg --export -a -o wittyale_public_key.txt
                                                                                     
┌──(kali㉿kali)-[~/.gnupg]
└─$ gpg --import wittyale_public_key.txt      
gpg: key [REDACTED]: "tryhackme <stuxnet@tryhackme.com>" not changed
gpg: key [REDACTED]: "Paradox <paradox@overpass.thm>" not changed
gpg: key [REDACTED]: "anonforce <melodias@anonforce.nsa>" not changed
gpg: key [REDACTED]: "witty <witty@email.com>" not changed
gpg: key [REDACTED]: "jesus <wittyale@mailfence.com>" not changed
gpg: Total number processed: 5
gpg:              unchanged: 5

──(kali㉿kali)-[~]
└─$ gpg -e jesus.txt                    
You did not specify a user ID. (you may use "-r")

Current recipients:

Enter the user ID.  End with an empty line: wittyale

Current recipients:
rsa3072/6F87336423BE4F5E 2022-10-23 "jesus <wittyale@mailfence.com>"

Enter the user ID.  End with an empty line: wittyale
gpg: skipped: public key already set

Current recipients:
rsa3072/6F87336423BE4F5E 2022-10-23 "jesus <wittyale@mailfence.com>"

Enter the user ID.  End with an empty line: 
                                                                                     
┌──(kali㉿kali)-[~]
└─$ ls
1_hash             Downloads                                  Public
2_hash             ferox-http_10_10_106_113-1664385770.state  rapidscan
47799.txt          ferox-http_10_10_238_70-1665338235.state   request.txt
agent.hash         ferox-http_internal_thm-1664380562.state   res
alfred             fowsniff.txt                               retrowl.txt
anonymous.txt      ftp_flag.txt                               sam.bak
anonymous.txt.gpg  gmapsapiscanner                            sandox_learning
armitage-tmp       hashctf2                                   share
asm                hoaxshell                                  shell.php
blog_wp            IDS_IPS_evasion                            skynet
bolt               jesus.txt                                  snmpcheck
book.txt           jesus.txt.gpg                              stager2.bat
bufferoverflow     koth                                       Sublist3r
chill_hack         mrphisher                                  suspicious.pcapng
clinic.lst         multi_launcher                             system.bak
confidential       Music                                      Templates
corp               mysqld.exe                                 top.txt.gpg
cred_harv          obfus                                      usernames-list.txt
crunch.txt         pass.txt                                   user.txt
Desktop            payloads                                   Videos
dict2.lst          Pictures                                   wireshark_op
dict.lst           powercat
Documents          PowerLessShell
                                                                                     
┌──(kali㉿kali)-[~]
└─$ gpg -d jesus.txt.gpg 
gpg: encrypted with 3072-bit RSA key, ID 6F87336423BE4F5E, created 2022-10-23
      "jesus <wittyale@mailfence.com>"
hi :0

┌──(kali㉿kali)-[~]
└─$ gpg -e jesus.txt    
You did not specify a user ID. (you may use "-r")

Current recipients:

Enter the user ID.  End with an empty line: wittyale

Current recipients:
rsa3072/6F87336423BE4F5E 2022-10-23 "jesus <wittyale@mailfence.com>"

Enter the user ID.  End with an empty line: witty

Current recipients:
rsa3072/466E734D80B976F9 2022-10-23 "witty <witty@email.com>"
rsa3072/6F87336423BE4F5E 2022-10-23 "jesus <wittyale@mailfence.com>"

Enter the user ID.  End with an empty line: 
File 'jesus.txt.gpg' exists. Overwrite? (y/N) y
                                                                                     
┌──(kali㉿kali)-[~]
└─$ gpg -d jesus.txt.gpg
gpg: encrypted with 3072-bit RSA key, ID 6F87336423BE4F5E, created 2022-10-23
      "jesus <wittyale@mailfence.com>"
gpg: encrypted with 3072-bit RSA key, ID 466E734D80B976F9, created 2022-10-23
      "witty <witty@email.com>"
hi :0


so the recipients (who'll receive it, makes sense and decrypt with private key, previously exported and imported)
```

###  SSH Protocol 1 



SSH Protocol 1

In your /etc/ssh/sshd_config file, if you see 

Protocol 1

or 

Protocol 1, 2

you should run far, far away. Just kidding! But really, you'll want to disable Protocol version 1 as soon as possible. It's available to run on Legacy machines but has been compromised and is no longer considered secure. SSH Protocol Version 2 is the current, more secure version of SSH.

### Creating an SSH Key Set 

Creating SSH Keys

Are you always logging in to SSH with a password? Well, I'm here to tell you to stop. By far, the most secure way to login to SSH is with the use of secure keys. These can be generated by any user and the command will generate their own set of public and private keys to be used with SSH.

Like I said - any user can do this. Typically in the user's home directory, they can use the command ssh-keygen to generate their own pair of public and private keys.

I've gone ahead and done this as the user nick so you can see what the process looks like if you don't know already.

![](https://i.imgur.com/OKKAPTW.png)

```
spooky@harden:~/.gnupg/private-keys-v1.d$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/spooky/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/spooky/.ssh/id_rsa.
Your public key has been saved in /home/spooky/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:4jTFca3SZgn1vavLr/F0u9WxBLmgiiVb8v6zkoxHK2c spooky@harden
The key's randomart image is:
+---[RSA 2048]----+
|        ..o.     |
|       ..o ....  |
|        oo +.o.  |
|       .. B . o. |
|     o+oS=   ..o |
|     oO+.     ..+|
|     o=oo   . o.+|
|     o.E . . = .o|
|      =.ooo =+oo.|
+----[SHA256]-----+

```

You can see that the prompts default to creating the keys in a hidden directory called .ssh in nick's home directory. Awesome! But we still can't login to SSH just yet.

Remember from our discussion earlier on public and private keys. Well, this command generates them as well. Your public key is for everyone while your private key is for your eyes only. In order to login to the SSH server, we need to share our public key with the remote SSH server. There are a few ways to do this

Copying Using ssh-copy-id

The easiest way to copy your ssh keys is by using the simple command ssh-copy-id. All you need to do is do ssh-copy-id username@remote-host and answer the questions and you're done. It's really as easy as that. I don't have a remote server to test this on so I unfortunately cannot demonstrate. To learn more, see Digital Ocean's[article](https://www.digitalocean.com/community/tutorials/how-to-set-up-ssh-keys-on-ubuntu-1604) for Ubuntu 16.04. It's an older Ubuntu version but the commands are the same.

Copying Manually

You can copy the keys manually as well. If you still have password access to your remote host, you can perform the following (this should be done as root and after keys have been generated):

mkdir -p ~/.ssh

From here, you'll want to create or modify an authorized_keys file in which you'll place your public key string into in a minute. Once this file is created you can cat /home/user/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys and that will copy the output of your public key into the authorized_keys file.

Once that is done, be sure (still as root in this case) to run chmod -R go= ~/.ssh which will recursively (-R) remove group and other permissions on the ~/.ssh directory.

If, after doing all of this, your remote host is still prompting for a password, be sure to check your permissions. I found that this Stack Exchange article helped me the most. However, that being said, permissions should be set up correctly when using the ssh-keygen command and if you are logged in as root when making the .ssh and authorized_keys directory and file, those permissions should be okay as well.

```
spooky@harden:~/.ssh$ sudo visudo

User_Alias      ADMINS = spooky
                ADMINS ALL=(ALL) ALL


spooky@harden:~/.ssh$ sudo su
root@harden:/home/spooky/.ssh# cd /root
root@harden:~# ls
root@harden:~# ls -lah
total 32K
drwx------  5 root root 4.0K Oct 23 01:55 .
drwxr-xr-x 24 root root 4.0K Aug 12  2020 ..
-rw-------  1 root root 1.9K Aug 12  2020 .bash_history
-rw-r--r--  1 root root 3.1K Apr  9  2018 .bashrc
drwx------  3 root root 4.0K Oct 23 01:55 .gnupg
drwxr-xr-x  3 root root 4.0K Aug 12  2020 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
drwx------  2 root root 4.0K Aug 12  2020 .ssh
root@harden:~# cd .ssh
root@harden:~/.ssh# ls 
authorized_keys
root@harden:~/.ssh# cat authorized_keys 
root@harden:~/.ssh# cat /home/spooky/.ssh/id_rsa.pub >> authorized_keys 
root@harden:~/.ssh# chmod -R go= ~/.ssh


root@harden:~/.ssh# ls
authorized_keys
root@harden:~/.ssh# cat authorized_keys 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC60BEthJS+9f4vm98RSbd6rCaZmr0siibB2F/kibWp/irTc9L8+3himeDL7YiNL/YTZZfJWV/lVFaGFdsLvZAMUcixjmEfaFBFPR9ZPqXTwH1uM3z4TGPfNyjYXukTQkhWXY6dbvFNjxrjEXK5zeDtRHgQ5zN1vFjLbWOQ92kBxjehgT4iB8KHD8rZDvY8RWf4ZXOeohLhPnuGajVJ24jZxUV6J76mFfylOBARIZbiBDMASYltFkl6/A1R90RSap+HSSU3X5uNxpnsjGrK2QZMWdxOBPakZ9NDdXEIPlzsc2w2pDu8NQ1atDjp0Ak+4hB9fXr5ckYlOwWMi1pj+qq5 spooky@harden
root@harden:~/.ssh# exit
exit
spooky@harden:~/.ssh$ ls
id_rsa  id_rsa.pub
spooky@harden:~/.ssh$ ssh root@10.10.207.65
The authenticity of host '10.10.207.65 (10.10.207.65)' can't be established.
ECDSA key fingerprint is SHA256:XsG7nU0SU8o2V2ZQBcXR+ZqhH4xdrcHNcWdKK4fmVwE.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '10.10.207.65' (ECDSA) to the list of known hosts.
Last login: Wed Aug 12 13:48:32 2020 from 192.168.86.26
root@harden:~# whoami
root



spooky@harden:~/.ssh$ ssh-keygen -t rsa -b 3072
Generating public/private rsa key pair.
Enter file in which to save the key (/home/spooky/.ssh/id_rsa): 
/home/spooky/.ssh/id_rsa already exists.
Overwrite (y/n)? y
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/spooky/.ssh/id_rsa.
Your public key has been saved in /home/spooky/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:PBRS0dmAcGl+y9wIxG9tG/g/YyAUAXkZcyPa+fv2FCI spooky@harden
The key's randomart image is:
+---[RSA 3072]----+
|      o+*B*Bo    |
|       oB+*=..   |
|       +ooo+     |
|       oo *.+    |
|        SB E.+ . |
|         .* *.. .|
|           ..o  .|
|             .*. |
|             o.+.|
+----[SHA256]-----+
spooky@harden:~/.ssh$ sudo su
[sudo] password for spooky: 
root@harden:/home/spooky/.ssh# cd /root
root@harden:~# cd .ssh/
root@harden:~/.ssh# ls
authorized_keys
root@harden:~/.ssh# cat /home/spooky/.ssh/id_rsa.pub >> authorized_keys
root@harden:~/.ssh# cat authorized_keys 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC60BEthJS+9f4vm98RSbd6rCaZmr0siibB2F/kibWp/irTc9L8+3himeDL7YiNL/YTZZfJWV/lVFaGFdsLvZAMUcixjmEfaFBFPR9ZPqXTwH1uM3z4TGPfNyjYXukTQkhWXY6dbvFNjxrjEXK5zeDtRHgQ5zN1vFjLbWOQ92kBxjehgT4iB8KHD8rZDvY8RWf4ZXOeohLhPnuGajVJ24jZxUV6J76mFfylOBARIZbiBDMASYltFkl6/A1R90RSap+HSSU3X5uNxpnsjGrK2QZMWdxOBPakZ9NDdXEIPlzsc2w2pDu8NQ1atDjp0Ak+4hB9fXr5ckYlOwWMi1pj+qq5 spooky@harden
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDeTzqT629y/7OqfitnXlKwY+oPLPC7mldAYEG4/UCXb+JV7Pl5fs+latzjaP8Pn1oJ6Knb5LTpl3CKhWOqB9uKJ0Sv1Qr66EGpGamJsTX0VgDgyaQnCvJv2Pm0gqMTdfr94ID4qMTeRbfoBvVAVmEWEXjcWVbf+ouq0EpeEmpyjij/uqs4v4XBaUyqh7C+oX9U9cDLtDRie5A1nLuGXAvsJAMPIP2XmANVx0+l4q7pi3trAZo23vrKY6JLJnScwv01d8nqx+hKWiRFNP/zLs0iEigdDOeUUcDkGQNmu0l1cnLMF0N3UTB3sh8BTmoGtXjcWy+oh1+78LTTy3I9tPWtcOTHeX7y1t25ZtdVBRdIYgevmdQHYj8KF/OOd1mE1scNIqPbz6uTboU+Ivy8t20aR/Sx8VJNs6CjeE/Y7Mcp8tty9XUkKZDwhKCx5onPHn3OEgRKqU7LjDOenn7fyl7zt2AosJLBO7CegWoImBL2NhHTHW0+B8k1dIko5WMxrCk= spooky@harden
root@harden:~/.ssh# cat /home/spooky/.ssh/id_rsa.pub > authorized_keys
root@harden:~/.ssh# chmod -R go= ~/.ssh
root@harden:~/.ssh# exit
exit
spooky@harden:~/.ssh$ ssh root@10.10.207.65
Last login: Sun Oct 23 02:07:39 2022 from 10.10.207.65
root@harden:~# whoami
root



spooky@harden:~/.ssh$ ssh-keygen -t ecdsa -b 384
Generating public/private ecdsa key pair.
Enter file in which to save the key (/home/spooky/.ssh/id_ecdsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/spooky/.ssh/id_ecdsa.
Your public key has been saved in /home/spooky/.ssh/id_ecdsa.pub.
The key fingerprint is:
SHA256:xVUzcfMLvy5iWMg3tkzqwD/TE4utxYV8WHk3Rn3Z/Mk spooky@harden
The key's randomart image is:
+---[ECDSA 384]---+
|            ..===|
|         . .  o=B|
|          o  +.+*|
|         .. + =E=|
|        S .+ o o |
|      .  o.Bo   .|
|       o  %o=  . |
|        o*.X ..  |
|        .+= o .. |
+----[SHA256]-----+
spooky@harden:~/.ssh$ ls
id_ecdsa  id_ecdsa.pub  id_rsa  id_rsa.pub  known_hosts
spooky@harden:~/.ssh$ cat id_ecdsa.pub 
ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBIyLCCQQeodz3OcfF28LokDQk4vbe95OOe+hmsHSb5LlKn4Wxzw7HWEeVvIu/ZS30IdgLhGVvqWOoZqRe/rwe0DiOBTBQoCGKsaOFL+xRsF6mmwzm/32umENUVVP45It9Q== spooky@harden
spooky@harden:~/.ssh$ sudo su
root@harden:/home/spooky/.ssh# cd /root
root@harden:~# cd .ssh/
root@harden:~/.ssh# ls
authorized_keys
root@harden:~/.ssh# cat /home/spooky/.ssh/id_ecdsa.pub > authorized_keys
root@harden:~/.ssh# exit
exit
spooky@harden:~/.ssh$ ssh root@10.10.207.65
Last login: Sun Oct 23 02:29:02 2022 from 10.10.207.65
root@harden:~# cd /root/.ssh/
root@harden:~/.ssh# cat authorized_keys 
ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBIyLCCQQeodz3OcfF28LokDQk4vbe95OOe+hmsHSb5LlKn4Wxzw7HWEeVvIu/ZS30IdgLhGVvqWOoZqRe/rwe0DiOBTBQoCGKsaOFL+xRsF6mmwzm/32umENUVVP45It9Q== spooky@harden


```

Creating Keys with Updated Encryption Algorithms

In the previous task, we used ssh-keygen to create our keys. By default this uses RSA with a 2048 size key. Generally this is pretty okay and fine for day to day going abouts. However, you should be aware that there are other supported encryption algorithms and bit sizes. And this wouldn't be a room about hardening without discussing at least how to create these keys.

The U.S. National Institute of Standards and Technology (NIST) are now recommending RSA of at least 3072 bits or an Elliptic Curve Digital Signature Algorithm (ECDSA) key of at least 384 bits.

RSA

To create that modified RSA key, we can use the following command during key generation

ssh-keygen -t rsa -b 3072

The -t option specifies the encryption type and the -b option specifies the bit size.  

ECDSA

By now you probably can guess how you'd go about creating your ECDSA key.

ssh-keygen -t ecdsa -b 384

The max key size with ECDSA is 521 bits. However, NIST does not recommend this key size as they could be susceptible to padding attacks. 384 bits is quite strong and although the key size is smaller than RSA's 3072 key size, it's just as strong as RSA while also requiring less computing power, which is a plus.


### Disable Username & Password SSH Login 

How to Disable Username & Password SSH Login

﻿You'll only want to do this step after you've verified that your key exchange login works. Otherwise, you risk locking yourself or other users out of the system. To do this, you'll go to the /etc/ssh/sshd_config file and edit the following line

![](https://i.imgur.com/HbLT9j8.png)

to

![](https://i.imgur.com/hPRpQe2.png)

which will completely remove password based logins. Again, BE SURE THAT YOU HAVE CONFIGURED THE KEY EXCHANGE TO WORK PROPERLY or this can completely lock you out from SSH.

```
PasswordAuthentication no

```

### X11 Forwarding & SSH Tunneling 

﻿X11 Forwarding

You've connected to your workstation that has SSH enabled and you go about your work on the command-line. Everything is going great. But then you run into a problem. You need to run a program that only has a GUI.  How would you accomplish that via SSH?  That's what X11 Forwarding is for. X11 allows you to forward GUI application displays to your local environment (thought it has to have a GUI itself, right?). However, X11 has some flaws that make it dangerous to use. So let's look at turning it off.

Turn off X11 Forwarding

To turn off X11 Forwarding is very simple. It's another setting in sshd_config. You'll want to find the line that says

X11 Forwarding yes    

and change that to "no"

SSH Tunneling

Let's say you're on your computer at work and your favorite streaming service is blocked. But you just wanna watch some <streaming_service> in peace and not work, right? SSH Tunneling lets you do this. By forwarding the SSH connection to a computer or device running SSH that you own (most likely at home), you can browse this site at work. There's a few settings in the sshd_config that allow a user to accomplish this.

![](https://i.imgur.com/IwaoEFR.png)

The ones we're looking for are AllowTcpForwarding, GatewayPorts, PermitTunnel. All of these should be set to "no" in order to prevent SSH Tunneling and further harden the system and SSH.


### Improving SSH Logging 

Configuring Improved SSH Logging

A log file is created any time someone logs in with a Protocol that uses SSH. So that would be SSH, SCP, or SFTP.  By default, Ubuntu stores this log file in /var/log/auth.log. It looks something like this

![](https://i.imgur.com/ZC0jJyP.png)

Neat. There's a few different levels of logging that you can find in the man pages of sshd_config.  hey are

    QUIET
    FATAL
    ERROR
    INFO
    VERBOSE
    DEBUG1
    DEBUG2
    DEBUG3

INFO is the default setting. This is one of the two we would normally care about. The other would be VERBOSE. To change the logging level is actually very simple and is an easy config change. Navigate to /etc/ssh/sshd_config and look for the line that says 

	#LogLevel INFO

We can uncomment that line and change it to any of the available levels above. And just like that, you'll now see more detailed logs in the /var/log/auth.log file.

###  ~~~~~ Chapter 4: Mandatory Access Control ~~~~~ 

Mandatory Access Control

﻿Mandatory Access Control (MAC) is a type of Access Control. It goes along with Discretionary Access Control, Role Based Access Control, and Rule Based Access Control. MAC is considered the strongest form of access control due to allowing more control over who has access over what. In a Linux system, there are multiple ways to implement MAC. Two of which being SELinux and AppArmor.  We're going to take a look at AppArmor in this chapter and see how a system administrator or security enthusiast could harden their systems using MAC. 

### Introduction to AppArmor 

AppArmor

﻿AppArmor comes preinstalled with Ubuntu so that means no additional tools to install (yay!). Both, AppArmor and SELinux can be used to implement MAC on a Linux system but since we're going over AppArmor in this walkthrough, let's look at some of the benefits of AppArmor.

    It can prevent malicious actors from accessing the data on your systems. As a system administrator, this is extremely important; protecting the confidentiality of your data
    Applications have their own profiles thus making it a little easier
    SELinux and AppArmor have the capability to create your own custom profiles but the scripting in AppArmor is a little easier to understand and reduces the learning curve

AppArmor Configuration

The AppArmor directory is located at /etc/apparmor.d. This directory contains all of the AppArmor profiles. The sbin.dhclient and usr.* files are AppArmor profiles.

![](https://i.imgur.com/QaOKHIo.png)

The abstractions directory is a sort of "includes" folder that has partially written profiles that can be used and included in your own profiles. Part of the work has already been done for you. Here is a listing of the abstractions directory

![](https://i.imgur.com/YkF0kiv.png)

Lots of things here for you to use in your custom profiles! Let's take a look at one. I've already gone through and checked a lot of these out and I picked one that I think goes over quite a bit. For this example, let's look at the gnupg file.

![](https://i.imgur.com/Xu4qZqJ.png)

	You'll notice that each line/rule ends in a comma. This is required syntax (even for the last rule). You'll also notice that each rule has an owner @{HOME} portion for each listing. The @{HOME} is an AppArmor variable that allows the rule to work with any user's home directory. The access methods before the end of the rule are what you'd expect - r for reading, w for writing. These indicate that the AppArmor daemon have those permissions to read and write to that location preceding it. Easy, right? The only one that you may not know is m which indicates that the file can be used for executable mapping - the file can be mapped into memory using mmap. Remember, these are not configured profiles. They are partials meant to be included in custom profiles. The only two profiles upon a fresh install of Ubuntu are the few mentioned earlier, sbin.dhclient and usr.*.
There are a few in the lxc directory and lxc-containers file but not much.

Additional profiles can be installed with sudo apt install apparmor-profiles apparmor-profiles-extra.

### AppArmor Command Line Utilities 

AppArmor Command-Line Utilities

﻿When working with AppArmor, you're going to undoubtedly need to know the commands to interact with it. But before you do that, you should probably know the different modes of AppArmor. A few have direct comparisons to SELinux if you know them already but to make things less confusing, I won't mention the comparisons.

To get the AppArmor status, we can enter aa-status. This gives us quite a long output.

![](https://i.imgur.com/dwDQcQ9.png)

We can see that AppArmor is indeed loaded and it is currently set to enforce mode. There are 19 profiles loaded. This segues nicely into the different AppArmor modes.

    Enforce - Enforces the active profiles
    Complain - Allows processes to perform disallowed actions by the profile and are logged
    Audit - The same as Enforce mode but allowed and disallowed actions get logged to /var/log/audit/audit.log or system log (depending on if auditd is installed)

In order to use any of the command-line utilities I'm about to show, you'll need to perform the following, sudo apt install apparmor-utils. This will enable the following commands, aa-enforce, aa-disable, aa-audit, aa-complain.  Let's set the usr.sbin.rsyslogd profile to enforce mode and then check the status.

![](https://i.imgur.com/C99o2MB.png)

From the output you can see that 20 profiles are now loaded which is 1 more than from the previous status we ran.

https://www.ma-no.org/es/redes/servers/que-es-apparmor-y-como-mantiene-seguro-ubuntu

###  ~~~~~ Chapter 4 Quiz ~~~~~ 

Summary

You did it! You've completed every chapter in the room and are now ready for the final quiz. This was a short chapter on AppArmor and Mandatory Access Control. Remember what you've learned and answer the questions!

 Where are the AppArmor profiles located?
*/etc/apparmor.d*



This directory includes partial profiles to be used in your own custom profiles
*abstractions*

This punctuation mark is REQUIRED at the end of every rule in a profile
*,*


This AppArmor mode enforces the profiles but also logs them
*audit*



This command checks the status of AppArmor
*aa-status*

### ~~~~~ Chapter 3: SSH and Encryption ~~~~~ 



Chapter 3: SSH and Encryption

Encryption is a super important topic. Everything needs encryption! Whether its that super secret puppy gif collection, corporate documents, personal documents, even entire hard drives; it can all be encrypted! Understanding how to put encryption into effect and in place at home and work is a vital piece of information to have. It could save your personal files from being compromised or work documents from being stolen.

Encryption covers a lot of different things. Just in the Sec+ alone, you cover symmetric and asymmetric encryption, private and public keys, various ciphers, hashing...it's a lot. This is going to be less than that and more focused on encryption as it pertains to Ubuntu and hardening your system/server. So sit back and let's get ready. We're going to cover a lot of things here.  Topics will include:

    GNU Privacy Guard
        Encrypting files with GPG
    SSH
        Disabling SSH Protocol 1
        Creating Keys
        Disabling username/password logins
        Configuring SSH encryption
        More detailed logging
        Disabling SSH Tunneling
        Disabling X11 Forwarding

Let's get started!

### Conclusion & Optional Challenges 



Closing Thoughts﻿

Well, you made it.  Thanks for sticking around and congratulations on completing this room.  We've gone through a lot and I hope you've learned something that you can take away and implement in your corporate/work environment or home environment or labs.

Really, there's so much to cover in terms of hardening.  It was really hard to pick which topics to go over but after a lot of thought, the ones I chose were ultimately the ones I felt that would have the most benefit for the users here on TryHackMe.  We could have an entire room on Firewall hardening and rules and logging and testing (and maybe someone will do that), but I wanted to give a good overview of hardening concepts and best practices.

If you're interested in learning more, I highly recommend the book, Mastering Linux Security and Hardening by Donald A. Tevault.  There's just so much I couldn't cover that is explained in great detail in this book.  A lot of the material in this room came from this book.  Check it out.

And lastly, it took a lot of research and effort to make this room.  I didn't know about all of the topics covered when I first started.  And I definitely didn't know about all of the secure practices covered.  That being said, I'm only human and if I missed something or if some information here is wrong or misleading, let me know in the Discord or a DM on the site and I'll do my best to fix it.

Resources

https://www.tecmint.com/configure-pam-in-centos-ubuntu-linux/

https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/4/html/security_guide/s2-wstation-privileges-noroot

https://help.ubuntu.com/community/IptablesHowTo#Saving_iptables

https://help.ubuntu.com/community/UFW

https://manpages.ubuntu.com/manpages/xenial/man5/apparmor.d.5.html

http://manpages.ubuntu.com/manpages/bionic/man7/PAM.7.html

https://www.digitalocean.com/community/tutorials/how-to-use-pam-to-configure-authentication-on-an-ubuntu-12-04-vps

https://linux.die.net/man/8/pam_pwhistory

https://www.amazon.com/Mastering-Linux-Security-Hardening-intruders/dp/1788620305

Challenges

I've set up some challenges for you to try to figure out while you play with the machine. You do not have to do these. They are entirely optional but will help cement the material and commands that you have learned. Enjoy!

Challenge List

[Easy] Make a User Alias called "ADMINS". Then make a Command Alias called "ADMIN COMMANDS" and assign it some commands. Practice what you learned. Assign it to someone other than spooky. You can test the configuration by trying commands that are not assigned to the alias. You can enter visudo as spooky with sudo.

[Medium] Spooky has a group that we talked about that should not be left on. Exploit it (research will be needed for this).

[Easy] Spooky has gone and mucked up the firewall. Users outside the organization are reporting that they cannot reach the webpage on port 80. Figure out what he did and make it right! (spooky:tryhackme)

[Medium] James has been notified that he needs to change his password as it is too simple. Login as James and change his password. You will need to conform to the following requirements. (james:easy)

    minlen=8
    difok=3
    lcredit=-1
    dcredit=-1
    ucredit=-1
    ocredit=-1

[Easy] Using James and Spooky, play around with Gnu Privacy Guard and encrypt and decrypt a file. Try using both, symmetric and asymmetric encryption types. If you did the challenge above and reset James's password, don't forget to write it down and use the new password!

[Easy] Configure SSH for Public Key Encryption. You do not need to change or modify anything in /etc/ssh/sshd_config. Test it with spooky. You should not need root login for this. If you need a hint, look in Task 21.


Have fun


[[Hardening Basics Part 1]]