---
Learn the basic concepts for secure API development (Part 2).
---

![](https://i.imgur.com/sP6d0iZ.png)

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/7a45f6ff36f59b4874143d01faa98e41.png)

### Quick Recap

 Start Machine

In the [previous room](https://tryhackme.com/jr/owaspapisecuritytop105w), we studied the first five principles of OWASP API Security. Now in this room, we will briefly discuss the remaining principles and their potential impact and mitigation measures.

**Learning Objectives**

-   Identification of security misconfigurations.
-   Preventing Denial of Service (DoS) against the API.
-   Ensuring appropriate logging and monitoring.

**Learning Pre-requisites**  
An understanding of the following topics is recommended before starting the room:

-   [How websites work](https://tryhackme.com/room/howwebsiteswork).
-   [HTTP protocols & methods](https://tryhackme.com/room/protocolsandservers).
-   [Principles of security](https://tryhackme.com/room/principlesofsecurity).
-   [OWASP top 10 web vulnerabilities](https://tryhackme.com/room/owasptop10).

**Connecting to the Machine**  
We will be using Windows as a development/test machine along with Talend API Tester - free edition throughout the room with the following credentials:

-   Machine IP:  `MACHINE_IP` 
-   Username:   `Administrator`
-   Password:    `Owasp@123`

You can start the virtual machine by clicking the `Start Machine button`. The machine will start in a split-screen view. In case the VM is not visible, use the blue Show Split View button at the top-right of the page. Alternatively, you can connect with the VM through Remote Desktop using the above credentials. Please wait 1-2 minutes after the system boots completely to let the auto scripts run successfully that will execute Talend API Tester and Laravel-based web application automatically.

![Image for RDP](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/2e8676dbcc93a6ac0b3f4a491be2ff06.png)  

Let's begin!

Answer the questions below

I can connect and log in to the machine.

### Vulnerability VI - Mass Assignment

﻿**How does it happen?**

Mass assignment reflects a scenario where **client-side data is automatically bound with server-side objects or class variables**. However, hackers exploit the feature by first understanding the **application's business logic** and sending specially crafted data to the server, acquiring administrative access or inserting tampered data. This functionality is widely exploited in the latest frameworks like Laravel, Code Ignitor etc.  

Consider a user's profiles dashboard where users can update their profile like associated email, name, address etc. The username of the user is a read-only attribute and cannot be changed; however, a malicious actor can edit the username and submit the form. If necessary filtration is not enabled on the server side (model), it will simply insert/update the data in the database. 

**Likely Impact** 

The attack may result in **data tampering and privilege escalation** from a regular user to an administrator. 

  

Practical Example  

-   Open the VM. You will find that the Chrome browser and Talend API Tester application are running automatically, which we will be using for debugging the API endpoints.  
    
-   Bob has been assigned to develop a signup API endpoint `/apirule6/user` that will take a name, username and password as input parameters (POST). The user's table has a `credit column` with a default value of `50`. Users will upgrade their membership to have a larger credit value.
-   Bob has successfully designed the form and used the mass assignment feature in Laravel to store all the incoming data from the client side to the database (as shown below).

![Image for Vulnerable Scenario](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/31d541b9eb6d7f67dec8fdb60d07f8af.png)  

-   What is the problem here? Bob is not doing any filtering on the server side. Since using the **mass assignment feature**, he is also inserting credit values in the database (malicious actors can update that value).  
    
-   The solution to the problem is pretty simple. Bob must ensure necessary filtering on the server side (`apirule6/user_s`) and ensure that the default value of credit should be inserted as `50`, even if more than 50 is received from the client side (as shown below). 

![Image for secure scenario](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/bfb2c99ce2c72649953967a629cbcc39.png)  

**Mitigation Measures** 

-   Before using any framework, one must study how the backend insertions and updates are carried out. In the Laravel framework, [fillable and guarded](https://laravel.com/docs/9.x/eloquent#inserts) arrays mitigate the above-mentioned scenarios. 
-   Avoid using functions that bind an input from a client to code variables automatically.
-   Allowlist those properties only that need to get updated from the client side. 

Answer the questions below

```ruby
Mass assignment is a feature in some programming languages and frameworks that allows for the initialization of an object's properties with a single assignment statement. This is often used to set multiple properties of an object at once, and is particularly useful when working with forms in web development. In languages like Ruby on Rails, mass assignment can be used to set multiple attributes of a database model at once, using a hash or array of attribute values. This can be useful for reducing the amount of code required, but it also requires careful consideration of security, as it can open up the possibility of malicious users injecting unwanted values into an object's properties.

Sure, here is a simple example of mass assignment in Ruby on Rails:

class Person < ApplicationRecord
  attr_accessible :name, :age, :gender
end

#creating a new person
person = Person.new(name: "John", age: 30, gender: "male")
person.save


In this example, we have a `Person` model with `name`, `age`, and `gender` attributes. The `attr_accessible` line specifies which attributes can be mass-assigned. In the last line, we use the new method to create a new person, passing in a hash of attribute values, which sets the `name`, `age`, and `gender` attributes all at once.

This is a very simple example, but in real-world application, you may want to be more careful and make sure the data passed in is sanitized and in the right format.

Method POST

http://127.0.0.1/MHT/apirule6/user

Add form parameter

name:Bob
username:bob_mht
password:anything
credit:100 (more than 50)

Request Body

{
"name": "Bob",
"username": "bob_mht",
"credit": "110",
"id": 6
}

http://127.0.0.1/MHT/apirule6/user_s

{
"name": "Bob",
"username": "bob_mht",
"credit": 50,
"id": 7
}

```

![[Pasted image 20230125115731.png]]

Is it a good practice to blindly insert/update user-provided data in the database (yea/nay)?

*nay*

Using /apirule6/user_s, insert a record in the database using the credit value as 1000.

No answer needed

What would be the returned credit value after performing Question#2?

*50*

### Vulnerability VII - Security Misconfiguration

﻿**How does it happen?**

Security misconfiguration depicts an implementation of **incorrect and poorly configured security controls** that put the security of the whole API at stake. Several factors can result in security misconfiguration, including improper/incomplete default configuration, publically accessible cloud storage, [Cross-Origin Resource Sharing (CORS)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS), and error messages displayed with sensitive data. Intruders can take advantage of these misconfigurations to perform detailed reconnaissance and get unauthorised access to the system. 

Security misconfigurations are usually detected by vulnerability scanners or auditing tools and thus can be curtailed at the initial level. API documentation, a list of endpoints, error logs etc., **must not be publically accessible** to ensure safety against security misconfigurations. Typically, companies deploy security controls like web application firewalls, which are not configured to block undesired requests and attacks.  

  

**Likely Impact** 

Security misconfiguration can give intruders complete knowledge of API components. Firstly, it allows intruders to bypass security mechanisms. **Stack trace or other detailed errors** can provide the malicious actor access to confidential data and essential system details, further aiding the intruder in profiling the system and gaining entry.    

  

Practical Example  

-   Continue to use the Chrome browser and Talend API Tester for debugging in the VM.  
    
-   The company MHT is facing serious server availability issues. Therefore, they assigned Bob to develop an API endpoint `/apirule7/ping_v` (GET) that will share details regarding server health and status.
-   Bob successfully designed the endpoint; however, he forgot to implement any error handling to avoid any information leakage.

![Image for Vulnerable Scenario](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/76b0298b5134ca3c04e4290b15f4e73a.png)  

-   What is the issue here? In case of an unsuccessful call, the server sends a complete stack trace in response, containing function names, controller and route information, file path etc. An attacker can use the information for profiling and preparing specific attacks on the environment.  
    
-   The solution to the issue is pretty simple. Bob will create an API endpoint `/apirule7/ping_s` that will carry out error handling and only share desired information with the user (as shown below).

![Image for Secure Scenario](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/9087274b07f2fa5174398b0bb0c69979.png)  

**Mitigation Measures** 

-   Limit access to the administrative interfaces for authorised users and disable them for other users. 
-   Disable default usernames and passwords for public-facing devices (routers, Web Application Firewall etc.).
-   Disable directory listing and set proper permissions for every file and folder. 
-   Remove unnecessary pieces of code snippets, error logs etc. and turn off debugging while the code is in production.

Answer the questions below

```json

"Cross-origin" refers to the relationship between two different web sites, or origins. An origin is defined as a combination of a scheme (such as "http" or "https"), a hostname, and a port number.

So, when a request is made from one origin to a resource on another origin, it is considered a "cross-origin" request. For example, if a web page served from "[http://example.com](http://example.com/)" makes an HTTP request to "[http://other-site.com](http://other-site.com/)", that is a cross-origin request.

The same-origin policy is a security feature implemented by web browsers that limits the ability of web pages to access resources on different origins. This policy is in place to prevent malicious web pages from making unauthorized requests to other sites and potentially stealing sensitive information. CORS (Cross-Origin Resource Sharing) is a way for web servers to relax the same-origin policy and allow certain cross-origin requests.

CORS (Cross-Origin Resource Sharing) is a security feature implemented by web browsers to prevent a web page from making requests to a different domain than the one that served the web page.

An example of this would be if a web page served from "[http://example.com](http://example.com/)" tried to make an HTTP request to "[http://other-site.com](http://other-site.com/)". Without CORS, the browser would block the request as a security measure.

However, if "[http://other-site.com](http://other-site.com/)" has enabled CORS, it can specify which origins are allowed to access its resources. This is done by setting appropriate headers in the server's response, such as `Access-Control-Allow-Origin`.

Here's an example of how CORS can be enabled in a Node.js Express server:

const express = require("express");
const app = express();

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "http://example.com");
  res.header("Access-Control-Allow-Methods", "GET,PUT,POST,DELETE");
  res.header("Access-Control-Allow-Headers", "Content-Type");
  next();
});

app.get("/data", (req, res) => {
  res.json({ message: "Hello from the server!" });
});

app.listen(3000, () => {
  console.log("Server listening on port 3000");
});


In this example, the server is allowing the origin "[http://example.com](http://example.com/)" to access its resources, and responding to the `GET` method, allowing the headers "Content-Type" as well. You will need to check the documentation of the framework you are using to know how to set CORS headers.

CORS is a simple concept to understand but the implementation can be a bit more complex depending on the specific use case.

An endpoint refers to a specific URL or URI (Uniform Resource Identifier) that represents a resource or service that can be accessed via the web or a network. An endpoint is the point of entry for a client to access a server and its resources.

In the context of web development, an endpoint typically refers to the address of a specific server-side script or resource that a client can make requests to. For example, a server might have an endpoint for creating new users, updating existing users, or fetching a list of all users. These endpoints are usually defined by a combination of the HTTP method (such as GET, POST, PUT, DELETE) and the URL path.

In RESTful web services, an endpoint typically refers to a specific resource, such as a user, that can be accessed via the web using a specific URL. For example, a RESTful API might have an endpoint like "[https://example.com/api/users/123](https://example.com/api/users/123)" to retrieve a specific user with ID 123.

Endpoints can also be used in other contexts, such as WebSockets, where it is the address or URL of the server to which the client connects to establish a real-time connection.

In summary, an endpoint is the point where a client can access a specific resource or service that is exposed by the server.

Code snippets are small pieces of code that can be reused in different parts of a program. They are often used to automate repetitive tasks and to quickly add commonly-used functionality to a program. Code snippets can be written in any programming language and can range from a single line of code to a complete block of functionality.

Code snippets can be stored in a variety of ways, such as in a code library, an integrated development environment (IDE), or in a code snippet manager. Some common features of code snippet managers include the ability to organize and categorize snippets, search for specific snippets, and share snippets with others.

Here's an example of a code snippet written in Python that calculates the factorial of a number:

def factorial(n):
    if n == 0:
        return 1
    else:
        return n * factorial(n-1)

print(factorial(5)) # Output: 120


And an example of a code snippet written in JavaScript that logs the current date and time:

console.log(new Date().toString());

These are just examples, but code snippets can be any piece of code that you can reuse, adapt and save for future use.

Method GET

Endpoint:

http://127.0.0.1/MHT/apirule7/ping_v

Request Body

string(6269) "#0 C:\xampp\htdocs\mht\vendor\laravel\framework\src\Illuminate\Routing\Controller.php(54): App\Http\Controllers\API7UsersController->auth_v(Object(Illuminate\Http\Request))
#1 C:\xampp\htdocs\mht\vendor\laravel\framework\src\Illuminate\Routing\ControllerDispatcher.php(45): Illuminate\Routing\Controller->callAction('auth_v', Array)
#2 C:\xampp\htdocs\mht\vendor\laravel\framework\src\Illuminate\Routing\Route.php(261): Illuminate\Routing\ControllerDispatcher->dispatch(Object(Illuminate\Routing\Route), Object(App\Http\Controllers\API7UsersController), 'auth_v')
#3 C:\xampp\htdocs\mht\vendor\laravel\framework\src\Illuminate\Routing\Route.php(204): Illuminate\Routing\Route->runController()
#4 C:\xampp\htdocs\mht\vendor\laravel\framework\src\Illuminate\Routing\Router.php(695): Illuminate\Routing\Route->run()
#5 C:\xampp\htdocs\mht\vendor\laravel\framework\src\Illuminate\Pipeline\Pipeline.php(128): Illuminate\Routing\Router->Illuminate\Routing\{closure}(Object(Illuminate\Http\Request))
#6 C:\xampp\htdocs\mht\vendor\laravel\framework\src\Illuminate\Routing\Middleware\SubstituteBindings.php(50): Illuminate\Pipeline\Pipeline->Illuminate\Pipeline\{closure}(Object(Illuminate\Http\Request))
#7 C:\xampp\htdocs\mht\vendor\laravel\framework\src\Illuminate\Pipeline\Pipeline.php(167): Illuminate\Routing\Middleware\SubstituteBindings->handle(Object(Illuminate\Http\Request), Object(Closure))
#8 C:\xampp\htdocs\mht\vendor\laravel\framework\src\Illuminate\Pipeline\Pipeline.php(103): Illuminate\Pipeline\Pipeline->Illuminate\Pipeline\{closure}(Object(Illuminate\Http\Request))
#9 C:\xampp\htdocs\mht\vendor\laravel\framework\src\Illuminate\Routing\Router.php(697): Illuminate\Pipeline\Pipeline->then(Object(Closure))
#10 C:\xampp\htdocs\mht\vendor\laravel\framework\src\Illuminate\Routing\Router.php(672): Illuminate\Routing\Router->runRouteWithinStack(Object(Illuminate\Routing\Route), Object(Illuminate\Http\Request))
#11 C:\xampp\htdocs\mht\vendor\laravel\framework\src\Illuminate\Routing\Router.php(636): Illuminate\Routing\Router->runRoute(Object(Illuminate\Http\Request), Object(Illuminate\Routing\Route))
#12 C:\xampp\htdocs\mht\vendor\laravel\framework\src\Illuminate\Routing\Router.php(625): Illuminate\Routing\Router->dispatchToRoute(Object(Illuminate\Http\Request))
#13 C:\xampp\htdocs\mht\vendor\laravel\framework\src\Illuminate\Foundation\Http\Kernel.php(166): Illuminate\Routing\Router->dispatch(Object(Illuminate\Http\Request))
#14 C:\xampp\htdocs\mht\vendor\laravel\framework\src\Illuminate\Pipeline\Pipeline.php(128): Illuminate\Foundation\Http\Kernel->Illuminate\Foundation\Http\{closure}(Object(Illuminate\Http\Request))
#15 C:\xampp\htdocs\mht\vendor\laravel\framework\src\Illuminate\Foundation\Http\Middleware\TransformsRequest.php(21): Illuminate\Pipeline\Pipeline->Illuminate\Pipeline\{closure}(Object(Illuminate\Http\Request))
#16 C:\xampp\htdocs\mht\vendor\laravel\framework\src\Illuminate\Foundation\Http\Middleware\ConvertEmptyStringsToNull.php(31): Illuminate\Foundation\Http\Middleware\TransformsRequest->handle(Object(Illuminate\Http\Request), Object(Closure))
#17 C:\xampp\htdocs\mht\vendor\laravel\framework\src\Illuminate\Pipeline\Pipeline.php(167): Illuminate\Foundation\Http\Middleware\ConvertEmptyStringsToNull->handle(Object(Illuminate\Http\Request), Object(Closure))
#18 C:\xampp\htdocs\mht\vendor\laravel\framework\src\Illuminate\Foundation\Http\Middleware\TransformsRequest.php(21): Illuminate\Pipeline\Pipeline->Illuminate\Pipeline\{closure}(Object(Illuminate\Http\Request))
#19 C:\xampp\htdocs\mht\vendor\laravel\framework\src\Illuminate\Foundation\Http\Middleware\TrimStrings.php(40): Illuminate\Foundation\Http\Middleware\TransformsRequest->handle(Object(Illuminate\Http\Request), Object(Closure))
#20 C:\xampp\htdocs\mht\vendor\laravel\framework\src\Illuminate\Pipeline\Pipeline.php(167): Illuminate\Foundation\Http\Middleware\TrimStrings->handle(Object(Illuminate\Http\Request), Object(Closure))
#21 C:\xampp\htdocs\mht\vendor\laravel\framework\src\Illuminate\Foundation\Http\Middleware\ValidatePostSize.php(27): Illuminate\Pipeline\Pipeline->Illuminate\Pipeline\{closure}(Object(Illuminate\Http\Request))
#22 C:\xampp\htdocs\mht\vendor\laravel\framework\src\Illuminate\Pipeline\Pipeline.php(167): Illuminate\Foundation\Http\Middleware\ValidatePostSize->handle(Object(Illuminate\Http\Request), Object(Closure))
#23 C:\xampp\htdocs\mht\vendor\laravel\framework\src\Illuminate\Foundation\Http\Middleware\PreventRequestsDuringMaintenance.php(86): Illuminate\Pipeline\Pipeline->Illuminate\Pipeline\{closure}(Object(Illuminate\Http\Request))
#24 C:\xampp\htdocs\mht\vendor\laravel\framework\src\Illuminate\Pipeline\Pipeline.php(167): Illuminate\Foundation\Http\Middleware\PreventRequestsDuringMaintenance->handle(Object(Illuminate\Http\Request), Object(Closure))
#25 C:\xampp\htdocs\mht\vendor\fruitcake\laravel-cors\src\HandleCors.php(38): Illuminate\Pipeline\Pipeline->Illuminate\Pipeline\{closure}(Object(Illuminate\Http\Request))
#26 C:\xampp\htdocs\mht\vendor\laravel\framework\src\Illuminate\Pipeline\Pipeline.php(167): Fruitcake\Cors\HandleCors->handle(Object(Illuminate\Http\Request), Object(Closure))
#27 C:\xampp\htdocs\mht\vendor\laravel\framework\src\Illuminate\Http\Middleware\TrustProxies.php(39): Illuminate\Pipeline\Pipeline->Illuminate\Pipeline\{closure}(Object(Illuminate\Http\Request))
#28 C:\xampp\htdocs\mht\vendor\laravel\framework\src\Illuminate\Pipeline\Pipeline.php(167): Illuminate\Http\Middleware\TrustProxies->handle(Object(Illuminate\Http\Request), Object(Closure))
#29 C:\xampp\htdocs\mht\vendor\laravel\framework\src\Illuminate\Pipeline\Pipeline.php(103): Illuminate\Pipeline\Pipeline->Illuminate\Pipeline\{closure}(Object(Illuminate\Http\Request))
#30 C:\xampp\htdocs\mht\vendor\laravel\framework\src\Illuminate\Foundation\Http\Kernel.php(141): Illuminate\Pipeline\Pipeline->then(Object(Closure))
#31 C:\xampp\htdocs\mht\vendor\laravel\framework\src\Illuminate\Foundation\Http\Kernel.php(110): Illuminate\Foundation\Http\Kernel->sendRequestThroughRouter(Object(Illuminate\Http\Request))
#32 C:\xampp\htdocs\mht\public\index.php(52): Illuminate\Foundation\Http\Kernel->handle(Object(Illuminate\Http\Request))
#33 C:\xampp\htdocs\mht\server.php(21): require_once('C:\\xampp\\htdocs...')
#34 {main}"

Method GET

Endpoint:

http://127.0.0.1/MHT/apirule7/ping_s

Request Body

{
"success": "false",
"msg": "Network Server @ 2 - Malfunctioned - Errod ID #1401. Please contact administator at support@mht.com for further queries."
}

Response 500 (Internal Server Error)


```


Is it an excellent approach to show error logs from the stack trace to general visitors (yea/nay)?

*nay*

Try to use the API call /apirule7/ping_s in the attached VM.

Question Done

What is the HTTP response code?

*500*

What is the Error ID number in the HTTP response message?

*1401*


### Vulnerability VIII - Injection

**How does it happen?**

Injection attacks are probably among the oldest API/web-based attacks and are still being carried out by hackers on real-world applications. Injection flaws occur when user input is **not filtered and is directly processed by an API**; thus enabling the attacker to perform unintended API actions without authorisation. An injection may come from [Structure Query Language (SQL)](https://tryhackme.com/room/sqlinjectionlm), operating system (OS) commands, Extensible Markup Language (XML) etc. Nowadays, frameworks offer functionality to protect against this attack through automatic sanitisation of data; however, applications built in custom frameworks like core PHP are still susceptible to such attacks. 

  

**Likely Impact** 

Injection flaws may lead to **information disclosure, data loss, DoS, and complete account takeover**. The successful injection attacks may also cause the intruders to access the sensitive data or even create new functionality and perform remote code execution. 

  

Practical Example  

-   Continue to use the Chrome browser and Talend API Tester for debugging in the VM.  
    
-   A few users of company MHT reported that their account password had changed, and they could not further log in to their original account. Consequently, the dev team found that Bob had developed a vulnerable login API endpoint `/apirule8/user/login_v` that is not filtering user input.  
    
-   A malicious attacker requires the username of the target, and for the password, they can use the payload `' OR 1=1--'` and get an authorisation key for any account (as shown below).

![Image for Vulnerable Scenario](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/fb4649a8c9226d5c68d2ece9e1e1246a.png)  

-   Bob immediately realised his mistake; he updated the API endpoint to `/apirule8/user/login_s` and used parameterised queries and built-in filters of Laravel to sanitise user input.
-   As a result, all malicious payloads on username and password parameters were effectively mitigated (as shown below)

![Image for secure scenario](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/496f9d46040c7a3088f710bbe29cfc0a.png)  

**Mitigation Measures**

-   Ensure to use a well-known library for client-side input validation.
-   If a framework is not used, all client-provided data must be validated first and then filtered and sanitised. 
-   Add necessary security rules to the Web Application Firewall (WAF). Most of the time, injection flaws can be mitigated at the network level.
-   Make use of built-in filters in frameworks like Laravel, Code Ignitor etc., to validate and filter data. 

Answer the questions below

```json
Denial of Service (DoS) is an attack on the target's availability to make the target service/system unavailable to legitimate users.

Method POST

Endpoint:

http://127.0.0.1/MHT/apirule8/user/login_v

Add form parameter

username:Text: admin
password:Text: ' or 1=1--'      (like select * from users where username ='admin' or 1=1--')
								 -- comment      or 1=1    true   ' close parameter

Request Body

{
"success": "true",
"authkey": "oWsZ8vWNuECjCAiZVJHOzsNsNH08zWRZ"
}

Method Post

Endpoint:

http://127.0.0.1/MHT/apirule8/user/login_s

Add form parameter

username:Text: admin
password:Text: ' or 1=1--'

Request Body

{
"success": "false",
"cause": "IncorrectUsernameOrPassword"
}

Response 403 (Forbidden)

```

Can injection attacks be carried out to extract data from the database (yea/nay)?

*yea*

Can injection attacks result in remote code execution (yea/nay)?

*yea*

What is the HTTP response code if a user enters an invalid username or password?

*403*

### Vulnerability IX - Improper Assets Management

﻿**How does it happen?**

Inappropriate Asset Management refers to a scenario where we have **two versions of an API available in our system**; let's name them APIv1 and APIv2. Everything is wholly switched to APIv2, but the previous version, APIv1, has not been deleted yet. Considering this, one might easily guess that the older version of the API, i.e., APIv1, doesn't have the updated or the latest security features. Plenty of other obsolete features of APIv1 make it possible to find vulnerable scenarios, which may lead to data leakage and server takeover via a shared database amongst API versions.

It is essentially about not properly tracking API endpoints. The potential reasons could be incomplete API documentation or absence of compliance with the [Software Development Life Cycle](https://tryhackme.com/room/securesdlc). A properly maintained, up-to-date API inventory and proper documentation are more critical than hardware-based security control for an organisation.  

  

**Likely Impact** 

The older or the **unpatched API versions** can allow the intruders to get unauthorised access to confidential data or even complete control of the system. 

  

Practical Example  

-   Continue to use the Chrome browser and Talend API Tester for debugging in the VM.  
    
-   During API development, the company MHT has developed different API versions like v1 and v2. The company ensured to use the latest versions and API calls but forgot to remove the old version from the server.  
    
-   Consequently, it was found that old API calls like `apirule9/v1/user/login` return more information like balance, address etc., against the user (as shown below).

![Image for secure scenario](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/a3d12beaea5bfdbcab5659d9145b189e.png)  

-   Bob being the developer of the endpoint, realised that he must immediately deactivate old and unused assets so that users can only access limited and desired information from the new endpoint `/apirul9/v2/user/login` (as shown below)

![Image for Secure Scenario](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/38d853bd141ee2e604216640d3af067c.png)

**Mitigation Measures**   

-   Access to previously developed sensitive and deprecated API calls must be blocked at the network level.
-   APIs developed for R&D, QA, production etc., must be segregated and hosted on separate servers.
-   Ensure documentation of all API aspects, including authentication, redirects, errors, CORS policy, and rate limiting. 
-   Adopt open standards to generate documentation automatically.

Answer the questions below

```json

R&D stands for Research and Development. It refers to the work a company or organization does to develop new products, services, or technologies. This can include researching new ideas, designing prototypes, testing and refining products, and bringing new offerings to market.

QA stands for Quality Assurance. It is the process of verifying that a product, service, or system meets certain quality standards, and that it performs as intended. QA is typically focused on identifying and resolving defects, and ensuring that the final product meets the requirements and specifications set out by the company or organization.

Method POST

Endpoint:

http://127.0.0.1/MHT/apirule9/v1/user/login

Add form parameter

username:Text:alice
password:Text:##!@#!!

Request Body

{
"id": 1,
"username": "alice",
" Balance": "100",
"country": "USA"
}

Method POST

Endpoint:

http://127.0.0.1/MHT/apirule9/v2/user/login

Add form parameter

username:Text:alice
password:Text:##!@#!!

Request Body

{
"id": 1,
"username": "alice"
}


```


Is it good practice to host all APIs on the same server (yea/nay)?

*nay*

Make an API call to /apirule9/v1/user/login using the username "**Alice**" and password "**##!@#!!**".

 Completed

What is the amount of balance associated with user Alice?  

*100*

What is the country of the user Alice?

*USA*

### Vulnerability X - Insufficient Logging & Monitoring

**How does it happen?**

Insufficient logging & monitoring reflects a scenario when an attacker conducts malicious activity on your server; however, when you try to track the hacker, **there is not enough evidence available due to the absence of logging and monitoring mechanisms**. Several organisations only focus on infrastructure logging like network events or server logging but lack API logging and monitoring. Information like the visitor's IP address, endpoints accessed, input data etc., along with a timestamp, enables the identification of threat attack patterns. If logging mechanisms are not in place, it would be challenging to identify the attacker and their details. Nowadays, the latest web frameworks can automatically log requests at different levels like error, debug, info etc. These errors can be logged in a database or file or even passed to a [SIEM solution](https://tryhackme.com/room/defensivesecurity) for detailed analysis.

  

**Likely Impact** 

Inability to identify attacker or hacker behind the attack. 

  

Practical Example  

-   Continue to use the Chrome browser and Talend API Tester for debugging in the VM.  
    
-   In the past, the company MHT has been susceptible to multiple attacks, and the exact culprit behind the attacks could not be identified. Therefore, Bob was assigned to make an API endpoint `/apirule10/logging` (GET) that will log users' metadata (IP address, browser version etc.) and save it in the database as well (as shown below).  
    

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/9112accb6150c21ee9daadff3d5560e7.png)  

-   Later, it was also decided that the same would be forwarded to a SIEM solution for correlation and analysis.

**Mitigation Measures** 

-   Ensure use of the Security Information and Event Management (SIEM) system for log management. 
-   Keep track of all denied accesses, failed authentication attempts, and input validation errors, using a format imported by SIEM and enough detail to identify the intruder.
-   Handle logs as sensitive data and ensure their integrity at rest and transit. Moreover, implement custom alerts to detect suspicious activities as well. 

Answer the questions below

```json

Method POST

Endpoint:

http://127.0.0.1/MHT/apirule10/logging

Request Body:

{
"message": "Hi, an abnormal activity has been detected. Your IP address 127.0.0.1 Browser: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36 Timestamp: 2023-01-25 22:56:48 has been logged"
}

Response 200 OK

```

Should the API logs be publically accessible so that the attacker must know they are being logged (yea/nay)?

*nay*

What is the HTTP response code in case of successful logging of user information?

*200*

### Conclusion

Phew. That was simple. It would be correct to say that over **half of OWASP API security's top 10 list is relevant to authorisation and authentication**. Most commonly, API systems are hacked because of failure in authorisation and authentication mechanisms and security misconfigurations.

In a nutshell, API developers must **safeguard APIs in line with best cyber security practices**. The modules like sign-in, role-based access, user profile setting etc., must be given more importance as malicious actors tend to target known endpoints for gaining access to the system.

Stay tuned! And keep developing secure APIs.



[[Temple]]