---
Learn the basic concepts for secure API development (Part 1).
---

![](https://i.imgur.com/sP6d0iZ.png)

![100](https://tryhackme-images.s3.amazonaws.com/room-icons/74be0ffb2200053145ccadac85dd24c5.png)

### Introduction

 Start Machine

OWASP - Open Web Application Security Project (OWASP) is a non-profit and collaborative online community that aims to improve application security via a set of security principles, articles, documentation etc. Back in 2019, OWASP released a list of the top 10 API vulnerabilities, which will be discussed in detail, along with its potential impact and a few effective mitigation measures. 

We have split this room into two parts. In **Part 1**, you will study the top 5 principles, and in Part 2 (coming soon), you will learn the remaining principles.

**Learning Objectives**

-   Best practices for API authorisation & authentication.
-   Identification of authorisation level issues.
-   Handling excessive data exposure.
-   Lack of resources and rate-limiting issues.

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

You can start the virtual machine by clicking `Start Machine`. The machine will start in a split-screen view. In case the VM is not visible, use the blue Show Split View button at the top-right of the page. Alternatively, you can connect with the VM through Remote Desktop using the above credentials. Please wait 1-2 minutes after the system boots completely to let the auto scripts run successfully that will execute Talend API Tester and Laravel-based web application automatically.

![Image for connecting remotely](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/2e8676dbcc93a6ac0b3f4a491be2ff06.png)  

Let's begin!

### Understanding APIs - A refresher

**What is an API & Why is it important?**

API stands for Application Programming Interface. It is a middleware that facilitates the communication of two software components utilising a set of protocols and definitions. In the API context, the term '**application**' refers to any software having specific functionality, and '**interface**' refers to the service contract between two apps that make communication possible via requests and responses. The API documentation contains all the information on how developers have structured those responses and requests. The significance of APIs to app development is in just a single sentence, i.e., **API is a building block for developing complex and enterprise-level applications**.

**Recent Data Breaches through APIs**

-   LinkedIn data breach: In June 2021, the data of over 700 million LinkedIn users were offered for sale on one of the dark web forums, which was scraped by exploiting the LinkedIn API. The hacker published a sample of 1 million records to confirm the legitimacy of the LinkedIn breach, containing full names of the users, email addresses, phone numbers, geolocation records, LinkedIn profile links, work experience information, and other social media account details. 
-   Twitter data breach: In June 2022, data of more than 5.4 Million [Twitter](https://privacy.twitter.com/en/blog/2022/an-issue-affecting-some-anonymous-accounts) users was released for sale on the dark web. Hackers conducted the breach by exploiting a zero-day in the Twitter API that showed Twitter's handle against a mobile number or email.
-   PIXLR data breach: In January 2021, PIXLR, an online photo editor app, suffered a data breach that impacted around 1.9 million users. All the data by the hackers was dumped on a dark web forum, which included usernames, email addresses, countries, and hashed passwords. 

Now that we understand the threat and the damage caused due to non-adherence to mitigation measures - let's discuss developing a secure API through **OWASP API Security Top 10 principles**.

Answer the questions below

```
An API, or Application Programming Interface, is a set of rules and protocols that allows different software programs to communicate with each other. It allows different systems to share data and functionality, and enables different software programs to interact with one another in a predefined way.

A simple example of an API is the one used to check the weather forecast. A weather forecasting website, for example, has a database of weather information that it makes available to other websites and applications through an API. This allows other websites and apps to access the weather information from the forecasting website and display it on their own platforms.

Another example, a developer could use an API from a social media platform such as Facebook to add a "Share on Facebook" button to their website. The API allows the developer to access the social media platform's functionality and integrate it into their website, so users can share the website's content on their Facebook page with a single click.

Another example, a developer could use an API from a payment processor like PayPal to add payment functionality to their website. The API allows the developer to access the payment processor's functionality and integrate it into their website, so users can make payments directly on the site.

In summary, an API is a set of rules and protocols that allows different software programs to communicate with each other, to share data and functionality and to interact with one another in a predefined way. It enables developers to access the functionality of other systems and integrate it into their own software.

```

In the LinkedIn breach (Jun 2021), how many million records (sample) were posted by a hacker on the dark web?

*1*

Is the API documentation a trivial item and not used after API development (yea/nay)?

*nay*

I understand the APIs and am ready to learn OWASP Top 10 Principles.


### Vulnerability I - Broken Object Level Authorisation (BOLA)

**How does it Happen?**

Generally, API endpoints are utilised for a common practice of retrieving and manipulating data through object identifiers. BOLA refers to Insecure Direct Object Reference (IDOR) - which creates a scenario where the user uses the **input functionality and gets access to the resources they are not authorised to access**. In an API, such controls are usually implemented through programming in Models (Model-View-Controller Architecture) at the code level.

Likely Impact

The absence of controls to prevent **unauthorised object access can lead to data leakage** and, in some cases, complete account takeover. User's or subscribers' data in the database plays a critical role in an organisation's brand reputation; if such data is leaked over the internet, that may result in substantial financial loss.

**Practical Example**  

-   Open the VM. You will find that the Chrome browser and Talend API Tester application are running automatically, which we will be using for debugging the API endpoints.
-   Bob is working as an API developer in `Company MHT` and developed an endpoint `/apirule1/users/{ID}` that will allow other applications or developers to request information by sending an employee ID. In the VM, you can request results by sending `GET` requests to `http://localhost:80/MHT/apirule1_v/user/1.`

![Image for Vulnerable Request BOLA](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/a6eec3c1ad211d50ca0ba20ba4f6898e.png)  

-   What is the issue with the above API call? The problem is that the endpoint is not validating any incoming API call to confirm whether the request is valid. It is not checking for any authorisation whether the person requesting the API call can ask for it or not.  
    
-   The solution for this problem is pretty simple; Bob will implement an authorisation mechanism through which he can identify who can make API calls to access employee ID information.  
    
-   The purpose is achieved through **access tokens or authorisation tokens** in the header. In the above example, Bob will add an authorisation token so that only headers with valid authorisation tokens can make a call to this endpoint.
-   In the VM, if you add a valid `Authorization-Token` and call `http://localhost:80/MHT/apirule1_s/user/1`, only then will you be able to get the correct results. Moreover, all API calls with an invalid token will show `403 Forbidden` an error message (as shown below).  
    

![Image for Secure Request BOLA](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/d7276bdd5c3d6fe7b6eea7731d261210.png)  

**Mitigation Measures**

-   An authorisation mechanism that relies on user policies and hierarchies should be adequately implemented. 
-   Strict access controls methods to check if the logged-in user is authorised to perform specific actions. 
-   Promote using completely random values (strong encryption and decryption mechanism) for nearly impossible-to-predict tokens.

Answer the questions below

```json
Model-View-Controller (MVC) is a design pattern that is commonly used in software development. It is a way of separating the code for an application into three distinct components: the model, the view, and the controller.

-   The Model represents the data and the business logic of the application. It is responsible for storing and manipulating the data.
    
-   The View is responsible for displaying the data to the user. It is the user interface of the application, such as the layout of the website or the layout of the mobile app.
    
-   The Controller is responsible for handling the communication between the Model and the View. It receives input from the user, updates the Model, and updates the View.
    

A simple example of how the MVC pattern can be applied is in a web-based application that allows users to view and edit a list of items. The Model would store the data for the items, the View would display the items to the user, and the Controller would handle the communication between the Model and the View, such as updating the data when an item is edited.

In summary, the Model-View-Controller (MVC) is a design pattern that separates the code for an application into three distinct components: the Model, the View, and the Controller. The Model represents the data and the business logic, the View is responsible for displaying the data to the user, and the Controller is responsible for handling the communication between the Model and the View. It makes the code more organized and easier to maintain.

using Talend API Tester

Method GET
http://127.0.0.1/MHT/apirule1_v/user/2

{
"id": 2,
"username": "Alice",
"name": "King",
"flag": "THM{838123}"
}

http://127.0.0.1/MHT/apirule1_v/user/3

{
"id": 3,
"username": "Bob",
"name": "Tester",
"flag": "THM{112312}"
}

http://127.0.0.1/MHT/apirule1_v/user/4

No Content

There are 3 users


```

Suppose the employee ID is an integer with incrementing value. Can you check through the vulnerable API endpoint the total number of employees in the company?

*3*

What is the flag associated with employee ID 2?

*THM{838123}*

What is the username of employee ID 3?

*Bob*


### Vulnerability II - Broken User Authentication (BUA)

**How does it happen?**

User authentication is the core aspect of developing any application containing sensitive data. Broken User Authentication (BUA) reflects a scenario where an API endpoint allows an attacker to access a database or acquire a higher privilege than the existing one. The primary reason behind BUA is either **invalid implementation of authentication** like using incorrect email/password queries etc., or the absence of security mechanisms like authorisation headers, tokens etc.

Consider a scenario in which an attacker acquires the capability to abuse an authentication API; it will eventually result in data leaks, deletion, modification, or even the complete account takeover by the attacker. Usually, hackers have created special scripts to profile, enumerate users on a system and identify authentication endpoints. A poorly implemented authentication system can lead any user to take on another user's identity. 

  

**Likely Impact** 

In broken user authentication, attackers can compromise the authenticated session or the authentication mechanism and easily access sensitive data. Malicious actors can pretend to be someone authorised and can conduct an undesired activity, including a complete account takeover. 

  

Practical Example  

-   Continue to use the Chrome browser and Talend API Tester for debugging in the VM.
-   Bob understands that authentication is critical and has been tasked to develop an API endpoint `apirule2/user/login_v` that will authenticate based on provided email and password.
-   The endpoint will return a token, which will be passed as an `Authorisation-Token` header (GET request) to `apirule2/user/details` to show details of the specific employee. Bob successfully developed the login endpoint; however, he only used email to validate the user from the `user table` and ignored the password field in the SQL query. An attacker only requires the victim's email address to get a valid token or account takeover.
-    In the VM, you can test this by sending a `POST` request to `http://localhost:80/MHT/apirule2/user/login_v` with email and password in the form parameters.

![Image for Vulnerable Scenario](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/dedcd5391fc513261706967f2c0e34cf.png)  

-   As we can see, the vulnerable endpoint received a token which can be forwarded to `/apirule2/user/details` to get detail of a user.
-   To fix this, we will update the login query logic and use both email and password for validation. The endpoint `/apirule2/user/login_s` is a valid endpoint, as shown below, that authorises the user based on password and email both.

![Image for Secure Scenario](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/44ee6cbacf493eb437c3711ae413965e.png)  

**Mitigation Measures** 

-   Ensure complex passwords with higher entropy for end users.
-   Do not expose sensitive credentials in **GET** or **POST** requests.
-   Enable strong JSON Web Tokens (JWT), authorisation headers etc.
-   Ensure the implementation of multifactor authentication (where possible), account lockout, or a captcha system to mitigate brute force against particular users. 
-   Ensure that passwords are not saved in plain text in the database to avoid further account takeover by the attacker. 

Answer the questions below

```json

JSON (JavaScript Object Notation) is a lightweight data-interchange format that is easy for humans to read and write and easy for machines to parse and generate. It is a text format that is completely language independent but uses conventions that are familiar to programmers of the C family of languages, including C, C++, C#, Java, JavaScript, Perl, Python, and many others. JSON is often used to transmit data between a server and a web application, as well as between different parts of a web application. JSON data is represented as key-value pairs, similar to a dictionary or hash table in other programming languages.

JSON Web Tokens (JWT) is a standard for creating and representing claims securely between two parties. JWT is a JSON object that is encoded as a string and it can be digitally signed, so the authenticity of the token can be verified. JWT is commonly used to authenticate users in web applications and APIs.

A JWT typically contains three parts: a header, a payload and a signature. The header contains information about the type of token and the algorithm used to generate the signature. The payload contains the claims, which are statements about an entity (typically, the user) and additional data. The signature is used to verify that the sender of the JWT is who it says it is and to ensure that the message wasn't changed along the way.

For example, when a user logs into a web application, the server will create a JWT that contains information about the user, such as their user ID and email address. The JWT is then sent to the client, typically as a part of the response. The client will then include this JWT in the header of subsequent requests to the server, to prove that the user is authenticated. The server will then use the JWT to identify the user and authorize their requests.

In short, JSON Web Tokens (JWT) is a standard for creating and representing claims securely between two parties, it's commonly used to authenticate users in web applications and APIs. It's a JSON object that is encoded as a string, it can be digitally signed, so the authenticity of the token can be verified and it contains three parts: a header, a payload, and a signature.

A JSON object is a collection of key-value pairs that are used to represent data in a structured way. It is a lightweight data interchange format that is easy for humans to read and write and easy for machines to parse and generate. JSON is a text format that is completely language-independent but uses conventions that are familiar to programmers of the C family of languages, including C, C++, C#, Java, JavaScript, Perl, Python, and many others.

The keys in a JSON object are strings and the values can be strings, numbers, booleans, arrays, or other JSON objects. JSON objects are delimited with curly braces {} and the key-value pairs are separated by a colon :.

A simple example of a JSON object is as follows:


{
    "name": "John Smith",
    "age": 35,
    "address": {
        "street": "123 Main St",
        "city": "Anytown",
        "state": "CA",
        "zip": "12345"
    },
    "phoneNumbers": [
        {
            "type": "home",
            "number": "555-555-1234"
        },
        {
            "type": "work",
            "number": "555-555-5678"
        }
    ]
}


This JSON object represents information about a person named John Smith, including his name, age, address and phone numbers. The address and phone numbers are represented as nested JSON objects. JSON objects are widely used in web development, in RESTful API, and in other services that require the exchange of data between different systems.

In summary, JSON object is a collection of key-value pairs that are used to represent data in a structured way, it's lightweight, easy for humans to read and write and easy for machines to parse and generate. JSON is widely used in web development, in RESTful API and in other services that require the exchange of data between different systems.

RESTful API (Representational State Transfer) is a type of web architecture and a set of constraints that are usually applied to web services. It is based on the principles of REST, which stands for Representational State Transfer, and it is an architectural style that defines a set of guidelines for building web services. RESTful APIs use HTTP requests to POST (create), PUT (update), GET (read), and DELETE (delete) data.

A RESTful API allows for communication between a web-based client and server and it is typically comprised of a base URL, an endpoint, and a set of HTTP methods. The base URL is the address of the server, the endpoint is the specific location on the server where the requested information is located, and the HTTP methods are used to retrieve or manipulate the information.

A simple example of a RESTful API is a weather forecasting service that allows a client to retrieve current weather information for a given location. The base URL for the service might be "[http://api.weather.com](http://api.weather.com/)", the endpoint might be "forecast" and the client could retrieve the current weather information by sending a GET request to "[http://api.weather.com/forecast?location=NewYork](http://api.weather.com/forecast?location=NewYork)"

In summary, RESTful API (Representational State Transfer) is a type of web architecture and a set of constraints that are usually applied to web services, it's based on the principles of REST, it uses HTTP requests to POST, PUT, GET and DELETE data and it's typically comprised of a base URL, an endpoint, and a set of HTTP methods. It allows for communication between a web-based client and server and it's widely used in web development.

Method POST

http://127.0.0.1/MHT/apirule2/user/login_v

add form parameters  

email Text admin@mht.com
password Text anything

Request Body

{
"success": "true",
"token": "0g*[v;~5lyx5L15J25sm$nm:cAWZv}"
}

Getting detail user with token

Method GET

http://127.0.0.1/MHT/apirule2/user/details

Header:

Authorization-Token : 0g*[v;~5lyx5L15J25sm$nm:cAWZv}

{
"id": 1,
"email": "admin@mht.com",
"name": "Bob",
"token": "0g*[v;~5lyx5L15J25sm$nm:cAWZv}",
"address": "H1 Turkey",
"city": "Mesport",
"country": "Turkey"
}

Method POST

http://127.0.0.1/MHT/apirule2/user/login_v

add form parameters  

email Text hr@mht.com
password Text witty

Request body

{
"success": "true",
"token": "cOC%Aonyis%H)mZ&uJkuI?_W#4&m>Y"
}

Method GET

http://127.0.0.1/MHT/apirule2/user/details

Header:

Authorization-Token : cOC%Aonyis%H)mZ&uJkuI?_W#4&m>Y

Request Body

{
"id": 2,
"email": "hr@mht.com",
"name": "Tara",
"token": "cOC%Aonyis%H)mZ&uJkuI?_W#4&m>Y",
"address": "H1 USA",
"city": "New York",
"country": "USA"
}

Method POST

http://127.0.0.1/MHT/apirule2/user/login_v

add form parameters  

email Text sales@mht.com
password Text witty

Request Body

{
"success": "true",
"token": "~jSkQD:u<Zdo!JDvX_9V[GrD%:JTtU"
}

Method GET

http://127.0.0.1/MHT/apirule2/user/details

Header:

Authorization-Token : ~jSkQD:u<Zdo!JDvX_9V[GrD%:JTtU

Request Body

{
"id": 3,
"email": "sales@mht.com",
"name": "Joyce",
"token": "~jSkQD:u<Zdo!JDvX_9V[GrD%:JTtU",
"address": "H1 China",
"city": "California",
"country": "China"
}


```


Can you find the token of hr@mht.com?

*cOC%Aonyis%H)mZ&uJkuI?_W#4&m>Y*

To which country does sales@mht.com belong?

Get a valid token from a vulnerable endpoint and pass it to /apirule2/user/details.

*China*

Is it a good practice to send a username and password in a GET request (yea/nay)?

*nay*


###  Vulnerability III - Excessive Data Exposure

**How does it happen?**

Excessive data exposure occurs when applications tend to **disclose more than desired information** to the user through an API response. The application developers tend to expose all object properties (considering the generic implementations) without considering their sensitivity level. They leave the filtration task to the front-end developer before it is displayed to the user. Consequently, an attacker can intercept the response through the API and quickly extract the desired confidential data. The runtime detection tools or the general security scanning tools can give an alert on this kind of vulnerability. However, it cannot differentiate between legitimate data that is supposed to be returned or sensitive data. 

  

**Likely Impact** 

A malicious actor can successfully sniff the traffic and easily access confidential data, including personal details, such as account numbers, phone numbers, access tokens and much more. Typically, APIs respond with sensitive tokens that can be later on used to make calls to other critical endpoints.

  

Practical Example  

-   Continue to use the Chrome browser and Talend API Tester for debugging in the VM.  
    
-   The company MHT launched a comment-based web portal that takes users' comments and stores them in the database and other information like location, device info, etc., to improve the user experience.  
    
-   Bob was tasked to develop an endpoint for showing users' comments on the company's main website. He developed an endpoint `apirule3/comment_v/{id}` that fetches all information available for a comment from the database. Bob assumed that the front-end developer would filter out information while showing it on the company's main website.

![Image for Vulnerable Scenario](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/6733955d8ce9471ce57924fb77a8caf6.png)  

-   What is the issue here? The API is sending more data than desired. Instead of relying on a front-end engineer to filter out data, only relevant data must be sent from the database.
-   Bob realising his mistake, updated the endpoint and created a valid endpoint `/apirule3/comment_s/{id}` that returns only the necessary information to the developer (as shown below).

![Image for Secure Scenario](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/23e044cc3efe648691292fac6f6e4acf.png)  

**Mitigation Measures** 

-   Never leave sensitive data filtration tasks to the front-end developer. 
-   Ensure time-to-time review of the response from the API to guarantee it returns only legitimate data and checks if it poses any security issue. 
-   Avoid using generic methods such as `to_string() and to_json()`. 
-   Use API endpoint testing through various test cases and verify through automated and manual tests if the API leaks additional data.

Answer the questions below

```json
Avoiding the use of generic methods such as `to_string()` and `to_json()` when working with APIs is a best practice for API security. This is because these methods can expose sensitive data that should not be accessible to the client.

`to_string()` and `to_json()` methods are often used to convert objects to a string or JSON representation, but they may include sensitive data such as passwords, private keys, or other confidential information. If these methods are used without proper filtering or scrubbing of sensitive data, this data could be exposed to the client.

The OWASP API Security Top 10 project recommends that sensitive data should be kept in a separate storage location and should only be accessed by authorized personnel. Additionally, the data should be encrypted when stored and decrypted when retrieved.

A URL (Uniform Resource Locator) is a string of characters that specifies the location of a resource on the internet. It is also commonly referred to as a web address. A URL typically consists of several parts including the protocol (such as HTTP or HTTPS), the domain name, and the path to the specific resource.

For example, the URL "[https://www.example.com/about](https://www.example.com/about)" specifies the location of a webpage on the "example.com" domain. The "https" at the beginning of the URL specifies that the webpage is accessed using the secure HTTPS protocol, the "www" indicates that the webpage is hosted on a server using the World Wide Web service, and the "/about" at the end of the URL specifies the specific resource being accessed, in this case, the "about" page of the website.

URLs are used in web browsers and in other internet-enabled applications to access web pages, images, videos, and other resources on the internet. They are also used in API calls to access specific resources in a RESTful API.

Method GET

Base URL

http://127.0.0.1/MHT/apirule3/comment_v/1

Request Body

{
"id": 1,
"postid": "1",
"deviceid": "Android 12.0",
"latitude": "45.5426274",
"longitude": "-122.7944111",
"commenttext": "This is my First Post",
"username": "baduser007"
}

http://127.0.0.1/MHT/apirule3/comment_v/2

Request Body

{
"id": 2,
"postid": "2",
"deviceid": "iOS15.411",
"latitude": "34.12312311",
"longitude": "54.123123123",
"commenttext": "This is another Post on the Blog.",
"username": "anotheruser007"
}

http://127.0.0.1/MHT/apirule3/comment_v/3

Request Body

{
"id": 3,
"postid": "3",
"deviceid": "Blackberry",
"latitude": "21.1251123",
"longitude": "43.12351212",
"commenttext": "This is my special post",
"username": "hacker#!"
}

It depends on the specific needs and requirements of your organization. Both network-level devices and programmatic controls through APIs can be used to control excessive data exposure.

Using network-level devices such as firewalls, intrusion detection systems, and load balancers can provide a physical barrier to protect sensitive data and control access to resources. These devices can be configured to block unauthorized access, limit the amount of data that can be transmitted, and encrypt sensitive data as it is transmitted over the network.

Managing data exposure programmatically through APIs can also be an effective way to control excessive data exposure. For example, you can use APIs to limit the amount of data that is returned in a single request, to filter sensitive data before it is returned to the client, and to encrypt sensitive data before it is transmitted.

Both methods have their own advantages and disadvantages, and the best approach depends on the specific needs and requirements of your organization. Network-level devices may provide a higher level of security, but they may also be more difficult to configure and manage. Programmatic controls through APIs may be easier to implement and manage, but they may not provide the same level of security as network-level devices.

It's recommended to use a combination of both network-level devices and programmatic controls through APIs, to have a multi-layered security approach, to provide a comprehensive protection for your sensitive data and resources.

A load balancer is a device or software that distributes incoming network traffic across multiple servers to ensure that no single server is overwhelmed with too much traffic. The load balancer directs incoming requests to the server that is best able to handle them, ensuring that the load is distributed evenly across all servers.

Load balancers are commonly used in web-based applications, where multiple servers are used to handle the high traffic volume. For example, a website that receives a large number of visitors would use a load balancer to distribute the incoming traffic across multiple web servers. This ensures that the website remains available and responsive, even during periods of high traffic.

A simple example of how a load balancer works is as follows:

-   A user visits a website that is hosted on a cluster of web servers.
-   The user's browser sends a request for the website to the load balancer.
-   The load balancer receives the request and forwards it to one of the web servers that has the least load.
-   The selected web server processes the request and sends the response back to the user's browser.
-   The load balancer can also monitor the health of the servers and redirect traffic away from servers that are down or not responding.

In summary, load balancer is a device or software that distributes incoming network traffic across multiple servers to ensure that no single server is overwhelmed with too much traffic, it directs incoming requests to the server that is best able to handle them, ensuring that the load is distributed evenly across all servers. It's commonly used in web-based applications, where multiple servers are used to handle the high traffic volume. It helps to ensure that the website remains available and responsive, even during periods of high traffic.

```


What is the device ID value for post-ID 2?

*iOS15.411*

What is the username value for post-ID 3?

*hacker#!*

Should we use network-level devices for controlling excessive data exposure instead of managing it through APIs (programmatically) - (yea/nay)?

*nay*

### Vulnerability IV - Lack of Resources & Rate Limiting

**How does it happen?**

Lack of resources and rate limiting means that **APIs do not enforce any restriction on** the frequency of clients' requested resources or the files' size, which badly affects the API server performance and leads to the DoS (Denial of Service) or non-availability of service. Consider a scenario where an API limit is not enforced, thus allowing a user (usually an intruder) to upload several GB files simultaneously or make any number of requests per second. Such API endpoints will result in excessive resource utilisation in network, storage, compute etc.

Nowadays, attackers are using such attacks to **ensure the non-availability of service for an organisation**, thus tarnishing the brand reputation through increased downtime. A simple example is non-compliance with the Captcha system on the login form, allowing anyone to make numerous queries to the database through a small script written in Python.

**Likely Impact** 

The attack primarily targets the **Availability** principles of security; however, it can tarnish the brand's reputation and cause financial loss.  

  

Practical Example

-   Continue to use the Chrome browser and Talend API Tester for debugging in the VM.  
    
-   The company MHT purchased an email marketing plan (20K emails per month) for sending marketing, password recovery emails etc. Bob realised that he had successfully developed a login API, but there must be a "Forgot Password" option that can be used to recover an account.  
    
-   He started building an endpoint `/apirule4/sendOTP_v` that will send a 4-digit numeric code to the user's email address. An authenticated user will use that One Time Password (OTP) to recover the account.

![Image for Vulnerable Scenario](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/e893ab4958ff54d17bedf53a0e22d772.png)  

-   What is the issue here? Bob has not enabled any rate limiting in the endpoint. A malicious actor can write a small script and brute force the endpoint, sending many emails in a few seconds and using the company's recently purchased email marketing plan (financial loss).
-   Finally, Bob came up with an intelligent solution `(/apirule4/sendOTP_s)` and enabled rate limiting such that the user has to wait 2 minutes to request an OTP token again.

![Image for Secure Scenario](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/a47bc005c405264850984ca7fb19b24b.gif)

**Mitigation Measures** 

-   Ensure using a captcha to avoid requests from automated scripts and bots.
-   Ensure implementation of a limit, i.e., how often a client can call an API within a specified time and notify instantly when the limit is exceeded. 
-   Ensure to define the maximum data size on all parameters and payloads, i.e., max string length and max number of array elements.

Answer the questions below

```json
OTP stands for One-Time Password, it's a password that is valid for only one login session or transaction, on a computer system or other digital device. OTPs provide an additional layer of security beyond a traditional username and password combination. They are often used in two-factor authentication (2FA) systems to protect against unauthorized access to an account.

An OTP is generated by an algorithm, it is typically a string of characters that is unique and cannot be predicted. It's sent to a user's email or phone number, or it can be generated using a hardware token or an app on a user's mobile device.

A simple example of an OTP use case is as follows:

-   A user attempts to log in to their online banking account.
-   The user enters their username and password as usual.
-   The bank's system then sends an OTP to the user's registered mobile number via SMS.
-   The user enters the OTP in the provided field on the login page.
-   The system verifies the OTP and grants access to the user's account if the OTP is valid.

In summary, OTP stands for One-Time Password, it's a password that is valid for only one login session or transaction, it provides an additional layer of security beyond a traditional username and password combination. It's often used in two-factor authentication (2FA) systems to protect against unauthorized access to an account and it's generated by an algorithm, typically a string of characters that is unique and cannot be predicted. It's sent to a user's email or phone number, or it can be generated using a hardware token or an app on a user's mobile device.

Method POST

Base URL

http://127.0.0.1/MHT/apirule4/sendOTP_v

Add form parameter:  email Text test@gmail.com

Request Body

{
"success": "true",
"msg": "4 Digit OTP sent on Email."
}

Base URL

http://127.0.0.1/MHT/apirule4/sendOTP_s

Add form parameter:  email Text hr@mht.com

Request Body

{
"success": "false",
"msg": "Invalid Email"
}

Response 200 OK

Base URL

http://127.0.0.1/MHT/apirule4/sendOTP_s

Add form parameter:  email Text sales@mht.com

Request Body

{
"success": "false",
"msg": "Invalid Email"
}


```


Can rate limiting be carried out at the network level through firewall etc. (yea/nay)?

*yea*

What is the HTTP response code when you send a POST request to **/apirule4/sendOTP_s** using the email address hr@mht.com?

*200*

What is the "msg key" value after an HTTP POST request to **/apirule4/sendOTP_s** using the email address sale@mht.com?  

*Invalid Email*


### Vulnerability V - Broken Function Level Authorisation

**How does it happen?**

Broken Function Level Authorisation reflects a scenario where a low privileged user (e.g., sales) bypasses system checks and gets access to **confidential data by impersonating a high privileged user (Admin)**. Consider a scenario of complex access control policies with various hierarchies, roles, and groups and a vague separation between regular and administrative functions leading to severe authorisation flaws. By taking advantage of these issues, the intruders can easily access the unauthorised resources of another user or, most dangerously – the administrative functions.   

Broken Function Level Authorisation reflects IDOR permission, where a user, most probably an intruder, can perform administrative-level tasks. APIs with complex user roles and permissions that can span the hierarchy are more prone to this attack. 

  

**Likely Impact** 

The attack primarily targets the authorisation and non-repudiation principles of security. Broken Functional Level Authorisation can lead an intruder to impersonate an authorised user and let the malicious actor get administrative rights to perform sensitive tasks. 

  

Practical Example  

-   Continue to use the Chrome browser and Talend API Tester for debugging in the VM.  
    
-   Bob has been assigned another task to develop an admin dashboard for company executives so that they can view all employee's data and perform specific tasks.  
    
-   Bob developed an endpoint `/apirule5/users_v` to fetch data of all employees from the database. To add protection, he added another layer to security by adding a special header `isAdmin` in each request. The API only fetches employee information from the database if `isAdmin=1` and `Authorization-Token` are correct. The authorisation token for HR user Alice is `YWxpY2U6dGVzdCFAISM6Nzg5Nzg=`.

![Image for vulnerable scenario](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/4fb8a31217d2d1af51cad8cbdc318754.png)  

-   We can see that Alice is a non-admin user (HR) but can see all employee's data by setting custom requests to the endpoint with `isAdmin value = 1`. 
-   The issue can be resolved programmatically by implementing correct authorisation rules and checking the functional roles of each user in the database during the query. Bob implemented another endpoint  `/apirule5/users_s` that validates each user's role and only shows employees' data if the role is Admin.

![Image for Secure Scenario](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/5a708a5bc9daad5002e4824a0eda5511.gif)  

  

**Mitigation Measures** 

-   Ensure proper design and testing of all authorisation systems and deny all access by default. 
-   Ensure that the operations are only allowed to the users belonging to the authorised group. 
-   Make sure to review API endpoints against flaws regarding functional level authorisation and keep in mind the apps and group hierarchy's business logic. 

Answer the questions below

```json

Non-repudiation is a principle of security that refers to the ability to prove that a specific individual or system was responsible for a particular action or event. It is used to ensure that parties cannot deny having performed an action, and it is a critical aspect of many security systems.

There are two types of non-repudiation: proof of origin and proof of receipt. Proof of origin ensures that the sender of a message cannot deny having sent it, while proof of receipt ensures that the recipient cannot deny having received it.

An example of non-repudiation in practice is the use of digital signatures in email communications. A digital signature is a mathematical technique used to verify the authenticity of a digital message or document. A sender can use a digital signature to prove that they were the originator of the message and that it has not been tampered with. The recipient can use the digital signature to prove that the message was indeed sent by the sender.

In summary, non-repudiation is a principle of security that refers to the ability to prove that a specific individual or system was responsible for a particular action or event, it is used to ensure that parties cannot deny having performed an action, and it's a critical aspect of many security systems. There are two types of non-repudiation: proof of origin and proof of receipt. An example of non-repudiation in practice is the use of digital signatures in email communications.


Method Get

Base URL
http://127.0.0.1/MHT/apirule5/users_v

Headers:

Authorization-Token : YWxpY2U6dGVzdCFAISM6Nzg5Nzg=    (alice:test!@!#:78978)

isAdmin : 1

Request Body

[
{
"id": 1,
"username": "admin",
"name": "Admin User",
"address": "THM{3432$@#2!}",
"mobileno": "8080808080",
"role": "admin"
},
{
"id": 2,
"username": "alice",
"name": "Alice",
"address": "H3! USA",
"mobileno": "+1235322323",
"role": "hr"
}
]

Method Get

Base URL
http://127.0.0.1/MHT/apirule5/users_s

Headers:

Authorization-Token : YWxpY2U6dGVzdCFAISM6Nzg5Nzg=    (alice:test!@!#:78978)

isAdmin : 1

Request Body

{
"success": "false",
"cause": "You are not an Admin."
}

Response 

403 Forbidden


```

What is the mobile number for the username Alice?

*+1235322323*

Is it a good practice to send isAdmin value through the hidden fields in form requests - yea/nay?

*nay*

What is the address flag of username admin?

*THM{3432$@#2!}*

![[Pasted image 20230123135918.png]]

### Conclusion

That's all for this room. In this room, we have studied the basic API development principles for Authorisation and Authentication and how excessive data exposure can lead to a complete account takeover.

Now, we will see you in Part 2 (coming soon) of this room, where we will go through the remaining five principles of OWASP API security.

Answer the questions below

I have completed the room (Part 1).


[[Secret Recipe]]