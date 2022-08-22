---
Learn how to use Intruder to automate requests in Burp Suite
---

### Room Outline 

In previous rooms of this module, we have covered Burp Suite's Proxy and Repeater functionality. If you have not completed these rooms and are not familiar with these aspects of the framework, then you are advised to complete at least the Burp Basics room before proceeding.

This room will cover the third of Burp Suite's primary modules: Intruder.

Intruder allows us to automate requests, which is very useful when fuzzing or bruteforcing. We will be looking at how to use Intruder to perform both of these functions in conjunction with the other tools we have already covered.

Let's begin!

### What is Intruder? 

Intruder is Burp Suite's in-built fuzzing tool. It allows us to take a request (usually captured in the Proxy before being passed into Intruder) and use it as a template to send many more requests with slightly altered values automatically. For example, by capturing a request containing a login attempt, we could then configure Intruder to swap out the username and password fields for values from a wordlist, effectively allowing us to bruteforce the login form. Similarly, we could pass in a fuzzing[1] wordlist and use Intruder to fuzz for subdirectories, endpoints, or virtual hosts. This functionality is very similar to that provided by command-line tools such as Wfuzz or Ffuf.

In short, as a method for automating requests, Intruder is extremely powerful -- there is just one problem: to access the full speed of Intruder, we need Burp Professional. We can still use Intruder with Burp Community, but it is heavily rate-limited. This speed restriction means that many hackers choose to use other tools for fuzzing and bruteforcing.

Limitations aside, Intruder is still very useful, so it is well worth learning to use it properly.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d9e176315f8850e719252ed/room-content/4d8d5926216e90c046d9d8ee1025bb6f.png)

The first view we get is a relatively sparse interface that allows us to choose our target. Assuming that we sent a request in from the Proxy (by using Ctrl + I or right-clicking and selecting "Send to Intruder"), this should already be populated for us.

There are four other Intruder sub-tabs:

    Positions allows us to select an Attack Type (we will cover these in an upcoming task), as well as configure where in the request template we wish to insert our payloads.
    Payloads allows us to select values to insert into each of the positions we defined in the previous sub-tab. For example, we may choose to load items in from a wordlist to serve as payloads. How these get inserted into the template depends on the attack type we chose in the Positions tab. There are many payload types to choose from (anything from a simple wordlist to regexes based on responses from the server). The Payloads sub-tab also allows us to alter Intruder's behaviour with regards to payloads; for example, we can define pre-processing rules to apply to each payload (e.g. add a prefix or suffix, match and replace, or skip if the payload matches a defined regex).
    Resource Pool is not particularly useful to us in Burp Community. It allows us to divide our resources between tasks. Burp Pro would allow us to run various types of automated tasks in the background, which is where we may wish to manually allocate our available memory and processing power between these automated tasks and Intruder. Without access to these automated tasks, there is little point in using this, so we won't devote much time to it.
    As with most of the other Burp tools, Intruder allows us to configure attack behaviour in the Options sub-tab. The settings here apply primarily to how Burp handles results and how Burp handles the attack itself. For example, we can choose to flag requests that contain specified pieces of text or define how Burp responds to redirect (3xx) responses.

We will take a closer look at some of these sub-tabs in the upcoming tasks. For now, just get to know where things are in the interface.

1. Fuzzing is when we take a set of data and apply it to a parameter to test functionality or to see if something exists. For example, we may choose to "fuzz for endpoints" in a web application; this would involve taking each word in a wordlist and adding it to the end of a request to see how the web server responds (e.g. http://MACHINE_IP/WORD_GOES_HERE).


Which section of the Options sub-tab allows you to control what information will be captured in the Intruder results?
*attack results*

In which Intruder sub-tab can we define the "Attack type" for our planned attack?
*Positions*

### Positions 

When we are looking to perform an attack with Intruder, the first thing we need to do is look at positions. Positions tell Intruder where to insert payloads (which we will look at in upcoming tasks).

Let's switch over to the Positions sub-tab:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d9e176315f8850e719252ed/room-content/c286bd89e92aab284460ab9302b3b18c.png)

Notice that Burp will attempt to determine the most likely places we may wish to insert a payload automatically -- these are highlighted in green and surrounded by silcrows (§).

On the right-hand side of the interface, we have the buttons labelled "Add §", "Clear §", and "Auto §":

    Add lets us define new positions by highlighting them in the editor and clicking the button.
    Clear removes all defined positions, leaving us with a blank canvas to define our own.
    Auto attempts to select the most likely positions automatically; this is useful if we cleared the default positions and want them back.

Here is a GIF demonstrating the process of adding, clearing, and automatically reselecting positions:

GIF showing how to select positions

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d9e176315f8850e719252ed/room-content/35caa3d4e70aae2084966b1928c3db5f.gif)


Have a play around with the positions selector. Make sure that you are comfortable with the processes of adding, clearing, and automatically selecting positions.
*No answer needed*

Clear all selected positions. *No answer needed*



Select the value of the "Host" header and add it as a position.

Your editor should look something like this:

![](https://assets.muirlandoracle.co.uk/thm/modules/burp/fed2938c4055.png)

Clear this position, then click the "Auto" button again to reselect the default positions.

Your editor should be back looking like it did in the first screenshot of this task.
*No answer needed*

###  Introduction 



Let's switch to the "Positions" sub-tab and look in the "Attack types" drop-down menu.

There are four attack types available:

    Sniper
    Battering ram
    Pitchfork
    Cluster bomb

We will look at each of these in turn.

###  Sniper 

Sniper is the first and most common attack type.

When conducting a sniper attack, we provide one set of payloads. For example, this could be a single file containing a wordlist or a range of numbers. From here on out, we will refer to a list of items to be slotted into requests using the Burp Suite terminology of a "Payload Set". Intruder will take each payload in a payload set and put it into each defined position in turn.

Take a look at our example template from before:

Example Positions

POST /support/login/ HTTP/1.1
Host: MACHINE_IP
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 37
Origin: http://MACHINE_IP
Connection: close
Referer: http://MACHINE_IP/support/login/
Upgrade-Insecure-Requests: 1

username=§pentester§&password=§Expl01ted§              


There are two positions defined here, targeting the username and password body parameters.

In a sniper attack, Intruder will take each position and substitute each payload into it in turn.

For example, let's assume we have a wordlist with three words in it: burp, suite, and intruder.

With the two positions that we have above, Intruder would use these words to make six requests:

Request Number
	Request Body
1
	username=burp&password=Expl01ted
2
	username=suite&password=Expl01ted
3
	username=intruder&password=Expl01ted
4
	username=pentester&password=burp
5
	username=pentester&password=suite
6
	username=pentester&password=intruder

Notice how Intruder starts with the first position (username) and tries each of our payloads, then moves to the second position and tries the same payloads again. We can calculate the number of requests that Intruder Sniper will make as requests = numberOfWords * numberOfPositions.

This quality makes Sniper very good for single-position attacks (e.g. a password bruteforce if we know the username or fuzzing for API endpoints).

If you were using Sniper to fuzz three parameters in a request, with a wordlist containing 100 words, how many requests would Burp Suite need to send to complete the attack? *300*

How many sets of payloads will Sniper accept for conducting an attack? *1*

Sniper is good for attacks where we are only attacking a single parameter, aye or nay?*aye*

###  Battering Ram 

Next, let's take a look at the Battering Ram Attack type.

Like Sniper, Battering ram takes one set of payloads (e.g. one wordlist). Unlike Sniper, the Battering ram puts the same payload in every position rather than in each position in turn.

Let's use the same wordlist and example request as we did in the last task to illustrate this.
Example Positions

POST /support/login/ HTTP/1.1
Host: MACHINE_IP
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 37
Origin: http://MACHINE_IP
Connection: close
Referer: http://MACHINE_IP/support/login/
Upgrade-Insecure-Requests: 1

username=§pentester§&password=§Expl01ted§              


If we use Battering ram to attack this, Intruder will take each payload and substitute it into every position at once.

With the two positions that we have above, Intruder would use the three words from before (burp, suite, and intruder) to make three requests:
Request Number
	Request Body
1
	username=burp&password=burp
2
	username=suite&password=suite
3
	username=intruder&password=intruder

As can be seen in the table, each item in our list of payloads gets put into every position for each request. True to the name, Battering ram just throws payloads at the target to see what sticks.



As a hypothetical question: you need to perform a Battering Ram Intruder attack on the example request above.

If you have a wordlist with two words in it (admin and Guest) and the positions in the request template look like this:
username=§pentester§&password=§Expl01ted§

What would the body parameters of the first request that Burp Suite sends be?

*username=admin&password=admin*

### Pitchfork 



Two down, two more to go!

After Sniper, Pitchfork is the attack type you are most likely to use. It may help to think of Pitchfork as being like having numerous Snipers running simultaneously. Where Sniper uses one payload set (which it uses on every position simultaneously), Pitchfork uses one payload set per position (up to a maximum of 20) and iterates through them all at once.

This type of attack can take a little time to get your head around, so let's use our bruteforce example from before, but this time we need two wordlists:

    Our first wordlist will be usernames. It contains three entries: joel, harriet, alex.
    Let's say that Joel, Harriet, and Alex have had their passwords leaked: we know that Joel's password is J03l, Harriet's password is Emma1815, and Alex's password is Sk1ll.

We can use these two lists to perform a pitchfork attack on the login form from before. The process for carrying out this attack will not be covered in this task, but you will get plenty of opportunities to perform attacks like this later!

When using Intruder in pitchfork mode, the requests made would look something like this:
Request Number
	Request Body
1
	username=joel&password=J03l
2
	username=harriet&password=Emma1815
3
	username=alex&password=Sk1ll

See how Pitchfork takes the first item from each list and puts them into the request, one per position? It then repeats this for the next request: taking the second item from each list and substituting it into the template. Intruder will keep doing this until one (or all) of the lists run out. Ideally, our payload sets should be identical lengths when working in Pitchfork, as Intruder will stop testing as soon as one of the lists is complete. For example, if we have two lists, one with 100 lines and one with 90 lines, Intruder will only make 90 requests, and the final ten items in the first list will not get tested.

This attack type is exceptionally useful when forming things like credential stuffing attacks (we have just encountered a small-scale version of this). We will be looking more into these later in the room.


What is the maximum number of payload sets we can load into Intruder in Pitchfork mode? *20*

### Cluster Bomb 

Finally, we come to the last of Intruder's attack types: the Cluster Bomb.

Like Pitchfork, Cluster bomb allows us to choose multiple payload sets: one per position, up to a maximum of 20; however, whilst Pitchfork iterates through each payload set simultaneously, Cluster bomb iterates through each payload set individually, making sure that every possible combination of payloads is tested.

Again, the best way to visualise this is with an example.

Let's use the same wordlists as before:

    Usernames: joel, harriet, alex.
    Passwords: J03l, Emma1815, Sk1ll.

But, this time, let's assume that we don't know which password belongs to which user. We have three users and three passwords, but we don't know how to match them up. In this case, we would use a cluster bomb attack; this will try every combination of values. The request table for our username and password positions looks something like this:
Request Number
	Request Body
1
	username=joel&password=J03l
2
	username=harriet&password=J03l
3
	username=alex&password=J03l
4
	username=joel&password=Emma1815
5
	username=harriet&password=Emma1815
6
	username=alex&password=Emma1815
7
	username=joel&password=Sk1ll
8
	username=harriet&password=Sk1ll
9
	username=alex&password=Sk1ll

Cluster Bomb will iterate through every combination of the provided payload sets to ensure that every possibility has been tested. This attack-type can create a huge amount of traffic (equal to the number of lines in each payload set multiplied together), so be careful! Equally, when using Burp Community and its Intruder rate-limiting, be aware that a Cluster Bomb attack with any moderately sized payload set will take an incredibly long time.

That said, this is another extremely useful attack type for any kind of credential bruteforcing where a username isn't known.



We have three payload sets. The first set contains 100 lines; the second contains 2 lines; and the third contains 30 lines.

How many requests will Intruder make using these payload sets in a Cluster Bomb attack? *6000* (Multiply the number of lines in each payload set together. See how very small numbers can add up fast...?)

###  Payloads 

That was a lot of theory, so kudos for reading through it! There will be plenty of practicals in the upcoming tasks, but first, it is imperative that we understand how to create, assign, and use payloads.

Switch over to the "Payloads" sub-tab; this is split into four sections:

    The Payload Sets section allows us to choose which position we want to configure a set for as well as what type of payload we would like to use.
        When we use an attack type that only allows for a single payload set (i.e. Sniper or Battering Ram), the dropdown menu for "Payload Set" will only have one option, regardless of how many positions we have defined.
        If we are using one of the attack types that use multiple payload sets (i.e. Pitchfork or Cluster Bomb), then there will be one item in the dropdown for each position.
        Note: Multiple positions should be read from top to bottom, then left to right when being assigned numbers in the "Payload set" dropdown. For example, with two positions (username=§pentester§&password=§Expl01ted§), the first item in the payload set dropdown would refer to the username field, and the second would refer to the password field.
    The second dropdown in this section allows us to select a "payload type". By default, this is a "Simple list" -- which, as the name suggests, lets us load in a wordlist to use. There are many other payload types available -- some common ones include: Recursive Grep, Numbers, and Username generator. It is well worth perusing this list to get a feel for the wide range of options available.

    Payload Options differ depending on the payload type we select for the current payload set. For example, a "Simple List" payload type will give us a box to add and remove payloads to and from the set:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d9e176315f8850e719252ed/room-content/aa7a5c278455b7f3066410b941354448.png)

We can do this manually using the "Add" text box, paste lines in with "Paste", or "Load..." from a file. The "Remove" button removes the currently selected line only. The "Clear" button clears the entire list. Be warned: loading extremely large lists in here can cause Burp to crash!
By contrast, the options for a Numbers payload type allows us to change options such as the range of numbers used and the base that we are working with.

    Payload Processing allows us to define rules to be applied to each payload in the set before being sent to the target. For example, we could capitalise every word or skip the payload if it matches a regex. You may not use this section particularly regularly, but you will definitely appreciate it when you do need it!

    Finally, we have the Payload Encoding section. This section allows us to override the default URL encoding options that are applied automatically to allow for the safe transmission of our payload. Sometimes it can be beneficial to not URL encode these standard "unsafe" characters, which is where this section comes in. We can either adjust the list of characters to be encoded or outright uncheck the "URL-encode these characters" checkbox.

When combined, these sections allow us to perfectly tailor our payload sets for any attack we wish to carry out.


Which payload type lets us load a list of words into a payload set? *Simple list*

Which Payload Processing rule could we use to add characters at the end of each payload in the set? *Add suffix*

### Example 

We have covered a lot of theory in the last section -- it is now past time that we put it all into practice.

Let's try to gain access to the support portal: /support/login.

This is a fairly typical login portal. Looking at the source code for the form, we can see that there are no protective measures in place:


Support Login Form Source Code


```
<form method="POST">
    <div class="form-floating mb-3">
        <input class="form-control" type="text" name=username  placeholder="Username" required>
        <label for="username">Username</label>
    </div>
    <div class="form-floating mb-3">
        <input class="form-control" type="password" name=password  placeholder="Password" required>
        <label for="password">Password</label>
    </div>
    <div class="d-grid"><button class="btn btn-primary btn-lg" type="submit">Login!</button></div>
</form>
```        

This lack of protective measures means that we could very easily attack this form using a cluster bomb attack for a bruteforce.

But, there is a much easier option available. Attached to this task (and available using wget http://10.10.75.215:9999/Credentials/BastionHostingCreds.zip for the sake of anyone using the AttackBox) is a list of leaked credentials for Bastion Hosting employees.

Bastion Hosting was hit with a cyber attack three months ago. The attack resulted in all of their employee usernames, emails, and plaintext passwords being leaked. Employees were told to change their passwords immediately; however, maybe one or two of them didn't listen...

As we have a list of known usernames, each associated with a password, we can avoid a straight bruteforce and instead use a credential stuffing attack. This will (blessedly) be much quicker when using the rate-limited version of Intruder.


Download and unzip the BastionHostingCreds.zip zipfile. It doesn't matter whether you do this by clicking the download link in the task or by using the files hosted on your deployed machine. *No answer needed*



The zip file should contain four wordlists:

    emails.txt
    usernames.txt
    passwords.txt
    combined.txt

These contain lists of leaked emails, usernames, and passwords, respectively. The last list contains the combined email and password lists.

We will be using the usernames.txt and passwords.txt lists. *No answer needed*

Navigate to http://10.10.75.215/support/login in your browser.

Activate the Burp Proxy and try to log in, catching the request in your proxy.

Note: It doesn't matter what credentials you use here -- we just need the request.
*No answer needed*



Send the request from the Proxy to Intruder by right-clicking and selecting "Send to Intruder" or by using the Ctrl + I shortcut.  *No answer needed*



Looking in the "Positions" sub-tab, we should see that the auto-selection should have chosen the username and password parameters, so we don't need to do anything else in terms of defining our positions. If you have already visited certain other pages on the site, then you may have a session cookie. If so, this will also be selected -- make sure to clear your positions and select only the username and passwords fields if this happens to you.

We also need the Attack type to be "Pitchfork":
![](https://assets.muirlandoracle.co.uk/thm/modules/burp/94051c86063c.png)



Let's switch over to the "Payloads" sub-tab. We should find that we have two payload sets available:

![](https://assets.muirlandoracle.co.uk/thm/modules/burp/7e24f5d27e84.png)

Although these aren't named, we know from the fact that the username field is to the left of the password field that the first position will be for usernames, and the second position will be for passwords.

We can leave both of these as the "Simple list" payload type.

In the first payload set, go to "Payload Options", choose "Load", then select our list of usernames.

Do the same thing for the second payload set and the list of passwords.

This process can be seen here:

![](https://assets.muirlandoracle.co.uk/thm/modules/burp/settingPayloads.gif)

*No answer needed*


We have done all we need to do for this very simple attack, so go ahead and click the "Start Attack" button. A warning about the rate-limiting in Burp Community will appear. Click "Ok" and start the attack!

Note: This will take a few minutes to complete in Burp Community -- hence the relatively small lists in use
*No answer needed*


Once the attack has completed, we will be presented with a new window giving us the results -- but we have a new problem. Burp sent 100 requests: how are we supposed to know which one(s), if any, are valid?

The most common solution to this problem is to use the status code of the response to differentiate between successful or unsuccessful login attempts; this only works if there is a difference in the status codes, however. Ideally, successful login requests would give us a 200 response code, and failed login requests would provide us with a 401; however, in many cases (this one included), we are just given a 302 redirect for all requests instead.

That solution is out.

The next most common solution is to use the Length of the responses to identify differences between them. For example, a successful login attempt may have a response with 400 bytes in it, whereas an unsuccessful login attempt may yield a response with 600 bytes in it.

We can sort by byte length by clicking on the header for the "Length" column:
![](https://assets.muirlandoracle.co.uk/thm/modules/burp/2ed757b27276.png)
Once we have sorted our results, one request should stand out as being different!
*No answer needed*

As you may have guessed, the request with the shorter response length was made with the valid credentials -- a fact we can confirm by attempting to log in with the credentials used in the successful request.

Note: These are selected randomly from the list at machine boot and so will be different every time you deploy a new instance of the machine.

Well done, you have successfully bruteforced the support login page with a credential stuffing attack! *No answer needed*

![[Pasted image 20220822164002.png]]

*found m.rivera:letmein1*

### Challenge 

In the previous task, we gained access to the support system. Now it's time to see what we can do with it!

The home interface shows us a table of tickets -- if we click on any of the rows in the table, we get redirected to a page where we can view the full ticket. Looking at the URL, we can see that these pages are numbered, e.g.:
http://10.10.75.215/support/ticket/NUMBER

So, what does this mean?

The numbering means that we know the tickets aren't being identified by hard-to-guess IDs -- they are simply assigned an integer identifier.

What happens if we use intruder to fuzz the/support/ticket/NUMBER  endpoint? One of two things will happen:

    The endpoint has been set up correctly only to allow us to view tickets that are assigned to our current user, or
    The endpoint has not had the correct access controls set, which would allow us to read all of the existing tickets! If this is the case, then a vulnerability called an IDOR (Insecure Direct Object References) is present.

Let's try fuzzing this endpoint!


Which attack type is best suited for this task? *sniper*


Configure an appropriate position and payload (the tickets are stored at values between 1 and 100), then start the attack.

You should find that at least five tickets will be returned with a status code of 200, indicating that they exist. *No answer needed*

Either using the Response tab in the Attack Results window or by looking at each successful (i.e. 200 code) request manually in your browser, find the ticket that contains the flag.
![[Pasted image 20220822165335.png]]
What is the flag? (ticket 83) *THM{MTMxNTg5NTUzMWM0OWRlYzUzMDVjMzJl}*

### CSRF Token Bypass 

Let's crank this up a notch with an extra mile exercise. This challenge will be a slightly harder variant of the credential stuffing attack that we carried out a few tasks ago -- only this time there will be measures in place to make bruteforcing harder. If you are comfortable using Burp Macros, please feel free to do this challenge blind; otherwise, read on!
Let's start by catching a request to http://10.10.75.215/admin/login/ and reviewing the response:

Example Positions

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 20 Aug 2021 22:31:16 GMT
Content-Type: text/html; charset=utf-8
Connection: close
Set-Cookie: session=eyJ0b2tlbklEIjoiMzUyNTQ5ZjgxZDRhOTM5YjVlMTNlMjIzNmI0ZDlkOGEifQ.YSA-mQ.ZaKKsUnNsIb47sjlyux_LN8Qst0; HttpOnly; Path=/
Vary: Cookie
Front-End-Https: on
Content-Length: 3922
---

```
<form method="POST">
    <div class="form-floating mb-3">
        <input class="form-control" type="text" name=username  placeholder="Username" required>
        <label for="username">Username</label>
    </div>
    <div class="form-floating mb-3">
        <input class="form-control" type="password" name=password  placeholder="Password" required>
        <label for="password">Password</label>
    </div>
    <input type="hidden" name="loginToken" value="84c6358bbf1bd8000b6b63ab1bd77c5e">
    <div class="d-grid"><button class="btn btn-warning btn-lg" type="submit">Login!</button></div>
</form>
```


We have the same username and password fields as before, but now there is also a session cookie set in the response, as well as a CSRF (Cross-Site Request Forgery) token included in the form as a hidden field. If we refresh the page, we should see that both of these change with each request: this means that we will need to extract valid values for both every time we make a request.

In other words, every time we attempt to log in, we will need unique values for the session cookie and loginToken hidden form input.

Enter: Macros.
In many cases, we could do this kind of thing using a payload type called "Recursive Grep", which would be a lot easier than what we're going to have to do here. Unfortunately, because the web app redirects us back to the login page rather than simply showing us both of our target parameters, we will need to do this the hard way.  Specifically, we will have to define a "macro" (i.e. a short set of repeated actions) to be executed before each request. This will grab a unique session cookie and matching login token, then substitute them into each request of our attack.

Before we get into the tricky stuff, let's deal with what we know.

Navigate to  http://10.10.75.215/admin/login/.

Activate the Burp Proxy and attempt to log in. Capture the request and send it to Intruder. *No answer needed*



Configure the positions the same way as we did for bruteforcing the support login:

    Set the attack type to be "Pitchfork".
    Clear all of the predefined positions and select only the username and password form fields. The other two positions will be handled by our macro.

![](https://assets.muirlandoracle.co.uk/thm/modules/burp/b9e8aefea3ce.png)

*No answer needed*



Now switch over to the Payloads sub-tab and load in the same username and password wordlists we used for the support login attack.

Up until this point, we have configured Intruder in almost the same way as our previous credential stuffing attack; this is where things start to get more complicated.

*No answer needed*

With the username and password parameters handled, we now need to find a way to grab the ever-changing loginToken and session cookie. Unfortunately, Recursive Grep won't work here due to the redirect response, so we can't do this entirely within Intruder -- we will need to build a macro.

Macros allow us to perform the same set of actions repeatedly. In this case, we simply want to send a GET request to /admin/login/.

Fortunately, setting this up is a very easy process.

    Switch over to the "Project Options" tab, then the "Sessions" sub-tab.
    Scroll down to the bottom of the sub-tab to the "Macros" section and click the "Add" button.
    The menu that appears will show us our request history. If there isn't a GET request to http://10.10.75.215/admin/login/ in the list already, navigate to this location in your browser and you should see a suitable request appear in the list.
    With the request selected, click Ok.
    Finally, give the macro a suitable name, then click "Ok" again to finish the process.

There are a lot of steps here, comparatively speaking, so the following GIF shows the entire process:

![](https://assets.muirlandoracle.co.uk/thm/modules/burp/creatingMacro.gif)



Now that we have a macro defined, we need to set Session Handling rules that define how the macro should be used.

    Still in the "Sessions" sub-tab of Project Options, scroll up to the "Session Handling Rules" section and choose to "Add" a new rule.
    A new window will pop up with two tabs in it: "Details" and "Scope". We are in the Details tab by default.

![](https://assets.muirlandoracle.co.uk/thm/modules/burp/38ceffeebf99.png)

Fill in an appropriate description, then switch over to the Scope tab.
In the "Tools Scope" section, deselect every checkbox other than Intruder -- we do not need this rule to apply anywhere else.
In the "URL Scope" section, choose "Use suite scope"; this will set the macro to only operate on sites that have been added to the global scope (as was discussed in Burp Basics). If you have not set a global scope, keep the "Use custom scope" option as default and add http://10.10.75.215/ to the scope in this section.

![](https://assets.muirlandoracle.co.uk/thm/modules/burp/4d3fc6d19a12.png)

Again, here is a GIF showing these steps of the process:

![](https://assets.muirlandoracle.co.uk/thm/modules/burp/configuringSessionHandlerP1.gif)

*No answer needed*



Now we need to switch back over to the Details tab and look at the "Rule Actions" section.

    Click the "Add" button -- this will cause a dropdown menu to appear with a list of actions we can add.
    Select "Run a Macro" from this list.
    In the new window that appears, select the macro we created earlier.

As it stands, this macro will now overwrite all of the parameters in our Intruder requests before we send them; this is great, as it means that we will be getting the loginTokens and session cookies added straight into our requests. That said, we should restrict which parameters and cookies are being updated before we start our attack:

    Select "Update only the following parameters", then click the "Edit" button next to the input box below the radio button.
    In the "Enter a new item" text field, type "loginToken". Press "Add", then "Close".
    Select "Update only the following cookies", then click the relevant "Edit" button.
    Enter "session" in the "Enter a new item" text field, press "Add", then "Close".
    Finally, press "Ok" to confirm our action.

The following GIF demonstrates this final stage of the process:

![](https://assets.muirlandoracle.co.uk/thm/modules/burp/addingRuleAction.gif)

*No answer needed*


Click "Ok", and we're done! *No answer needed*

Phew, that was a long process!

You should now have a macro defined that will substitute in the CSRF token and session cookie. All that's left to do is switch back to Intruder and start the attack!

Note: You should be getting 302 status code responses for every request in this attack. If you see 403 errors, then your macro is not working properly.
*No answer needed*



As with the support login credential stuffing attack we carried out, the response codes here are all the same (302 Redirects). Once again, order your responses by Length to find the valid credentials. Your results won't be quite as clear-cut as last time -- you will see quite a few different response lengths: however, the response that indicates a successful login should still stand out as being quite significantly shorter.
*No answer needed*

Use the credentials you just found to log in (you may need to refresh the login page before entering the credentials).
*No answer needed*

*to work*

![[Pasted image 20220822173623.png]]

![[Pasted image 20220822173841.png]]

*found admin -> o.bennett:bella1*

### Conclusion 

You have now completed the Intruder room!

This room looked at how to use the Intruder aspect of the Burp Suite framework when automating requests. You should now be comfortable using Intruder and its various attack types when attacking a web application. You should also be comfortable with the concept of using macros to extend the functionality of Burp functionality. The examples given here are only the tip of the iceberg! Intruder can be used any time you need to automate requests -- your imagination is the limit.

In the next room of the module, we will be looking at some of Burp Suite's lesser-known tools.


I can use Intruder! *No answer needed*

![[Pasted image 20220822174211.png]]
[Bonus Question -- Optional] Use Intruder to automate the column enumeration of the Union SQLi in the Repeater Extra Mile exercise.

[[Burp Suite Extender]]