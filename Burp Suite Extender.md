---
Learn how to use Extender to broaden the functionality of Burp Suite
---

### Outline 

Welcome to the Burp Suite Extender room!

This room will focus on Burp Suite's modular aspects: the exposed functionality, which allows developers to craft extra additional modules for the framework.

Coding Burp modules is far outwith the scope of this module, but we will take a quick look at the API documentation, as well as going over the typical process for adding new modules using the Burp Suite "BApp" store.

You will not need the target machine to complete this room, but you should ensure that you have access to a copy of Burp Suite. If you are using the AttackBox, make sure to start it now.

### The Extender Interface 

Let's start by taking a look through the Extender interface:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d9e176315f8850e719252ed/room-content/2209ba3b83c43b82b7cbc0c2883386fe.png)

The default view in the Extender interface gives us an overview of the extensions that we have loaded into Burp Suite. There are none in the screenshot above -- we will change this in the next few tasks. The first box (towards the top of the interface) provides us with a list of extensions that we have installed and allows us to activate or deactivate them for this project.

The options to the left of this box allow us to uninstall extensions with the Remove button or install new ones from files on our disk with the Add button. These could be either modules that we have coded or modules that have been made available on the internet but are not in the BApp store. The Up and Down buttons in this section control the order that installed extensions are listed in. Extensions are invoked in descending order based on this list. In other words: all traffic passing through Burp Suite will be passed through each extension in order, starting at the top of the list and working down. This can be very important when dealing with extensions that modify the requests as some may counteract or otherwise hinder one another.

Towards the bottom of the window, we have Details, Output and Errors for the currently selected module. These can be used to view module information, as well as for debugging.


Familiarise yourself with the Extender management interface. *No answer needed*

Are extensions invoked in ascending (A) or descending (D) order? *D*

### The BApp Store 

The Burp App Store (or BApp Store for short) gives us a way to easily list official extensions and integrate them seamlessly with Burp Suite. Extensions can be written in a variety of languages -- most commonly Java (which integrates into the framework automatically) or Python (which requires the Jython interpreter -- more on this in the next task!).

Let's start by installing a Java extension, just to get a feel for the BApp store.

The Request Timer extension (Written by Nick Taylor) allows us to log the time that each request we send takes to receive a response; this can be extremely useful for discovering the presence of (and exploiting) time-based vulnerabilities. For example, if a login form takes an extra second to process requests that contain a valid username than it does for accounts that do not exist, then we can quickly generate a list of possible usernames and use the difference in times to see which usernames are valid.

Switch over to the "BApp Store" sub-tab, then search for "Request Timer". There should only be one result. Click on the returned Extension, then click "Install":

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d9e176315f8850e719252ed/room-content/7a9077f19a68a81647874639a6afaeb4.gif)

Notice that a new tab appeared in the main menu at the top of the screen. Different extensions have different behaviours: some merely add a new item to right-click context menus; others create entirely new tabs in the main menu bar.

As this was just an example of using the BApp store, we won't cover using the Request Timer here; however, switching to the new tab and taking a look is highly recommended!


Install the Request Timer module and take a look at the new tab in the menu.
*No answer needed*

Look through the list of apps in the BApp store and install at least one other that catches your fancy. *No answer needed* (The Logger++ for extended logging functionality is a really good choice!)

### Jython 

Note: Integrating Jython into Burp Suite has already been done for us in the AttackBox, so please feel free to skip this task if you are not using a local machine.

If we want to use Python modules in Burp Suite, we need to have downloaded and included the separate Jython Interpreter JAR file. The Jython interpreter is a Java implementation of Python. The website gives us the option to either install Jython to our system or download it as a standalone Java archive (JAR). We need it as a standalone archive to integrate it with Burp.

Note: we can do the same thing with Ruby modules and the JRuby integration; however, we will not cover this here as: A) Python modules are much more common and B) it's exactly the same process for both.

First up, we need to download an up-to-date copy of the Jython JAR archive from the Jython website. We are looking for the Jython Standalone option:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d9e176315f8850e719252ed/room-content/90bdfdaaf37cd1902bafc5620724a895.png)

Save the JAR file somewhere on your disk, then switch to the "Options" sub-tab in Extender.

Scroll down to the "Python Environment" section, and set the "Location of Jython standalone JAR file" to the path of the archive:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d9e176315f8850e719252ed/room-content/e205758f48300e42913d4e648a71c6d1.png)

Simple as that, we can now install Python modules from the BApp store!

This is a very simple step that significantly increases the number of extensions available to us.

Note: Due to the multi-platform nature of Java, the exact same steps will work for adding Jython to Burp Suite on any operating system.


[Bonus Question -- Optional] Add JRuby to your Burp Suite install. A download link can be found here. The process for this is exactly the same as with Jython. *No answer needed*

### The Burp Suite API 

Whilst coding our own modules is far outwith the scope of this module, it is worth looking (very briefly) at how such a task might be approached.

Extender exposes a large number of API Endpoints that new modules can hook into when integrating with Burp Suite.

We can view these in the "APIs" sub-tab:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d9e176315f8850e719252ed/room-content/b34067667b533a26fdc4fe2e5bf9c012.png)

Each item in the list on the left of this sub-tab documents a different API endpoint -- all of which can be called from within extensions. The endpoints here give developers a lot of power when writing extensions to interact seamlessly with the existing functionality of Burp Suite. As you may expect, we can interact with these endpoints in any of the languages supported by Burp Suite for use in extensions: Java (natively), Python (via Jython), and Ruby (via JRuby).

If you are particularly interested in coding your own extensions for Burp Suite, PortSwigger provide a wonderful reference which can be found [here](https://portswigger.net/burp/extender/writing-your-first-burp-suite-extension).



[Bonus Question -- Optional] Read through the list of API endpoints and find a few which interest you. Have a look through the documentation. Can you see how the endpoints might be used? *No answer needed*

### Room Conclusion 

Short and sweet: you have completed the Burp Suite Extender Room.

If you have been working through these rooms in order, then you have also completed the module: kudos to you!

You should now have a good understanding of how Extender can be used to extend the functionality offered by Burp Suite significantly. Not only can we install a great many powerful modules from the BApp store, but we also have access to an extensive set of API endpoints that allow us to write our own Burp modules in Java, Python or Ruby.


I can use Burp Suite Extender! *No answer needed*

[[Command Injection]]