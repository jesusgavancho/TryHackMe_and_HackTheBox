---
To exploit a website, you first need to know how they are created.
---

### How websites work

By the end of this room, you'll know how websites are created and will be introduced to some basic security issues.

When you visit a website, your browser (_like Safari or Google Chrome_) makes a request to a web server asking for information about the page you're visiting. It will respond with data that your browser uses to show you the page; a web server is just a dedicated computer somewhere else in the world that handles your requests.

![](https://assets.tryhackme.com/additional/how-websites-work/client%20server.png)

There are two major components that make up a website:

1.  Front End (Client-Side) - the way your browser renders a website.
2.  Back End (Server-Side) - a server that processes your request and returns a response.

There are many other processes involved in your browser making a request to a web server, but for now, you just need to understand that you make a request to a server, and it responds with data your browser uses to render information to you.

  
What term best describes the side your browser renders a website? *Client side*

### HTML

Websites are primarily created using:

-   HTML, to build websites and define their structure
-   CSS, to make websites look pretty by adding styling options
-   JavaScript, implement complex features on pages using interactivity

**H**yper**T**ext **M**arkup **L**anguage (HTML) is the language websites are written in. Elements (also known as tags) are the building blocks of HTML pages and tells the browser how to display content. The code snippet below shows a simple HTML document, the structure of which is the same for every website:

![](https://assets.tryhackme.com/additional/how-websites-work/example_html.png)

The HTML structure (as shown in the screenshot) has the following components:

-   The `<!DOCTYPE html>` defines that the page is a HTML5 document. This helps with standardisation across different browsers and tells the browser to use HTML5 to interpret the page.
-   The `<html>` element is the root element of the HTML page - all other elements come after this element.
-   The `<head>` element contains information about the page (such as the page title)
-   The `<body>` element defines the HTML document's body; only content inside of the body is shown in the browser.
-   The `<h1>` element defines a large heading
-   The `<p>` element defines a paragraph
-   There are many other elements (tags) used for different purposes. For example, there are tags for buttons (`<button>`), images (`<img>`), lists, and much more.   
    

Tags can contain attributes such as the class attribute which can be used to style an element (e.g. make the tag a different color) `<p class="bold-text">`, or the _src_ attribute which is used on images to specify the location of an image: `<img src="img/cat.jpg">.`An element can have multiple attributes each with its own unique purpose, e.g., <p attribute1="value1" attribute2="value2">.

Elements can also have an id attribute (`<p id="example">`), which is unique to the element. Unlike the class attribute, where multiple elements can use the same class, an element must have different id's to identify them uniquely. Element id's are used for styling and to identify it by JavaScript.

You can view the HTML of any website by right-clicking and selecting "View Page Source" (Chrome) / "Show Page Source" (Safari).

  
Let's play with some HTML! On the right-hand side, you should see a box that renders HTML - If you enter some HTML into the box and click the green "Render HTML Code" button, it will render your HTML on the page; you should see an image of some cats. *No answer needed*

```img
<img src='img/cat-2.jpg'>
```
One of the images on the cat website is broken - fix it, and the image will reveal the hidden text answer! *HTMLHERO*

```
<!-- Add dog image here -->
<img src='img/dog-1.png'>
```
Add a dog image to the page by adding another img tag (<img>) on line 11. The dog image location is img/dog-1.png *DOGHTML*

### JavaScript

JavaScript (JS) is one of the most popular coding languages in the world and allows pages to become interactive. HTML is used to create the website structure and content, while JavaScript is used to control the functionality of web pages - without JavaScript, a page would not have interactive elements and would always be static. JS can dynamically update the page in real-time, giving functionality to change the style of a button when a particular event on the page occurs (such as when a user clicks a button) or to display moving animations.

JavaScript is added within the page source code and can be either loaded within `<script>` tags or can be included remotely with the src attribute: `<script src="/location/of/javascript_file.js"></script>`

The following JavaScript code finds a HTML element on the page with the id of "demo" and changes the element's contents to "Hack the Planet" : `document.getElementById("demo").innerHTML = "Hack the Planet";`

HTML elements can also have events, such as "onclick" or "onhover" that execute JavaScript when the event occurs. The following code changes the text of the element with the demo ID to Button Clicked: `<button onclick='document.getElementById("demo").innerHTML = "Button Clicked";'>Click Me!</button>` - onclick events can also be defined inside the JavaScript script tags, and not on elements directly.

```js
document.getElementById("demo").innerHTML = "Hack the Planet";
```
Click the "View Site" button on this task. On the right-hand side, add JavaScript that changes the demo element's content to "Hack the Planet" *JSISFUN*

```
<button onclick='document.getElementById("demo").innerHTML = "Button Clicked";'>Click Me!</button>
```
Add the button HTML from this task that changes the element's text to "Button Clicked" on the editor on the right, update the code by clicking the "Render HTML+JS Code" button and then click the button. *No answer needed*

###  Sensitive Data Exposure

Sensitive Data Exposure occurs when a website doesn't properly protect (or remove) sensitive clear-text information to the end-user; usually found in a site's frontend source code.

We now know that websites are built using many HTML elements (tags), all of which we can see simply by "viewing the page source". A website developer may have forgotten to remove login credentials, hidden links to private parts of the website or other sensitive data shown in HTML or JavaScript.

![](https://assets.tryhackme.com/additional/how-websites-work/html_source.png)

Sensitive information can be potentially leveraged to further an attacker's access within different parts of a web application. For example, there could be HTML comments with temporary login credentials, and if you viewed the page's source code and found this, you could use these credentials to log in elsewhere on the application (or worse, used to access other backend components of the site).

Whenever you're assessing a web application for security issues, one of the first things you should do is review the page source code to see if you can find any exposed login credentials or hidden links.

```sourcecode
<html><head>
    <title>How websites work</title>
    <link rel="stylesheet" href="css/style.css">
<style type="text/css">[id^=root], [id^=docs], .cc_cursor, body, .ogdlpmhglpejoiomcodnpjnfgcpmgale_default, body, html, input[type="date"], input[type="time"], input[type="datetime-local"], input[type="month"], input::-webkit-contacts-auto-fill-button, input:read-only {cursor: url("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAAAXNSR0IArs4c6QAABAtJREFUSEu1lX1Mm1UUxp/D5GupQvmqUArYLAMGDMFRJmuZkSxkdYEFEhgqCUsWCfKVaMDOIBQlOKJbphPYCNbEJc5MysYYThHTlzkHlIQG6ChgpQMmQ0A6gZYONl7TTomYbXzN8+977vO7z3mfey+pNV3q5s62Dsc/zbKCggITnnDRmaYL4yW6a7zt13/5slXZcIyIdE+SQeqx4U/eaL+Up7s1jI/gN5ienl7I5XIbnhSEqmurRV+Zxjt+cmXBd9iKSt/oxZGe3uTcN3ObiGhpsyCKj48P+TXMV6sP49u0dnv4ItnkjMuVtYUMw9QSkXEzEFIoFDsGufa9VfMjdjOLd21a/K3PIMeev+gyZvwuKyvrCBFNbBRCLMv6jM/NNEqav4jUz00v67g6OCHfMxgHvYTGhvoLIrlcrt8IxApwrK+v/zhvTpfzGxZsGs9zn4WE5w/nLfZwtbNH+G3zpEKhyKirq/ueiO6vB0TW5tjYWPnSkYSSm87AWXESXByccHGkH0EuHvh5cgRTc7MQ901NR0REHBeLxeXrBpSWlr4nSUsu1S2ZaGjWiBN9bdjl7oO3dsRA3q3C4MwUsoNE2DM6jz2i6B/a29tfS0lJmVwLyOZgaGjodYFAUF07pOHYgTBhMUHk4YtPde1wc3SGP8cVzWN67HLn46hfJK6qVCqDwXC4qKhoeDWIDcCybADDMKrcmRsB7N8rOE85oDL6Fehnp/G1oRehXB7KeloR77MNp3fuw9tZ2TeVSmU6EV17HMQGsFZiYqI27kNZSF7nFezlBaAq+gDe1bSgYbQfUv52vODujQ96Wm29CYJAnIzaD+Xpz02pqalyrVZ7SiqVPsj4f2oZkJmZqc099n5I6KVKaBOyUaT5EdZzsdtTgIOCIBztaoHqdwOW2AceYzwFkAXHYLGr/55Go9lZVlb20DtsGTAwMKC8z+MmhTdWIdLNB9/sTcXwnBEl3SoYFyyQhYoR6sqDfvYPJKrO2SBhmtGl49K0U+Xl5TKGYSyPdcCy7AGtQd8oM3Sg6dbgit5gFw9kB0YjzluIqIYqbJkwmlPvOIyeKavYT0SGNf0D64ErLi62IOml5Vn7OD+NtOfCkOQXjM8G1LjYdBkpoli9W8dA+YmKivNEtOr7sTwi6y7y8/NZ7uFEyLsZ2BGhMESMMfMMVMODEI4YEQinDNmhDEYoFK4az39crQC0tbXdMQfwXA5dPY9JixlktsDbiTMfrlR3fNvYmENEN1bL/SNTZP1gNptPmhbu5kuYs7it7Wcj7jm2FsclnXtZIqlZr/BDHVTW1ER5e3mpr3ReR1jMi69uI8cWqVS6pivhURtYMaK+vj5/DocjFwgE72zmDfg3bAVgo2NYU0z/D3Gr5l8vfJQoo9Z1sAAAAABJRU5ErkJggg==") 0 0 , auto !important; }[role^=button], button, .cc_pointer, [type="search"]::-webkit-search-cancel-button, a, select, [type="search"]::-webkit-search-decoration, .paper-button, .ytp-progress-bar-container, input[type=submit], :link, :visited, a > *, img, button, ::-webkit-scrollbar-button, .ogdlpmhglpejoiomcodnpjnfgcpmgale_pointer, ::-webkit-file-upload-button, button, .ytp-volume-panel, #myogdlpmhglpejoiomcodnpjnfgcpmgale .icon { cursor: url("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAAAXNSR0IArs4c6QAABO9JREFUSEuVlnlsFkUYh5+ZPb+7trS2SCpFQGlRQxCQSKIoSkRIExUSvNCIRwIaCAQi/tESwQMTYxSPYEzliFGQCkqERhEDasBQokEMKIegiCLQfke/c3fH7FcKpUCFTSY7xzvvM+87M79dQbdHfYGVv4KFymOblWezGEu2+7hf37IF/RbBMDReMY5xp5iC29Ome1t0b+SaGeJZtIogAWnwJrDCHMPO7japtcyRkplK0V9lmRN+gNcuGdDaYG+79trsGBkGGUKJEH/rUbYqh4zbDm4bA1WGm7w8tspDLsuRhU3m+KWt+b0Xg5yJYMmE/pW6TB2bPuUEehRkpLNoEfBy4J4CLwOq4/Q7B/uOaLy3IbykbVB8wZo1F07VWcD4ms9zTmripLFtDLrOOQuIgnLBOQ4qDd7pggONTUGkCO23Avq4xV8fO3yhKIqAZfcOHhFPF9afTKSrRt0Y565bsxxKQvNOmDsdDBOcv2ByIzxfD3Xl8PMBwYpNUcpjIUojwYWzN+xvvCCgsRHZ9+faRcmO7HPH4x3YgSRPTM7QrhRrW2Hu45DIQaAdZrwOL94PJQYsWmFRKISLAL+UxGTZlPf3nOoJEdNvKO0XDWobNSGG5h2XXMHhmakp+g90SQqIVMDn38PoSigzQGVg70HB8k02ggCxoEUsZCOF/GDOFwceOw9QX804qWlfWoZOwNSxDYOrq2DmtHZOudCmoOZqSB6EI39CXR/YtMPgq50BbNPA7ppnGv/Ymnbf7I0HvjvnHkzsx1WaJtZKIUdYpi47JxjMezyJ7p+isEBakDuqcNOKVEKwbluIeNLEtgwCho5t6uia/tmsDb/VnxeB31FfTa0SYokm5T2mrhUB0ZBGyO6cbFsmqYxDItWBpeuAWYzWt/PHDU2+PWP9rzMueor8gUl96SMN+ZKUYnoXpOjc0AnaFgpBLpfvTGOxGMW6rmvvWiczsx/75vfzZMX3e45UTC4nHK2WS+MJ8YiGJnxHAcMgFLCIhkJ4Thegc+WWJVvykcCkp5a1Fv73JncZdPzEgpZm8cLK5VIaxXTphIM2VWUlWJIzEQwZGWfAsH/rqsblf7lkLfINC/toVFkavl0ueKNZ4qcrZJvUVJZREQkUN3ZQbTvD649i6d4oUccPvQLUodtsUfPNmfwVdtMoTRo6tsLXewSrNgh0aVBXXUlNRYzKsjQj7zhEcLCLm2CydTOf9ApIfxqeGSjc/Y6Ysqao67kdNMogDZntoJXC5p8ETSsF11dXMnZ4kKEDDxMeUEArBy/OPPt2Xu0d8LF81i3gRh7y3squY5yn86Heh/Ls7k6A7+jHA4IfWiJMnZgjIHLFfhkEt50lwXrm9wpIrqZWCHOXXqXwEgVLZUGLQf4gyFinXCsPZOC003inO+Wfm4S2KviA+3CvgEQzZYbHE8qMjRJGeoKXJSVMt9Q94eErvDjtuOtdXHkHOH/6YHN75MH86Es6RW1NlOjl4SrNSz+pHDFLZdyi9vsyIUJnI/BBbhsoJ4Z7Mr4nMo2hlwToMko1M9+oiC4uHE5IL4UjjOLn05NBnGIUFso5qYXAE15C7Qo/wvDLAiQ+YrBVxVQ3HXi68EfmZc2XaANHj5Dy3Tqe7CNcfTHKaXKOe1sij7L6sgDFDVyNlrsmWmMPT+zvOVm1XBlKa8naoJbefaHfmp72/wHAxMQoy57wBgAAAABJRU5ErkJggg==") 4 0, auto !important; } * {cursor: url("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAAAXNSR0IArs4c6QAABAtJREFUSEu1lX1Mm1UUxp/D5GupQvmqUArYLAMGDMFRJmuZkSxkdYEFEhgqCUsWCfKVaMDOIBQlOKJbphPYCNbEJc5MysYYThHTlzkHlIQG6ChgpQMmQ0A6gZYONl7TTomYbXzN8+977vO7z3mfey+pNV3q5s62Dsc/zbKCggITnnDRmaYL4yW6a7zt13/5slXZcIyIdE+SQeqx4U/eaL+Up7s1jI/gN5ienl7I5XIbnhSEqmurRV+Zxjt+cmXBd9iKSt/oxZGe3uTcN3ObiGhpsyCKj48P+TXMV6sP49u0dnv4ItnkjMuVtYUMw9QSkXEzEFIoFDsGufa9VfMjdjOLd21a/K3PIMeev+gyZvwuKyvrCBFNbBRCLMv6jM/NNEqav4jUz00v67g6OCHfMxgHvYTGhvoLIrlcrt8IxApwrK+v/zhvTpfzGxZsGs9zn4WE5w/nLfZwtbNH+G3zpEKhyKirq/ueiO6vB0TW5tjYWPnSkYSSm87AWXESXByccHGkH0EuHvh5cgRTc7MQ901NR0REHBeLxeXrBpSWlr4nSUsu1S2ZaGjWiBN9bdjl7oO3dsRA3q3C4MwUsoNE2DM6jz2i6B/a29tfS0lJmVwLyOZgaGjodYFAUF07pOHYgTBhMUHk4YtPde1wc3SGP8cVzWN67HLn46hfJK6qVCqDwXC4qKhoeDWIDcCybADDMKrcmRsB7N8rOE85oDL6Fehnp/G1oRehXB7KeloR77MNp3fuw9tZ2TeVSmU6EV17HMQGsFZiYqI27kNZSF7nFezlBaAq+gDe1bSgYbQfUv52vODujQ96Wm29CYJAnIzaD+Xpz02pqalyrVZ7SiqVPsj4f2oZkJmZqc099n5I6KVKaBOyUaT5EdZzsdtTgIOCIBztaoHqdwOW2AceYzwFkAXHYLGr/55Go9lZVlb20DtsGTAwMKC8z+MmhTdWIdLNB9/sTcXwnBEl3SoYFyyQhYoR6sqDfvYPJKrO2SBhmtGl49K0U+Xl5TKGYSyPdcCy7AGtQd8oM3Sg6dbgit5gFw9kB0YjzluIqIYqbJkwmlPvOIyeKavYT0SGNf0D64ErLi62IOml5Vn7OD+NtOfCkOQXjM8G1LjYdBkpoli9W8dA+YmKivNEtOr7sTwi6y7y8/NZ7uFEyLsZ2BGhMESMMfMMVMODEI4YEQinDNmhDEYoFK4az39crQC0tbXdMQfwXA5dPY9JixlktsDbiTMfrlR3fNvYmENEN1bL/SNTZP1gNptPmhbu5kuYs7it7Wcj7jm2FsclnXtZIqlZr/BDHVTW1ER5e3mpr3ReR1jMi69uI8cWqVS6pivhURtYMaK+vj5/DocjFwgE72zmDfg3bAVgo2NYU0z/D3Gr5l8vfJQoo9Z1sAAAAABJRU5ErkJggg==") 0 0 , auto }a, button, [type^=button], [role^=button]   { cursor: url("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAAAXNSR0IArs4c6QAABO9JREFUSEuVlnlsFkUYh5+ZPb+7trS2SCpFQGlRQxCQSKIoSkRIExUSvNCIRwIaCAQi/tESwQMTYxSPYEzliFGQCkqERhEDasBQokEMKIegiCLQfke/c3fH7FcKpUCFTSY7xzvvM+87M79dQbdHfYGVv4KFymOblWezGEu2+7hf37IF/RbBMDReMY5xp5iC29Ome1t0b+SaGeJZtIogAWnwJrDCHMPO7japtcyRkplK0V9lmRN+gNcuGdDaYG+79trsGBkGGUKJEH/rUbYqh4zbDm4bA1WGm7w8tspDLsuRhU3m+KWt+b0Xg5yJYMmE/pW6TB2bPuUEehRkpLNoEfBy4J4CLwOq4/Q7B/uOaLy3IbykbVB8wZo1F07VWcD4ms9zTmripLFtDLrOOQuIgnLBOQ4qDd7pggONTUGkCO23Avq4xV8fO3yhKIqAZfcOHhFPF9afTKSrRt0Y565bsxxKQvNOmDsdDBOcv2ByIzxfD3Xl8PMBwYpNUcpjIUojwYWzN+xvvCCgsRHZ9+faRcmO7HPH4x3YgSRPTM7QrhRrW2Hu45DIQaAdZrwOL94PJQYsWmFRKISLAL+UxGTZlPf3nOoJEdNvKO0XDWobNSGG5h2XXMHhmakp+g90SQqIVMDn38PoSigzQGVg70HB8k02ggCxoEUsZCOF/GDOFwceOw9QX804qWlfWoZOwNSxDYOrq2DmtHZOudCmoOZqSB6EI39CXR/YtMPgq50BbNPA7ppnGv/Ymnbf7I0HvjvnHkzsx1WaJtZKIUdYpi47JxjMezyJ7p+isEBakDuqcNOKVEKwbluIeNLEtgwCho5t6uia/tmsDb/VnxeB31FfTa0SYokm5T2mrhUB0ZBGyO6cbFsmqYxDItWBpeuAWYzWt/PHDU2+PWP9rzMueor8gUl96SMN+ZKUYnoXpOjc0AnaFgpBLpfvTGOxGMW6rmvvWiczsx/75vfzZMX3e45UTC4nHK2WS+MJ8YiGJnxHAcMgFLCIhkJ4Thegc+WWJVvykcCkp5a1Fv73JncZdPzEgpZm8cLK5VIaxXTphIM2VWUlWJIzEQwZGWfAsH/rqsblf7lkLfINC/toVFkavl0ueKNZ4qcrZJvUVJZREQkUN3ZQbTvD649i6d4oUccPvQLUodtsUfPNmfwVdtMoTRo6tsLXewSrNgh0aVBXXUlNRYzKsjQj7zhEcLCLm2CydTOf9ApIfxqeGSjc/Y6Ysqao67kdNMogDZntoJXC5p8ETSsF11dXMnZ4kKEDDxMeUEArBy/OPPt2Xu0d8LF81i3gRh7y3squY5yn86Heh/Ls7k6A7+jHA4IfWiJMnZgjIHLFfhkEt50lwXrm9wpIrqZWCHOXXqXwEgVLZUGLQf4gyFinXCsPZOC003inO+Wfm4S2KviA+3CvgEQzZYbHE8qMjRJGeoKXJSVMt9Q94eErvDjtuOtdXHkHOH/6YHN75MH86Es6RW1NlOjl4SrNSz+pHDFLZdyi9vsyIUJnI/BBbhsoJ4Z7Mr4nMo2hlwToMko1M9+oiC4uHE5IL4UjjOLn05NBnGIUFso5qYXAE15C7Qo/wvDLAiQ+YrBVxVQ3HXi68EfmZc2XaANHj5Dy3Tqe7CNcfTHKaXKOe1sij7L6sgDFDVyNlrsmWmMPT+zvOVm1XBlKa8naoJbefaHfmp72/wHAxMQoy57wBgAAAABJRU5ErkJggg==") 4 0, auto }</style></head>

<body>
    <div id="html-code-box">
        <div id="html-bar">
            <span id="html-url">https://vulnerable-site.com</span>
        </div>
        <div class="theme" id="html-code">
            <div class="logo-pos"><img src="img/logo_white.png"></div>
            <p id="login-msg">Incorrect credentials. <i class="hint" onclick="viewSourceCode()">Try looking at the source code</i> or pressing CTRL+U at the same time.</p>
            <form method="post" id="form" autocomplete="off">
                <div class="form-field">
                    <input class="input-text" type="text" name="username" placeholder="Username..">
                </div>
                <div class="form-field">
                    <input class="input-text" type="password" name="password" placeholder="Password..">
                </div>
                <button onclick="login()" type="button" class="login">Login</button>
                <!--
                    TODO: Remove test credentials!
                        Username: admin
                        Password: testpasswd
                -->
            </form>
            <div class="footer">Copyright Â© Vulnerable Website</div>
        </div>
    </div>
    <script src="js/script.js"></script>


</body></html>
```

  
View the website on this task. What is the password hidden in the source code? *testpasswd*

### HTML Injection

HTML Injection is a vulnerability that occurs when unfiltered user input is displayed on the page. If a website fails to sanitise user input (filter any "malicious" text that a user inputs into a website), and that input is used on the page, an attacker can inject HTML code into a vulnerable website.

Input sanitisation is very important in keeping a website secure, as information a user inputs into a website is often used in other frontend and backend functionality. A vulnerability you'll explore in another lab is database injection, where you can manipulate a database lookup query to log in as another user by controlling the input that's directly used in the query - but for now, let's focus on HTML injection (which is client-side).

When a user has control of how their input is displayed, they can submit HTML (or JavaScript) code, and the browser will use it on the page, allowing the user to control the page's appearance and functionality.

![](https://assets.tryhackme.com/additional/how-websites-work/html_injection.png)

The image above shows how a form outputs text to the page. Whatever the user inputs into the "What's your name" field is passed to a JavaScript function and output to the page, which means if the user adds their own HTML or JavaScript in the field, it's used in the sayHi function and is added to the page - this means you can add your own HTML (such as a <h1/> tag) and it will output your input as pure HTML.

The general rule is never to trust user input. To prevent malicious input, the website developer should sanitise everything the user enters before using it in the JavaScript function; in this case, the developer could remove any HTML tags.

```
<a href=http://hacker.com >
```
View the website on this task and inject HTML so that a malicious link to http://hacker.com is shown. *HTML_INJ3CTI0N*

[[Extending Your Network]]
