---
I received a suspicious email with a very weird looking attachment. It keeps on asking me to "enable macros". What are those?
---

![|333](https://tryhackme-images.s3.amazonaws.com/room-icons/5de2b57caa0e6e1fd6309c84fc20f5fa.png)



I received a suspicious email with a very weird-looking attachment. It keeps on asking me to "enable macros". What are those?


Access this challenge by deploying the machine attached to this task by pressing the green "Start Machine" button. The files you need are located in /home/ubuntu/mrphisher on the VM. 

Can't see the VM? Press the "Split Screen" button at the top of the page.

```
┌──(kali㉿kali)-[~]
└─$ mkdir mrphisher  
                                                                                                         
┌──(kali㉿kali)-[~]
└─$ cd mrphisher           
                                                                                                         
┌──(kali㉿kali)-[~/mrphisher]
└─$ ls
                                                                                                         
┌──(kali㉿kali)-[~/mrphisher]
└─$ rlwrap nc -nlvp 1337 > MrPhisher.docm   
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.105.182.
Ncat: Connection from 10.10.105.182:52050.

                                                                                                         
┌──(kali㉿kali)-[~/mrphisher]
└─$ ls
MrPhisher.docm
                                                                                                         
┌──(kali㉿kali)-[~/mrphisher]
└─$ file MrPhisher.docm 
MrPhisher.docm: Microsoft Word 2007+


┌──(kali㉿kali)-[~]
└─$ mkdir mrphisher  
                                                                                                         
┌──(kali㉿kali)-[~]
└─$ cd mrphisher           
                                                                                                         
┌──(kali㉿kali)-[~/mrphisher]
└─$ ls
                                                                                                         
┌──(kali㉿kali)-[~/mrphisher]
└─$ rlwrap nc -nlvp 1337 > MrPhisher.docm   
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.105.182.
Ncat: Connection from 10.10.105.182:52050.

machine

ubuntu@thm-mr-phisher:~/mrphisher$ nc 10.18.1.77 1337 < MrPhisher.docm
                                                                                                         
┌──(kali㉿kali)-[~/mrphisher]
└─$ ls
MrPhisher.docm
                                                                                                         
┌──(kali㉿kali)-[~/mrphisher]
└─$ file MrPhisher.docm 
MrPhisher.docm: Microsoft Word 2007+

I normally use a tool called olevba to analysis any documents for macros. Oletools is a package of python tools to analyze Microsoft OLE2 files (also called Structured Storage, Compound File Binary Format or Compound Document File Format), such as Microsoft Office documents or Outlook messages, mainly for malware analysis, forensics and debugging.

┌──(kali㉿kali)-[~/mrphisher]
└─$ pip3 install oletools                                     
Defaulting to user installation because normal site-packages is not writeable
Collecting oletools
  Downloading oletools-0.60.1-py2.py3-none-any.whl (977 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 977.2/977.2 kB 5.9 MB/s eta 0:00:00
Collecting easygui
  Downloading easygui-0.98.3-py2.py3-none-any.whl (92 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 92.7/92.7 kB 5.8 MB/s eta 0:00:00
Collecting colorclass
  Downloading colorclass-2.2.2-py2.py3-none-any.whl (18 kB)
Collecting pcodedmp>=1.2.5
  Downloading pcodedmp-1.2.6-py2.py3-none-any.whl (30 kB)
Collecting msoffcrypto-tool
  Downloading msoffcrypto_tool-5.0.0-py3-none-any.whl (33 kB)
Collecting pyparsing<3,>=2.1.0
  Downloading pyparsing-2.4.7-py2.py3-none-any.whl (67 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 67.8/67.8 kB 4.1 MB/s eta 0:00:00
Requirement already satisfied: olefile>=0.46 in /usr/lib/python3/dist-packages (from oletools) (0.46)
Requirement already satisfied: cryptography>=2.3 in /usr/lib/python3/dist-packages (from msoffcrypto-tool->oletools) (3.4.8)
Installing collected packages: easygui, pyparsing, msoffcrypto-tool, colorclass, pcodedmp, oletools
  WARNING: The script msoffcrypto-tool is installed in '/home/kali/.local/bin' which is not on PATH.
  Consider adding this directory to PATH or, if you prefer to suppress this warning, use --no-warn-script-location.                                                                                               
  WARNING: The script pcodedmp is installed in '/home/kali/.local/bin' which is not on PATH.             
  Consider adding this directory to PATH or, if you prefer to suppress this warning, use --no-warn-script-location.                                                                                               
  WARNING: The scripts ezhexviewer, ftguess, mraptor, msodde, olebrowse, oledir, olefile, oleid, olemap, olemeta, oleobj, oletimes, olevba, pyxswf and rtfobj are installed in '/home/kali/.local/bin' which is not on PATH.                                                                                               
  Consider adding this directory to PATH or, if you prefer to suppress this warning, use --no-warn-script-location.                                                                                               
ERROR: pip's dependency resolver does not currently take into account all the packages that are installed. This behaviour is the source of the following dependency conflicts.                                    
ospd-openvas 21.4.4 requires redis<4.0.0,>=3.5.3, but you have redis 4.3.4 which is incompatible.        
Successfully installed colorclass-2.2.2 easygui-0.98.3 msoffcrypto-tool-5.0.0 oletools-0.60.1 pcodedmp-1.2.6 pyparsing-2.4.7


┌──(root㉿kali)-[/home/kali/mrphisher]
└─# pip install oletools
Collecting oletools
  Downloading oletools-0.60.1-py2.py3-none-any.whl (977 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 977.2/977.2 kB 5.8 MB/s eta 0:00:00
Collecting colorclass
  Downloading colorclass-2.2.2-py2.py3-none-any.whl (18 kB)
Collecting easygui
  Downloading easygui-0.98.3-py2.py3-none-any.whl (92 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 92.7/92.7 kB 12.9 MB/s eta 0:00:00
Collecting pyparsing<3,>=2.1.0
  Downloading pyparsing-2.4.7-py2.py3-none-any.whl (67 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 67.8/67.8 kB 3.9 MB/s eta 0:00:00
Collecting msoffcrypto-tool
  Downloading msoffcrypto_tool-5.0.0-py3-none-any.whl (33 kB)
Requirement already satisfied: olefile>=0.46 in /usr/lib/python3/dist-packages (from oletools) (0.46)
Collecting pcodedmp>=1.2.5
  Downloading pcodedmp-1.2.6-py2.py3-none-any.whl (30 kB)
Requirement already satisfied: cryptography>=2.3 in /usr/lib/python3/dist-packages (from msoffcrypto-tool->oletools) (3.4.8)
Installing collected packages: easygui, pyparsing, msoffcrypto-tool, colorclass, pcodedmp, oletools
  Attempting uninstall: pyparsing
    Found existing installation: pyparsing 3.0.7
    Not uninstalling pyparsing at /usr/lib/python3/dist-packages, outside environment /usr
    Can't uninstall 'pyparsing'. No files were found to uninstall.
ERROR: pip's dependency resolver does not currently take into account all the packages that are installed. This behaviour is the source of the following dependency conflicts.                                    
ospd-openvas 21.4.4 requires redis<4.0.0,>=3.5.3, but you have redis 4.3.4 which is incompatible.        
Successfully installed colorclass-2.2.2 easygui-0.98.3 msoffcrypto-tool-5.0.0 oletools-0.60.1 pcodedmp-1.2.6 pyparsing-2.4.7
WARNING: Running pip as the 'root' user can result in broken permissions and conflicting behaviour with the system package manager. It is recommended to use a virtual environment instead: https://pip.pypa.io/warnings/venv                                                                                              
                                                                                                         
┌──(root㉿kali)-[/home/kali/mrphisher]
└─# olevba MrPhisher.docm 
olevba 0.60.1 on Python 3.10.7 - http://decalage.info/python/oletools
===============================================================================
FILE: MrPhisher.docm
Type: OpenXML
WARNING  For now, VBA stomping cannot be detected for files in memory
-------------------------------------------------------------------------------
VBA MACRO ThisDocument.cls 
in file: word/vbaProject.bin - OLE stream: 'VBA/ThisDocument'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
-------------------------------------------------------------------------------
VBA MACRO NewMacros.bas 
in file: word/vbaProject.bin - OLE stream: 'VBA/NewMacros'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Sub Format()
Dim a()
Dim b As String
a = Array(102, 109, 99, 100, 127, 100, 53, 62, 105, 57, 61, 106, 62, 62, 55, 110, 113, 114, 118, 39, 36, 118, 47, 35, 32, 125, 34, 46, 46, 124, 43, 124, 25, 71, 26, 71, 21, 88)
For i = 0 To UBound(a)
b = b & Chr(a(i) Xor i)
Next
End Sub
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|Suspicious|Chr                 |May attempt to obfuscate specific strings    |
|          |                    |(use option --deobf to deobfuscate)          |
|Suspicious|Xor                 |May attempt to obfuscate specific strings    |
|          |                    |(use option --deobf to deobfuscate)          |
+----------+--------------------+---------------------------------------------+

then use a compiler vba

'                             Online VB Compiler.
'                 Code, Compile, Run and Debug VB program online.
' Write your code in this editor and press "Run" button to execute it.
Module VBModule
    Sub Main()
        Dim i As Byte
        Dim a() = {102, 109, 99, 100, 127, 100, 53, 62, 105, 57, 61, 106, 62, 62, 55, 110, 113, 114, 118, 39, 36, 118, 47, 35, 32, 125, 34, 46, 46, 124, 43, 124, 25, 71, 26, 71, 21, 88}
        Dim b As String
        For i = 0 To UBound(a)
            b = b & Chr(a(i) Xor i)
            'Console.WriteLine(b)
            Next
        Console.WriteLine(b)
    End Sub
End Module

Visual Basic.Net Compiler version 0.0.0.5943 (Mono 4.7 - tarball)
Copyright (C) 2004-2010 Rolf Bjarne Kvinge. All rights reserved.

/home/main.vb (7,14) : warning VBNC42020: Variable declaration without an 'As' clause; Object type assumed.
Assembly 'a, Version=0.0, Culture=neutral, PublicKeyToken=null' saved successfully to '/home/a.out'.
There were 0 errors and 1 warnings.
Compilation successful
Compilation took 00:00:01.0611550
flag{a39a07a239aacd40c948d852a5c9f8d1}

https://onlinegdb.com/71dfFgki_

```


Uncover the flag in the email attachment!
*flag{a39a07a239aacd40c948d852a5c9f8d1}*


[[Flatline]]