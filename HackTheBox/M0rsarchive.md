```
 CHALLENGE DESCRIPTION

Just unzip the archive ... several times ...

┌──(witty㉿kali)-[~/Downloads]
└─$ file M0rsarchive.zip                    
M0rsarchive.zip: Zip archive data, at least v2.0 to extract, compression method=store

┌──(witty㉿kali)-[~/Downloads]
└─$ unzip M0rsarchive.zip 
Archive:  M0rsarchive.zip
[M0rsarchive.zip] flag_999.zip password: 
   skipping: flag_999.zip            incorrect password
   skipping: pwd.png                 incorrect password

──(witty㉿kali)-[~/Downloads]
└─$ mkdir M0rs     
                                                                              
┌──(witty㉿kali)-[~/Downloads]
└─$ mv M0rsarchive.zip M0rs
                                                                              
┌──(witty㉿kali)-[~/Downloads]
└─$ cd M0rs 
                                                                              
┌──(witty㉿kali)-[~/Downloads/M0rs]
└─$ ls
M0rsarchive.zip
                                                                              
┌──(witty㉿kali)-[~/Downloads/M0rs]
└─$ stegoveritas M0rsarchive.zip              
Running Module: MultiHandler

Found something worth keeping!
Zip archive data, at least v2.0 to extract, compression method=store
+--------+------------------+------------------------------------------------------------------------------------------------------------------------------+-----------+
| Offset | Carved/Extracted | Description                                                                                                                  | File Name |
+--------+------------------+------------------------------------------------------------------------------------------------------------------------------+-----------+
| 0x0    | Carved           | Zip archive data, encrypted at least v2.0 to extract, compressed size: 624826, uncompressed size: 624814, name: flag_999.zip | 0.zip     |
| 0x0    | Extracted        | Zip archive data, encrypted at least v2.0 to extract, compressed size: 624826, uncompressed size: 624814, name: flag_999.zip | pwd.png   |
+--------+------------------+------------------------------------------------------------------------------------------------------------------------------+-----------+
Exif
====
+---------------------+--------------------------------------------+
| key                 | value                                      |
+---------------------+--------------------------------------------+
| SourceFile          | /home/witty/Downloads/M0rs/M0rsarchive.zip |
| ExifToolVersion     | 12.57                                      |
| FileName            | M0rsarchive.zip                            |
| Directory           | /home/witty/Downloads/M0rs                 |
| FileSize            | 625 kB                                     |
| FileModifyDate      | 2023:07:29 20:27:00-04:00                  |
| FileAccessDate      | 2023:07:29 20:35:06-04:00                  |
| FileInodeChangeDate | 2023:07:29 20:34:55-04:00                  |
| FilePermissions     | -rw-r--r--                                 |
| FileType            | ZIP                                        |
| FileTypeExtension   | zip                                        |
| MIMEType            | application/zip                            |
| ZipRequiredVersion  | 20                                         |
| ZipBitFlag          | 0x0001                                     |
| ZipCompression      | None                                       |
| ZipModifyDate       | 2018:10:03 20:02:32                        |
| ZipCRC              | 0x89df2058                                 |
| ZipCompressedSize   | 624826                                     |
| ZipUncompressedSize | 624826                                     |
| ZipFileName         | flag_999.zip                               |
+---------------------+--------------------------------------------+
                                                                              
┌──(witty㉿kali)-[~/Downloads/M0rs]
└─$ ls
M0rsarchive.zip  results
                                                                              
┌──(witty㉿kali)-[~/Downloads/M0rs]
└─$ cd results 
                                                                              
┌──(witty㉿kali)-[~/Downloads/M0rs/results]
└─$ ls
exif  keepers
                                                                              
┌──(witty㉿kali)-[~/Downloads/M0rs/results]
└─$ cd exif   
                                                                              
┌──(witty㉿kali)-[~/Downloads/M0rs/results/exif]
└─$ ls
directory            filesize           zipcompression
exiftoolversion      filetype           zipcrc
fileaccessdate       filetypeextension  zipfilename
fileinodechangedate  mimetype           zipmodifydate
filemodifydate       sourcefile         ziprequiredversion
filename             zipbitflag         zipuncompressedsize
filepermissions      zipcompressedsize
                                                                              
┌──(witty㉿kali)-[~/Downloads/M0rs/results/exif]
└─$ cd ../keepers                                           
                                                                              
┌──(witty㉿kali)-[~/Downloads/M0rs/results/keepers]
└─$ ls
0.zip                                                flag_999.zip
1690677306.9593613-a0deb4824e505c6df32efedb4eb82d9c  pwd.png

nope xd the pass is hackthebox

┌──(witty㉿kali)-[~/Downloads/M0rs]
└─$ unzip M0rsarchive.zip 
Archive:  M0rsarchive.zip
[M0rsarchive.zip] flag_999.zip password: 
 extracting: flag_999.zip            
 extracting: pwd.png                 
                                                                              
┌──(witty㉿kali)-[~/Downloads/M0rs]
└─$ ls
flag_999.zip  M0rsarchive.zip  pwd.png  results

┌──(witty㉿kali)-[~/Downloads/M0rs]
└─$ tesseract pwd.png output_5 -l eng txt && cat output_5.txt 

uhmm

----. morse code

9

┌──(witty㉿kali)-[~/Downloads/M0rs]
└─$ unzip flag_999.zip
Archive:  flag_999.zip
[flag_999.zip] flag/flag_998.zip password: 
 extracting: flag/flag_998.zip       
  inflating: flag/pwd.png            
                                                                              
┌──(witty㉿kali)-[~/Downloads/M0rs]
└─$ ls
flag  flag_999.zip  M0rsarchive.zip  output_5.txt  pwd.png  results
                                                                              
┌──(witty㉿kali)-[~/Downloads/M0rs]
└─$ cd flag 
                                                                              
┌──(witty㉿kali)-[~/Downloads/M0rs/flag]
└─$ ls
flag_998.zip  pwd.png

another morse code then we need to unzip 999 

┌──(witty㉿kali)-[~/Downloads/M0rs/flag]
└─$ chmod +x exploit.py 
                                                                              
┌──(witty㉿kali)-[~/Downloads/M0rs/flag]
└─$ ./exploit.py pwd.png                                                     
08
                                                                              
┌──(witty㉿kali)-[~/Downloads/M0rs/flag]
└─$ cat exploit.py 
#!/usr/bin/env python3

import sys
from PIL import Image

code_morse = {'A': '.-',     'B': '-...',   'C': '-.-.', 
        'D': '-..',    'E': '.',      'F': '..-.',
        'G': '--.',    'H': '....',   'I': '..',
        'J': '.---',   'K': '-.-',    'L': '.-..',
        'M': '--',     'N': '-.',     'O': '---',
        'P': '.--.',   'Q': '--.-',   'R': '.-.',
        'S': '...',    'T': '-',      'U': '..-',
        'V': '...-',   'W': '.--',    'X': '-..-',
        'Y': '-.--',   'Z': '--..',

        '0': '-----',  '1': '.----',  '2': '..---',
        '3': '...--',  '4': '....-',  '5': '.....',
        '6': '-....',  '7': '--...',  '8': '---..',
        '9': '----.' 
        }

def get_morse():
    im = Image.open(sys.argv[1])

    width,height = im.size
    morse_color = min(im.getcolors(2))[1]
    morseCode = ""
    
    for c in range(height):
        count = 0
        for r in range(width):
            if im.getpixel((r,c)) == morse_color:
                count += 1 
            else:
                if count != 0: # have we found a colored pixel?
                    morseCode += ("-" if count == 3 else ".") # depending on the length add morse char
                    count = 0 # reset pixel length
        morseCode += " " # new character
    return morseCode

CODE_REVERSED = {value:key for key,value in code_morse.items()}

def from_morse(s):
    return ''.join(CODE_REVERSED.get(i) for i in s.split())

print(from_morse(get_morse()).lower())

┌──(witty㉿kali)-[~/Downloads/M0rs/flag]
└─$ cat exploit.sh
#!/bin/bash

for i in `seq 0 999`;
do
        Zip_pwd="`$1 $2`";
        unzip -P "$Zip_pwd" flag_*.zip;
        cd flag;
        echo $Zip_pwd;
        echo $i;
done

cat flag;
                                                                              
┌──(witty㉿kali)-[~/Downloads/M0rs/flag]
└─$ chmod +x exploit.sh

┌──(witty㉿kali)-[~/Downloads/M0rs/flag]
└─$ ./exploit.sh /home/witty/Downloads/M0rs/flag/exploit.py ./pwd.png
991
Archive:  flag_6.zip
 extracting: flag/flag_5.zip         
 extracting: flag/pwd.png            
sav9jr9u62nz34kxxrycejoj53
992
Archive:  flag_5.zip
 extracting: flag/flag_4.zip         
 extracting: flag/pwd.png            
bthbz9txo29nmj1edo30h2dsfj
993
Archive:  flag_4.zip
 extracting: flag/flag_3.zip         
 extracting: flag/pwd.png            
dn4elassppz5c5lx8kwk6wuge6
994
Archive:  flag_3.zip
 extracting: flag/flag_2.zip         
 extracting: flag/pwd.png            
e5ikp56dxhypoznwlq5ts1c7a6
995
Archive:  flag_2.zip
 extracting: flag/flag_1.zip         
 extracting: flag/pwd.png            
278er7uxqo17ge0rp89827brp2
996
Archive:  flag_1.zip
 extracting: flag/flag_0.zip         
  inflating: flag/pwd.png            
pp4ij1o3vhv1688hjuc0z2soyt
997
Archive:  flag_0.zip
 extracting: flag/flag               
7920
998
Traceback (most recent call last):
  File "/home/witty/Downloads/M0rs/flag/exploit.py", line 46, in <module>
    print(from_morse(get_morse()).lower())
                     ^^^^^^^^^^^
  File "/home/witty/Downloads/M0rs/flag/exploit.py", line 23, in get_morse
    im = Image.open(sys.argv[1])
         ^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/PIL/Image.py", line 3227, in open
    fp = builtins.open(filename, "rb")
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
FileNotFoundError: [Errno 2] No such file or directory: './pwd.png'
unzip:  cannot find or open flag_*.zip, flag_*.zip.zip or flag_*.zip.ZIP.

No zipfiles found.
./exploit.sh: line 7: cd: flag: File name too long

999
HTB{D0_y0u_L1k3_m0r53??}



```
![[Pasted image 20230729195240.png]]
![[Pasted image 20230729195559.png]]

[[toc2]]