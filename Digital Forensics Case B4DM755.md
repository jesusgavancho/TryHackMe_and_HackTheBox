----
Acquire the critical skills of evidence preservation, disk imaging, and artefact analysis for use in court.
----

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/d6713968f4510b8f13466039574decb6.png)

![](https://tryhackme-images.s3.amazonaws.com/room-icons/f8cb3550ee90bd530a581ef5199348ac.png)

### Task 1  Introduction

Disclaimer

This fictional scenario presents a narrative with invented names, characters, and events. It is not meant to suggest any connection or resemblance to actual individuals, locations, structures, or merchandise.

Building up on Intro to Digital Forensics

During [Intro to Digital Forensics](https://tryhackme.com/room/introdigitalforensics), we learned about the two types of investigations that either the public-sector or private-sector initiates, the digital forensic process, and some practical examples of how we can apply our newly acquired knowledge of digital forensics.

In this room, we will simulate an actual crime scenario whereby a court of law has authorised us to conduct a search on a specific person and analyse obtained artefacts and evidence.

Room Objectives

Learn about the following to build up the confidence of future Forensics Lab Analysts, DFIR First Responders, and Digital Forensics Investigators:

- Ensure proper Chain of Custody procedures for transport to the Forensics Laboratory.
- Use FTK Imager to acquire a forensic disk image and preserve digital artefacts and evidence.
- Analyse forensic artefacts received at the Forensics Laboratory for presentation during a trial in a court of law.

Room Prerequisites

Before starting with this room, we recommend you clear [Intro to Digital Forensics](https://tryhackme.com/room/introdigitalforensics) and [Introduction to Cryptography](https://tryhackme.com/room/cryptographyintro).

Answer the questions below

I'm ready to investigate the case.

Question Done

### Task 2  Case B4DM755: Details of the Crime

Case B4DM755 - Details

|   |   |
|---|---|
|Suspect:<br><br>- William S. McClean (William Super McClean)<br><br>Nationality:<br><br>- British<br><br>Charges Pressed / Accused Crimes:<br><br>- Corporate espionage<br>- Theft of trade secrets|![Law enforcement officer writing down the case details.](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/a9e62254f6d62a745d61a4448dd213e4.png)|

Scenario

As a **Forensics Lab Analyst**, you analyse the artefacts from crime scenes. Occasionally, the law enforcement agency you work for receives "intelligence reports" about different cases, and today is one such day. A trusted informant, who has connections to an international crime syndicate, contacted your supervisor about William S. McClean from Case #B4DM755.

The informant provided information about the suspect's whereabouts in Metro Manila, Philippines, which is currently at large, and a transaction that will happen today with a local gang member. They also knew the exact location of the meetup and that the suspect would have incriminating materials at the time.

The law enforcement agency prepared for the operation by obtaining proper search authority and assigning a **DFIR (Digital Forensics & Incident Response) First Responder** (i.e., you) to ensure the appropriate acquisition of **digital artefacts and evidence** for examination at the Forensics Lab, and eventually for use in litigation. The court issued a **search warrant** on the same day, allowing law enforcement officers to investigate the suspect and his place of residence based on the informant's tip.

**NOTE:** In an understaffed agency, one person may be assigned multiple roles, including acquisition and analysis, particularly for high-profile cases. This can help minimize evidence tampering, and ensure accountability as the chain of custody is mainly handled by a single individual (i.e., you).

Answer the questions below

What is your official role?  

*Forensics Lab Analyst*

What role was assigned to you for this specific scenario?

*DFIR First Responder*

What do you have to gather?  

*digital artefacts and evidence*

What document is needed before performing any legal search?

*search warrant*

### Task 3  Practical Application of the Digital Forensics Process

Forensic Acquisition Process for Digital Artefacts and Evidence

|   |   |
|---|---|
|![A DFIR First Responder holding bagged obtained artefacts](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/3a1189ccbd08be24b29e5018ba0b702f.png)|Each department might have unique protocols for acquiring digital artefacts and evidence. However, DFIR First Responders should typically adhere to the following guidelines if there is any computer system at the scene of a crime:<br><br>- Taking an image of the RAM.<br>- Checking for **drive encryption**.<br>- Taking an image of the drive(s).|

Process for Establishing Chain of Custody

|   |   |
|---|---|
|Each department might have unique protocols regarding maintaining the chain of custody. However, DFIR First Responders should typically adhere to the following guidelines when handling digital artefacts and evidence before, during, and after collection:<br><br>- **Ensure proper documentation** of any seized materials as evidence (devices/files).<br>- **Hash and copy** obtained files to maintain the integrity of the original.<br>- Do not perform an appropriate shutdown of devices. Pull the power plug from suspect devices instead. This is to avoid data alteration as a proper shutdown may trigger anti-forensic measures.<br>- **Bag, Seal, and Tag the obtained artefacts** before sending them to the Forensics Laboratory.|![A DFIR First Responder handing over Chain of Custody documentation](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/fc8d5a99443ea77fd174d9d35fe5d407.png)|

Before, during, and after turnover, ensure that the artefacts and evidence are complete and the Field Operative and Forensics Lab Analyst verifies inventory. Any related Chain of Custody forms must be adequately filled-out to guarantee a transparent and untainted handover of artefacts and evidence.

Answer the questions below

Before imaging drives, what must we check them for?  

*drive encryption*

What should be done to ensure and maintain the integrity of original files in the Chain of Custody?  

*Hash and copy*

What must be done before sending obtained artefacts to the Forensics Laboratory?

*Bag, Seal, and Tag the obtained artefacts*

### Task 4  Case B4DM755: At the Scene of Crime

Scenario (continuation)

Unfortunately, law enforcement arrived late at the suspect's residence, where the transaction supposedly happened. Upon arrival, everyone appeared to have already left; there were indications of evidence eradication attempts, and a transaction between the nefarious elements had successfully occurred.

![Shiny object under the suspect's desk](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/f15398599a0753df59bb6ea25def34f8.png)

  

During a thorough search of the suspect's place, law enforcement officers discovered a _flash drive_ under the desk. A key chain with the initials **WSM** was attached to the flash drive, which the team believes belongs to the suspect. It may have been left behind accidentally in their haste to vacate the place.

![A DFIR First Responder picking up the shiny object which turns out to be a flash drive](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/f4ef6fc0a0314d179989cea608d14c1b.png)

  

As a DFIR First Responder accompanying the Field Operatives, you documented, labelled, and preserved the artefact found and completed the Chain of Custody form. You then transported the artefact to the Forensics Laboratory for further examination.

Answer the questions below

What is the only possible artefact found in the suspect's residence?

*flash drive*

Based on the scenario and the previous task, what should be done with that acquired suspect artefact?

Task 3 explains the guidelines for proper forensic acquisition.

*Taking an image*

What is the crucial aspect of the Chain of Custody that ensures individual accountability and guarantees a transparent and untainted transfer of artefacts and evidence?

Task 3 explains the critical aspects of the Chain of Custody.

*Ensure proper documentation*

### Task 5  Introduction to FTK Imager

 Start Machine

Connecting to the machine

Start the virtual machine in split-screen view by clicking on the green **Start Machine** button on the upper right section of this task. If the VM is not visible, use the blue **Show Split View** button at the top-right of the page. Alternatively, you can connect to the VM via RDP using the credentials below if **Split View** does not work. 

![THM Key Credentials](https://tryhackme-images.s3.amazonaws.com/user-uploads/63588b5ef586912c7d03c4f0/room-content/be629720b11a294819516c1d4e738c92.png)

|   |   |
|---|---|
|**Username**|analyst|
|**Password**|DFIR321!|
|**IP**|MACHINE_IP|

  

**IMPORTANT:** The attached VM has a copy of the FTK Imager installation. **Proceed to work on the subsequent tasks, and experiment with FTK Imager through a case example.**

FTK Imager

|   |   |
|---|---|
|![FTK Imager Logo](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/cb64e7b1e02c87966c903d9f40ee2a08.png)|FTK Imager is a forensics tool that allows forensic specialists to acquire computer data and perform analysis without affecting the original evidence, preserving its authenticity, integrity, and validity for presentation during a trial in a court of law.|

**NOTE:** In a real-world scenario, a Forensics Lab Analyst will use a write-blocking device to mount the suspect drive / forensic artefact to prevent accidental tampering.

  

![Write-Blocking Device with the obtained flash drive plugged in](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/7bbef302d561e22537008c216c695cc2.png)

  

FTK Imager - User Interface (UI)

|   |
|---|
|FTK Imager includes vital UI components that are crucial to its functionality. These components are:<br><br>- **Evidence Tree Pane**: Displays a hierarchical view of the added evidence sources such as hard drives, flash drives, and forensic image files.<br>- **File List Pane:** Displays a list of files and folders contained in the selected directory from the Evidence Tree Pane.<br>- **Viewer Pane:** Displays the content of selected files in either the Evidence Tree Pane or the File List Pane.|

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/37252c1b0e6cec4f601a242f18484fd2.png)

  

Working with FTK Imager

**OBJECTIVES:** Verify encryption, obtain a forensic disk image, and analyse the recovered artefact.

**IMPORTANT:** The VM contains an emulated flash drive,**"\\PHYSICALDRIVE2 - Microsoft Virtual Disk [1GB SCSI]"**, to replicate the scenario where a physical drive, connected to a write blocker, is attached to an actual machine for forensic analysis. The steps performed in this activity are practically the same as in real-world situations. The write-protected flash drive is automatically attached to the VM upon startup.

STEP 1: Detecting EFS Encryption with FTK Imager  

**IMPORTANT:** The drive's file system must be NTFS to utilise EFS encryption. EFS encryption is not compatible with FAT32 or exFAT file systems.

A Forensics Lab Analyst can perform the following steps to detect the presence of EFS encryption on a physical drive:

1. Open **FTK Imager** and navigate to `File > Add Evidence Item`
    
    ![Adding an evidence item using FTK Imager](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/88ed441cbcafc54ad8b5c8dec6aed905.png)
    
      
      
    
2. Choose **Physical Drive** on the **Select Source** window, then click **Next**.
    
    ![Selecting a physical drive as an evidence source](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/cec6c1bc55012367443dce64401ab63e.png)
    
      
      
    
3. Choose **Microsoft Virtual Disk** (our virtual flash drive) on the **Select Drive** window, then click **Finish**.
    
    ![Choosing the forensic artefact from the scenario as the evidence source](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/a64bdbce76699e99de5829a6d6a5a9f2.png)
    
      
      
    
4. Navigate and click `File > Detect EFS Encryption` to scan the drive and detect the presence of encryption.
    
    ![Detecting EFS Encryption with FTK Imager on the forensic artefact](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/a0ec76d036d3e190af6995b7f58e855d.png)
    
      
      
    
5. A message box will indicate whether or not EFS encryption is on the attached drive.
    
    ![Result of Detecting EFS Encryption on the forensic artefact](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/73e789a98a7bbff0e761be604a0236b9.png)
    

Answer the questions below

```
EFS stands for "Encrypting File System," and it is a feature in some operating systems that provides transparent encryption of files and folders on a storage device. When EFS is enabled for a file or folder, the data is encrypted before being written to disk and decrypted when accessed, providing an additional layer of security for sensitive data.

EFS encryption uses a combination of asymmetric and symmetric encryption. Each file or folder has an associated file encryption key (FEK), which is used for symmetric encryption. The FEK is then encrypted using the public key of the user who encrypted the file, and this encrypted FEK is stored in the file's metadata. When a user wants to access the encrypted file, their private key is used to decrypt the FEK, which is then used to decrypt the file's contents.

EFS encryption is a powerful security feature that helps protect data at rest. However, it's important to note that EFS only protects data on the storage device. Data in transit or while it is being processed in memory is not covered by EFS. Additionally, it's crucial to manage and protect the private keys used in the encryption process to ensure the overall security of the system.
```

Start the attached VM, work on the subsequent tasks, and experiment with FTK Imager through a case example.

 Completed

What device will prevent tampering when acquiring a forensic disk image?

*write-blocking device*

What is the UI element of FTK Imager which displays a hierarchical view of the added evidence sources?  

*Evidence Tree Pane*

Is the attached flash drive encrypted? (Y/N)  

*N*

What is the UI element of FTK Imager which displays a list of files and folders?

*File List Pane*

### Task 6  Using FTK Imager to Acquire Digital Artefacts and Evidence

STEP 2: Creating a Forensic Disk Image with FTK Imager

A Forensics Lab Analyst can perform the following steps to create a forensic disk image from a physical drive:

1. Open **FTK Imager** and navigate to `File > Create Disk Image`
    
    ![Creating a frensic disk image with FTK Imager](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/0e7ea55370ea0332c7245ccde32068af.png)
    
      
      
    
2. Choose **Physical Drive** on the **Select Source** window, then click **Next**.
    
    ![Selecting a physical drive as an evidence source](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/cec6c1bc55012367443dce64401ab63e.png)
    
      
      
    
3. Choose **Microsoft Virtual Disk** (our virtual flash drive) on the **Select Drive** window, then click **Finish**.
    
    ![Choosing the forensic artefact from the scenario as the evidence source for forensic disk imaging](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/a64bdbce76699e99de5829a6d6a5a9f2.png)
    
      
      
    
4. Ensure you check **"Verify images after they are created"** and **"Create directory listings of all files in the image after they are created"** on the **Create Image** window. Press **Add** to open the **Select Image Type** window, choose **Raw (dd)**, then click **Next**.
    
    ![Enabling settings to verify the hash and create a directory list of the forensic disk image](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/38af98abce307957467524499b300d1a.png)
    
      
      
    
5. Enter case details in the **Evidence Item Information** window, then click **Next**.
    
    ![Entering case details in FTK Imager for the forensic disk image](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/c59a724295ea2b39ccf5f4b77d0da760.png)
    
      
      
    
6. Enter the **Image Destination Folder** and **Image Filename**, then click **Finish**.
    
    ![Setting the destination folder to save the forensic disk image](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/f4bf4cba837a3007cacea98f51d57c16.png)
    
      
      
    
7. Press **Start** to begin creating the _forensic disk image_.
    
    ![Starting the creation of a forensic disk image](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/1a178a908a7d958d6e599a6764a5d891.png)  
      
    ![Creating a Forensic Disk Image with FTK Imager](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/c3b45ce276a4dc72d14ed9bebe35f8fc.png)
    
      
      
    
8. When you check **"Verify images after they are created"**, FTK Imager will hash both the physical drive and the forensic disk image after disk imaging. It will then **validate if both hashes are equal to confirm a match**.
    
    ![Validating that the hash of the physical drive and the forensic disk image matches](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/2a50cfb87386c1d28892fe874223c4f4.png)
    

  

**Note:** You can go ahead and answer Question 1 and 2, then come back and follow along with the Step 3 section.

STEP 3: Mounting a Forensic Disk Image and Extracting Artefacts

A Forensics Lab Analyst can perform the following steps to mount a forensic disk image and extract artefacts using FTK Imager:

1. Open **FTK Imager** and navigate to `File > Add Evidence Item`
    
    ![Adding an evidence item using FTK Imager](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/88ed441cbcafc54ad8b5c8dec6aed905.png)
    
      
      
    
2. Choose **Image File** on the **Select Source** window, then click **Next**.
    
    ![Selecting an image file as an evidence source](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/85d9567493ee24ac1f13cfb434a429df.png)
    
      
      
    
3. Set **Evidence Source** to the path of the forensic disk image that we created previously and click **Finish**.
    
    ![Choosing the captured forensic disk image as the evidence source](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/6bcf66b86bbb01c667093d5f0ccca15e.png)
    
      
      
    
4. The **Evidence Tree Pane** will be populated, and artefacts will be visible on the **File List Pane**. The **Viewer Pane** will display the contents of selected elements for analysis.
    
    **IMPORTANT:** During forensic analysis with FTK Imager, it is always crucial to analyse using the forensic disk image that has been created. It is also equally important to look for signs of **deleted files (i.e., those with an x symbol)**, **corrupted files (e.g., 0 file size)** and **obfuscation (e.g., conflicting information about a file's extension and header information)**.
    
    ![FTK Imager UI when an evidence source has been mounted](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/c08e4d566d3ea219b2d28dbe915f716e.png)
    
      
      
    
5. To recover all deleted files, right-click on the target directory or file and press **Export Files** to save artefacts.
    
    ![Recovering deleted files by exporting them](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/d2f97b261a575cd76f84ba75021997c5.png)  
      
    ![Prompt upon successful export of files](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/da2529c7e7cdf4918269b911ddc8f002.png)  
      
    ![Navigating to the recovered files using Windows Explorer](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/48d1d5f31a7fa69336a8a52c3efc8092.png)
    

Answer the questions below

What is the UI element of FTK Imager which displays the content of selected files?  

*Viewer Pane*

What is the SHA1 hash of the physical drive and forensic image?  

*d82f393a67c6fc87a023b50c785a7247ab1ac395*

Including hidden files, how many files are currently stored on the flash drive?  

Use Windows Explorer and open the flash drive.

![[Pasted image 20230718134650.png]]

*8*

How many files were deleted in total?  

The x Symbol might be hard to see; look closely in the File List Pane.

![[Pasted image 20230718134755.png]]

*6*

How many recovered files are corrupted (e.g., 0 file size)?

*3*

### Task 7  Case B4DM755: At the Forensics Laboratory

Scenario (continuation)

Upon receiving the artefacts and evidence from the crime scene at the Forensics Lab, it is imperative to establish their authenticity. Since the DFIR First Responders recovered only a flash drive, you then proceed with the following actions:

- Verify and document every detail of the Chain of Custody form from the crime scene to the present.
- Use FTK Imager to create a forensic disk image of the seized flash drive from the suspect's (William S. McClean) residence in Case B4DM755.
- Match the cryptographic hashes of the physical drive and the acquired forensic image to guarantee the authenticity and integrity of the artefacts, making them admissible evidence in a court of law.
- Preserve the physical evidence (i.e., flash drive) for presentation in a court of law during trial after creating a forensic disk image.
- Perform any review and analysis on the created forensic disk image to avoid tampering with evidence.
- Document all examination operations and activities to ensure the admissibility of evidence in court.
- During a presentation at trial, ensure that the cryptographic hashes of the physical evidence and the forensic disk image MATCH.

![Commencing Digital Forensic Analysis at the Forensics Lab](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/4671303c6698961dc2e6becbb618e960.png)

Answer the questions below

Aside from FTK Imager, what is the directory name of the other tool located in the tools directory under Desktop?  

![[Pasted image 20230718135028.png]]

*exiftool-12.47*

What is the visible extension of the "hideout" file?

*.pdf*

View the metadata of the "hideout" file. What is its actual extension?

FTK Imager's Viewer Pane or exiftool can help.

```
C:\Users\dfir>cd C:\tools\exiftool-12.47

C:\tools\exiftool-12.47>dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\tools\exiftool-12.47

05/25/2023  02:23 PM    <DIR>          .
05/25/2023  02:23 PM    <DIR>          ..
10/04/2022  02:40 AM         8,903,384 exiftool.exe
               1 File(s)      8,903,384 bytes
               2 Dir(s)  27,171,061,760 bytes free

C:\tools\exiftool-12.47>exiftool.exe C:\Users\dfir\Desktop\artefacts\[root]\hideout.pdf
ExifTool Version Number         : 12.47
File Name                       : hideout.pdf
Directory                       : C:/Users/dfir/Desktop/artefacts/[root]
File Size                       : 4.7 MB
File Modification Date/Time     : 2022:09:11 04:31:48+00:00
File Access Date/Time           : 2023:03:31 21:02:26+00:00
File Creation Date/Time         : 2023:03:31 21:02:23+00:00
File Permissions                : -rw-rw-rw-
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
Exif Byte Order                 : Big-endian (Motorola, MM)
Make                            : OnePlus
Camera Model Name               : ONEPLUS A6013
Orientation                     : Horizontal (normal)
X Resolution                    : 72
Y Resolution                    : 72
Resolution Unit                 : inches
Modify Date                     : 2022:09:11 12:31:48
Y Cb Cr Positioning             : Centered
Exposure Time                   : 1/220
F Number                        : 1.7
Exposure Program                : Program AE
ISO                             : 100
Exif Version                    : 0220
Date/Time Original              : 2022:09:11 12:31:48
Create Date                     : 2022:09:11 12:31:48
Components Configuration        : Y, Cb, Cr, -
Shutter Speed Value             : 1/219
Aperture Value                  : 1.7
Brightness Value                : 2.87
Exposure Compensation           : 0
Max Aperture Value              : 1.7
Metering Mode                   : Multi-segment
Light Source                    : Unknown
Flash                           : Off, Did not fire
Focal Length                    : 4.3 mm
Sub Sec Time                    : 728794
Sub Sec Time Original           : 728794
Sub Sec Time Digitized          : 728794
Flashpix Version                : 0100
Color Space                     : sRGB
Exif Image Width                : 4608
Exif Image Height               : 3456
Interoperability Index          : R98 - DCF basic file (sRGB)
Interoperability Version        : 0100
Sensing Method                  : Not defined
Scene Type                      : Directly photographed
Exposure Mode                   : Auto
White Balance                   : Auto
Focal Length In 35mm Format     : 25 mm
Scene Capture Type              : Standard
Compression                     : JPEG (old-style)
Thumbnail Offset                : 900
Thumbnail Length                : 40889
XMP Toolkit                     : Adobe XMP Core 5.1.0-jc003
Capture Mode                    : Photo
Scene                           : AutoHDR
Is HDR Active                   : False
Is Night Mode Active            : False
Scene Detect Result Ids         : [60, 42]
Scene Detect Result Confidences : [0.99988556, 0.97189426]
Lens Facing                     : Back
Image Width                     : 4608
Image Height                    : 3456
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Aperture                        : 1.7
Image Size                      : 4608x3456
Megapixels                      : 15.9
Scale Factor To 35 mm Equivalent: 5.9
Shutter Speed                   : 1/220
Create Date                     : 2022:09:11 12:31:48.728794
Date/Time Original              : 2022:09:11 12:31:48.728794
Modify Date                     : 2022:09:11 12:31:48.728794
Thumbnail Image                 : (Binary data 40889 bytes, use -b option to extract)
Circle Of Confusion             : 0.005 mm
Field Of View                   : 71.5 deg
Focal Length                    : 4.3 mm (35 mm equivalent: 25.0 mm)
Hyperfocal Distance             : 2.08 m
Light Value                     : 9.3

or using FTK Imager

https://en.wikipedia.org/wiki/List_of_file_signatures

FF D8 FF E1 .jpg


```

![[Pasted image 20230718141113.png]]

![[Pasted image 20230718141656.png]]

*.jpg*

A phone was used to photograph the "hideout". What is the phone's model?  

*ONEPLUS A6013*

A phone was used to photograph the "warehouse". What is the phone's model?  

![[Pasted image 20230718141316.png]]

![[Pasted image 20230718141735.png]]

*Mi 9 Lite*

Are there any indications that the suspect is involved in other illegal activity? (Y/N)

One obfuscated file is a zip file, change the file extension and unpack it.

```
https://en.wikipedia.org/wiki/List_of_file_signatures

50 4B 03 04 ZIP


```

![[Pasted image 20230718141846.png]]

![[Pasted image 20230718141932.png]]

*y*

Who was the point of contact of Mr William S. McClean in 2022?

```
==========================================================

CSSC Annual Meetup: 09-09 / 9th of September
Topic: Product Distribution Schedule


==========================================================

Shipment Details:
- Schedule: 3rd day of every month
- Products: 0days, Trojans, Ransomware, Backdoors, Rootkits

> Year: 2020
  - Total Profits: $824,156,789.31
  - Meetup: 14°32'29.3"N 120°58'43.6"E
  - PoC: Rodrigo Lopez Cabrerra / 09985675432 / gangmemberone@gmail.com

> Year: 2021
  - Total Profits: $983,234,654.86
  - Meetup: 14°35'31.3"N 120°57'22.2"E
  - PoC: Karl Renato Abelardo / 09124329876 / karlrenatoabelardo@gmail.com

> Year: 2022
  - Total Profits: $1,092,564,789.23
  - Meetup: 14°26'25.7"N 120°59'00.8"E
  - PoC: Karl Renato Abelardo / 09124329876 / karlrenatoabelardo@gmail.com


==========================================================

Underground Community Creds:
- DarkPool Marketplace: SerpentWhisperer86 / Cr1m$0nSh@d0w$3rp3nt5
- Menacingly Marketplace: KingCrimson201 / Sh@d0wSerp3nt$C4rt3l


==========================================================

Send email to Mr. DeVentura and Mr. Durr Alessio later.

-----------------------------------------------
Subject: Task Completed - All Traces Erased
Message:

Mr. DeVentura, Mr. Durr Alessio,

I am pleased to inform you that the requested task has been successfully executed. You can now rest assured that all tracks with our counter-parties and other institutions have been meticulously cleaned, leaving no traces behind. Please feel free to reach out if you need any further assistance.

Best regards,

William, WSM
-----------------------------------------------

DarkVault$Pandora=DONOTOPEN!K1ngCr1ms0n!


```

*Karl Renato Abelardo*

A meetup occurred in 2022. What are the GPS coordinates during that time?  

![[Pasted image 20230718142249.png]]

*14°26'25.7"N 120°59'00.8"E*

What is the password to extract the contents of pandorasbox.zip?

*DarkVault$Pandora=DONOTOPEN!K1ngCr1ms0n!*

From which company did the source code in the pandorasbox directory originate?

```
C:\Users\dfir\AppData\Local\Temp\2\Temp1_operations.zip\operations\pandorasbox.zip\pandorasbox\HFT_Algorithm

#!/usr/bin/python3
# ---------------------------------------------------------------------------
# Filename: main.py
# Author: Perry Parsons
# Company: SwiftSpend Financial
# Creation Date: November 1, 2005
# Modification Date: November 30, 2005
# Description: Main entry point for the High-Frequency Trading algorithm.
# File Labeling: CONFIDENTIAL AND PROPRIETARY
# ---------------------------------------------------------------------------

import threading
import time
from config import settings, trading_parameters
from data.market_data import MarketDataHandler
from data.historical_data import HistoricalDataHandler
from execution.execution_handler import ExecutionHandler
from execution.order_manager import OrderManager
from models.example_strategy import ExampleStrategy
from models.risk_management import RiskManagement

def run_trading_loop(strategy, market_data_handler, historical_data_handler, risk_management, order_manager, execution_handler):
    # Main trading loop
    while True:
        # Implement your trading logic here
        # For example, fetch market data and generate trading signals based on the strategy
        signal = strategy.generate_signal(market_data_handler)
        
        if signal:
            proposed_order = order_manager.create_order(signal['action'], trading_parameters.TRADE_SIZE)
            
            # Check risk and execute the order if it passes the risk management criteria
            if risk_management.check_risk(proposed_order):
                execution_handler.execute_order(signal['action'], trading_parameters.TRADE_SIZE)

        time.sleep(1)

if __name__ == "__main__":
    market_data_handler = MarketDataHandler()
    historical_data_handler = HistoricalDataHandler()
    execution_handler = ExecutionHandler()
    order_manager = OrderManager()
    strategy = ExampleStrategy()
    risk_management = RiskManagement()

    # Connect to IBKR TWS or Gateway
    market_data_handler.connect(settings.IBKR_HOST, settings.IBKR_PORT, settings.IBKR_CLIENT_ID)
    historical_data_handler.connect(settings.IBKR_HOST, settings.IBKR_PORT, settings.IBKR_CLIENT_ID + 1)
    execution_handler.connect(settings.IBKR_HOST, settings.IBKR_PORT, settings.IBKR_CLIENT_ID + 2)

    # Start the trading loop
    trading_thread = threading.Thread(target=run_trading_loop, args=(strategy, market_data_handler, historical_data_handler, risk_management, order_manager, execution_handler))
    trading_thread.start()

    # Run the message loops for the API connections
    market_data_handler.run()
    historical_data_handler.run()
    execution_handler.run()


```

*SwiftSpend Financial*

In one of the documents that the suspect has yet to sign, who was listed as the beneficiary?

![[Pasted image 20230718142734.png]]

*Mr. Giovanni Vittorio DeVentura*

What is the hidden flag?

![[Pasted image 20230718142814.png]]

*THM{sCr0LL_sCr0LL_cL1cK_cL1cK_4TT3NT10N_2_D3T41L5_15_CRUC14L!!}*

### Task 8  Post-Analysis of Evidence to Court Proceedings

If there is reasonable suspicion that the suspect possesses and distributes these materials, the law enforcement agency handling the case must follow these **4 Phases of Investigation**. Additionally, the DFIR First Responder must observe the following steps before, during, and after acquiring digital artefacts and evidence:

|   |   |
|---|---|
|**Pre-search**<br><br>- Send a request to preserve the data and logs of the suspect to social media networks (subscriber's information, traffic, and content data).<br>- Send a request to preserve the data and logs of the suspect to ISPs (subscriber's information, traffic, and content data).<br>- Obtain a warrant for search, seizure, and examination of the suspect's computer data for violation of domestic and international laws.<br>- Perform an inspection of the suspect's social media accounts and public profiles.|![Court room judge smashing the hammer](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/d261e70b9c317d14c34f6daaa5d3bcd3.png)|

|   |   |
|---|---|
|![Lawyers arguing at the courtroom](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/7cc977da5055d34ed19fe07f34a69b32.png)|**Search**<br><br>- By a warrant issued by a court of law, obtain data requested from social media networks and ISPs.<br>- Perform search, seizure, and examination of the suspect's computer data.<br><br>  <br><br>**Post-search**<br><br>- Perform forensic analysis of acquired digital artefacts & evidence.<br><br>  <br><br>**Trial**<br><br>- Present forensic artefacts & evidence together with proper documentation during court proceedings.|

  

![The End](https://tryhackme-images.s3.amazonaws.com/user-uploads/63da722f2d207d0049da10b1/room-content/d43112342917d7e842f10392db250d11.png)

Answer the questions below

In which phase is a warrant obtained for search, seizure, and examination of the suspect's computer data due to violations of domestic and international laws?  

*Pre-search*

In which phase is a forensic analysis performed on the acquired digital evidence requested from various sources?

*Post-search*

Which phase involves presenting forensic artefacts and evidence with proper documentation in a court of law?

*Trial*



[[Templated]]