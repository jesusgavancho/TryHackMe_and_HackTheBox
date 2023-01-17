---
Provide understanding to Sigma, a Generic Signature Format for SIEM Systems.
---

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/2cdd7c4c0da4c5f1c890b8406c30c363.png)

![](https://assets.tryhackme.com/room-banners/sigma.png)


###  Introduction

Introduction

Detection engineering is an important role and task for a security analyst. It involves developing processes that will guide you as an analyst to identify threats before they cause any harm to an environment through the use of rules. This room will introduce you to Sigma, an open-source generic signature language used to write detection rules applicable across different SIEM backends.

  

Learning Objectives  

-   Introduction to the Sigma rule language.
-   Learn about Sigma Rule writing syntax and conversion to various SIEM query languages.
-   Navigate through writing rules for various detections on Windows Event Logs.
-   Practice writing Sigma rules for an interactive case.

Prerequisites

It is advisable to check out the following rooms to understand the defensive security operations that would be useful for a security analyst during threat detection.

-   [Security Operations](https://tryhackme.com/room/securityoperations)
-   [Windows Event Logs](https://tryhackme.com/room/windowseventlogs)
-   [Sysmon](https://tryhackme.com/room/sysmon)
-   [Splunk 101](https://tryhackme.com/room/splunk101)
-   [Investigating with ELK 101](https://tryhackme.com/room/investigatingwithelk101)

### What is Sigma?

Through log monitoring and analysis, SOC analysts are tasked with collecting, analysing and extracting as much usable information from logs and using it to build detection queries and searches for their environments. However, on most occasions, it becomes challenging to standardise investigations and have the ability to share them with other analysts for detection enrichment. Sharing Indicators of compromise (IOC) and signatures may not be enough, as log events are often left unattended. Here is where Sigma seeks to bridge the gap.

[Sigma](https://github.com/SigmaHQ/sigma) is an open-source generic signature language developed by Florian Roth & Thomas Patzke to describe log events in a structured format. This allows for quick sharing of detection methods by security analysts. It is mentioned that **"Sigma is for log files as Snort is for network traffic, and Yara is for files."**

Sigma makes it easy to perform content matching based on collected logs to raise threat alerts for analysts to investigate. Log files are usually collected and stored in a database or SIEM solution for further analysis.

### Sigma Use Cases

Sigma was developed to satisfy the following uses:

-   To make detection methods and signatures shareable alongside IOCs and Yara rules.
-   To write SIEM searches that avoid vendor lock-in.
-   To share signatures with threat intelligence communities.
-   To write custom detection rules for malicious behaviour based on specific conditions.

### Sigma Development Process

As a SOC analyst, the process of using Sigma to write up your detection rules will involve understanding the elements mentioned below:

-   **Sigma Rule Format:** Generic structured log descriptions written in YAML.
-   **Sigma Converter:** A set of python scripts that will process the rules on the backend and perform custom field matching based on specified SIEM query language.
-   **Machine Query:** Resulting search query to filter out alerts during investigations. The query will be based on the specified SIEM.

The [Sigma GitHub repo](https://github.com/SigmaHQ/sigma) provides information about the project, public rules, tests and conversion tools. Please have a look at the project as we progress through the room.

![Analyst Tuning Rules for different SIEM outputs](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/3ca5f3390de82a626b59a4a02ce2ef1d.png)

### Sigma Rule Syntax

 Download Task Files

As indicated in the previous task, Sigma rules are written in YAML Ain't Markup Language ([YAML](http://yaml.org/)), a data serialisation language that is human-readable and useful for managing data. It's often used as a format for configuration files, but its object serialisation abilities make it a substitute for languages like JSON.

Common factors to note about YAML files are:

-   YAML is case-sensitive.
-   Files should have the `.yml` extension.
-   Spaces are used for indentation and not tabs.
-   Comments are attributed using the `#` character.
-   Key-value pairs are denoted using the colon `:` character.
-   Array elements are denoted using the dash `-` character.

[QuickYAML Guide](https://www.tutorialspoint.com/yaml/yaml_quick_guide.htm)

### Sigma Syntax

![Sigma Syntax template](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/9e7c91812a16cd85cccf3671ff8027ee.png)Following the understanding of using YAML for Sigma rules, the syntax defines various mandatory and optional fields that go into every rule. This can be highlighted using the image:

Let us use an example of a WMI Event Subscription [rule](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/wmi_event/sysmon_wmi_event_subscription.yml) to define the different syntax elements. Download the attached task file, and open it in a text editor to go through this room's rule syntax and rule writing sections.

-   **Title:** Names the rule based on what it is supposed to detect. This should be short and clear.
    
-   **ID:** A globally unique identifier mainly used by the developers of Sigma to maintain the order of identification for the rules submitted to the public repository, found in UUID format. 
    
    You may also add references to related rule IDs using the _related_ attribute, making it easier to form relationships between detections. These relations would fall under the following types:
    
    -   Derived: This will describe that the rule has sprung from another rule, which may still be active.
    -   Obsolete: This will indicate that the listed rule is no longer being used.
    -   Merged: This will indicate that the rule combines linked rules.
    -   Renamed: This indicates the rule was previously identified under a different ID but has now been changed due to changes in naming schemes or avoiding collisions. 
    -   Similar: This attribute points to corresponding rules, such as indicating the same detection content applied to different log sources.

  

-   **Status:** Describes the stage in which the rule maturity is at while in use. There are five declared statuses that you can use:  
    

-   _Stable_: The rule may be used in production environments and dashboards.
-   _Test_: Trials are being done to the rule and could require fine-tuning.
-   _Experimental_: The rule is very generic and is being tested. It could lead to false results, be noisy, and identify interesting events.
-   _Deprecated_: The rule has been replaced and would no longer yield accurate results. The`related` field is used to create associations between the current rule and one that has been deprecated.
-   _Unsupported_: The rule is not usable in its current state (unique correlation log, homemade fields).

  

-   **Description:** Provides more context about the rule and its intended purpose. With the rule, you can be as verbose as possible on the malicious activity you intend to detect.  
    

WMI_Event_Subscription.yml

```shell-session
title: WMI Event Subscription
id: 0f06a3a5-6a09-413f-8743-e6cf35561297
status: test
description: Detects creation of WMI event subscription persistence method.
```

-   **Logsource:** Describes the log data to be used for the detection. It consists of other optional attributes:  
    
    -   _Product_: Selects all log outputs of a particular product. Examples are Windows, Apache.
    -   _Category_: Selects the log files written by the selected product. Examples are firewall, web, and antivirus.
    -   _Service_: Selects only a subset of the logs from the selected product. Examples are _sshd_ on Linux or _Security_ on Windows.
    -   _Definition_: Describes the log source and any applied configurations.
    
      
    

WMI_Event_Subscription.yml

```shell-session
logsource:
   product: windows    
   category: wmi_event 
      
```

-   **Detection:** A required field in the detection rule describes the parameters of the malicious activity we need an alert for. The parameters are divided into two main parts: the search identifiers - the fields and values that the detection should be searching for -  and condition expression - which sets the action to be taken on the detection, such as selection or filtering. More on this is below.
    
    This rule has a detection modifier that looks for logs with one of Windows Event IDs 19, 20 or 21. The condition informs the detection engine to match and select the identified logs.
    

WMI_Event_Subscription.yml

```shell-session
detection:
  selection:
    EventID:  # This shows the search identifier value
      - 19    # This shows the search's list value
      - 20
      - 21
  condition: selection
```

-   **FalsePositives:** A list of known false positive outputs based on log data that may occur.
    
-   **Level:** Describes the severity with which the activity should be taken under the written rule. The attribute comprises five levels: Informational -> Low -> Medium -> High -> Critical
    
-   **Tags:** Adds information that may be used to categorise the rule. Tags may include values for CVE numbers and tactics and techniques from the MITRE ATT&CK framework. Sigma developers have defined a list of [predefined tags](https://github.com/SigmaHQ/sigma/wiki/Tags).
    

WMI_Event_Subscription.yml

```shell-session
falsepositives:
    - Exclude legitimate (vetted) use of WMI event subscription in your network

level: medium

tags:
  - attack.persistence # Points to the MITRE tactic.
  - attack.t1546.003   # Points to the MITRE technique.      
       
```

### Search Identifiers and Condition Expressions

As mentioned earlier, the detection section of the rule describes what you intend to search for within the log data and how the selection and filters are to be evaluated. The definition of the search identifiers can comprise two data structures - **lists and maps** - which dictate the order in which the detection would be processed.

When the identifiers are provided using lists, they will be presented using strings linked with a logical **'OR'** operation. Mainly, they will be listed using hyphens (-). For example, below, we can look at an extract of the [Netcat Powershell Version rule](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_classic/posh_pc_powercat.yml) where the detection is written to match on the `HostApplication` field containing 'powercat' or 'powercat.ps1' as its value.

Posh_PC_Powercat.yml

```shell-session
detection:
  selection:
    HostApplication|contains:
         - 'powercat'
         - 'powercat.ps1'
  condition: selection     
      
```

On the other hand, maps comprise key/value pairs where the key matches up to a field in the log data while the value presented is a string or numeral value to be searched for within the log. Maps follow a logical **'AND'** operation.

As an example, we can look at the [Clear Linux log rule](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_clear_logs.yml) where the `selection` term forms the map, and the rule intends to match on `Image|endswith` either of the values listed, AND `CommandLine` contains either value listed. This example shows how maps and lists can be used together when developing detections. It should be noted that `endswith` and `contains` are value modifiers, and two lists are used for the search values, where one of each group has to match for the rule to initiate an alert. 

Process_Creation_Lnx_Clear_Logs.yml

```shell-session
detection:
  selection:
    Image|endswith:
         - '/rm' # covers /rmdir as well
         - '/shred'
    CommandLine|contains:
         - '/var/log'
         - '/var/spool/mail'
  condition: selection
```

As we have mentioned the value modifier, it is worth noting that they are appended after the field name with a pipe character (|), and there are two types of value modifiers:

-   **Transformation modifiers:** These change the values provided into different values and can modify the logical operations between values. They include:
    
    -   _contains:_ The value would be matched anywhere in the field.
    -   _all:_ This changes the OR operation of lists into an AND operation. This means that the search conditions has to match all listed values.
    -   _base64:_ This looks at values encoded with Base64.
    -   _endswith:_ With this modifier, the value is expected to be at the end of the field. For example, this is representative of `*\cmd.exe`.
    -   _startswith:_ This modifier will match the value at the beginning of the field. For example, `power*`.
-   **Type modifiers:** These change the type of the value or sometimes even the value itself. Currently, the only usable type modifier is `re`, which is supported by Elasticsearch queries to handle the value as a regular expression.

For conditions, this is based on the names set for your detections, such as _selection and_ _filter,_ and will determine the specification of the rule based on a selected expression. Some of the terms supported include:

-   **Logical AND/OR**
-   **1/all of search-identifier**
-   **1/all of them**
-   **not**

An example of these conditional values can be seen in the extract below from the [Remote File Copy rule](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/builtin/lnx_file_copy.yml), where the detection seeks to look for either of the tools: `scp`, `rsync` or `sftp` and with either filter values `@` or `:`.

Remote_File_Copy.yml

```shell-session
detection:
  tools:
         - 'scp'
         - 'rsync'
         - 'sftp'
  filter:
         - '@'
         - ':'
  condition: tools and filter
```

Another example to showcase a combination of the conditional expressions can be seen in the extract below from the [Run Once Persistence Registry Event rule](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_event/registry_event_runonce_persistence.yml), where the detection seeks to look for values on the map that start and end with various registry values while filtering out Google Chrome and Microsoft Edge entries that would raise false positive alerts.

Registry_Event_RunOnce_Persistence.yml

```shell-session
detection:
  selection:
    TargetObject|startswith: 'HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components'
    TargetObject|endswith: '\StubPath'
  filter_chrome:
    Details|startswith: '"C:\Program Files\Google\Chrome\Application\'
    Details|endswith: '\Installer\chrmstp.exe" --configure-user-settings --verbose-logging --system-level'
  filter_edge:
    Details|startswith:
    - '"C:\Program Files (x86)\Microsoft\Edge\Application\'
    - '"C:\Program Files\Microsoft\Edge\Application\'
    Details|endswith: '\Installer\setup.exe" --configure-user-settings --verbose-logging --system-level --msedge 
    --channel=stable'
  condition: selection and not 1 of filter_*
```

Click the link to find more information about the [Sigma syntax specification.](https://github.com/SigmaHQ/sigma/wiki/Specification)

Answer the questions below

Which status level could lead to false results or be noisy, but could also identify interesting events?

*experimental*

The rule detection comprises two main elements: __ and condition expressions.

*search identifiers*

What two data structures are used for the search identifiers?

answer1 and answer2

*lists and maps*


### Rule Writing & Conversion

 Start Machine

After going through the basic syntax of Sigma rules, it is crucial to understand how to write them based on a threat investigation. As a SOC analyst, you must go through the thought process of developing your detection and writing the rules appropriate for your environment. We shall use the scenario below to go through this process.

Start up the attached machine and give it 5 minutes to load. Login to the Kibana dashboard on [http://MACHINE_IP/](http://machine_ip/), which has been populated with logs for testing the detection rules written in this task and the practical scenario in task 6. Use the credentials **THM_Analyst: THM_Analyst1234.** Deploy the AttackBox and log in to the Kibana dashboard using Firefox.

### Scenario

![Image showing intel on the malicious use of AnyDesk.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/8599f0378042bcfa6680158b3f1ff759.png)Administrators rely on remote tools to ensure devices are configured, patched and maintained. However, your SOC Manager just received and shared intel on how AnyDesk, a legitimate remote tool, can be downloaded and installed silently on a user's machine using the file description on the right-hand side. (Source: [TheDFIRReport](https://twitter.com/TheDFIRReport/status/1423361127472377860?s=20&t=mHiJFnlfWH3cO3XdXEQo_Q)). As a SOC analyst, you have been tasked to analyse the intel and write a Sigma rule to detect the installation of AnyDesk on Windows devices.

You should use the SIGMA specification file downloaded from Task 3  as a basis for writing the rule. If you are using the AttackBox, the file is available in the directory `/root/Rooms/sigma/Sigma_Rule_File.yml`.

#### Step 1: Intel Analysis

The shared intel shows us a lot of information and commands to download and install AnyDesk. An adversary could wrap this up in a malicious executable sent to an unsuspecting user through a phishing email. We can start picking out values that would be important for detecting any occurrence of an installation.

-   Source URL: This marks the download source for the software, highlighted by the $url variable.
-   Destination File: The adversary would seek to identify a destination directory for the download. This is marked by the $file variable.
-   Installation Command: From the intel, we can see that various instances of `CMD.exe` are being used to install and set a user password by the script. From this, we can pick out the installation attributes such as `--install`, `--start-with-win` and `--silent`.

Other essential pieces of information from the intel would include:

-   Adversary Persistence: The adversary would seek to maintain access to the victim's machine. In this instance, they would create a user account `oldadministrator` and give the user elevated privileges to run other tasks.
-   Registry Edit: We can also pick out the registry edit, where the added user is added to a `SpecialAccounts` user list.

With this information, we can evaluate the creation of a rule to aid in detecting when an installation has taken place.

#### Step 2: Rule Identification

We can start building our rule by filling in the Title and Description sections, given the information that we are looking for an AnyDesk remote tool installation. Let us also set the status as `experimental` , as this rule will be tested internally.

Process_Creation_AnyDesk_Installation.yml

```shell-session
title: AnyDesk Installation
status: experimental
description: AnyDesk Remote Desktop installation can be used by attacker to gain remote access.
```

#### Step 3: Log Source

As indicated from our intel, Windows devices would be our targetted device. Windows Eventlog and Sysmon provide events such as process creation and file creation. Our case focuses on the creation of an installation process, thus listing our logsource category as `process_creation.`

Process_Creation_AnyDesk_Installation.yml

```shell-session
logsource:
    category: process_creation
    product: windows
```

#### Step 4: Detection Description

The detection section of our rule is the essential part. The information derived from the intel will define what we need to detect within our environment. For the AnyDesk installation, we noted the installation commands that would be used by the adversary that contains the strings: `install`, and `start-with-win`. We can therefore write our search identifiers as below with the modifiers `contains` and `all` to indicate that the rule will match all those values.

Additionally, we can include searching for the current directory where the commands will be executed from, `C:\ProgramData\AnyDesk.exe`

For our condition expression, this evaluates the selection of our detection.

Process_Creation_AnyDesk_Installation.yml

```shell-session
detection:
    selection:
        CommandLine|contains|all: 
            - '--install'
            - '--start-with-win'
        CurrentDirectory|contains:
            - 'C:\ProgramData\AnyDesk.exe'
    condition: selection
```

#### Step 5: Rule Metadata

After adding the required and vital bits to our rule, we can add other helpful information under level, tags, references and false positives. We can reference the MITRE ATT&CK Command and Control tactic and its corresponding [T1219](https://attack.mitre.org/techniques/T1219/) technique for tags.

With this, we have our rule, which we can now convert to the SIEM query of our choice and test the detection.

Process_Creation_AnyDesk_Installation.yml

```shell-session
falsepositives:
    - Legitimate deployment of AnyDesk
level: high
references:
    - https://twitter.com/TheDFIRReport/status/1423361119926816776?s=20
tags:
    - attack.command_and_control
    - attack.t1219
```

### Rule Conversion

Sigma rules need to be converted to the appropriate SIEM target that is being utilised to store all the logs. Using the rule we have written above, we shall now learn how to use the sigmac and uncoder.io tools to convert them into ElasticSearch and Splunk queries.

#### Sigmac

[Sigmac](https://github.com/SigmaHQ/sigma/tree/8bb3379b6807610d61d29db1d76f5af4840b8208/tools) is a Python-written tool that converts Sigma rules by matching the detection log source field values to the appropriate SIEM backend fields. As part of the Sigma repo (Advisable to clone the repo to get the tool and all the available rules published by the Sigma team), this tool allows for quick and easy conversion of Sigma rules from the command line. Below is a snippet of how to use the tool through its help command, and we shall display the basic syntax of using the tool by converting the AnyDesk rule we have written to the Splunk query.

Note: Sigmac will be deprecated by end of 2022, and attention from the owners will shift to sigma-cli. However, a copy of Sigmac is available on the AttackBox, and you can initiate the use of the tool for the rest of the room using `python3.9 root/Rooms/sigma/sigma/tools/sigmac`.

  

Sigmac Help Options

```shell-session
SecurityNomad@THM:~# cd /root/Rooms/sigma/sigma/tools/
SecurityNomad@THM:~/Rooms/sigma/sigma/tools# python3.9 sigmac -h

usage: sigmac [-h] [--recurse] [--filter FILTER]
              [--target {chronicle,kibana-ndjson,sumologic,sumologic-cse,es-rule-eql,athena,carbonblack,limacharlie,netwitness,csharp,hawk,opensearch-monitor,powershell,ala-rule,elastalert,sql,xpack-watcher,netwitness-epl,ala,lacework,logiq,qualys,sysmon,arcsight-esm,fireeye-helix,hedera,fortisiem,humio,kibana,mdatp,grep,streamalert,sumologic-cse-rule,uberagent,es-qs-lr,es-eql,es-dsl,es-rule,sqlite,stix,fieldlist,devo,es-qs,splunkxml,logpoint,datadog-logs,splunkdm,qradar,sentinel-rule,crowdstrike,elastalert-dsl,arcsight,ee-outliers,splunk,graylog}]
              [--lists] [--lists-files-after-date LISTS_FILES_AFTER_DATE]
              [--config CONFIG] [--output OUTPUT]
              [--output-fields OUTPUT_FIELDS] [--output-format {json,yaml}]
              [--output-extention OUTPUT_EXTENTION] [--print0]
              [--backend-option BACKEND_OPTION]
              [--backend-config BACKEND_CONFIG] [--backend-help BACKEND_HELP]
              [--defer-abort] [--ignore-backend-errors] [--verbose] [--debug]
              [inputs [inputs ...]]

Convert Sigma rules into SIEM signatures.
```

  

The main options to be used are:

-   -t: This sets the targeted SIEM backend you wish to get queries for (Elasticsearch, Splunk, QRadar, ElastAlert).
-   -c: This sets the configuration file used for the conversion. The file handles the field mappings between the rule and the target SIEM environment, ensuring that the necessary fields are correct for performing investigations on your environment.
-   --backend-option: This allows you to pass a backend configuration file or individual modifications that dictate alert options for the target SIEM environment. For example, in ElasticSearch, we can specify specific field properties to be our primary keyword_field to be searched against, such as fields that end in the `.keyword` or `.security` fields below:

Sigmac ElasticSearch Conversion

```shell-session
SecurityNomad@THM:~/Rooms/sigma/sigma/tools# python3.9 sigmac -t es-qs -c tools/config/winlogbeat.yml --backend-option keyword_field=".keyword" --backend-option analyzed_sub_field_name=".security" ../rules/windows/sysmon/sysmon_accessing_winapi_in_powershell_credentials_dumping.yml

(winlog.channel.security:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id.security:("8" OR "10") AND winlog.event_data.SourceImage.keyword:*\\powershell.exe AND winlog.event_data.TargetImage.keyword:*\\lsass.exe)
```

You can find more information through the [Sigmac documentation](https://github.com/SigmaHQ/sigma/blob/master/tools/README.md). We can convert our AnyDesk Installation rule  to a Splunk alert as shown below:

Sigmac Splunk Conversion

```shell-session
SecurityNomad@THM:~/Rooms/sigma/sigma/tools# python3.9 sigmac -t splunk -c splunk-windows Process_Creation_AnyDesk_Installation.yml

(CommandLine="*--install*" CommandLine="*--start-with-win*" (CurrentDirectory="*C:\\ProgramData\\AnyDesk.exe*"))
```

Sigma developers are working on a python library that will be Sigmac's replacement, known as [pySigma](https://github.com/SigmaHQ/pySigma).  

  

#### Uncoder.io

[Uncoder.IO](https://uncoder.io/) is an open-source web Sigma converter for numerous SIEM and EDR platforms. It is easy to use as it allows you to copy your Sigma rule on the platform and select your preferred backend application for translation.

We can copy our rule and convert it into different queries of our choice. Below, the rule has been converted into Elastic Query, QRadar and Splunk. You can copy the translation into the SIEM platform to test for any matches.

![Images showing the use of Uncoder.io to convert a Sigma Rule.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5fc2847e1bbebc03aa89fbf2/room-content/0ac9b68040fceb58d0aef7731575f81b.gif)  

Convert the AnyDesk Installation Sigma rule we have written throughout this task to an Elastic Query and use it to analyse log data from the launched machine on the Kibana dashboard. Use the information found to answer the following questions.

**TIP: Be aware that the converted queries may not all work verbatim as converted from the tools. This is due to the processing of regex characters (\,*), and you may be required to adjust the queries, especially around escaped blank space. For example, for this exercise, you have to remove the * characters from the result and only escape the colon (:) in the folder path and the directory slashes.**

Answer the questions below

```
┌──(kali㉿kali)-[~/Downloads]
└─$ nano Process_Creation_AnyDesk_Installation.yml
                                                                                      
┌──(kali㉿kali)-[~/Downloads]
└─$ cat Process_Creation_AnyDesk_Installation.yml 
title: AnyDesk Installation
status: experimental
description: AnyDesk Remote Desktop installation can be used by attacker to gain remote access.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all: 
            - '--install'
            - '--start-with-win'
        CurrentDirectory|contains:
            - 'C:\ProgramData\AnyDesk.exe'
    condition: selection
falsepositives:
    - Legitimate deployment of AnyDesk
level: high
references:
    - https://twitter.com/TheDFIRReport/status/1423361119926816776?s=20
tags:
    - attack.command_and_control
    - attack.t1219


(process.command_line.text:*\-\-install* AND process.command_line.text:*\-\-start\-with\-win* AND process.working_directory.text:*C\:\\ProgramData\\AnyDesk.exe*)

login: **THM_Analyst: THM_Analyst1234**

then search : 1 year before

(process.command_line.text:--install AND process.command_line.text:--start-with-win AND process.working_directory.text:C\:\\ProgramData\\AnyDesk.exe)

and find 1 result

{
  "_index": ".ds-winlogbeat-8.2.3-2022.06.27-000001",
  "_id": "kVdlrIEB3iMYFrgzf9-i",
  "_version": 1,
  "_score": 1,
  "_source": {
    "agent": {
      "name": "THM_Aurora_Test",
      "id": "ba6b17a6-3ca3-45a9-b4b2-fc995ab1c73a",
      "type": "winlogbeat",
      "ephemeral_id": "c483a7ab-6222-40f5-af9e-467e53880dac",
      "version": "8.2.3"
    },
    "process": {
      "args": [
        "C:\\Users\\Administrator\\Desktop\\AnyDesk.exe",
        "--install",
        "C:\\Program Files (x86)\\AnyDesk",
        "--start-with-win",
        "--create-shortcuts",
        "--create-taskbar-icon",
        "--create-desktop-icon",
        "--install-driver:mirror",
        "--update-disabled",
        "--svc-conf",
        "C:\\Users\\Administrator\\AppData\\Roaming\\AnyDesk\\service.conf",
        "--sys-conf",
        "C:\\Users\\Administrator\\AppData\\Roaming\\AnyDesk\\system.conf"
      ],
      "parent": {
        "args": [
          "C:\\Users\\Administrator\\Desktop\\AnyDesk.exe",
          "/S"
        ],
        "name": "AnyDesk.exe",
        "pid": 1392,
        "args_count": 2,
        "entity_id": "{c5d2b969-7bf0-62bb-0103-000000001f01}",
        "executable": "C:\\Users\\Administrator\\Desktop\\AnyDesk.exe",
        "command_line": "\"C:\\Users\\Administrator\\Desktop\\AnyDesk.exe\" /S "
      },
      "pe": {
        "file_version": "7.0.10",
        "product": "AnyDesk",
        "description": "AnyDesk",
        "original_file_name": "-",
        "company": "AnyDesk Software GmbH"
      },
      "name": "AnyDesk.exe",
      "pid": 2612,
      "working_directory": "C:\\Users\\Administrator\\Desktop\\",
      "args_count": 13,
      "entity_id": "{c5d2b969-7e54-62bb-0603-000000001f01}",
      "hash": {
        "sha1": "9779751121508f17cbd831e9c2780b4cf0e1b96c",
        "sha256": "d7b9f1141c649c08254a4978f98211a5ab3b10591693fcf271409e36beae2933",
        "md5": "0dbe3504bc5daa73e7b3f75bbb104e42"
      },
      "executable": "C:\\Users\\Administrator\\Desktop\\AnyDesk.exe",
      "command_line": "\"C:\\Users\\Administrator\\Desktop\\AnyDesk.exe\" --install \"C:\\Program Files (x86)\\AnyDesk\"  --start-with-win --create-shortcuts --create-taskbar-icon --create-desktop-icon --install-driver:mirror --update-disabled --svc-conf \"C:\\Users\\Administrator\\AppData\\Roaming\\AnyDesk\\service.conf\"  --sys-conf \"C:\\Users\\Administrator\\AppData\\Roaming\\AnyDesk\\system.conf\" "
    },
    "winlog": {
      "computer_name": "THM_Aurora_Test",
      "process": {
        "pid": 3528,
        "thread": {
          "id": 2908
        }
      },
      "channel": "Microsoft-Windows-Sysmon/Operational",
      "event_data": {
        "Company": "AnyDesk Software GmbH",
        "LogonGuid": "{c5d2b969-7ee7-62b9-4833-170000000000}",
        "Description": "AnyDesk",
        "TerminalSessionId": "2",
        "IntegrityLevel": "High",
        "ParentUser": "THM_AURORA_TEST\\Administrator",
        "Product": "AnyDesk",
        "FileVersion": "7.0.10",
        "LogonId": "0x173348"
      },
      "opcode": "Info",
      "version": 5,
      "record_id": "9284",
      "event_id": "1",
      "task": "Process Create (rule: ProcessCreate)",
      "provider_guid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
      "api": "wineventlog",
      "provider_name": "Microsoft-Windows-Sysmon",
      "user": {
        "identifier": "S-1-5-18",
        "domain": "NT AUTHORITY",
        "name": "SYSTEM",
        "type": "User"
      }
    },
    "log": {
      "level": "information"
    },
    "rule": {
      "name": "technique_id=T1036,technique_name=Masquerading"
    },
    "message": "Process Create:\nRuleName: technique_id=T1036,technique_name=Masquerading\nUtcTime: 2022-06-28 22:19:00.780\nProcessGuid: {c5d2b969-7e54-62bb-0603-000000001f01}\nProcessId: 2612\nImage: C:\\Users\\Administrator\\Desktop\\AnyDesk.exe\nFileVersion: 7.0.10\nDescription: AnyDesk\nProduct: AnyDesk\nCompany: AnyDesk Software GmbH\nOriginalFileName: -\nCommandLine: \"C:\\Users\\Administrator\\Desktop\\AnyDesk.exe\" --install \"C:\\Program Files (x86)\\AnyDesk\"  --start-with-win --create-shortcuts --create-taskbar-icon --create-desktop-icon --install-driver:mirror --update-disabled --svc-conf \"C:\\Users\\Administrator\\AppData\\Roaming\\AnyDesk\\service.conf\"  --sys-conf \"C:\\Users\\Administrator\\AppData\\Roaming\\AnyDesk\\system.conf\" \nCurrentDirectory: C:\\Users\\Administrator\\Desktop\\\nUser: THM_AURORA_TEST\\Administrator\nLogonGuid: {c5d2b969-7ee7-62b9-4833-170000000000}\nLogonId: 0x173348\nTerminalSessionId: 2\nIntegrityLevel: High\nHashes: SHA1=9779751121508F17CBD831E9C2780B4CF0E1B96C,MD5=0DBE3504BC5DAA73E7B3F75BBB104E42,SHA256=D7B9F1141C649C08254A4978F98211A5AB3B10591693FCF271409E36BEAE2933,IMPHASH=00000000000000000000000000000000\nParentProcessGuid: {c5d2b969-7bf0-62bb-0103-000000001f01}\nParentProcessId: 1392\nParentImage: C:\\Users\\Administrator\\Desktop\\AnyDesk.exe\nParentCommandLine: \"C:\\Users\\Administrator\\Desktop\\AnyDesk.exe\" /S \nParentUser: THM_AURORA_TEST\\Administrator",
    "cloud": {
      "availability_zone": "eu-west-1b",
      "image": {
        "id": "ami-0844a966e30ab3c23"
      },
      "instance": {
        "id": "i-0f365e6a14c6c7ae1"
      },
      "provider": "aws",
      "machine": {
        "type": "t2.medium"
      },
      "service": {
        "name": "EC2"
      },
      "region": "eu-west-1",
      "account": {
        "id": "739930428441"
      }
    },
    "@timestamp": "2022-06-28T22:19:00.780Z",
    "ecs": {
      "version": "1.12.0"
    },
    "related": {
      "user": [
        "Administrator"
      ],
      "hash": [
        "d7b9f1141c649c08254a4978f98211a5ab3b10591693fcf271409e36beae2933",
        "9779751121508f17cbd831e9c2780b4cf0e1b96c",
        "0dbe3504bc5daa73e7b3f75bbb104e42"
      ]
    },
    "host": {
      "hostname": "THM_Aurora_Test",
      "os": {
        "build": "17763.1821",
        "kernel": "10.0.17763.1821 (WinBuild.160101.0800)",
        "name": "Windows Server 2019 Datacenter",
        "family": "windows",
        "type": "windows",
        "version": "10.0",
        "platform": "windows"
      },
      "ip": [
        "fe80::8495:da75:43eb:5822",
        "10.10.222.40"
      ],
      "name": "THM_Aurora_Test",
      "id": "c5d2b969-b61a-4159-8f78-6391a1c805db",
      "mac": [
        "02:23:bb:82:ce:19"
      ],
      "architecture": "x86_64"
    },
    "event": {
      "ingested": "2022-06-28T22:19:01.919824857Z",
      "code": "1",
      "provider": "Microsoft-Windows-Sysmon",
      "created": "2022-06-28T22:19:00.897Z",
      "kind": "event",
      "module": "sysmon",
      "action": "Process Create (rule: ProcessCreate)",
      "type": [
        "start"
      ],
      "category": [
        "process"
      ]
    },
    "user": {
      "domain": "THM_AURORA_TEST",
      "name": "Administrator",
      "id": "S-1-5-18"
    }
  },
  "fields": {
    "process.hash.md5": [
      "0dbe3504bc5daa73e7b3f75bbb104e42"
    ],
    "event.category": [
      "process"
    ],
    "host.os.name.text": [
      "Windows Server 2019 Datacenter"
    ],
    "process.parent.command_line": [
      "\"C:\\Users\\Administrator\\Desktop\\AnyDesk.exe\" /S "
    ],
    "process.parent.name": [
      "AnyDesk.exe"
    ],
    "process.parent.pid": [
      1392
    ],
    "process.hash.sha256": [
      "d7b9f1141c649c08254a4978f98211a5ab3b10591693fcf271409e36beae2933"
    ],
    "host.hostname": [
      "THM_Aurora_Test"
    ],
    "host.mac": [
      "02:23:bb:82:ce:19"
    ],
    "winlog.process.pid": [
      3528
    ],
    "host.os.version": [
      "10.0"
    ],
    "agent.name": [
      "THM_Aurora_Test"
    ],
    "winlog.event_data.Company": [
      "AnyDesk Software GmbH"
    ],
    "user.id": [
      "S-1-5-18"
    ],
    "host.os.type": [
      "windows"
    ],
    "cloud.region": [
      "eu-west-1"
    ],
    "agent.hostname": [
      "THM_Aurora_Test"
    ],
    "process.pe.product": [
      "AnyDesk"
    ],
    "related.user": [
      "Administrator"
    ],
    "host.architecture": [
      "x86_64"
    ],
    "cloud.provider": [
      "aws"
    ],
    "event.provider": [
      "Microsoft-Windows-Sysmon"
    ],
    "cloud.machine.type": [
      "t2.medium"
    ],
    "winlog.event_data.FileVersion": [
      "7.0.10"
    ],
    "event.code": [
      "1"
    ],
    "agent.id": [
      "ba6b17a6-3ca3-45a9-b4b2-fc995ab1c73a"
    ],
    "winlog.event_data.LogonGuid": [
      "{c5d2b969-7ee7-62b9-4833-170000000000}"
    ],
    "winlog.event_data.Description": [
      "AnyDesk"
    ],
    "process.command_line.text": [
      "\"C:\\Users\\Administrator\\Desktop\\AnyDesk.exe\" --install \"C:\\Program Files (x86)\\AnyDesk\"  --start-with-win --create-shortcuts --create-taskbar-icon --create-desktop-icon --install-driver:mirror --update-disabled --svc-conf \"C:\\Users\\Administrator\\AppData\\Roaming\\AnyDesk\\service.conf\"  --sys-conf \"C:\\Users\\Administrator\\AppData\\Roaming\\AnyDesk\\system.conf\" "
    ],
    "winlog.process.thread.id": [
      2908
    ],
    "user.name": [
      "Administrator"
    ],
    "process.working_directory": [
      "C:\\Users\\Administrator\\Desktop\\"
    ],
    "process.entity_id": [
      "{c5d2b969-7e54-62bb-0603-000000001f01}"
    ],
    "host.ip": [
      "fe80::8495:da75:43eb:5822",
      "10.10.222.40"
    ],
    "cloud.instance.id": [
      "i-0f365e6a14c6c7ae1"
    ],
    "agent.type": [
      "winlogbeat"
    ],
    "process.pe.original_file_name": [
      "-"
    ],
    "process.executable.text": [
      "C:\\Users\\Administrator\\Desktop\\AnyDesk.exe"
    ],
    "winlog.api": [
      "wineventlog"
    ],
    "user.domain": [
      "THM_AURORA_TEST"
    ],
    "host.id": [
      "c5d2b969-b61a-4159-8f78-6391a1c805db"
    ],
    "process.pe.file_version": [
      "7.0.10"
    ],
    "process.working_directory.text": [
      "C:\\Users\\Administrator\\Desktop\\"
    ],
    "winlog.user.name": [
      "SYSTEM"
    ],
    "cloud.image.id": [
      "ami-0844a966e30ab3c23"
    ],
    "process.pe.company": [
      "AnyDesk Software GmbH"
    ],
    "event.action": [
      "Process Create (rule: ProcessCreate)"
    ],
    "event.ingested": [
      "2022-06-28T22:19:01.919Z"
    ],
    "@timestamp": [
      "2022-06-28T22:19:00.780Z"
    ],
    "winlog.channel": [
      "Microsoft-Windows-Sysmon/Operational"
    ],
    "cloud.account.id": [
      "739930428441"
    ],
    "host.os.platform": [
      "windows"
    ],
    "winlog.opcode": [
      "Info"
    ],
    "agent.ephemeral_id": [
      "c483a7ab-6222-40f5-af9e-467e53880dac"
    ],
    "winlog.event_data.TerminalSessionId": [
      "2"
    ],
    "process.hash.sha1": [
      "9779751121508f17cbd831e9c2780b4cf0e1b96c"
    ],
    "user.name.text": [
      "Administrator"
    ],
    "winlog.event_data.LogonId": [
      "0x173348"
    ],
    "process.name.text": [
      "AnyDesk.exe"
    ],
    "winlog.provider_name": [
      "Microsoft-Windows-Sysmon"
    ],
    "winlog.provider_guid": [
      "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"
    ],
    "related.hash": [
      "d7b9f1141c649c08254a4978f98211a5ab3b10591693fcf271409e36beae2933",
      "9779751121508f17cbd831e9c2780b4cf0e1b96c",
      "0dbe3504bc5daa73e7b3f75bbb104e42"
    ],
    "process.pid": [
      2612
    ],
    "winlog.computer_name": [
      "THM_Aurora_Test"
    ],
    "cloud.availability_zone": [
      "eu-west-1b"
    ],
    "process.parent.entity_id": [
      "{c5d2b969-7bf0-62bb-0103-000000001f01}"
    ],
    "winlog.record_id": [
      "9284"
    ],
    "host.os.name": [
      "Windows Server 2019 Datacenter"
    ],
    "log.level": [
      "information"
    ],
    "host.name": [
      "THM_Aurora_Test"
    ],
    "event.kind": [
      "event"
    ],
    "winlog.version": [
      5
    ],
    "rule.name": [
      "technique_id=T1036,technique_name=Masquerading"
    ],
    "process.parent.args_count": [
      2
    ],
    "process.name": [
      "AnyDesk.exe"
    ],
    "cloud.service.name": [
      "EC2"
    ],
    "process.parent.executable.text": [
      "C:\\Users\\Administrator\\Desktop\\AnyDesk.exe"
    ],
    "ecs.version": [
      "1.12.0"
    ],
    "event.created": [
      "2022-06-28T22:19:00.897Z"
    ],
    "process.pe.description": [
      "AnyDesk"
    ],
    "agent.version": [
      "8.2.3"
    ],
    "host.os.family": [
      "windows"
    ],
    "winlog.event_data.ParentUser": [
      "THM_AURORA_TEST\\Administrator"
    ],
    "process.parent.name.text": [
      "AnyDesk.exe"
    ],
    "winlog.user.type": [
      "User"
    ],
    "host.os.build": [
      "17763.1821"
    ],
    "event.module": [
      "sysmon"
    ],
    "host.os.kernel": [
      "10.0.17763.1821 (WinBuild.160101.0800)"
    ],
    "process.executable": [
      "C:\\Users\\Administrator\\Desktop\\AnyDesk.exe"
    ],
    "winlog.user.identifier": [
      "S-1-5-18"
    ],
    "winlog.task": [
      "Process Create (rule: ProcessCreate)"
    ],
    "winlog.user.domain": [
      "NT AUTHORITY"
    ],
    "process.parent.executable": [
      "C:\\Users\\Administrator\\Desktop\\AnyDesk.exe"
    ],
    "process.parent.command_line.text": [
      "\"C:\\Users\\Administrator\\Desktop\\AnyDesk.exe\" /S "
    ],
    "process.args_count": [
      13
    ],
    "winlog.event_data.IntegrityLevel": [
      "High"
    ],
    "process.args": [
      "C:\\Users\\Administrator\\Desktop\\AnyDesk.exe",
      "--install",
      "C:\\Program Files (x86)\\AnyDesk",
      "--start-with-win",
      "--create-shortcuts",
      "--create-taskbar-icon",
      "--create-desktop-icon",
      "--install-driver:mirror",
      "--update-disabled",
      "--svc-conf",
      "C:\\Users\\Administrator\\AppData\\Roaming\\AnyDesk\\service.conf",
      "--sys-conf",
      "C:\\Users\\Administrator\\AppData\\Roaming\\AnyDesk\\system.conf"
    ],
    "message": [
      "Process Create:\nRuleName: technique_id=T1036,technique_name=Masquerading\nUtcTime: 2022-06-28 22:19:00.780\nProcessGuid: {c5d2b969-7e54-62bb-0603-000000001f01}\nProcessId: 2612\nImage: C:\\Users\\Administrator\\Desktop\\AnyDesk.exe\nFileVersion: 7.0.10\nDescription: AnyDesk\nProduct: AnyDesk\nCompany: AnyDesk Software GmbH\nOriginalFileName: -\nCommandLine: \"C:\\Users\\Administrator\\Desktop\\AnyDesk.exe\" --install \"C:\\Program Files (x86)\\AnyDesk\"  --start-with-win --create-shortcuts --create-taskbar-icon --create-desktop-icon --install-driver:mirror --update-disabled --svc-conf \"C:\\Users\\Administrator\\AppData\\Roaming\\AnyDesk\\service.conf\"  --sys-conf \"C:\\Users\\Administrator\\AppData\\Roaming\\AnyDesk\\system.conf\" \nCurrentDirectory: C:\\Users\\Administrator\\Desktop\\\nUser: THM_AURORA_TEST\\Administrator\nLogonGuid: {c5d2b969-7ee7-62b9-4833-170000000000}\nLogonId: 0x173348\nTerminalSessionId: 2\nIntegrityLevel: High\nHashes: SHA1=9779751121508F17CBD831E9C2780B4CF0E1B96C,MD5=0DBE3504BC5DAA73E7B3F75BBB104E42,SHA256=D7B9F1141C649C08254A4978F98211A5AB3B10591693FCF271409E36BEAE2933,IMPHASH=00000000000000000000000000000000\nParentProcessGuid: {c5d2b969-7bf0-62bb-0103-000000001f01}\nParentProcessId: 1392\nParentImage: C:\\Users\\Administrator\\Desktop\\AnyDesk.exe\nParentCommandLine: \"C:\\Users\\Administrator\\Desktop\\AnyDesk.exe\" /S \nParentUser: THM_AURORA_TEST\\Administrator"
    ],
    "winlog.event_id": [
      "1"
    ],
    "process.parent.args": [
      "C:\\Users\\Administrator\\Desktop\\AnyDesk.exe",
      "/S"
    ],
    "event.type": [
      "start"
    ],
    "process.command_line": [
      "\"C:\\Users\\Administrator\\Desktop\\AnyDesk.exe\" --install \"C:\\Program Files (x86)\\AnyDesk\"  --start-with-win --create-shortcuts --create-taskbar-icon --create-desktop-icon --install-driver:mirror --update-disabled --svc-conf \"C:\\Users\\Administrator\\AppData\\Roaming\\AnyDesk\\service.conf\"  --sys-conf \"C:\\Users\\Administrator\\AppData\\Roaming\\AnyDesk\\system.conf\" "
    ],
    "winlog.event_data.Product": [
      "AnyDesk"
    ]
  }
}


```

![[Pasted image 20230117130332.png]]


What command line tool is used to convert Sigma rules?

*sigmac*

At what time was the AnyDesk installation event created? [MMM DD, YYYY @ HH:MM:SS]

*Jun 28, 2022 @ 22:19:00*

What version of AnyDesk was installed?

Look at the available version fields.

*7.0.10*


### SecOps Decisions

Threat and log investigations may flow in different directions depending on factors such as SIEM backends, log sources and process flows established within organisations. Sigma rules are not different; as an analyst, you must make various investigation decisions.

For example, the Sigmac CLI tool or Uncoder.io would be essential to the detection investigations. You may encounter instances where the tools produce slightly different conversion outputs from the same rule and may not entirely match up with your backend configuration.

Let us consider converting the [Chmod Suspicious Directory Linux rule](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_susp_chmod_directories.yml) into Elastic Query. Starting with Sigmac, we set our target backend as Elastic Query using the `-t es-qs` option and follow that with selecting our preferred configuration option. After that, set the rule from your directory and  obtain our output which is a query that matches the process using the field names `image` and `commandline`, with options that point to various directory files where it would be suspicious to find the “change mode” `chmod` command being run.

Sigmac Conversion - Linux Chmod

```shell-session
root@THM:~/Rooms/sigma/sigma/tools# python3.9 sigmac -t es-qs -c elk-linux ../rules/linux/process_creation/proc_creation_lnx_susp_chmod_directories.yml

(Image.keyword:*\/chmod AND CommandLine.keyword:(*\/tmp\/* OR *\/.Library\/* OR *\/etc\/* OR *\/opt\/*))
```

On the side of using Uncoder.io, the rule conversion produces a query that matches based on the field names **process.executable** and **process.command_line**.

Uncoder.io Conversion - Linux Chmod

```shell-session
(process.executable:*\/chmod AND process.command_line:(*\/tmp\/* OR *\/.Library\/* OR *\/etc\/* OR *\/opt\/*))
```

Despite the similarities in the output, you would end up deciding on the best outcome for your configuration and considering any regex used to escape any special characters.

Answer the questions below

Read the above.

```
root@ip-10-10-103-84:~/Rooms/sigma/sigma/tools# ls
build                README.md     sigma_configurations_check
config               setup.cfg     sigma_similarity
dist                 setup.py      sigmatools.egg-info
LICENSE.LGPL.txt     sigma         sigma_uuid
LONG_DESCRIPTION.md  sigma2attack  tests
MANIFEST.in          sigma2misp
merge_sigma          sigmac
root@ip-10-10-103-84:~/Rooms/sigma/sigma/tools# python3.9 sigmac -t es-qs -c elk-linux ../rules/linux/process_creation/proc_creation_lnx_susp_chmod_directories.yml
(Image.keyword:*\/chmod AND CommandLine.keyword:(*\/tmp\/* OR *\/.Library\/* OR *\/etc\/* OR *\/opt\/*))
root@ip-10-10-103-84:~/Rooms/sigma/sigma/tools# cd ..
root@ip-10-10-103-84:~/Rooms/sigma/sigma# ls
BREAKING_CHANGES.md         Makefile          rules-placeholder
CHANGELOG.md                other             rules-unsupported
_config.yml                 Pipfile           sigma-schema.rx.yml
contrib                     Pipfile.lock      tests
images                      README.md         tools
LICENSE                     rules
LICENSE.Detection.Rules.md  rules-deprecated
root@ip-10-10-103-84:~/Rooms/sigma/sigma# cd rules
root@ip-10-10-103-84:~/Rooms/sigma/sigma/rules# ls
application  cloud  compliance  linux  macos  network  proxy  web  windows
root@ip-10-10-103-84:~/Rooms/sigma/sigma/rules# cd linux
root@ip-10-10-103-84:~/Rooms/sigma/sigma/rules/linux# ls
auditd   file_create  network_connection  process_creation
builtin  modsecurity  other
root@ip-10-10-103-84:~/Rooms/sigma/sigma/rules/linux# cd process_creation/
root@ip-10-10-103-84:~/Rooms/sigma/sigma/rules/linux/process_creation# ls
proc_creation_lnx_at_command.yml
proc_creation_lnx_base64_decode.yml
proc_creation_lnx_base64_execution.yml
proc_creation_lnx_base64_shebang_cli.yml
proc_creation_lnx_bpftrace_unsafe_option_usage.yml
proc_creation_lnx_cat_sudoers.yml
proc_creation_lnx_chattr_immutable_removal.yml
proc_creation_lnx_clear_logs.yml
proc_creation_lnx_clear_syslog.yml
proc_creation_lnx_clipboard_collection.yml
proc_creation_lnx_crontab_removal.yml
proc_creation_lnx_crypto_mining.yml
proc_creation_lnx_curl_usage.yml
proc_creation_lnx_cve_2022_26134_atlassian_confluence.yml
proc_creation_lnx_cve_2022_33891_spark_shell_command_injection.yml
proc_creation_lnx_dd_file_overwrite.yml
proc_creation_lnx_doas_execution.yml
proc_creation_lnx_file_and_directory_discovery.yml
proc_creation_lnx_file_deletion.yml
proc_creation_lnx_install_root_certificate.yml
proc_creation_lnx_local_account.yml
proc_creation_lnx_local_groups.yml
proc_creation_lnx_network_service_scanning.yml
proc_creation_lnx_nohup.yml
proc_creation_lnx_omigod_scx_runasprovider_executescript.yml
proc_creation_lnx_omigod_scx_runasprovider_executeshellcommand.yml
proc_creation_lnx_process_discovery.yml
proc_creation_lnx_proxy_connection.yml
proc_creation_lnx_python_pty_spawn.yml
proc_creation_lnx_remote_system_discovery.yml
proc_creation_lnx_schedule_task_job_cron.yml
proc_creation_lnx_security_software_discovery.yml
proc_creation_lnx_security_tools_disabling.yml
proc_creation_lnx_services_stop_and_disable.yml
proc_creation_lnx_setgid_setuid.yml
proc_creation_lnx_sudo_cve_2019_14287.yml
proc_creation_lnx_susp_chmod_directories.yml
proc_creation_lnx_susp_curl_fileupload.yml
proc_creation_lnx_susp_curl_useragent.yml
proc_creation_lnx_susp_history_delete.yml
proc_creation_lnx_susp_history_recon.yml
proc_creation_lnx_susp_interactive_bash.yml
proc_creation_lnx_susp_java_children.yml
proc_creation_lnx_susp_pipe_shell.yml
proc_creation_lnx_susp_recon_indicators.yml
proc_creation_lnx_system_info_discovery.yml
proc_creation_lnx_system_network_connections_discovery.yml
proc_creation_lnx_system_network_discovery.yml
proc_creation_lnx_triple_cross_rootkit_execve_hijack.yml
proc_creation_lnx_triple_cross_rootkit_install.yml
proc_creation_lnx_webshell_detection.yml
root@ip-10-10-103-84:~/Rooms/sigma/sigma/rules/linux/process_creation# cat proc_creation_lnx_susp_chmod_directories.yml
title: Chmod Suspicious Directory
id: 6419afd1-3742-47a5-a7e6-b50386cd15f8
status: experimental
description: Detects chmod targeting files in abnormal directory paths.
references:
    - https://www.intezer.com/blog/malware-analysis/new-backdoor-sysjoker/
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1222.002/T1222.002.md
author: 'Christopher Peacock @SecurePeacock, SCYTHE @scythe_io'
date: 2022/06/03
tags:
    - attack.defense_evasion
    - attack.t1222.002
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/chmod'
        CommandLine|contains:
            - '/tmp/'
            - '/.Library/'
            - '/etc/'
            - '/opt/'
    condition: selection
falsepositives:
    - Admin changing file permissions.
level: medium

```

### Practical Scenario

It's time to test the knowledge gained about Sigma and its use. In this task, you are expected to write rules based on provided scenarios, convert them to the appropriate SIEM used in the deployed machine and identify any useful information using the queries to help you answer the questions.

  

### Scenario

Your organisation, Aurora, has recently been experiencing unusual activities on some of the machines on the network. Amongst these activities, the IT Manager noted that an unknown entity created some scheduled tasks on one of the machines and that a ransomware activity was also recorded.

The SOC Manager has approached you to find ways of identifying these activities from the logs collected on the environment. It would be best if you used Sigma rules to set your detection parameters and perform search queries through the Kibana dashboard.

To complete the task, you will require two Sigma rules processed into ElasticSearch to query for the scheduled task and the ransomware events. Below are tips to construct a good rule for the task:

-   For the Scheduled Task, understand that it is a **process creation** event.
-   The rule's detection variables should contain **image and commandline** arguments.
-   You may choose to exclude **SYSTEM** accounts from the query.
-   For the ransomware activity, you'll look for a created file ending with **.txt**.
-   The file creation process would be run via **cmd.exe.**
-   Change the default time window on Kibana from the default **last 30 days** to **last 1 year** (or ensure it encompasses 2022).

Answer the questions below

```yml
title: #Title of your rule
id: #Universally Unique Identifier (UUID) Generate one from https://www.uuidgenerator.net
status: #stage of your rule testing 
description: #Details about the detection intensions of the rule.
author: #Who wrote the rule.
date: #When was the rule written.
modified: #When was it updated
logsource:
  category: #Classification of the log data for detection
  product: #Source of the log data
detection:
  selection:
    FieldName1: Value #Search identifiers for the detection
    FieldName2: Value
  condition: selection #Action to be taken.
fields: #List of associated fields that are important for the detection

falsepositives: #Any possible false positives that could trigger the rule.

level: medium #Severity level of the detection rule.
tags: #Associated TTPs from MITRE ATT&CK
  - attack.credential_access #MITRE Tactic
  - attack.t1110 #MITRE Technique

https://www.uuidgenerator.net
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks
https://www.nextron-systems.com/2018/02/10/write-sigma-rules/
https://fourcore.io/blogs/sigma-rules-open-source-threat-hunting-approach

First Sigma Rule

┌──(kali㉿kali)-[~/Downloads]
└─$ nano Scheduled_Task.yml                       
                                                                                      
┌──(kali㉿kali)-[~/Downloads]
└─$ cat Scheduled_Task.yml 
title: Scheduled task
id: 99229f4b-a114-485f-8728-cb3ecfe92aef
status: experimental
description: detect schedule
author: witty
date: 01/17/2023
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image: '\schtasks.exe'
    CommandLine|contains|all:
      - 'schtasks'
      - 'create'
  condition: selection


(process.executable.text:"\schtasks.exe" AND process.command_line.text:*schtasks* AND process.command_line.text:*create*)


{
  "_index": ".ds-winlogbeat-8.2.3-2022.06.27-000001",
  "_id": "7lfgrIEB3iMYFrgzW_Q0",
  "_version": 1,
  "_score": 1,
  "_source": {
    "agent": {
      "name": "THM_Aurora_Test",
      "id": "ba6b17a6-3ca3-45a9-b4b2-fc995ab1c73a",
      "ephemeral_id": "c483a7ab-6222-40f5-af9e-467e53880dac",
      "type": "winlogbeat",
      "version": "8.2.3"
    },
    "process": {
      "args": [
        "SCHTASKS",
        "/Create",
        "/SC",
        "ONCE",
        "/TN",
        "spawn",
        "/TR",
        "C:\\windows\\system32\\cmd.exe",
        "/ST",
        "20:10"
      ],
      "parent": {
        "args": [
          "cmd.exe",
          "/c",
          "SCHTASKS /Create /SC ONCE /TN spawn /TR C:\\windows\\system32\\cmd.exe /ST 20:10"
        ],
        "name": "cmd.exe",
        "pid": 3264,
        "args_count": 3,
        "entity_id": "{c5d2b969-9dc7-62bb-6a03-000000001f01}",
        "executable": "C:\\Windows\\System32\\cmd.exe",
        "command_line": "\"cmd.exe\" /c \"SCHTASKS /Create /SC ONCE /TN spawn /TR C:\\windows\\system32\\cmd.exe /ST 20:10\""
      },
      "pe": {
        "file_version": "10.0.17763.1613 (WinBuild.160101.0800)",
        "product": "Microsoft® Windows® Operating System",
        "imphash": "0bf09ee8918142ee8d325d5955aa1cd9",
        "description": "Task Scheduler Configuration Tool",
        "original_file_name": "schtasks.exe",
        "company": "Microsoft Corporation"
      },
      "name": "schtasks.exe",
      "pid": 5864,
      "working_directory": "C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\",
      "args_count": 10,
      "entity_id": "{c5d2b969-9dc7-62bb-6c03-000000001f01}",
      "hash": {
        "sha1": "82aa3192719be60f7d8464be1fec653a50c16f87",
        "sha256": "4b679ccc4e0e84a9eddc24362ea4a86835597a90d94a1ae0ea905d7bcd9f771c",
        "md5": "2f6ce97faf2d5eea919e4393bdd416a7"
      },
      "executable": "C:\\Windows\\System32\\schtasks.exe",
      "command_line": "SCHTASKS  /Create /SC ONCE /TN spawn /TR C:\\windows\\system32\\cmd.exe /ST 20:10"
    },
    "winlog": {
      "computer_name": "THM_Aurora_Test",
      "process": {
        "pid": 3528,
        "thread": {
          "id": 2908
        }
      },
      "channel": "Microsoft-Windows-Sysmon/Operational",
      "event_data": {
        "Company": "Microsoft Corporation",
        "Description": "Task Scheduler Configuration Tool",
        "LogonGuid": "{c5d2b969-7ee7-62b9-4833-170000000000}",
        "IntegrityLevel": "High",
        "TerminalSessionId": "2",
        "ParentUser": "THM_AURORA_TEST\\Administrator",
        "Product": "Microsoft® Windows® Operating System",
        "FileVersion": "10.0.17763.1613 (WinBuild.160101.0800)",
        "LogonId": "0x173348"
      },
      "opcode": "Info",
      "version": 5,
      "record_id": "14559",
      "task": "Process Create (rule: ProcessCreate)",
      "event_id": "1",
      "provider_guid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
      "api": "wineventlog",
      "provider_name": "Microsoft-Windows-Sysmon",
      "user": {
        "identifier": "S-1-5-18",
        "domain": "NT AUTHORITY",
        "name": "SYSTEM",
        "type": "User"
      }
    },
    "log": {
      "level": "information"
    },
    "rule": {
      "name": "technique_id=T1059,technique_name=Command-Line Interface"
    },
    "message": "Process Create:\nRuleName: technique_id=T1059,technique_name=Command-Line Interface\nUtcTime: 2022-06-29 00:33:11.426\nProcessGuid: {c5d2b969-9dc7-62bb-6c03-000000001f01}\nProcessId: 5864\nImage: C:\\Windows\\System32\\schtasks.exe\nFileVersion: 10.0.17763.1613 (WinBuild.160101.0800)\nDescription: Task Scheduler Configuration Tool\nProduct: Microsoft® Windows® Operating System\nCompany: Microsoft Corporation\nOriginalFileName: schtasks.exe\nCommandLine: SCHTASKS  /Create /SC ONCE /TN spawn /TR C:\\windows\\system32\\cmd.exe /ST 20:10\nCurrentDirectory: C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\\nUser: THM_AURORA_TEST\\Administrator\nLogonGuid: {c5d2b969-7ee7-62b9-4833-170000000000}\nLogonId: 0x173348\nTerminalSessionId: 2\nIntegrityLevel: High\nHashes: SHA1=82AA3192719BE60F7D8464BE1FEC653A50C16F87,MD5=2F6CE97FAF2D5EEA919E4393BDD416A7,SHA256=4B679CCC4E0E84A9EDDC24362EA4A86835597A90D94A1AE0EA905D7BCD9F771C,IMPHASH=0BF09EE8918142EE8D325D5955AA1CD9\nParentProcessGuid: {c5d2b969-9dc7-62bb-6a03-000000001f01}\nParentProcessId: 3264\nParentImage: C:\\Windows\\System32\\cmd.exe\nParentCommandLine: \"cmd.exe\" /c \"SCHTASKS /Create /SC ONCE /TN spawn /TR C:\\windows\\system32\\cmd.exe /ST 20:10\"\nParentUser: THM_AURORA_TEST\\Administrator",
    "cloud": {
      "availability_zone": "eu-west-1b",
      "image": {
        "id": "ami-0844a966e30ab3c23"
      },
      "instance": {
        "id": "i-0f365e6a14c6c7ae1"
      },
      "provider": "aws",
      "machine": {
        "type": "t2.medium"
      },
      "service": {
        "name": "EC2"
      },
      "region": "eu-west-1",
      "account": {
        "id": "739930428441"
      }
    },
    "@timestamp": "2022-06-29T00:33:11.426Z",
    "ecs": {
      "version": "1.12.0"
    },
    "related": {
      "user": [
        "Administrator"
      ],
      "hash": [
        "4b679ccc4e0e84a9eddc24362ea4a86835597a90d94a1ae0ea905d7bcd9f771c",
        "82aa3192719be60f7d8464be1fec653a50c16f87",
        "2f6ce97faf2d5eea919e4393bdd416a7",
        "0bf09ee8918142ee8d325d5955aa1cd9"
      ]
    },
    "host": {
      "hostname": "THM_Aurora_Test",
      "os": {
        "build": "17763.1821",
        "kernel": "10.0.17763.1821 (WinBuild.160101.0800)",
        "name": "Windows Server 2019 Datacenter",
        "type": "windows",
        "family": "windows",
        "version": "10.0",
        "platform": "windows"
      },
      "ip": [
        "fe80::8495:da75:43eb:5822",
        "10.10.222.40"
      ],
      "name": "THM_Aurora_Test",
      "id": "c5d2b969-b61a-4159-8f78-6391a1c805db",
      "mac": [
        "02:23:bb:82:ce:19"
      ],
      "architecture": "x86_64"
    },
    "event": {
      "ingested": "2022-06-29T00:33:13.518375473Z",
      "code": "1",
      "provider": "Microsoft-Windows-Sysmon",
      "created": "2022-06-29T00:33:12.492Z",
      "kind": "event",
      "module": "sysmon",
      "action": "Process Create (rule: ProcessCreate)",
      "type": [
        "start"
      ],
      "category": [
        "process"
      ]
    },
    "user": {
      "domain": "THM_AURORA_TEST",
      "name": "Administrator",
      "id": "S-1-5-18"
    }
  },
  "fields": {
    "process.hash.md5": [
      "2f6ce97faf2d5eea919e4393bdd416a7"
    ],
    "event.category": [
      "process"
    ],
    "host.os.name.text": [
      "Windows Server 2019 Datacenter"
    ],
    "process.parent.command_line": [
      "\"cmd.exe\" /c \"SCHTASKS /Create /SC ONCE /TN spawn /TR C:\\windows\\system32\\cmd.exe /ST 20:10\""
    ],
    "process.parent.name": [
      "cmd.exe"
    ],
    "process.parent.pid": [
      3264
    ],
    "process.hash.sha256": [
      "4b679ccc4e0e84a9eddc24362ea4a86835597a90d94a1ae0ea905d7bcd9f771c"
    ],
    "host.hostname": [
      "THM_Aurora_Test"
    ],
    "host.mac": [
      "02:23:bb:82:ce:19"
    ],
    "winlog.process.pid": [
      3528
    ],
    "host.os.version": [
      "10.0"
    ],
    "agent.name": [
      "THM_Aurora_Test"
    ],
    "winlog.event_data.Company": [
      "Microsoft Corporation"
    ],
    "user.id": [
      "S-1-5-18"
    ],
    "host.os.type": [
      "windows"
    ],
    "cloud.region": [
      "eu-west-1"
    ],
    "agent.hostname": [
      "THM_Aurora_Test"
    ],
    "process.pe.product": [
      "Microsoft® Windows® Operating System"
    ],
    "related.user": [
      "Administrator"
    ],
    "host.architecture": [
      "x86_64"
    ],
    "cloud.provider": [
      "aws"
    ],
    "event.provider": [
      "Microsoft-Windows-Sysmon"
    ],
    "cloud.machine.type": [
      "t2.medium"
    ],
    "winlog.event_data.FileVersion": [
      "10.0.17763.1613 (WinBuild.160101.0800)"
    ],
    "event.code": [
      "1"
    ],
    "agent.id": [
      "ba6b17a6-3ca3-45a9-b4b2-fc995ab1c73a"
    ],
    "winlog.event_data.LogonGuid": [
      "{c5d2b969-7ee7-62b9-4833-170000000000}"
    ],
    "winlog.event_data.Description": [
      "Task Scheduler Configuration Tool"
    ],
    "process.command_line.text": [
      "SCHTASKS  /Create /SC ONCE /TN spawn /TR C:\\windows\\system32\\cmd.exe /ST 20:10"
    ],
    "winlog.process.thread.id": [
      2908
    ],
    "user.name": [
      "Administrator"
    ],
    "process.working_directory": [
      "C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\"
    ],
    "process.entity_id": [
      "{c5d2b969-9dc7-62bb-6c03-000000001f01}"
    ],
    "host.ip": [
      "fe80::8495:da75:43eb:5822",
      "10.10.222.40"
    ],
    "cloud.instance.id": [
      "i-0f365e6a14c6c7ae1"
    ],
    "agent.type": [
      "winlogbeat"
    ],
    "process.pe.original_file_name": [
      "schtasks.exe"
    ],
    "process.executable.text": [
      "C:\\Windows\\System32\\schtasks.exe"
    ],
    "winlog.api": [
      "wineventlog"
    ],
    "user.domain": [
      "THM_AURORA_TEST"
    ],
    "host.id": [
      "c5d2b969-b61a-4159-8f78-6391a1c805db"
    ],
    "process.pe.file_version": [
      "10.0.17763.1613 (WinBuild.160101.0800)"
    ],
    "process.working_directory.text": [
      "C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\"
    ],
    "winlog.user.name": [
      "SYSTEM"
    ],
    "cloud.image.id": [
      "ami-0844a966e30ab3c23"
    ],
    "process.pe.company": [
      "Microsoft Corporation"
    ],
    "event.action": [
      "Process Create (rule: ProcessCreate)"
    ],
    "event.ingested": [
      "2022-06-29T00:33:13.518Z"
    ],
    "@timestamp": [
      "2022-06-29T00:33:11.426Z"
    ],
    "winlog.channel": [
      "Microsoft-Windows-Sysmon/Operational"
    ],
    "cloud.account.id": [
      "739930428441"
    ],
    "host.os.platform": [
      "windows"
    ],
    "winlog.opcode": [
      "Info"
    ],
    "agent.ephemeral_id": [
      "c483a7ab-6222-40f5-af9e-467e53880dac"
    ],
    "winlog.event_data.TerminalSessionId": [
      "2"
    ],
    "process.hash.sha1": [
      "82aa3192719be60f7d8464be1fec653a50c16f87"
    ],
    "user.name.text": [
      "Administrator"
    ],
    "winlog.event_data.LogonId": [
      "0x173348"
    ],
    "process.name.text": [
      "schtasks.exe"
    ],
    "winlog.provider_name": [
      "Microsoft-Windows-Sysmon"
    ],
    "winlog.provider_guid": [
      "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"
    ],
    "related.hash": [
      "4b679ccc4e0e84a9eddc24362ea4a86835597a90d94a1ae0ea905d7bcd9f771c",
      "82aa3192719be60f7d8464be1fec653a50c16f87",
      "2f6ce97faf2d5eea919e4393bdd416a7",
      "0bf09ee8918142ee8d325d5955aa1cd9"
    ],
    "process.pid": [
      5864
    ],
    "winlog.computer_name": [
      "THM_Aurora_Test"
    ],
    "cloud.availability_zone": [
      "eu-west-1b"
    ],
    "process.parent.entity_id": [
      "{c5d2b969-9dc7-62bb-6a03-000000001f01}"
    ],
    "winlog.record_id": [
      "14559"
    ],
    "host.os.name": [
      "Windows Server 2019 Datacenter"
    ],
    "log.level": [
      "information"
    ],
    "host.name": [
      "THM_Aurora_Test"
    ],
    "event.kind": [
      "event"
    ],
    "winlog.version": [
      5
    ],
    "rule.name": [
      "technique_id=T1059,technique_name=Command-Line Interface"
    ],
    "process.parent.args_count": [
      3
    ],
    "process.name": [
      "schtasks.exe"
    ],
    "cloud.service.name": [
      "EC2"
    ],
    "process.parent.executable.text": [
      "C:\\Windows\\System32\\cmd.exe"
    ],
    "ecs.version": [
      "1.12.0"
    ],
    "event.created": [
      "2022-06-29T00:33:12.492Z"
    ],
    "process.pe.description": [
      "Task Scheduler Configuration Tool"
    ],
    "agent.version": [
      "8.2.3"
    ],
    "host.os.family": [
      "windows"
    ],
    "winlog.event_data.ParentUser": [
      "THM_AURORA_TEST\\Administrator"
    ],
    "process.parent.name.text": [
      "cmd.exe"
    ],
    "winlog.user.type": [
      "User"
    ],
    "host.os.build": [
      "17763.1821"
    ],
    "event.module": [
      "sysmon"
    ],
    "host.os.kernel": [
      "10.0.17763.1821 (WinBuild.160101.0800)"
    ],
    "process.executable": [
      "C:\\Windows\\System32\\schtasks.exe"
    ],
    "winlog.user.identifier": [
      "S-1-5-18"
    ],
    "winlog.task": [
      "Process Create (rule: ProcessCreate)"
    ],
    "winlog.user.domain": [
      "NT AUTHORITY"
    ],
    "process.parent.executable": [
      "C:\\Windows\\System32\\cmd.exe"
    ],
    "process.parent.command_line.text": [
      "\"cmd.exe\" /c \"SCHTASKS /Create /SC ONCE /TN spawn /TR C:\\windows\\system32\\cmd.exe /ST 20:10\""
    ],
    "process.args_count": [
      10
    ],
    "winlog.event_data.IntegrityLevel": [
      "High"
    ],
    "process.args": [
      "SCHTASKS",
      "/Create",
      "/SC",
      "ONCE",
      "/TN",
      "spawn",
      "/TR",
      "C:\\windows\\system32\\cmd.exe",
      "/ST",
      "20:10"
    ],
    "message": [
      "Process Create:\nRuleName: technique_id=T1059,technique_name=Command-Line Interface\nUtcTime: 2022-06-29 00:33:11.426\nProcessGuid: {c5d2b969-9dc7-62bb-6c03-000000001f01}\nProcessId: 5864\nImage: C:\\Windows\\System32\\schtasks.exe\nFileVersion: 10.0.17763.1613 (WinBuild.160101.0800)\nDescription: Task Scheduler Configuration Tool\nProduct: Microsoft® Windows® Operating System\nCompany: Microsoft Corporation\nOriginalFileName: schtasks.exe\nCommandLine: SCHTASKS  /Create /SC ONCE /TN spawn /TR C:\\windows\\system32\\cmd.exe /ST 20:10\nCurrentDirectory: C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\\nUser: THM_AURORA_TEST\\Administrator\nLogonGuid: {c5d2b969-7ee7-62b9-4833-170000000000}\nLogonId: 0x173348\nTerminalSessionId: 2\nIntegrityLevel: High\nHashes: SHA1=82AA3192719BE60F7D8464BE1FEC653A50C16F87,MD5=2F6CE97FAF2D5EEA919E4393BDD416A7,SHA256=4B679CCC4E0E84A9EDDC24362EA4A86835597A90D94A1AE0EA905D7BCD9F771C,IMPHASH=0BF09EE8918142EE8D325D5955AA1CD9\nParentProcessGuid: {c5d2b969-9dc7-62bb-6a03-000000001f01}\nParentProcessId: 3264\nParentImage: C:\\Windows\\System32\\cmd.exe\nParentCommandLine: \"cmd.exe\" /c \"SCHTASKS /Create /SC ONCE /TN spawn /TR C:\\windows\\system32\\cmd.exe /ST 20:10\"\nParentUser: THM_AURORA_TEST\\Administrator"
    ],
    "winlog.event_id": [
      "1"
    ],
    "process.parent.args": [
      "cmd.exe",
      "/c",
      "SCHTASKS /Create /SC ONCE /TN spawn /TR C:\\windows\\system32\\cmd.exe /ST 20:10"
    ],
    "process.pe.imphash": [
      "0bf09ee8918142ee8d325d5955aa1cd9"
    ],
    "event.type": [
      "start"
    ],
    "process.command_line": [
      "SCHTASKS  /Create /SC ONCE /TN spawn /TR C:\\windows\\system32\\cmd.exe /ST 20:10"
    ],
    "winlog.event_data.Product": [
      "Microsoft® Windows® Operating System"
    ]
  }
}


SCHTASKS /Create /SC ONCE /TN spawn /TR C:\\windows\\system32\\cmd.exe /ST 20:10


https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create

/tn taskname
/tr taskrun
/sc scheduletype
/st starttime


Second Sigma Rule

https://github.com/SigmaHQ/sigma-specification/blob/main/Taxonomy_specification.md

┌──(kali㉿kali)-[~/Downloads]
└─$ nano Ransomware_detect.yml
                                                                                      
┌──(kali㉿kali)-[~/Downloads]
└─$ cat Ransomware_detect.yml 
title: Ransomware detect
id: 0b9acb09-dfcf-4855-bf54-ae81a7a663ce
status: experimental
description: Detect Ransomware
author: witty
date: 01/17/2023
logsource:
  category: file_event
  product: windows
detection:
  selection:
    Image: '\cmd.exe'
    TargetFilename|endswith: '.txt'    
  condition: selection

(process.executable.text:"\cmd.exe" AND file.path.text:*.txt)


{
  "_index": ".ds-winlogbeat-8.2.3-2022.06.27-000001",
  "_id": "gVcVrYEB3iMYFrgz8PhT",
  "_version": 1,
  "_score": 1,
  "_source": {
    "agent": {
      "name": "THM_Aurora_Test",
      "id": "ba6b17a6-3ca3-45a9-b4b2-fc995ab1c73a",
      "type": "winlogbeat",
      "ephemeral_id": "c483a7ab-6222-40f5-af9e-467e53880dac",
      "version": "8.2.3"
    },
    "process": {
      "name": "cmd.exe",
      "pid": 4052,
      "entity_id": "{c5d2b969-ab7f-62bb-9903-000000001f01}",
      "executable": "C:\\Windows\\SYSTEM32\\cmd.exe"
    },
    "winlog": {
      "computer_name": "THM_Aurora_Test",
      "process": {
        "pid": 3528,
        "thread": {
          "id": 2908
        }
      },
      "channel": "Microsoft-Windows-Sysmon/Operational",
      "event_data": {
        "CreationUtcTime": "2022-06-29 01:31:43.251"
      },
      "opcode": "Info",
      "version": 2,
      "record_id": "15427",
      "task": "File created (rule: FileCreate)",
      "event_id": "11",
      "provider_guid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
      "api": "wineventlog",
      "provider_name": "Microsoft-Windows-Sysmon",
      "user": {
        "identifier": "S-1-5-18",
        "domain": "NT AUTHORITY",
        "name": "SYSTEM",
        "type": "User"
      }
    },
    "log": {
      "level": "information"
    },
    "message": "File created:\nRuleName: -\nUtcTime: 2022-06-29 01:31:43.251\nProcessGuid: {c5d2b969-ab7f-62bb-9903-000000001f01}\nProcessId: 4052\nImage: C:\\Windows\\SYSTEM32\\cmd.exe\nTargetFilename: C:\\Users\\Administrator\\Desktop\\YOUR_FILES.txt\nCreationUtcTime: 2022-06-29 01:31:43.251\nUser: THM_AURORA_TEST\\Administrator",
    "cloud": {
      "image": {
        "id": "ami-0844a966e30ab3c23"
      },
      "availability_zone": "eu-west-1b",
      "instance": {
        "id": "i-0f365e6a14c6c7ae1"
      },
      "provider": "aws",
      "service": {
        "name": "EC2"
      },
      "machine": {
        "type": "t2.medium"
      },
      "region": "eu-west-1",
      "account": {
        "id": "739930428441"
      }
    },
    "@timestamp": "2022-06-29T01:31:43.251Z",
    "file": {
      "path": "C:\\Users\\Administrator\\Desktop\\YOUR_FILES.txt",
      "extension": "txt",
      "name": "YOUR_FILES.txt",
      "directory": "C:\\Users\\Administrator\\Desktop"
    },
    "ecs": {
      "version": "1.12.0"
    },
    "related": {
      "user": [
        "Administrator"
      ]
    },
    "host": {
      "hostname": "THM_Aurora_Test",
      "os": {
        "build": "17763.1821",
        "kernel": "10.0.17763.1821 (WinBuild.160101.0800)",
        "name": "Windows Server 2019 Datacenter",
        "type": "windows",
        "family": "windows",
        "version": "10.0",
        "platform": "windows"
      },
      "ip": [
        "fe80::8495:da75:43eb:5822",
        "10.10.222.40"
      ],
      "name": "THM_Aurora_Test",
      "id": "c5d2b969-b61a-4159-8f78-6391a1c805db",
      "mac": [
        "02:23:bb:82:ce:19"
      ],
      "architecture": "x86_64"
    },
    "event": {
      "ingested": "2022-06-29T01:31:45.105801017Z",
      "code": "11",
      "provider": "Microsoft-Windows-Sysmon",
      "created": "2022-06-29T01:31:44.071Z",
      "kind": "event",
      "module": "sysmon",
      "action": "File created (rule: FileCreate)",
      "type": [
        "creation"
      ],
      "category": [
        "file"
      ]
    },
    "user": {
      "domain": "THM_AURORA_TEST",
      "name": "Administrator",
      "id": "S-1-5-18"
    }
  },
  "fields": {
    "file.path": [
      "C:\\Users\\Administrator\\Desktop\\YOUR_FILES.txt"
    ],
    "event.category": [
      "file"
    ],
    "process.name.text": [
      "cmd.exe"
    ],
    "host.os.name.text": [
      "Windows Server 2019 Datacenter"
    ],
    "winlog.provider_name": [
      "Microsoft-Windows-Sysmon"
    ],
    "winlog.provider_guid": [
      "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"
    ],
    "host.hostname": [
      "THM_Aurora_Test"
    ],
    "process.pid": [
      4052
    ],
    "winlog.computer_name": [
      "THM_Aurora_Test"
    ],
    "host.mac": [
      "02:23:bb:82:ce:19"
    ],
    "winlog.process.pid": [
      3528
    ],
    "cloud.availability_zone": [
      "eu-west-1b"
    ],
    "host.os.version": [
      "10.0"
    ],
    "winlog.record_id": [
      "15427"
    ],
    "host.os.name": [
      "Windows Server 2019 Datacenter"
    ],
    "log.level": [
      "information"
    ],
    "agent.name": [
      "THM_Aurora_Test"
    ],
    "host.name": [
      "THM_Aurora_Test"
    ],
    "event.kind": [
      "event"
    ],
    "winlog.version": [
      2
    ],
    "file.path.text": [
      "C:\\Users\\Administrator\\Desktop\\YOUR_FILES.txt"
    ],
    "user.id": [
      "S-1-5-18"
    ],
    "host.os.type": [
      "windows"
    ],
    "cloud.region": [
      "eu-west-1"
    ],
    "agent.hostname": [
      "THM_Aurora_Test"
    ],
    "related.user": [
      "Administrator"
    ],
    "host.architecture": [
      "x86_64"
    ],
    "process.name": [
      "cmd.exe"
    ],
    "cloud.provider": [
      "aws"
    ],
    "event.provider": [
      "Microsoft-Windows-Sysmon"
    ],
    "cloud.machine.type": [
      "t2.medium"
    ],
    "event.code": [
      "11"
    ],
    "cloud.service.name": [
      "EC2"
    ],
    "agent.id": [
      "ba6b17a6-3ca3-45a9-b4b2-fc995ab1c73a"
    ],
    "ecs.version": [
      "1.12.0"
    ],
    "event.created": [
      "2022-06-29T01:31:44.071Z"
    ],
    "file.extension": [
      "txt"
    ],
    "agent.version": [
      "8.2.3"
    ],
    "host.os.family": [
      "windows"
    ],
    "winlog.process.thread.id": [
      2908
    ],
    "winlog.event_data.CreationUtcTime": [
      "2022-06-29 01:31:43.251"
    ],
    "user.name": [
      "Administrator"
    ],
    "process.entity_id": [
      "{c5d2b969-ab7f-62bb-9903-000000001f01}"
    ],
    "winlog.user.type": [
      "User"
    ],
    "host.os.build": [
      "17763.1821"
    ],
    "host.ip": [
      "fe80::8495:da75:43eb:5822",
      "10.10.222.40"
    ],
    "cloud.instance.id": [
      "i-0f365e6a14c6c7ae1"
    ],
    "agent.type": [
      "winlogbeat"
    ],
    "process.executable.text": [
      "C:\\Windows\\SYSTEM32\\cmd.exe"
    ],
    "event.module": [
      "sysmon"
    ],
    "host.os.kernel": [
      "10.0.17763.1821 (WinBuild.160101.0800)"
    ],
    "winlog.api": [
      "wineventlog"
    ],
    "user.domain": [
      "THM_AURORA_TEST"
    ],
    "host.id": [
      "c5d2b969-b61a-4159-8f78-6391a1c805db"
    ],
    "process.executable": [
      "C:\\Windows\\SYSTEM32\\cmd.exe"
    ],
    "winlog.user.identifier": [
      "S-1-5-18"
    ],
    "winlog.task": [
      "File created (rule: FileCreate)"
    ],
    "file.directory": [
      "C:\\Users\\Administrator\\Desktop"
    ],
    "winlog.user.domain": [
      "NT AUTHORITY"
    ],
    "file.name": [
      "YOUR_FILES.txt"
    ],
    "message": [
      "File created:\nRuleName: -\nUtcTime: 2022-06-29 01:31:43.251\nProcessGuid: {c5d2b969-ab7f-62bb-9903-000000001f01}\nProcessId: 4052\nImage: C:\\Windows\\SYSTEM32\\cmd.exe\nTargetFilename: C:\\Users\\Administrator\\Desktop\\YOUR_FILES.txt\nCreationUtcTime: 2022-06-29 01:31:43.251\nUser: THM_AURORA_TEST\\Administrator"
    ],
    "winlog.user.name": [
      "SYSTEM"
    ],
    "winlog.event_id": [
      "11"
    ],
    "cloud.image.id": [
      "ami-0844a966e30ab3c23"
    ],
    "event.action": [
      "File created (rule: FileCreate)"
    ],
    "event.ingested": [
      "2022-06-29T01:31:45.105Z"
    ],
    "@timestamp": [
      "2022-06-29T01:31:43.251Z"
    ],
    "winlog.channel": [
      "Microsoft-Windows-Sysmon/Operational"
    ],
    "cloud.account.id": [
      "739930428441"
    ],
    "host.os.platform": [
      "windows"
    ],
    "event.type": [
      "creation"
    ],
    "winlog.opcode": [
      "Info"
    ],
    "agent.ephemeral_id": [
      "c483a7ab-6222-40f5-af9e-467e53880dac"
    ],
    "user.name.text": [
      "Administrator"
    ]
  }
}

search YOUR_FILES.txt

{
  "_index": ".ds-winlogbeat-8.2.3-2022.06.27-000001",
  "_id": "f1cVrYEB3iMYFrgz8PhT",
  "_version": 1,
  "_score": 1,
  "_source": {
    "agent": {
      "name": "THM_Aurora_Test",
      "id": "ba6b17a6-3ca3-45a9-b4b2-fc995ab1c73a",
      "type": "winlogbeat",
      "ephemeral_id": "c483a7ab-6222-40f5-af9e-467e53880dac",
      "version": "8.2.3"
    },
    "process": {
      "args": [
        "cmd.exe",
        "/c",
        "echo T1486 - Purelocker Ransom Note > %%USERPROFILE%%\\Desktop\\YOUR_FILES.txt"
      ],
      "parent": {
        "args": [
          "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        ],
        "name": "powershell.exe",
        "pid": 5248,
        "args_count": 1,
        "entity_id": "{c5d2b969-810a-62b9-0e01-000000001f01}",
        "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "command_line": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" "
      },
      "pe": {
        "file_version": "10.0.17763.1697 (WinBuild.160101.0800)",
        "product": "Microsoft® Windows® Operating System",
        "imphash": "272245e2988e1e430500b852c4fb5e18",
        "description": "Windows Command Processor",
        "original_file_name": "Cmd.Exe",
        "company": "Microsoft Corporation"
      },
      "name": "cmd.exe",
      "pid": 4052,
      "working_directory": "C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\",
      "args_count": 3,
      "entity_id": "{c5d2b969-ab7f-62bb-9903-000000001f01}",
      "hash": {
        "sha1": "ded8fd7f36417f66eb6ada10e0c0d7c0022986e9",
        "sha256": "bc866cfcdda37e24dc2634dc282c7a0e6f55209da17a8fa105b07414c0e7c527",
        "md5": "911d039e71583a07320b32bde22f8e22"
      },
      "executable": "C:\\Windows\\System32\\cmd.exe",
      "command_line": "\"cmd.exe\" /c \"echo T1486 - Purelocker Ransom Note > %%USERPROFILE%%\\Desktop\\YOUR_FILES.txt\""
    },
    "winlog": {
      "computer_name": "THM_Aurora_Test",
      "process": {
        "pid": 3528,
        "thread": {
          "id": 2908
        }
      },
      "channel": "Microsoft-Windows-Sysmon/Operational",
      "event_data": {
        "Company": "Microsoft Corporation",
        "Description": "Windows Command Processor",
        "LogonGuid": "{c5d2b969-7ee7-62b9-4833-170000000000}",
        "IntegrityLevel": "High",
        "TerminalSessionId": "2",
        "Product": "Microsoft® Windows® Operating System",
        "ParentUser": "THM_AURORA_TEST\\Administrator",
        "FileVersion": "10.0.17763.1697 (WinBuild.160101.0800)",
        "LogonId": "0x173348"
      },
      "opcode": "Info",
      "version": 5,
      "record_id": "15425",
      "event_id": "1",
      "task": "Process Create (rule: ProcessCreate)",
      "provider_guid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
      "api": "wineventlog",
      "provider_name": "Microsoft-Windows-Sysmon",
      "user": {
        "identifier": "S-1-5-18",
        "domain": "NT AUTHORITY",
        "name": "SYSTEM",
        "type": "User"
      }
    },
    "log": {
      "level": "information"
    },
    "rule": {
      "name": "technique_id=T1059,technique_name=Command-Line Interface"
    },
    "message": "Process Create:\nRuleName: technique_id=T1059,technique_name=Command-Line Interface\nUtcTime: 2022-06-29 01:31:43.203\nProcessGuid: {c5d2b969-ab7f-62bb-9903-000000001f01}\nProcessId: 4052\nImage: C:\\Windows\\System32\\cmd.exe\nFileVersion: 10.0.17763.1697 (WinBuild.160101.0800)\nDescription: Windows Command Processor\nProduct: Microsoft® Windows® Operating System\nCompany: Microsoft Corporation\nOriginalFileName: Cmd.Exe\nCommandLine: \"cmd.exe\" /c \"echo T1486 - Purelocker Ransom Note > %%USERPROFILE%%\\Desktop\\YOUR_FILES.txt\"\nCurrentDirectory: C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\\nUser: THM_AURORA_TEST\\Administrator\nLogonGuid: {c5d2b969-7ee7-62b9-4833-170000000000}\nLogonId: 0x173348\nTerminalSessionId: 2\nIntegrityLevel: High\nHashes: SHA1=DED8FD7F36417F66EB6ADA10E0C0D7C0022986E9,MD5=911D039E71583A07320B32BDE22F8E22,SHA256=BC866CFCDDA37E24DC2634DC282C7A0E6F55209DA17A8FA105B07414C0E7C527,IMPHASH=272245E2988E1E430500B852C4FB5E18\nParentProcessGuid: {c5d2b969-810a-62b9-0e01-000000001f01}\nParentProcessId: 5248\nParentImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\nParentCommandLine: \"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" \nParentUser: THM_AURORA_TEST\\Administrator",
    "cloud": {
      "image": {
        "id": "ami-0844a966e30ab3c23"
      },
      "availability_zone": "eu-west-1b",
      "instance": {
        "id": "i-0f365e6a14c6c7ae1"
      },
      "provider": "aws",
      "machine": {
        "type": "t2.medium"
      },
      "service": {
        "name": "EC2"
      },
      "region": "eu-west-1",
      "account": {
        "id": "739930428441"
      }
    },
    "@timestamp": "2022-06-29T01:31:43.203Z",
    "ecs": {
      "version": "1.12.0"
    },
    "related": {
      "user": [
        "Administrator"
      ],
      "hash": [
        "bc866cfcdda37e24dc2634dc282c7a0e6f55209da17a8fa105b07414c0e7c527",
        "ded8fd7f36417f66eb6ada10e0c0d7c0022986e9",
        "911d039e71583a07320b32bde22f8e22",
        "272245e2988e1e430500b852c4fb5e18"
      ]
    },
    "host": {
      "hostname": "THM_Aurora_Test",
      "os": {
        "build": "17763.1821",
        "kernel": "10.0.17763.1821 (WinBuild.160101.0800)",
        "name": "Windows Server 2019 Datacenter",
        "type": "windows",
        "family": "windows",
        "version": "10.0",
        "platform": "windows"
      },
      "ip": [
        "fe80::8495:da75:43eb:5822",
        "10.10.222.40"
      ],
      "name": "THM_Aurora_Test",
      "id": "c5d2b969-b61a-4159-8f78-6391a1c805db",
      "mac": [
        "02:23:bb:82:ce:19"
      ],
      "architecture": "x86_64"
    },
    "event": {
      "ingested": "2022-06-29T01:31:45.104358079Z",
      "code": "1",
      "provider": "Microsoft-Windows-Sysmon",
      "created": "2022-06-29T01:31:44.071Z",
      "kind": "event",
      "module": "sysmon",
      "action": "Process Create (rule: ProcessCreate)",
      "type": [
        "start"
      ],
      "category": [
        "process"
      ]
    },
    "user": {
      "domain": "THM_AURORA_TEST",
      "name": "Administrator",
      "id": "S-1-5-18"
    }
  },
  "fields": {
    "process.hash.md5": [
      "911d039e71583a07320b32bde22f8e22"
    ],
    "event.category": [
      "process"
    ],
    "host.os.name.text": [
      "Windows Server 2019 Datacenter"
    ],
    "process.parent.command_line": [
      "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" "
    ],
    "process.parent.name": [
      "powershell.exe"
    ],
    "process.parent.pid": [
      5248
    ],
    "process.hash.sha256": [
      "bc866cfcdda37e24dc2634dc282c7a0e6f55209da17a8fa105b07414c0e7c527"
    ],
    "host.hostname": [
      "THM_Aurora_Test"
    ],
    "host.mac": [
      "02:23:bb:82:ce:19"
    ],
    "winlog.process.pid": [
      3528
    ],
    "host.os.version": [
      "10.0"
    ],
    "agent.name": [
      "THM_Aurora_Test"
    ],
    "winlog.event_data.Company": [
      "Microsoft Corporation"
    ],
    "user.id": [
      "S-1-5-18"
    ],
    "host.os.type": [
      "windows"
    ],
    "cloud.region": [
      "eu-west-1"
    ],
    "agent.hostname": [
      "THM_Aurora_Test"
    ],
    "process.pe.product": [
      "Microsoft® Windows® Operating System"
    ],
    "related.user": [
      "Administrator"
    ],
    "host.architecture": [
      "x86_64"
    ],
    "cloud.provider": [
      "aws"
    ],
    "event.provider": [
      "Microsoft-Windows-Sysmon"
    ],
    "cloud.machine.type": [
      "t2.medium"
    ],
    "winlog.event_data.FileVersion": [
      "10.0.17763.1697 (WinBuild.160101.0800)"
    ],
    "event.code": [
      "1"
    ],
    "agent.id": [
      "ba6b17a6-3ca3-45a9-b4b2-fc995ab1c73a"
    ],
    "winlog.event_data.LogonGuid": [
      "{c5d2b969-7ee7-62b9-4833-170000000000}"
    ],
    "winlog.event_data.Description": [
      "Windows Command Processor"
    ],
    "process.command_line.text": [
      "\"cmd.exe\" /c \"echo T1486 - Purelocker Ransom Note > %%USERPROFILE%%\\Desktop\\YOUR_FILES.txt\""
    ],
    "winlog.process.thread.id": [
      2908
    ],
    "user.name": [
      "Administrator"
    ],
    "process.working_directory": [
      "C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\"
    ],
    "process.entity_id": [
      "{c5d2b969-ab7f-62bb-9903-000000001f01}"
    ],
    "host.ip": [
      "fe80::8495:da75:43eb:5822",
      "10.10.222.40"
    ],
    "cloud.instance.id": [
      "i-0f365e6a14c6c7ae1"
    ],
    "agent.type": [
      "winlogbeat"
    ],
    "process.pe.original_file_name": [
      "Cmd.Exe"
    ],
    "process.executable.text": [
      "C:\\Windows\\System32\\cmd.exe"
    ],
    "winlog.api": [
      "wineventlog"
    ],
    "user.domain": [
      "THM_AURORA_TEST"
    ],
    "host.id": [
      "c5d2b969-b61a-4159-8f78-6391a1c805db"
    ],
    "process.pe.file_version": [
      "10.0.17763.1697 (WinBuild.160101.0800)"
    ],
    "process.working_directory.text": [
      "C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\"
    ],
    "winlog.user.name": [
      "SYSTEM"
    ],
    "cloud.image.id": [
      "ami-0844a966e30ab3c23"
    ],
    "process.pe.company": [
      "Microsoft Corporation"
    ],
    "event.action": [
      "Process Create (rule: ProcessCreate)"
    ],
    "event.ingested": [
      "2022-06-29T01:31:45.104Z"
    ],
    "@timestamp": [
      "2022-06-29T01:31:43.203Z"
    ],
    "winlog.channel": [
      "Microsoft-Windows-Sysmon/Operational"
    ],
    "cloud.account.id": [
      "739930428441"
    ],
    "host.os.platform": [
      "windows"
    ],
    "winlog.opcode": [
      "Info"
    ],
    "agent.ephemeral_id": [
      "c483a7ab-6222-40f5-af9e-467e53880dac"
    ],
    "winlog.event_data.TerminalSessionId": [
      "2"
    ],
    "process.hash.sha1": [
      "ded8fd7f36417f66eb6ada10e0c0d7c0022986e9"
    ],
    "user.name.text": [
      "Administrator"
    ],
    "winlog.event_data.LogonId": [
      "0x173348"
    ],
    "process.name.text": [
      "cmd.exe"
    ],
    "winlog.provider_name": [
      "Microsoft-Windows-Sysmon"
    ],
    "winlog.provider_guid": [
      "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"
    ],
    "related.hash": [
      "bc866cfcdda37e24dc2634dc282c7a0e6f55209da17a8fa105b07414c0e7c527",
      "ded8fd7f36417f66eb6ada10e0c0d7c0022986e9",
      "911d039e71583a07320b32bde22f8e22",
      "272245e2988e1e430500b852c4fb5e18"
    ],
    "process.pid": [
      4052
    ],
    "winlog.computer_name": [
      "THM_Aurora_Test"
    ],
    "cloud.availability_zone": [
      "eu-west-1b"
    ],
    "process.parent.entity_id": [
      "{c5d2b969-810a-62b9-0e01-000000001f01}"
    ],
    "winlog.record_id": [
      "15425"
    ],
    "host.os.name": [
      "Windows Server 2019 Datacenter"
    ],
    "log.level": [
      "information"
    ],
    "host.name": [
      "THM_Aurora_Test"
    ],
    "event.kind": [
      "event"
    ],
    "winlog.version": [
      5
    ],
    "rule.name": [
      "technique_id=T1059,technique_name=Command-Line Interface"
    ],
    "process.parent.args_count": [
      1
    ],
    "process.name": [
      "cmd.exe"
    ],
    "cloud.service.name": [
      "EC2"
    ],
    "process.parent.executable.text": [
      "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    ],
    "ecs.version": [
      "1.12.0"
    ],
    "event.created": [
      "2022-06-29T01:31:44.071Z"
    ],
    "process.pe.description": [
      "Windows Command Processor"
    ],
    "agent.version": [
      "8.2.3"
    ],
    "host.os.family": [
      "windows"
    ],
    "winlog.event_data.ParentUser": [
      "THM_AURORA_TEST\\Administrator"
    ],
    "process.parent.name.text": [
      "powershell.exe"
    ],
    "winlog.user.type": [
      "User"
    ],
    "host.os.build": [
      "17763.1821"
    ],
    "event.module": [
      "sysmon"
    ],
    "host.os.kernel": [
      "10.0.17763.1821 (WinBuild.160101.0800)"
    ],
    "process.executable": [
      "C:\\Windows\\System32\\cmd.exe"
    ],
    "winlog.user.identifier": [
      "S-1-5-18"
    ],
    "winlog.task": [
      "Process Create (rule: ProcessCreate)"
    ],
    "winlog.user.domain": [
      "NT AUTHORITY"
    ],
    "process.parent.executable": [
      "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    ],
    "process.parent.command_line.text": [
      "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" "
    ],
    "process.args_count": [
      3
    ],
    "winlog.event_data.IntegrityLevel": [
      "High"
    ],
    "process.args": [
      "cmd.exe",
      "/c",
      "echo T1486 - Purelocker Ransom Note > %%USERPROFILE%%\\Desktop\\YOUR_FILES.txt"
    ],
    "message": [
      "Process Create:\nRuleName: technique_id=T1059,technique_name=Command-Line Interface\nUtcTime: 2022-06-29 01:31:43.203\nProcessGuid: {c5d2b969-ab7f-62bb-9903-000000001f01}\nProcessId: 4052\nImage: C:\\Windows\\System32\\cmd.exe\nFileVersion: 10.0.17763.1697 (WinBuild.160101.0800)\nDescription: Windows Command Processor\nProduct: Microsoft® Windows® Operating System\nCompany: Microsoft Corporation\nOriginalFileName: Cmd.Exe\nCommandLine: \"cmd.exe\" /c \"echo T1486 - Purelocker Ransom Note > %%USERPROFILE%%\\Desktop\\YOUR_FILES.txt\"\nCurrentDirectory: C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\\nUser: THM_AURORA_TEST\\Administrator\nLogonGuid: {c5d2b969-7ee7-62b9-4833-170000000000}\nLogonId: 0x173348\nTerminalSessionId: 2\nIntegrityLevel: High\nHashes: SHA1=DED8FD7F36417F66EB6ADA10E0C0D7C0022986E9,MD5=911D039E71583A07320B32BDE22F8E22,SHA256=BC866CFCDDA37E24DC2634DC282C7A0E6F55209DA17A8FA105B07414C0E7C527,IMPHASH=272245E2988E1E430500B852C4FB5E18\nParentProcessGuid: {c5d2b969-810a-62b9-0e01-000000001f01}\nParentProcessId: 5248\nParentImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\nParentCommandLine: \"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" \nParentUser: THM_AURORA_TEST\\Administrator"
    ],
    "winlog.event_id": [
      "1"
    ],
    "process.parent.args": [
      "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    ],
    "process.pe.imphash": [
      "272245e2988e1e430500b852c4fb5e18"
    ],
    "event.type": [
      "start"
    ],
    "process.command_line": [
      "\"cmd.exe\" /c \"echo T1486 - Purelocker Ransom Note > %%USERPROFILE%%\\Desktop\\YOUR_FILES.txt\""
    ],
    "winlog.event_data.Product": [
      "Microsoft® Windows® Operating System"
    ]
  }
}

T1486 - Purelocker Ransom Note
https://www.bleepingcomputer.com/news/security/purelocker-ransomware-can-lock-files-on-windows-linux-and-macos/

https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1486/T1486.md

For example, if the password for the encrypted archive is "password123", the path for the encrypted archive is "C:\myfiles\secrets.7z", the path for the file to be added is "C:\myfiles\sensitive_data.txt", the command would be:



7z a -p"password123" "C:\myfiles\secrets.7z" "C:\myfiles\sensitive_data.txt"

This will add the sensitive_data.txt file to the secrets.7z archive with password "password123"

“Technology alone cannot protect you.”

```

![[Pasted image 20230117135248.png]]

To detect the creation of the scheduled task, what detection value would be appropriate for the Sigma rule?

	Ensure to include the \ in the answer.

	*\schtasks.exe*

What was the name of the scheduled task created?

*spawn*

What time is this task meant to run?

*20:10*

To detect ransomware activity, what logsource category would be appropriate for the Sigma rule?

The Sigma taxonomy provides a list of log source categories.

*file_event*

What is the name of the created file?

*YOUR_FILES.txt*

What was the event code associated with the activity?

*11*

What were the contents of the created ransomware file?

Search for an event with the filename as part of the command line.

*T1486 - Purelocker Ransom Note*

###  Conclusion

 Download Task Files

In this room, we have gone through the use of Sigma for writing threat detections that can be used to raise alerts within a SOC environment. Additionally, we practised applying these rules to an Elastic Stack environment and extracting information for investigations.

This room covers a small part of the thought process security analysts should go through while developing their detection engineering frameworks. Download the cheatsheet on this task for a quick recap. 

Answer the questions below

To more learning!


[[Tactical Detection]]