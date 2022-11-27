```
***enumerating***
rustscan -a 10.10.9.58 --ulimit 5000 -b 65535 -- -A 
***log ssh port 22***
via linux
ssh thm@10.10.168.200
pass -> tryhackme
or via putty (windows)
***installing tor***
sudo apt-get install tor
***start service***
service tor start
***stop service***
service tor stop
***ver status(started or stopped)
service tor status
***install proxychains***
sudo apt install proxychains
***configure***
nano /etc/proxychains.conf
uncomment dynamic_chain  with and comment others # also uncomment proxy_dns
proxychains firefox (will open a new firefox)
go to dnsleaktest.com to see my dns if leaked
***installing tor browser***
sudo apt update
sudo apt install -y tor torbrowser-launcher
inicializar tor web browser (security mode safer)
Access the website below and capture the flag by copying bitcoin address at the bottom of the page!
http://danielas3rtn54uwmofdo3x2bsdifr47huasnmbgqzfrec5ubupvtpid.onion/
Answ: 1K918TvvE4PMPzPuZT7zSDAQV4ZNUjHBm5
service tor stop


```

[[Tmux]]