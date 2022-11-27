```
tmux, the terminal multiplexer, is easily one of the most used tools by the Linux community (and not just pentesters!). While not a malicious tool, tmux makes running simultaneous tasks throughout a pentest incredibly easy. In this primer room, we'll walk through the process of installing and using some of the most common key combinations used in tmux. (Note, the installation process in this is geared towards Kali/Ubuntu.)

First things first, let's go ahead and install tmux. This can be done on Ubuntu/Kali with the command: apt-get install tmux


Once tmux is installed, let's launch a new session. What command do we use to launch a new session without a custom name?
tmux
All tmux commands start with a keyboard button combination. What is the first key in this combination?Control


How about the second key? Note, these keys must be pressed at the same time and released before pressing the next target key in the combination. 
B


Lets go ahead and detach from our newly created tmux session. What key do we need to add to the combo in order to detach?
D


Well shoot, we've detached from our session. How do we list all of our sessions?
tmux ls


What did our session name default to when we created one without a set name?
This should be a number, it's where arrays start in programming if you're using a good programming language ;) 
0
Now that we've found the name of our session, how do we attach to it?
tmux a -t 0


Let's go ahead and make a new window in this session. What key do we add to the combo in order to do this?

Run the following scan against the VM: nmap -sV -vv -sC TARGET_IP


Whew! Plenty of output to work with now! If you work with a relatively small terminal like me, this output might not all fit on screen at once. To fix that, let's enter 'copy mode'. What key do we add to the combo to enter copy mode?
[


Copy mode is very similar to 'less' and allows up to scroll up and down using the arrow keys. What if we want to go up to the very top?
g


How about the bottom?
G

What key do we press to exit 'copy mode'?
q
This window we're working in is nice and all but I think we need an upgrade. What key do we add to the combo to split the window vertically?
%


How about horizontally?
"


We can now move between these panes using the key combo and arrow keys, try it out!
ctrl + b + o

Wait a minute, we've forgotten about our original window! We can go back it using the key combo and the number of the session! Try going back to this original window and then returning to our new one!
ctrl + b + flechas
Say one of these newly minted panes becomes unresponsive or we're just done working in it, what key do we add to the combo to 'kill' the pane?

ctrl + b +x

Now that's we've finished out work, what can we type to close the session?
exit


Last but not least, how do we spawn a named tmux session named 'neat'?

tmux new -s neat
```

[[Revil_Corp]]