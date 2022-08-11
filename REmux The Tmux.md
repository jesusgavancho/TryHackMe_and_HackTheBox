---
Tmux is known as a terminal multiplexer. That allows you to craft a single terminal however you need it.
---

### ssh

```
ssh tux@10.10.52.44
```
`tux:tmuxwithremux`

### Starting tmux "Sessions" and default tmux "prefix" 

```start
tmux
```

> The first session create will have the name "0". By default, tmux status bar will be green. With session name on the left. Windows in the middle and window names in the middle. Hostname, time, and date on the right of the bottom green bar.

> Tmux doesn't allow to create of a nested tmux within a tmux unless you force it to.

>To change the session name from "0" -> "box-dev". Must first learn how tmux is called. All commands within a tmux session all start with the tmux prefix is. By default, the tmux prefix is "Ctrl b".

>After the tmux prefix. To the hotkeys to change the current tmux session's name is "shift $". 
ctrl b shift $
Retype the new name and then enter-key to save the new session name.

```
tmux new -s tryhackme -d
```

>If there is a need to create another tmux session within the current one. Use the -d argument with the tmux command. To spawn a new tmux session without attaching to it. In the example image below. The -s argument is used to specify the session name for the new session. 

```
tmux ls
```

>To list all active tmux sessions.

>Exiting a tmux session without closing it can be done with the prefix. Followed by d
ctrl b d
Checking again with the tmux ls command. "(attached)" is missing from both sessions. This means the sessions are active but we are detached and are unable to interact with either session.

>To reattach to an active tmux session. Run tmux with the attach option and -t followed by the desired session name.

```
tmux attach -t tryhackme
```

> Delete a single session by its session name. Is done with the kill-session option with tmux. Followed by -t and the target-session-name-to-delete

```
tmux kill-session -t box-dev
```

```except
tmux kill-session -t tryhackme -a

```
###  Manage tmux "Panes" 

>ctrl b s (list sessions to choose)

> ctrl b shift : (start directory)

> ctrl b shift " (pane horizontally)

> ctrl b shift % (pane vertically)

> The exit command can be used to close the currently selected pane.

> ctrl b arrow key  (move around)

> ctrl b o (move next pane)

> ctrl b ; (left to right)

> ctrl b x y (close pane)

> ctrl b shift } (move clockwise)

> ctrl b shift { (move counter-clockwise)

> ctrl b esc 4 (Another way to manage the pane location is with five built-in layouts. )

> ctrl b spacebar (To cycle through the built-in pane layouts one at a time.)

> ctrl b q (identify pane numbers)

> ctrl b : swap-pane -s 3 -t 0

> ctrl b : swap-pane -s 0 -t 3 (change parrot and cow)

###  Manage tmux "Windows" 

> ctrl b c (new empty window)

> ctrl b , (change the current window name)

> ctrl b shift ! (To detach a pane into its own window. )

> ctrl b n (next window cycling)

>ctrl b p (previous windows cycling)

> ctrl b w (switch desired window)

> ctrl b shift & (close window if it's unresponsive)

> ctrl b shift : join-pane -s tryhackme (join windows)

> ctrl b shift : join-pane -s tryhackme -v  (fuse vertically)

> ctrl b shift : join-pane -s tryhackme -h(fuse horizontally)

###  Tmux "copy" mode 

> ctrl b [ (to scroll up and dow) ==q to quit==

`ctrl r -> to search up`

`ctrl s -> to search down`

> To copy and paste within tmux copy-mode takes 4 steps. Note that this method will only apply to the tmux clipboard as follows.

> ctrl b [ # (copy mode)

> scroll to the start of the block of text you would like to copy

> enable highlighting with ctrl spacebar. Then use the arrow keys to up to select all the text. Down if you start from the top instead.

> copy all the highlighted text to the tmux clipboard with alt w. Note! Even though the highlight will disappear. The text still copied to the tmux clipboard.

> create a new file to paste the final text with ctrl b ]

> To double-check what the text that is currently copied to the tmux clipboard. Do prefix followed by shift #

> ctrl b shift #

==Note. Even though the text might look broken don't worry it will paste as it was copied within a terminal file editor. To quit back to the terminal. Hit the q key once.==

> Pasting again with prefix ] shows that it pasted corrected from the origin ASCII image. ctrl b ]

###  Oh My Tmux and beyond 

> tmux show -g (show default oprions)

- Do the ctrl and b keys need to be held down the whole time with every commands to work? yea/nay *nay* ==just press ctrl +b/ released/no pressed/then/the key u need==
- How to start tmux with the session with the name "thm"? *tmux new -s thm*
- How to change the current tmux session name?*ctrl b shift $*
- How to quit a tmux session without closing the session? To attach back later.*ctrl b d*
- How to list all tmux sessions?*tmux ls*
- How to reattach to a detached tmux session with the session name of "thm"*tmux -t thm*
- How to create a new tmux session from your current tmux session with the name kali?*tmux new -s kali -d*
- How to switch between two or more tmux sessions without detaching from the current tmux session?*ctrl b d*
- How do you force kill the tmux session named "thm" if it's not responsive from a new terminal window or tmux session?*tmux kill-session -t thm -a*
- Within a nested tmux session. A second tmux session within the first one. How to change the session name of the second/internal tmux session?*ctrl b ctrl b shift $*
- How to get into a tmux prompt to run/type tmux commands?*ctrl b shift :*
- Are there more than one way to exit a tmux prompt? yea/nay*yea*
- Is tmux case sensitive. Will hitting the caps lock break tmux? yea/nay*yea*
- Within tmux prompt or command mode how would you change the tmux directory? Where a new window or pane will start from the changed directory of /opt.*1 -c /opt*
- How to kill all tmux sessions accept the one currently in use? With the name "notes".*tmux kill-session -t notes -a*
- How to create a new pane split horizontally?*ctrl b shift "*
- How to close a tmux pane like closing a ssh session?*exit*
- How to create a new pane split vertically? *ctrl b shift %*
- How to cycle between tmux pre built layout options? Starting with the number 1.*ctrl b  esc 1*
- How to cycle/toggle between tmux layouts, one at a time?*ctrl b spacebar*
- How to force quit a frozen, crashed or borked pane? *ctrl b x y*
- How to move between the two must used tmux panes for the current tmux window?*ctrl b ;*
- Can you use the arrow to move to the desired pane? yea/nay*yea*
- How to move the currently selected pane clockwise?*ctrl b shift {*
- How to move the currently selected pane counter-clockwise*ctrl b shift }*
- Before using swap-pane. How to check for which pane has what number?*ctrl b q*
- How to swap two panes and move with the swapped pane?  Within tmux prompt mode. 1 -> 3 location *:swap-pane -s 1 -t 3*
- How to swap two panes without changing the currently selected pane location? Within tmux prompt mode. 1 -> 4 pane number *:swap-pane -s 1 -t 4*
- How to create a new empty tmux window?*ctrl b c*
- How to change the currently select window's name?*ctrl b ,*
- How to move the currently selected pane to it's own tmux window?*ctrl b shift !*
- How to fuse two panes together with the "source" window of "bash"? After entering a tmux prompt?*:join-pane -s bash*
- How to fuse two panes together with the "destination" window of "sudo"? After entering a tmux prompt?*:join-pane -t sudo*
- What option can added with question 4 and 5 to fuse together vertically?*-v*
- What option can added with question 4 and 5 to fuse together horizontally?*-h*
- With join-pane can you use the window number instead of the window's name? yea/nay *yea*
- How to kill or completely close a window. Including all the panes open on that window. If it's unresponsive?*ctrl b shift &*
- How to view and cycle between all the tmux windows for the current tmux session without detaching from the current session?*ctrl b w*
- How to move back to the previous tmux window?*ctrl b p*
- How to move up to the next tmux window?*ctrl b n*
- How to start copy mode?*ctrl b q*
- While in copy mode. How to search/grep up the wall of terminal text?*ctrl r*
- While in copy mode. How to search/grep down the wall of terminal text?*ctrl s*
- How to exit search up or search down within copy mode?*esc*
- What single key can also be used to to exit out of copy mode.*q*
- After starting copy mode. How do you enable text highlighting to select for text copying?*ctrl spacebar*
- After selecting the text you want to copy. How do copy it?*alt w*
- When in a terminal text editor. How to paste from the tmux clipboard?*ctrl b ]*
- How to double check what is currently copied to the tmux clipboard *ctrl b shift #*
-  Does tmux have a default tmux.conf config file? yea/nay *nay*
- Where can you find examples for custom tmux.conf config files?*/usr/share/doc/tmux*
- Can you use Hex color codes in place of the color name? yea/nay *yea*
- What directory must the .tmux.conf be put in to work with the next tmux session*home*
- How would you update tmux changes without quitting the tmux session from a tmux prompt?*:source-file ~/.tmux.conf*
- How to completely reset tmux to its default and kill all sessions? If the .tmux.conf is borked. *tmux kill-server*
- How would you select addition hotkeys. Without overwriting the default hotkey?*bind*
- How would you change the prefix to Ctrl a?*set -g prefix C-a*
- Can you display shell command output. From a script or one line command? yea/nay*yea*
- How would you load a plugin into a tmux config file?*set -g @plugin*
- How can you run the desired plugin after loading it?*run-shell*














