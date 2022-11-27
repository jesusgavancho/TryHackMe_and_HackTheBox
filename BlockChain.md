```
https://tryhackme.com/room/blockchainvkkgjrph7y

┌──(kali㉿kali)-[~/Downloads/Blockchain]
└─$ ftp 10.10.131.24
Connected to 10.10.131.24.
220 (vsFTPd 3.0.3)
Name (10.10.131.24:kali): bouncer
331 Please specify the password.
Password: cyberbouncer
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||10659|)
150 Here comes the directory listing.
-rw-rw-r--    1 1001     1001       242207 Jul 04 20:27 blockchain-demo-master.zip
drwxr-xr-x    2 1001     1001         4096 Jul 04 21:28 test
-rw-rw-r--    1 1001     1001     15803548 Jul 04 20:27 ufonet-master.zip
226 Directory send OK.
ftp> more test
Failed to open file.
ftp> cat test
?Invalid command.
ftp> more test
Failed to open file.
ftp> type test
test: unknown mode.
ftp> get blockchain-demo-master.zip
local: blockchain-demo-master.zip remote: blockchain-demo-master.zip
229 Entering Extended Passive Mode (|||10029|)
150 Opening BINARY mode data connection for blockchain-demo-master.zip (242207 bytes).
100% |*****************************************|   236 KiB  178.80 KiB/s    00:00 ETA
226 Transfer complete.
242207 bytes received in 00:01 (149.62 KiB/s)
ftp> ^D
221 Goodbye.

Download the simulator

The first thing we have to do is start the machine "Bouncer Store", attached to this task.

To download the simulator we must connect to the machine via ftp.

Open your linux attack machine and run a terminal. Copy paste the following commands in the terminal:


ftp ip;

# (ip= ip of "Bouncer Store")

# Introduce the user:

bouncer

# Enter the password:

cyberbouncer

# Download the simulator with the command:

get blockchain-demo-master.zip

# We can exit from ftp with:

Ctl + D 


Now we are in possession of the simulator the next step is to install it in our linux attack machine:

#The file is in zip format...

#Unzip the simulator: 

unzip blockchain-demo-master.zip 

#Move to the simulator directory:

cd blockchain-demo-master;
#Create a server using "docker":

sudo docker-compose up -d;

#Give it time to execute the server...


Point a web browser at the simulator

Copy this url in your attack box browser to move to the "Hash" part of the simulator, in your localhost under port:3000-->   http://localhost:3000/hash


#Do the following only in case of error:

If you are not using the "THM attack box" it may be that you have problems starting the server, in that case try to install docker-compose with the follow commands and start the server again:

sudo apt update;

sudo apt install docker-compose -y;

sudo docker-compose up -d;

Blockchain Demo -> http://localhost:3000/hash



A hash is a function that meets the encrypted demands needed to solve for a blockchain computation. Hashes are of a fixed length since it makes it nearly impossible to guess the length of the hash if someone was trying to crack the blockchain. The same data will always produce the same hashed value.
When you are in the simulator ...
In the "data" box: Write random letters. Is the hash changing? Yes or no ("y" or "n") y




Click the "Block" tab in the simulator webpage tab menu or paste this link in the url  http://localhost:3000/block 

A block is a place in a blockchain where information is stored and encrypted. Blocks are identified by long numbers that include encrypted transaction information from previous blocks and new transaction information. Blocks and the information within them must be verified by a network before new blocks can be created.



"Nonce" is a portmanteau of "number used only once." It is a four-bit number added to a hashed—or encrypted—block in a blockchain that, when rehashed, meets the difficulty level restrictions. The nonce is the number that blockchain miners are solving for.

Write what you want  in the "nonce" box.

Mine the block...

is the nonce changing? And the hash? ("y" or "n","y" or "n") n,n

Now try it with the data part, write "distributed" in the data box. 

Mine the block.

Whats the new hash? (copy paste all hash) 00009718b21748a9b14da4603ab9f289dc500b20be3fdf9715d32f6803a440c4

Now write  "distriBUTED", is the hash changing? ("y" or "n") y




Click the "Blockchain" tab in the simulator webpage tab menu or paste this link in the url  http://localhost:3000/blockchain

Blockchain is a system of recording information in a way that makes it difficult or impossible to change, hack, or cheat the system. A blockchain is essentially a digital ledger of transactions that is duplicated and distributed across the entire network of computer systems on the blockchain.


The security of a blockchain is that if any of the blocks is modified, even with a blank space, the rest of the chain also changes... true or false (t or f)  t




Click the "Distributed" tab in the simulator webpage tab menu or paste this link in the url  http://localhost:3000/distributed

All nodes on a blockchain are connected to each other and they constantly exchange the latest blockchain data with each other so all nodes stay up to date. They store, spread and preserve the blockchain data, so theoretically a blockchain exists on nodes.



In the "peer A" block 3, write in the data box: "Peer-to-peer" 

In the "peer B" block 5, write in the data box: "Peer to peer" 

Mine the blocks until all blocks turn green.

Do you think that this is a valid blockchain? (y or n)
Compare the hashes of the end blocks in every chain. n

An attack in a blockchain can happens when a malicious user in a network acquires control of a given blockchain's mining capabilities. The attackers can stop the confirmation and order of new transactions.

The most effective attack consists in a potential attack on the integrity of a blockchain system in which a single malicious actor or organization manages to control more than half of the total hashing power of the network, potentially causing network disruption. 

What is the most famous way attack for a blockchain?("a" or "b" or "c" or "d")

a) brute force attack

b) 51% attack

c) blockchain injection attack

d) a blockchain can't be overcome in any way

The attacker needs control of most of the nodes in the blockchain  b

An attack on a blockchain by a group of miners controlling over 50% of a network’s mining hashrate – the sum of all computing power dedicated to mining and processing transactions – is called a 51% attack.

A blockchain is a type of ledger technology that stores and records data. Put simply, a blockchain is a distributed list of transactions that is constantly being updated and reviewed. One of the key features of a blockchain is that it is made up of a decentralized network of nodes (a crucial piece of ensuring that a cryptocurrency remains decentralized and secure).





In order to refresh the webpage, write this link in the browser: http://localhost:3000/distributed

In the "peer B" block 4, write: "crypto"

In the "peer C" block 4, write the same.

Mine the blocks until all blocks turn green. y

The majorities always win



```

[[BinaryHeaven]]