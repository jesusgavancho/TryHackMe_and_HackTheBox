----
Hey, do a flip!
----

![222](https://tryhackme-images.s3.amazonaws.com/room-icons/30129d71d291d86c1976d56c3333d8f7.png)


### Task 1  Source Code

 Download Task Files

First, go ahead and review the source code before moving on to Task 2.  
  
You can review the source code by clicking on the Download Task Files button at the top of this task to download the required file.

Answer the questions below

Download the source code.  

 Completed

### Task 2  What is the flag?

 Start Machine

Log in as the admin and capture the flag!

If you can...  

Whenever you are ready, click on the **Start Machine** button to fire up the Virtual Machine. Please allow 3-5 minutes for the VM to fully start.

The server is listening on port 1337 via TCP. You can connect to it using Netcat or any other tool you prefer.

Answer the questions below

What is the flag?

```
import socketserver 
import socket, os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Random import get_random_bytes
from binascii import unhexlify

flag = open('flag','r').read().strip()

def encrypt_data(data,key,iv):
    padded = pad(data.encode(),16,style='pkcs7')
    cipher = AES.new(key, AES.MODE_CBC,iv)
    enc = cipher.encrypt(padded)
    return enc.hex()

def decrypt_data(encryptedParams,key,iv):
    cipher = AES.new(key, AES.MODE_CBC,iv)
    paddedParams = cipher.decrypt( unhexlify(encryptedParams))
    if b'admin&password=sUp3rPaSs1' in unpad(paddedParams,16,style='pkcs7'):
        return 1
    else:
        return 0

def send_message(server, message):
    enc = message.encode()
    server.send(enc)

def setup(server,username,password,key,iv):
        message = 'access_username=' + username +'&password=' + password
        send_message(server, "Leaked ciphertext: " + encrypt_data(message,key,iv)+'\n')
        send_message(server,"enter ciphertext: ")

        enc_message = server.recv(4096).decode().strip()

        try:
                check = decrypt_data(enc_message,key,iv)
        except Exception as e:
                send_message(server, str(e) + '\n')
                server.close()

        if check:
                send_message(server, 'No way! You got it!\nA nice flag for you: '+ flag)
                server.close()
        else:
                send_message(server, 'Flip off!')
                server.close()

def start(server):
        key = get_random_bytes(16)
        iv = get_random_bytes(16)
        send_message(server, 'Welcome! Please login as the admin!\n')
        send_message(server, 'username: ')
        username = server.recv(4096).decode().strip()

        send_message(server, username +"'s password: ")
        password = server.recv(4096).decode().strip()

        message = 'access_username=' + username +'&password=' + password

        if "admin&password=sUp3rPaSs1" in message:
            send_message(server, 'Not that easy :)\nGoodbye!\n')
        else:
            setup(server,username,password,key,iv)

class RequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        start(self.request)

if __name__ == '__main__':
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    server = socketserver.ThreadingTCPServer(('0.0.0.0', 1337), RequestHandler)
    server.serve_forever()

┌──(witty㉿kali)-[/usr/share/wordlists/seclists/Passwords]
└─$ nc 10.10.212.171 1337
Welcome! Please login as the admin!
username: admin
admin's password: sUp3rPaSs1
Not that easy :)
Goodbye!

┌──(witty㉿kali)-[/usr/share/wordlists/seclists/Passwords]
└─$ nc 10.10.212.171 1337
Welcome! Please login as the admin!
username: bdmin
bdmin's password: sUp3rPaSs1
Leaked ciphertext: 51d22bb11e1b8ea82f19c94ee689f3ef868afc48784d1603ce1e18628269cf41167926f553079ed7fa4ce546d43e4273

┌──(witty㉿kali)-[/usr/share/wordlists/seclists/Passwords]
└─$ nc 10.10.212.171 1337
Welcome! Please login as the admin!
username: bdmin
bdmin's password: sUp3rPaSs1
Leaked ciphertext: b8f8ee11c7b25dd536f2a7818c2fbac348a15eed7c0c1f929cc891590f75b7a346b8bab98797c2fe05694d1d49fd20ae
enter ciphertext: b8f8ee11c7b25dd536f2a7818c2fbac348a15eed7c0c1f929cc891590f75b7a346b8bab98797c2fe05694d1d49fd20ae
Flip off! 

CBC (Cipher Block Chaining) mode is a widely used block cipher mode of operation in cryptography. It is used to encrypt data in blocks, where each block is typically 128 bits (16 bytes) in length. CBC mode adds an additional layer of security and prevents patterns from appearing in the encrypted output.

In CBC mode, the plaintext is divided into blocks, and each block is XORed with the previous ciphertext block before encryption. This XOR operation introduces a feedback mechanism, making the encryption of each block dependent on the previous ciphertext block. It helps prevent identical plaintext blocks from producing the same ciphertext blocks, adding a level of diffusion and making it more resistant to certain types of attacks.

Here's a simple example of how CBC mode encryption works:

Suppose we have the following plaintext (16 bytes):

arduinoCopy code

`Plain text:  "Hello, CBC mode!"`

1. Initialization Vector (IV) generation: An Initialization Vector is a random value of the same block size used to start the chaining process. For the first block, there's no previous ciphertext block, so we use an IV. Let's assume the IV is:

vbnetCopy code

`IV:  "RandomIVValue!!"`

2. Padding: If the plaintext is not exactly divisible by the block size, padding is added to make it a multiple of the block size. In this example, assume no padding is required.
    
3. Encryption:
    

- Block 1: XOR the IV with the first block of plaintext and then encrypt the result.

rustCopy code

`IV XOR "Hello, CBC mode!" --> "RandomIVValue!! XOR Hello, CBC mode!" --> "EncryptedBlock1"`

- Block 2: XOR the encrypted Block 1 with the second block of plaintext and then encrypt the result.

rustCopy code

`EncryptedBlock1 XOR "!" --> "EncryptedBlock1 XOR !" --> "EncryptedBlock2"`

- Continue this process for the remaining blocks of plaintext until all blocks are encrypted.

4. Final ciphertext:

vbnetCopy code

`Ciphertext:  "EncryptedBlock1 EncryptedBlock2 ..."`

The ciphertext is the output of the encryption process and can be safely transmitted or stored without revealing the original plaintext.

It's important to note that the IV must be unique and unpredictable for each encryption process to achieve the desired security properties. Additionally, to decrypt the ciphertext, the receiver must have the correct IV and the encryption key used during the encryption process. Otherwise, decryption will not produce the correct original plaintext.

https://zhangzeyu2001.medium.com/attacking-cbc-mode-bit-flipping-7e0a1c185511

┌──(witty㉿kali)-[~]
└─$ python3                  
Python 3.11.2 (main, Feb 12 2023, 00:48:52) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> len('access_username=admin&password=sUp3rPaSs1')
41
>>> len('0fedab00e630932f011e423fcb4ef82e1ac83a5911ffd729c3695b536e612959674af015040a1c9e2af754ff9196496a')
96
>>> 96/2
48.0

┌──(witty㉿kali)-[~]
└─$ cat flip_attack.py 
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Util.number import bytes_to_long
from Crypto.Random import get_random_bytes
from binascii import unhexlify
from pwn import *
import re

key = get_random_bytes(16)
iv = get_random_bytes(16)

def encrypt_data(data):
    padded = pad(data.encode(),16,style='pkcs7')
    cipher = AES.new(key, AES.MODE_CBC,iv)
    enc = cipher.encrypt(padded)
    return enc.hex()

def decrypt_data(encryptedParams):
    cipher = AES.new(key, AES.MODE_CBC,iv)
    paddedParams = cipher.decrypt( unhexlify(encryptedParams))
    print(paddedParams)
    if b'admin&password=sUp3rPaSs1' in unpad(paddedParams,16,style='pkcs7'):
        return 1
    else:
        return 0

user = 'admin&parsword=sUp3rPaSs1'
password = 'sUp3rPaSs1'
msg = 'access_username=' + user +'&password=' + password
print(msg, len(msg))

xor = ord('r') ^ ord('s')
cipher = encrypt_data(msg)
cipher = cipher[:16] + hex(int(cipher[16:18], 16) ^ xor)[2:] + cipher[18:]
print(decrypt_data(cipher))

conn = remote('10.10.212.171', 1337)

print(conn.recv())
print(conn.recv())
conn.send('admin&parsword=sUp3rPaSs1\r\n')
print(conn.recv())
conn.send('\r\n')

match = re.match(r'Leaked ciphertext: (.+)\n', conn.recv().decode())
print('Ciphertext:', match[1])

cipher = match[1]
cipher = cipher[:16] + hex(int(cipher[16:18], 16) ^ xor)[2:] + cipher[18:]
print('Modified Ciphertext', cipher)

print()
conn.send(cipher + '\r\n')
print(conn.recv())

conn.close()


┌──(witty㉿kali)-[~]
└─$ python3 flip_attack.py 
access_username=admin&parsword=sUp3rPaSs1&password=sUp3rPaSs1 61
b'$\xbe>\xa6\xd4\x1e\x16\x08\x96!:o\x98I\xbc\xadadmin&password=sUp3rPaSs1&password=sUp3rPaSs1\x03\x03\x03'
1
[+] Opening connection to 10.10.212.171 on port 1337: Done
b'Welcome! Please login as the admin!\n'
b'username: '
/home/witty/flip_attack.py:41: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  conn.send('admin&parsword=sUp3rPaSs1\r\n')
b"admin&parsword=sUp3rPaSs1's password: "
/home/witty/flip_attack.py:43: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  conn.send('\r\n')
Ciphertext: a2467a0b6331e478f22bdd215246f26562817d09b3bbb9097f17403453fed0308793df5b901e338d4044dca43de47c93f8347003f3800876c9d430d1ed2c9ecf
Modified Ciphertext a2467a0b6331e478f32bdd215246f26562817d09b3bbb9097f17403453fed0308793df5b901e338d4044dca43de47c93f8347003f3800876c9d430d1ed2c9ecf

/home/witty/flip_attack.py:53: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  conn.send(cipher + '\r\n')
b'enter ciphertext: No way! You got it!\nA nice flag for you: THM{FliP_DaT_B1t_oR_G3t_Fl1pP3d}'
[*] Closed connection to 10.10.212.171 port 1337

https://www.youtube.com/watch?v=QG-z0r9afIs

https://0xboku.com/2021/09/14/0dayappsecBeginnerGuide.html

```

*THM{FliP_DaT_B1t_oR_G3t_Fl1pP3d}*


[[Intro to Detection Engineering]]