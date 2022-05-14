from myconfig import HOST, PORT

from pwn import *

server = remote(HOST, PORT)

input_message = b"This is the message"
server.send(input_message)

ciphertext = server.recv(1024)

print(ciphertext)
