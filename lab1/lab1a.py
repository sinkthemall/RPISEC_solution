from pwn import *
s = process(executable = "./lab1A", argv = [])
username = b"d4rkn19ht"
serial = 0
serial = (username[3] ^ 0x1337) + 6221293
for i in range(len(username)):
    serial = (serial + ((serial ^ username[i]) ) % 0x539)
s.sendline(username)
#print(serial)
#s.interactive()
s.sendline(str(serial).encode())
s.interactive()
