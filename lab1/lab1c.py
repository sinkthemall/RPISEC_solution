from pwn import *
s = process(executable = "./lab1C", argv = [])
s.sendline(b"5274")
s.interactive()
