from pwn import *
s = process(executable = "./lab1B", argv = [])
def xor(a,b):
    return bytes([i ^ j for i,j in zip(a,b)])

target = b"Congratulations!"
original = b"Q}|u`sfg~sf{}|a3"
ans = 0
for i in range(22):
    if xor(bytes([i]) * len(target), original) == target:
        ans = i
        break
s.sendline(str(322424845 - ans).encode())
s.interactive()
